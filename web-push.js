// Web Push with nothing but Node's built-in crypto: no dependencies, so a GitHub Actions workflow
// (or any script) can notify a phone without `npm install`.
//
// Two standards do all the work:
//   RFC 8292 (VAPID)  an ES256-signed token that identifies the sender to the push service
//   RFC 8291          aes128gcm encryption of the payload, readable only by the subscribed browser
// and RFC 8030 is the plain HTTP POST that carries them.
//
// As a library:
//   const { sendNotification } = require('./web-push');
//   const status = await sendNotification(subscription, { title: 'Hi', body: 'From CI' },
//       { vapidKey, subject: 'mailto:you@example.com' });
//
// From the command line (Node 18+):
//   node web-push.js keys                       generate a VAPID key pair
//   node web-push.js send "Title" "Body" [url]  send to PUSH_SUBSCRIPTION (one, or a JSON array)
//   node web-push.js --selftest                 RFC 8291's own test vector, plus signing checks
// `send` reads VAPID_PRIVATE_KEY (the JWK `keys` printed), VAPID_SUBJECT and PUSH_SUBSCRIPTION.
const crypto = require('crypto');

const b64u = buf => Buffer.from(buf).toString('base64url');
const unb64u = s => Buffer.from(String(s).replace(/\s+/g, ''), 'base64url');

// One aes128gcm record of 4096 bytes holds the 86-byte header, the 16-byte tag and the 1-byte
// delimiter, which leaves this much for the payload.
const MAX_PAYLOAD = 4096 - 86 - 16 - 1;

// HKDF with a single 32-byte output block, which is all RFC 8291 ever asks for.
const hmac = (key, data) => crypto.createHmac('sha256', key).update(data).digest();
const hkdf = (salt, ikm, info, len) => hmac(hmac(salt, ikm), Buffer.concat([info, Buffer.from([1])])).subarray(0, len);

function keysFor(salt, shared, auth, uaPublic, asPublic) {
    const ikm = hkdf(auth, shared, Buffer.concat([Buffer.from('WebPush: info\0'), uaPublic, asPublic]), 32);
    return {
        cek: hkdf(salt, ikm, Buffer.from('Content-Encoding: aes128gcm\0'), 16),
        nonce: hkdf(salt, ikm, Buffer.from('Content-Encoding: nonce\0'), 12),
    };
}

// RFC 8291 aes128gcm: one record, the payload followed by the 0x02 last-record delimiter.
// `fixed` ({ salt, asPrivate }) exists only to reproduce the RFC's test vector; leave it out, and
// every message gets a fresh salt and a fresh sender key, as the standard requires.
function encrypt(payload, subscription, fixed = {}) {
    const plain = Buffer.from(payload);
    if (plain.length > MAX_PAYLOAD) throw new Error(`payload is ${plain.length} bytes; Web Push allows ${MAX_PAYLOAD}`);
    const salt = fixed.salt || crypto.randomBytes(16);
    const ecdh = crypto.createECDH('prime256v1');
    if (fixed.asPrivate) ecdh.setPrivateKey(fixed.asPrivate); else ecdh.generateKeys();
    const asPublic = ecdh.getPublicKey();
    const uaPublic = unb64u(subscription.keys.p256dh), auth = unb64u(subscription.keys.auth);
    const { cek, nonce } = keysFor(salt, ecdh.computeSecret(uaPublic), auth, uaPublic, asPublic);
    const cipher = crypto.createCipheriv('aes-128-gcm', cek, nonce);
    const body = Buffer.concat([cipher.update(Buffer.concat([plain, Buffer.from([2])])), cipher.final(), cipher.getAuthTag()]);
    const header = Buffer.alloc(21);
    salt.copy(header, 0);
    header.writeUInt32BE(4096, 16);
    header[20] = asPublic.length;
    return Buffer.concat([header, asPublic, body]);
}

// The browser's side, so the selftest can prove a round trip as well as the RFC vector.
function decrypt(message, uaEcdh, auth) {
    const salt = message.subarray(0, 16), idlen = message[20], asPublic = message.subarray(21, 21 + idlen);
    const { cek, nonce } = keysFor(salt, uaEcdh.computeSecret(asPublic), auth, uaEcdh.getPublicKey(), asPublic);
    const data = message.subarray(21 + idlen);
    const d = crypto.createDecipheriv('aes-128-gcm', cek, nonce);
    d.setAuthTag(data.subarray(data.length - 16));
    const plain = Buffer.concat([d.update(data.subarray(0, data.length - 16)), d.final()]);
    return plain.subarray(0, plain.lastIndexOf(2)).toString();
}

// The public key in the form the browser's pushManager.subscribe() wants: the uncompressed
// P-256 point, base64url.
const vapidPublicKey = jwk => b64u(Buffer.concat([Buffer.from([4]), unb64u(jwk.x), unb64u(jwk.y)]));

// A new key pair: the private half as a JWK (keep it secret), the public half for the page.
function generateVapidKeys() {
    const { privateKey } = crypto.generateKeyPairSync('ec', { namedCurve: 'prime256v1' });
    const jwk = privateKey.export({ format: 'jwk' });
    return { privateJwk: jwk, publicKey: vapidPublicKey(jwk) };
}

// RFC 8292: a JWT for the push service's origin, valid 12 hours, signed ES256 (raw r||s).
function vapidAuthorization(endpoint, jwk, subject, now = Date.now()) {
    if (!/^(mailto:|https:\/\/)/.test(subject || '')) throw new Error('VAPID subject must be a mailto: or https: URL');
    const head = b64u(JSON.stringify({ typ: 'JWT', alg: 'ES256' }));
    const claims = b64u(JSON.stringify({ aud: new URL(endpoint).origin, exp: Math.floor(now / 1000) + 12 * 3600, sub: subject }));
    const key = crypto.createPrivateKey({ key: jwk, format: 'jwk' });
    const sig = crypto.sign('sha256', Buffer.from(`${head}.${claims}`), { key, dsaEncoding: 'ieee-p1363' });
    return `vapid t=${head}.${claims}.${b64u(sig)}, k=${vapidPublicKey(jwk)}`;
}

// Sends one notification and returns the push service's HTTP status. 201 means accepted; 404 or
// 410 means the subscription is gone (permission revoked, site data cleared), so drop it.
async function sendNotification(subscription, payload, { vapidKey, subject, ttl = 43200, urgency = 'normal' } = {}) {
    const res = await fetch(subscription.endpoint, {
        method: 'POST',
        headers: {
            Authorization: vapidAuthorization(subscription.endpoint, vapidKey, subject),
            'Content-Encoding': 'aes128gcm',
            'Content-Type': 'application/octet-stream',
            TTL: String(ttl),
            Urgency: urgency,
        },
        body: encrypt(typeof payload === 'string' ? payload : JSON.stringify(payload), subscription),
    });
    return res.status;
}

async function cli(args) {
    if (args[0] === 'keys') {
        const { privateJwk, publicKey } = generateVapidKeys();
        console.log('VAPID_PRIVATE_KEY (store as a secret, never commit):');
        console.log(JSON.stringify(privateJwk));
        console.log('\nPublic key (paste into index.html; safe to publish):');
        console.log(publicKey);
        return;
    }
    if (args[0] === 'send') {
        const [, title = 'Notification', body = '', url] = args;
        const read = name => { const v = process.env[name]; if (!v) throw new Error(`${name} is not set`); return v; };
        const vapidKey = JSON.parse(read('VAPID_PRIVATE_KEY'));
        const subject = read('VAPID_SUBJECT');
        const subs = [].concat(JSON.parse(read('PUSH_SUBSCRIPTION')));
        let failed = 0;
        for (const sub of subs) {
            const status = await sendNotification(sub, { title, body, ...(url ? { url } : {}) }, { vapidKey, subject });
            const host = new URL(sub.endpoint).host;
            const ok = status >= 200 && status < 300;
            if (!ok) failed++;
            console.log(`${host}: ${status}${status === 404 || status === 410 ? ' (subscription expired: subscribe again)' : ''}`);
        }
        process.exitCode = failed ? 1 : 0;
        return;
    }
    console.log('usage: node web-push.js keys | send "Title" "Body" [url] | --selftest');
    process.exitCode = 1;
}

function selftest() {
    const assert = require('assert');

    // RFC 8291, Section 5 and Appendix A: fixed keys, salt and plaintext give this exact message.
    const ua = crypto.createECDH('prime256v1');
    ua.setPrivateKey(unb64u('q1dXpw3UpT5VOmu_cf_v6ih07Aems3njxI-JWgLcM94'));
    const sub = { endpoint: 'https://push.example.net/push/JzLQ3raZJfFBR0aqvOMsLrt54w4rJUsV',
        keys: { p256dh: b64u(ua.getPublicKey()), auth: 'BTBZMqHH6r4Tts7J_aSIgg' } };
    assert.strictEqual(sub.keys.p256dh, 'BCVxsr7N_eNgVRqvHtD0zTZsEc6-VV-JvLexhqUzORcxaOzi6-AYWXvTBHm4bjyPjs7Vd8pZGH6SRpkNtoIAiw4');
    const wire = encrypt('When I grow up, I want to be a watermelon', sub, {
        salt: unb64u('DGv6ra1nlYgDCS1FRnbzlw'), asPrivate: unb64u('yfWPiYE-n46HLnH0KqZOF1fJJU3MYrct3AELtAQ-oRw') });
    // Appendix A gives the 86-byte header and the ciphertext separately; compare bytes, since two
    // base64 strings cannot simply be joined when the first is not a multiple of 3 bytes.
    const expected = Buffer.concat([
        unb64u('DGv6ra1nlYgDCS1FRnbzlwAAEABBBP4z 9KsN6nGRTbVYI_c7VJSPQTBtkgcy27ml mlMoZIIgDll6e3vCYLocInmYWAmS6Tlz AC8wEqKK6PBru3jl7A8'),
        unb64u('8pfeW0KbunFT06SuDKoJH9Ql87S1QUrd irN6GcG7sFz1y1sqLgVi1VhjVkHsUoEs bI_0LpXMuGvnzQ'),
    ]);
    assert.ok(wire.equals(expected), 'RFC 8291 test vector');

    // A random message decrypts on the browser's side.
    const auth = crypto.randomBytes(16);
    const live = { endpoint: sub.endpoint, keys: { p256dh: sub.keys.p256dh, auth: b64u(auth) } };
    assert.strictEqual(decrypt(encrypt('{"title":"Hi"}', live), ua, auth), '{"title":"Hi"}');
    assert.throws(() => encrypt('x'.repeat(MAX_PAYLOAD + 1), live), /Web Push allows/);

    // VAPID: the token verifies with the public half, and is scoped to the push service.
    const { privateJwk, publicKey } = generateVapidKeys();
    assert.strictEqual(unb64u(publicKey).length, 65, 'an uncompressed P-256 point');
    const [jwt] = vapidAuthorization(sub.endpoint, privateJwk, 'mailto:a@example.com').slice('vapid t='.length).split(', k=');
    const [h, c, s] = jwt.split('.');
    const pub = crypto.createPublicKey({ key: { ...privateJwk, d: undefined }, format: 'jwk' });
    assert.ok(crypto.verify('sha256', Buffer.from(`${h}.${c}`), { key: pub, dsaEncoding: 'ieee-p1363' }, unb64u(s)));
    assert.strictEqual(JSON.parse(unb64u(c)).aud, 'https://push.example.net');
    assert.throws(() => vapidAuthorization(sub.endpoint, privateJwk, 'a@example.com'), /mailto/);
    console.log('selftest ok');
}

if (require.main === module) {
    if (process.argv.includes('--selftest')) selftest();
    else cli(process.argv.slice(2)).catch(e => { console.error(e.message); process.exitCode = 1; });
}
module.exports = { sendNotification, generateVapidKeys, vapidPublicKey, vapidAuthorization, encrypt, decrypt, MAX_PAYLOAD };
