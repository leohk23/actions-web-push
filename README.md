# actions-web-push

Send push notifications to your phone from **GitHub Actions** (or any Node script), with **no
dependencies**: just Node's built-in `crypto`.

Useful when your project is a static site or a scheduled workflow with no server of its own: a
price alert, a build that finished, a scraper that found something. The workflow is the sender,
and the browser's own push service delivers the notification, even when the page is closed.

- One file, `web-push.js`: no `npm install`, so a workflow can run it straight after checkout.
- Standards only: [RFC 8292](https://www.rfc-editor.org/rfc/rfc8292) (VAPID) to identify the
  sender and [RFC 8291](https://www.rfc-editor.org/rfc/rfc8291) to encrypt the payload end to end.
- Tested against RFC 8291's own test vector, byte for byte (`node web-push.js --selftest`).

## How it works

```
your phone ──(1) subscribe once──▶ push service (Google, Mozilla, Apple)
     ▲                                    ▲
     │ (3) notification                   │ (2) encrypted POST, signed with your VAPID key
     └────────────────────────────────────┴──── GitHub Actions: node web-push.js send ...
```

1. A page you host (`index.html` + `sw.js`) asks the phone for permission and produces a
   **subscription**: an endpoint URL plus two keys. You store it as a secret.
2. The workflow encrypts the message for that subscription and POSTs it to the endpoint.
3. The phone's service worker (`sw.js`) shows it.

## Setup

**Needs:** Node 18 or later, and somewhere to host two static files over HTTPS (GitHub Pages works).

1. **Make a key pair.**

   ```sh
   node web-push.js keys
   ```

   Keep the private JWK secret. Paste the public key into `VAPID_PUBLIC_KEY` in `index.html`.

2. **Host the page.** Enable GitHub Pages for this repository (Settings → Pages → deploy from the
   main branch, root folder). `index.html`, `sw.js` and `manifest.webmanifest` must sit together.

3. **Subscribe a device.** Open the page on the phone and press **Enable notifications**. Copy the
   code it shows.
   - **Android** (Chrome, Firefox): works in the browser.
   - **iPhone and iPad** (iOS 16.4 or later): first add the page to the Home Screen, then open
     it from there and subscribe. Safari does not allow web push for a page in a tab.

4. **Add three repository secrets** (Settings → Secrets and variables → Actions):

   | Secret | Value |
   |---|---|
   | `VAPID_PRIVATE_KEY` | the private JWK from step 1 |
   | `VAPID_SUBJECT` | `mailto:you@example.com` (or an `https:` URL): push services require a contact |
   | `PUSH_SUBSCRIPTION` | the code from step 3, or a JSON array of several |

5. **Send one.** Actions → notify → Run workflow. Or from your own workflow:

   ```yaml
   - run: node web-push.js send "Deploy finished" "main is live"
     env:
       VAPID_PRIVATE_KEY: ${{ secrets.VAPID_PRIVATE_KEY }}
       VAPID_SUBJECT: ${{ secrets.VAPID_SUBJECT }}
       PUSH_SUBSCRIPTION: ${{ secrets.PUSH_SUBSCRIPTION }}
   ```

   An optional third argument is a URL to open when the notification is tapped.

## As a library

```js
const { sendNotification } = require('./web-push');

const status = await sendNotification(
  subscription,                               // the object index.html produced
  { title: 'Price alert', body: 'AMD +6.2% today', tag: 'moves', url: 'https://example.com' },
  { vapidKey: privateJwk, subject: 'mailto:you@example.com', ttl: 43200, urgency: 'high' },
);
```

It returns the push service's HTTP status. **201** means accepted. **404** or **410** means the
subscription no longer exists (the user revoked permission or cleared the site's data), so
subscribe that device again. `tag` makes a newer notification replace an unread one with the same
tag; `ttl` is how long, in seconds, the push service keeps it for an offline device.

## Limits

- **Payload:** up to 3,993 bytes, one encrypted record. `encrypt()` throws if it is longer.
- **No retries or queueing.** One request per subscription; act on the status yourself.
- **Delivery timing** is the push service's and the device's. Android may delay notifications
  while the phone is in deep sleep, unless `urgency` is `high`.
- Browser support follows the platforms' Web Push support. Tested by the author on Firefox for
  Android; Chrome and iOS are covered by the same standards. Issues and reports are welcome.

## Security

- The **VAPID private key** is the only real secret: it lets anyone send to your subscriptions.
- A **subscription** identifies one device. It cannot be used without your private key, but
  keep it out of public places anyway.
- Payloads are encrypted for the receiving browser; the push service cannot read them.

## Licence

MIT. See [LICENSE](LICENSE).
