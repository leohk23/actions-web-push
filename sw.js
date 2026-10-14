// Shows the notifications web-push.js sends, whether or not the page is open. It caches nothing:
// it exists only because a push needs somewhere to land.
self.addEventListener('install', () => self.skipWaiting());
self.addEventListener('activate', e => e.waitUntil(self.clients.claim()));

// The payload is the JSON sent: { title, body, tag?, url? }. A plain-text payload becomes the body.
self.addEventListener('push', e => {
    let msg = { title: 'Notification', body: '' };
    if (e.data) {
        try { msg = { ...msg, ...e.data.json() }; } catch { msg.body = e.data.text(); }
    }
    e.waitUntil(self.registration.showNotification(msg.title, {
        body: msg.body,
        tag: msg.tag,              // a newer notification with the same tag replaces an unread one
        renotify: Boolean(msg.tag),
        data: { url: msg.url },
    }));
});

// Tap: open the payload's url, or this site, focusing it if it is already open.
self.addEventListener('notificationclick', e => {
    e.notification.close();
    const target = new URL(e.notification.data?.url || './', self.registration.scope).href;
    e.waitUntil(self.clients.matchAll({ type: 'window', includeUncontrolled: true }).then(list => {
        const open = list.find(c => c.url === target);
        return open ? open.focus() : self.clients.openWindow(target);
    }));
});
