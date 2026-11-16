// Retires the offline service worker the web app registered at this address
// before the website moved. Browsers check this file for updates; this
// version deletes the old caches, unregisters itself and reloads the pages
// it controlled, which then redirect to the new website.
self.addEventListener("install", () => self.skipWaiting());

self.addEventListener("activate", (event) => {
  event.waitUntil((async () => {
    for (const key of await caches.keys()) {
      if (key.startsWith("c2paseal-")) await caches.delete(key);
    }
    await self.registration.unregister();
    for (const client of await self.clients.matchAll({ type: "window" })) client.navigate(client.url);
  })());
});
