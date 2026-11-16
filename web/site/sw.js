// Retires the service worker that the checker registered here, at the site
// root, before it moved to app/ (which has its own, app/sw.js). Browsers
// check this file for updates; this version deletes the old cache,
// unregisters itself and reloads the pages it controlled, so they load the
// current site from the network.
self.addEventListener("install", () => self.skipWaiting());

self.addEventListener("activate", (event) => {
  event.waitUntil((async () => {
    for (const key of await caches.keys()) {
      // The old root worker's caches; app/sw.js uses "c2paseal-app-".
      if (key.startsWith("c2paseal-") && !key.startsWith("c2paseal-app-")) await caches.delete(key);
    }
    await self.registration.unregister();
    for (const client of await self.clients.matchAll({ type: "window" })) client.navigate(client.url);
  })());
});
