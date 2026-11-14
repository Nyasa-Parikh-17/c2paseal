// Service worker: keeps the app working offline after the first visit.
// Registered by app.js only when the WebAssembly build is present (not under
// `c2paseal serve`). Files are served from the cache first; the pages
// workflow replaces VERSION with the commit, so a new deployment installs a
// new cache and removes the old one.
const VERSION = "dev";
const CACHE = "c2paseal-" + VERSION;
const ASSETS = [
  "./",
  "index.html",
  "app.js",
  "app.css",
  "icon.svg",
  "wasm_exec.js",
  "c2paseal.wasm",
  "demo/demo-chain.pem",
  "demo/demo.key",
  "demo/demo-root.pem",
  "demo/sample.jpg",
];

self.addEventListener("install", (event) => {
  event.waitUntil(caches.open(CACHE).then((c) => c.addAll(ASSETS)).then(() => self.skipWaiting()));
});

self.addEventListener("activate", (event) => {
  event.waitUntil((async () => {
    for (const key of await caches.keys()) {
      if (key.startsWith("c2paseal-") && key !== CACHE) await caches.delete(key);
    }
    await self.clients.claim();
  })());
});

self.addEventListener("fetch", (event) => {
  const req = event.request;
  if (req.method !== "GET" || new URL(req.url).origin !== self.location.origin) return;
  event.respondWith((async () => {
    const cache = await caches.open(CACHE);
    const hit = await cache.match(req, { ignoreSearch: true }) ||
      (req.mode === "navigate" ? await cache.match("./") : undefined);
    return hit || fetch(req);
  })());
});
