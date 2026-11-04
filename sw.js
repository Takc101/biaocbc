/* 表白墙 PWA Service Worker
   策略：页面走「网络优先」保证每次都是最新代码；静态资源走「缓存优先」加速。 */
const CACHE = "bq-shell-v4";
const ASSETS = [
  "./",
  "./index.html",
  "./manifest.webmanifest",
  "./icon-192.png",
  "./icon-512.png",
  "./apple-touch-icon.png"
];

self.addEventListener("install", event => {
  self.skipWaiting();
  event.waitUntil(
    caches.open(CACHE).then(cache => cache.addAll(ASSETS).catch(() => {}))
  );
});

self.addEventListener("activate", event => {
  event.waitUntil(
    caches.keys()
      .then(keys => Promise.all(keys.filter(k => k !== CACHE).map(k => caches.delete(k))))
      .then(() => self.clients.claim())
  );
});

self.addEventListener("fetch", event => {
  const req = event.request;
  if (req.method !== "GET") return;

  const url = new URL(req.url);
  if (url.origin !== self.location.origin) return; /* 跨域接口交给浏览器 */

  /* 音频不走缓存：播放器要发 Range 请求边下边放，被缓存挡一刀会在部分机型上卡住 */
  if (/\.(mp3|m4a|aac|wav|ogg|oga|flac|weba)$/i.test(url.pathname)) return;

  const isPage = req.mode === "navigate" || /\/index\.html$/.test(url.pathname) || url.pathname.endsWith("/");
  const isFresh = /\/qq-daily\.json$/.test(url.pathname); /* 歌单每天变，不能被缓存定死 */

  if (isPage || isFresh) {
    event.respondWith(
      fetch(req)
        .then(res => {
          const copy = res.clone();
          caches.open(CACHE).then(c => c.put(req, copy)).catch(() => {});
          return res;
        })
        .catch(() => caches.match(req).then(hit => hit || (isPage ? caches.match("./index.html") : Response.error())))
    );
    return;
  }

  event.respondWith(
    caches.match(req).then(hit => {
      if (hit) return hit;
      return fetch(req).then(res => {
        if (res && res.status === 200 && res.type === "basic") {
          const copy = res.clone();
          caches.open(CACHE).then(c => c.put(req, copy)).catch(() => {});
        }
        return res;
      });
    })
  );
});
