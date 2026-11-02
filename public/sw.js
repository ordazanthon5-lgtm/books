// public/sw.js
const CACHE_NAME = '501books-static-v10';  // bump this number every time you change sw.js
const APP_SHELL = ['/', '/index.html', '/db.js?v=2'];
const CDN_ASSETS = [
  'https://cdnjs.cloudflare.com/ajax/libs/jszip/3.10.1/jszip.min.js',
  'https://cdn.jsdelivr.net/npm/epubjs/dist/epub.min.js',
  'https://cdnjs.cloudflare.com/ajax/libs/jquery/3.6.0/jquery.min.js',
  'https://cdnjs.cloudflare.com/ajax/libs/chess.js/0.10.3/chess.min.js',
  'https://unpkg.com/@chrisoakman/chessboardjs@1.0.0/dist/chessboard-1.0.0.min.js',
  'https://unpkg.com/@chrisoakman/chessboardjs@1.0.0/dist/chessboard-1.0.0.min.css'
];

self.addEventListener('install', (e) => {
  e.waitUntil((async () => {
    const cache = await caches.open(CACHE_NAME);
    // Same-origin files MUST cache, otherwise the install fails and retries later
    await cache.addAll(APP_SHELL);
    // CDN files are best-effort (opaque responses)
    await Promise.all(CDN_ASSETS.map(async (url) => {
      try {
        const res = await fetch(url, { mode: 'no-cors' });
        await cache.put(url, res);
      } catch (err) {
        console.warn('CDN cache failed:', url, err);
      }
    }));
  })());
  self.skipWaiting();
});

self.addEventListener('activate', (e) => {
  e.waitUntil((async () => {
    const keys = await caches.keys();
    await Promise.all(
      keys
        // ONLY remove old static caches. Never touch the downloaded-epub cache.
        .filter((k) => k.startsWith('501books-static-') && k !== CACHE_NAME)
        .map((k) => caches.delete(k))
    );
    await self.clients.claim();
  })());
});

self.addEventListener('fetch', (e) => {
  const req = e.request;
  if (req.method !== 'GET') return;

  const url = new URL(req.url);
  if (url.pathname.startsWith('/api/')) return;

  // Page loads: network first; keep the saved copy of the page fresh; cached copy when offline
  if (req.mode === 'navigate') {
    e.respondWith((async () => {
      try {
        const res = await fetch(req);
        if (res.ok && (url.pathname === '/' || url.pathname === '/index.html')) {
          const cache = await caches.open(CACHE_NAME);
          cache.put('/index.html', res.clone());
        }
        return res;
      } catch (err) {
        return (await caches.match('/index.html')) ||
               (await caches.match('/')) ||
               new Response('Offline', { status: 503 });
      }
    })());
    return;
  }

  // Everything else: serve the saved copy instantly; refresh own files in the background
  e.respondWith((async () => {
    const cached = await caches.match(req);
    const sameOrigin = url.origin === self.location.origin;

    const refresh = sameOrigin
      ? fetch(req).then(async (res) => {
          if (res.ok) {
            const cache = await caches.open(CACHE_NAME);
            await cache.put(req, res.clone());
          }
          return res;
        }).catch(() => null)
      : null;

    if (cached) {
      if (refresh) e.waitUntil(refresh);
      return cached;
    }

    if (refresh) {
      return (await refresh) || new Response('', { status: 503 });
    }
    try {
      const res = await fetch(req);
      // Self-healing: any CDN script/stylesheet that loads fine online gets saved for offline use
      const isLib = req.destination === 'script' || req.destination === 'style';
      if (isLib && (res.ok || res.type === 'opaque')) {
        const cache = await caches.open(CACHE_NAME);
        cache.put(req, res.clone());
      }
      return res;
    } catch (err) {
      return new Response('', { status: 503 });
    }
  })());
});