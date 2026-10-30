// public/sw.js

const CACHE_NAME = '501books-static-v7';
const ASSETS_TO_CACHE = [
  '/',
  '/index.html',
  'https://cdnjs.cloudflare.com/ajax/libs/jszip/3.10.1/jszip.min.js',
  'https://cdn.jsdelivr.net/npm/epubjs/dist/epub.min.js',
  'https://cdnjs.cloudflare.com/ajax/libs/jquery/3.6.0/jquery.min.js',
  'https://cdnjs.cloudflare.com/ajax/libs/chess.js/0.10.3/chess.min.js',
  'https://unpkg.com/@chrisoakman/chessboardjs@1.0.0/dist/chessboard-1.0.0.min.js',
  'https://unpkg.com/@chrisoakman/chessboardjs@1.0.0/dist/chessboard-1.0.0.min.css'
];

// Install Event: Cache app shell and scripts safely using cache.put() for opaque CDN responses
self.addEventListener('install', (e) => {
  e.waitUntil(
    caches.open(CACHE_NAME).then(async (cache) => {
      await Promise.all(
        ASSETS_TO_CACHE.map(async (url) => {
          try {
            const response = await fetch(new Request(url, { mode: 'no-cors' }));
            if (response) {
              await cache.put(url, response);
            }
          } catch (err) {
            console.warn('Failed to cache asset during install:', url, err);
          }
        })
      );
    })
  );
  self.skipWaiting();
});

// Activate Event: Clean up old caches
self.addEventListener('activate', (e) => {
  e.waitUntil(
    caches.keys().then((keys) => {
      return Promise.all(
        keys.map((key) => {
          if (key !== CACHE_NAME) {
            return caches.delete(key);
          }
        })
      );
    })
  );
  self.clients.claim();
});

// Fetch Event: Serve cached assets offline, let API calls pass through
self.addEventListener('fetch', (e) => {
  const url = new URL(e.request.url);

  // Bypass service worker for backend API endpoints
  if (url.pathname.startsWith('/api/')) {
    return;
  }

  // Handle navigation requests (cold starts / page loads)
  if (e.request.mode === 'navigate') {
    e.respondWith(
      fetch(e.request)
        .catch(() => {
          return caches.match('/') || caches.match('/index.html');
        })
    );
    return;
  }

  // Standard cache-first strategy for static assets & scripts
  e.respondWith(
    caches.match(e.request).then((cachedResponse) => {
      if (cachedResponse) {
        return cachedResponse;
      }
      return fetch(e.request).catch(() => {
        // Fallback for sub-resources if needed
      });
    })
  );
});