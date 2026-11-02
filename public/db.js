// public/db.js
// Offline storage for 501Books.
// - Book files  -> IndexedDB (more reliable than the Cache API inside app wrappers)
// - Progress queue + small metadata -> localStorage (synchronous, survives the app being killed)

const DB_NAME = '501books-offline';
const STORE = 'books';
const LEGACY_CACHE = '501books-offline-epub-v1'; // books saved by the old Download button
const META_KEY = 'my_offline_books_meta';
const SYNC_QUEUE_KEY = '501books_offline_sync_queue';

// Ask the OS not to auto-delete downloaded books
async function ensurePersistentStorage() {
  try {
    if (navigator.storage && navigator.storage.persist) {
      const persisted = await navigator.storage.persist();
      console.log(`Storage persistence granted: ${persisted}`);
    }
  } catch (err) {
    console.warn('Persistence request failed:', err);
  }
}
ensurePersistentStorage();

let dbPromise = null;
function openDB() {
  if (!dbPromise) {
    dbPromise = new Promise((resolve, reject) => {
      const req = indexedDB.open(DB_NAME, 1);
      req.onupgradeneeded = () => {
        if (!req.result.objectStoreNames.contains(STORE)) {
          req.result.createObjectStore(STORE, { keyPath: 'id' });
        }
      };
      req.onsuccess = () => resolve(req.result);
      req.onerror = () => { dbPromise = null; reject(req.error); };
    });
  }
  return dbPromise;
}

function tx(mode, fn) {
  return openDB().then(db => new Promise((resolve, reject) => {
    const t = db.transaction(STORE, mode);
    const result = fn(t.objectStore(STORE));
    t.oncomplete = () => resolve(result && 'result' in result ? result.result : undefined);
    t.onerror = () => reject(t.error);
    t.onabort = () => reject(t.error || new Error('Transaction aborted'));
  }));
}

function readMeta() {
  try { return JSON.parse(localStorage.getItem(META_KEY) || '[]'); } catch (e) { return []; }
}

// ---------- Book files ----------

// bookData: { id, title, author, cover_url, url, fileBlob }
export async function saveBookOffline(bookData) {
  const id = Number(bookData.id);
  const data = await bookData.fileBlob.arrayBuffer();
  await tx('readwrite', store => { store.put({ id, data, savedAt: Date.now() }); });

  const list = readMeta().filter(b => Number(b.id) !== id);
  list.push({
    id,
    title: bookData.title || 'Downloaded Book',
    author: bookData.author || 'Offline Reader',
    cover_url: bookData.cover_url || '',
    url: bookData.url || ''
  });
  localStorage.setItem(META_KEY, JSON.stringify(list));
  return true;
}

export async function getOfflineBook(bookId) {
  const id = Number(bookId);
  try {
    const row = await tx('readonly', store => store.get(id));
    if (row && row.data) {
      return { fileBlob: new Blob([row.data], { type: 'application/epub+zip' }) };
    }
  } catch (err) {
    console.error('IndexedDB read failed:', err);
  }
  // Books saved by the old version of the app
  try {
    const cache = await caches.open(LEGACY_CACHE);
    const response = await cache.match(`/book-file-${id}`);
    if (response) return { fileBlob: await response.blob() };
  } catch (e) {}
  return null;
}

export async function isBookDownloaded(bookId) {
  const id = Number(bookId);
  try {
    const n = await tx('readonly', store => store.count(IDBKeyRange.only(id)));
    if (n > 0) return true;
  } catch (e) {}
  try {
    const cache = await caches.open(LEGACY_CACHE);
    return !!(await cache.match(`/book-file-${id}`));
  } catch (e) {
    return false;
  }
}

export async function listDownloadedIds() {
  try {
    return (await tx('readonly', store => store.getAllKeys())).map(Number);
  } catch (e) {
    return [];
  }
}

export async function removeOfflineBook(bookId) {
  const id = Number(bookId);
  try { await tx('readwrite', store => { store.delete(id); }); } catch (e) {}
  try { const c = await caches.open(LEGACY_CACHE); await c.delete(`/book-file-${id}`); } catch (e) {}
  localStorage.setItem(META_KEY, JSON.stringify(readMeta().filter(b => Number(b.id) !== id)));
}

// ---------- Reading-progress sync queue ----------

// Keeps only the latest position per book
export async function queueOfflineBookmark(bookId, bookmarkData) {
  let queue = [];
  try { queue = JSON.parse(localStorage.getItem(SYNC_QUEUE_KEY) || '[]'); } catch (e) {}
  queue = queue.filter(item => item.bookId !== bookId);
  queue.push({ bookId, ...bookmarkData, timestamp: Date.now() });
  localStorage.setItem(SYNC_QUEUE_KEY, JSON.stringify(queue));
  return true;
}

// Read the queue WITHOUT clearing it (items are removed only after the server confirms)
export async function getSyncQueue() {
  try { return JSON.parse(localStorage.getItem(SYNC_QUEUE_KEY) || '[]'); } catch (e) { return []; }
}

// Remove an entry only if it has not been replaced by newer progress in the meantime
export async function removeFromSyncQueue(bookId, timestamp) {
  const queue = await getSyncQueue();
  localStorage.setItem(
    SYNC_QUEUE_KEY,
    JSON.stringify(queue.filter(i => !(i.bookId === bookId && i.timestamp === timestamp)))
  );
}