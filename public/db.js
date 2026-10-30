// public/db.js

const DB_NAME = '501Books_OfflineDB';
const DB_VERSION = 2; // Incremented version to support sync queue store
const STORE_NAME = 'downloaded_books';
const SYNC_QUEUE_STORE = 'offline_sync_queue';

// Open or initialize IndexedDB
export function openDB() {
  return new Promise((resolve, reject) => {
    const request = indexedDB.open(DB_NAME, DB_VERSION);
    
    request.onupgradeneeded = (e) => {
      const db = e.target.result;
      if (!db.objectStoreNames.contains(STORE_NAME)) {
        db.createObjectStore(STORE_NAME, { keyPath: 'id' });
      }
      if (!db.objectStoreNames.contains(SYNC_QUEUE_STORE)) {
        db.createObjectStore(SYNC_QUEUE_STORE, { keyPath: 'bookId' });
      }
    };

    request.onsuccess = () => resolve(request.result);
    request.onerror = () => reject(request.error);
  });
}

// Save downloaded book blob/arrayBuffer to IndexedDB
export async function saveBookOffline(bookData) {
  const db = await openDB();
  return new Promise((resolve, reject) => {
    const tx = db.transaction(STORE_NAME, 'readwrite');
    const store = tx.objectStore(STORE_NAME);
    const req = store.put(bookData);
    
    req.onsuccess = () => resolve(true);
    req.onerror = () => reject(req.error);
  });
}

// Retrieve saved book from IndexedDB
export async function getOfflineBook(bookId) {
  const db = await openDB();
  return new Promise((resolve, reject) => {
    const tx = db.transaction(STORE_NAME, 'readonly');
    const store = tx.objectStore(STORE_NAME);
    const req = store.get(bookId);
    
    req.onsuccess = () => resolve(req.result);
    req.onerror = () => reject(req.error);
  });
}

// Check if a book exists in local offline storage
export async function isBookDownloaded(bookId) {
  const book = await getOfflineBook(bookId);
  return !!book;
}

// Save bookmark progress to queue when offline
export async function queueOfflineBookmark(bookId, bookmarkData) {
  const db = await openDB();
  return new Promise((resolve, reject) => {
    const tx = db.transaction(SYNC_QUEUE_STORE, 'readwrite');
    const store = tx.objectStore(SYNC_QUEUE_STORE);
    const req = store.put({ bookId, ...bookmarkData, timestamp: Date.now() });
    
    req.onsuccess = () => resolve(true);
    req.onerror = () => reject(req.error);
  });
}

// Get and clear pending offline bookmark syncs when back online
export async function getAndClearSyncQueue() {
  const db = await openDB();
  return new Promise((resolve, reject) => {
    const tx = db.transaction(SYNC_QUEUE_STORE, 'readwrite');
    const store = tx.objectStore(SYNC_QUEUE_STORE);
    const getAllReq = store.getAll();

    getAllReq.onsuccess = () => {
      const items = getAllReq.result || [];
      store.clear();
      resolve(items);
    };
    getAllReq.onerror = () => reject(getAllReq.error);
  });
}