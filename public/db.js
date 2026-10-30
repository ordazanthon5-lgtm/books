// public/db.js

const CACHE_NAME = '501books-offline-epub-v1';
const SYNC_QUEUE_KEY = '501books_offline_sync_queue';

// Request OS persistence so mobile devices never auto-delete downloaded books
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

// Save downloaded book blob to Cache API
export async function saveBookOffline(bookData) {
  // bookData expects: { id, title, author, cover_url, url, fileBlob }
  try {
    const cache = await caches.open(CACHE_NAME);
    const response = new Response(bookData.fileBlob);
    await cache.put(`/book-file-${bookData.id}`, response);

    // Save metadata list locally in localStorage for fast querying
    let savedList = JSON.parse(localStorage.getItem('my_offline_books_meta') || '[]');
    if (!savedList.some(b => b.id === bookData.id)) {
      savedList.push({
        id: bookData.id,
        title: bookData.title || 'Downloaded Book',
        author: bookData.author || 'Offline Reader',
        cover_url: bookData.cover_url || '',
        url: bookData.url || ''
      });
      localStorage.setItem('my_offline_books_meta', JSON.stringify(savedList));
    }
    return true;
  } catch (err) {
    console.error('Failed to save book offline via Cache API:', err);
    throw err;
  }
}

// Retrieve saved book ArrayBuffer from Cache API
export async function getOfflineBook(bookId) {
  try {
    const cache = await caches.open(CACHE_NAME);
    const response = await cache.match(`/book-file-${bookId}`);
    if (response) {
      const blob = await response.blob();
      return { fileBlob: blob };
    }
  } catch (err) {
    console.error('Failed to retrieve offline book:', err);
  }
  return null;
}

// Check if a book exists in local offline storage
export async function isBookDownloaded(bookId) {
  try {
    const cache = await caches.open(CACHE_NAME);
    const match = await cache.match(`/book-file-${bookId}`);
    return !!match;
  } catch (e) {
    return false;
  }
}

// Save bookmark progress to queue when offline
export async function queueOfflineBookmark(bookId, bookmarkData) {
  try {
    let queue = JSON.parse(localStorage.getItem(SYNC_QUEUE_KEY) || '[]');
    // Remove duplicate entry for the same book if exists, then push latest
    queue = queue.filter(item => item.bookId !== bookId);
    queue.push({ bookId, ...bookmarkData, timestamp: Date.now() });
    localStorage.setItem(SYNC_QUEUE_KEY, JSON.stringify(queue));
    return true;
  } catch (err) {
    console.error('Failed to queue offline bookmark:', err);
    throw err;
  }
}

// Get and clear pending offline bookmark syncs when back online
export async function getAndClearSyncQueue() {
  try {
    const queue = JSON.parse(localStorage.getItem(SYNC_QUEUE_KEY) || '[]');
    localStorage.removeItem(SYNC_QUEUE_KEY);
    return queue;
  } catch (err) {
    console.error('Failed to clear sync queue:', err);
    return [];
  }
}