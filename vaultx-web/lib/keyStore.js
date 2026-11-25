/**
 * VaultX IndexedDB Key Store
 * Secure client-side persistence for non-extractable CryptoKeys with in-memory fallback.
 */

import { exportPublicKeyPem, computeKeyFingerprint } from './vaultCrypto.js';

export { exportPublicKeyPem, computeKeyFingerprint };

export const DB_NAME = 'vaultx_keystore';
export const STORE_NAME = 'keys';
export const VERSION = 1;

// Seamless in-memory fallback for Node.js / SSR / restricted environments
const memoryStore = new Map();

/**
 * Opens or initializes the IndexedDB key store database.
 * Returns an IDBDatabase instance in browsers, or a mock representation in Node.js.
 */
export async function openKeyStoreDB() {
  if (typeof window === 'undefined' || !window.indexedDB) {
    return { isMock: true, memoryStore };
  }

  return new Promise((resolve, reject) => {
    try {
      const request = window.indexedDB.open(DB_NAME, VERSION);

      request.onupgradeneeded = (event) => {
        const db = event.target.result;
        if (!db.objectStoreNames.contains(STORE_NAME)) {
          db.createObjectStore(STORE_NAME, { keyPath: 'username' });
        }
      };

      request.onsuccess = (event) => {
        resolve(event.target.result);
      };

      request.onerror = (event) => {
        console.warn('[keyStore] IndexedDB open error, using in-memory store:', event.target.error);
        resolve({ isMock: true, memoryStore });
      };
    } catch (err) {
      console.warn('[keyStore] IndexedDB exception, using in-memory store:', err);
      resolve({ isMock: true, memoryStore });
    }
  });
}

/**
 * Stores a user's cryptographic keypair and public metadata in the key store.
 */
export async function storeUserKey(username, keyPair, publicKeyPem, fingerprint) {
  if (!username) {
    throw new Error('Username is required to store user key');
  }

  const record = {
    username,
    keyPair,
    publicKeyPem,
    fingerprint,
    updatedAt: new Date().toISOString()
  };

  if (typeof window === 'undefined' || !window.indexedDB) {
    memoryStore.set(username, record);
    return { success: true };
  }

  try {
    const db = await openKeyStoreDB();
    if (db.isMock) {
      memoryStore.set(username, record);
      return { success: true };
    }

    return await new Promise((resolve, reject) => {
      try {
        const tx = db.transaction(STORE_NAME, 'readwrite');
        const store = tx.objectStore(STORE_NAME);
        const req = store.put(record);

        req.onsuccess = () => resolve({ success: true });
        req.onerror = () => {
          memoryStore.set(username, record);
          resolve({ success: true });
        };
      } catch (err) {
        memoryStore.set(username, record);
        resolve({ success: true });
      }
    });
  } catch (err) {
    memoryStore.set(username, record);
    return { success: true };
  }
}

/**
 * Retrieves a user's key entry from the key store by username.
 * Returns { username, keyPair, publicKeyPem, fingerprint } or null.
 */
export async function getUserKey(username) {
  if (!username) return null;

  if (typeof window === 'undefined' || !window.indexedDB) {
    return memoryStore.get(username) || null;
  }

  try {
    const db = await openKeyStoreDB();
    if (db.isMock) {
      return memoryStore.get(username) || null;
    }

    return await new Promise((resolve) => {
      try {
        const tx = db.transaction(STORE_NAME, 'readonly');
        const store = tx.objectStore(STORE_NAME);
        const req = store.get(username);

        req.onsuccess = () => {
          resolve(req.result || memoryStore.get(username) || null);
        };

        req.onerror = () => {
          resolve(memoryStore.get(username) || null);
        };
      } catch (err) {
        resolve(memoryStore.get(username) || null);
      }
    });
  } catch (err) {
    return memoryStore.get(username) || null;
  }
}

/**
 * Checks whether a user's key entry exists in the key store.
 */
export async function hasUserKey(username) {
  const entry = await getUserKey(username);
  return Boolean(entry);
}

/**
 * Removes a user's key entry from the key store.
 */
export async function clearUserKey(username) {
  if (!username) return { success: true };

  memoryStore.delete(username);

  if (typeof window !== 'undefined' && window.indexedDB) {
    try {
      const db = await openKeyStoreDB();
      if (!db.isMock) {
        await new Promise((resolve) => {
          try {
            const tx = db.transaction(STORE_NAME, 'readwrite');
            const store = tx.objectStore(STORE_NAME);
            const req = store.delete(username);
            req.onsuccess = () => resolve();
            req.onerror = () => resolve();
          } catch (err) {
            resolve();
          }
        });
      }
    } catch (err) {
      // Ignore cleanup error
    }
  }

  return { success: true };
}
