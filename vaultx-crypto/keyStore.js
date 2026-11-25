/**
 * VaultX Client Key Store (IndexedDB)
 * Stores non-extractable RSA-OAEP private keys locally in the browser.
 */

const DB_NAME = "vaultx-keystore";
const DB_VERSION = 1;
const STORE_NAME = "keys";

/**
 * Open (or initialize) the IndexedDB key store database.
 * @returns {Promise<IDBDatabase>}
 */
export function openKeyDb() {
  return new Promise((resolve, reject) => {
    if (typeof indexedDB === "undefined") {
      reject(new Error("IndexedDB is not available in this environment."));
      return;
    }

    const request = indexedDB.open(DB_NAME, DB_VERSION);

    request.onupgradeneeded = () => {
      const db = request.result;
      if (!db.objectStoreNames.contains(STORE_NAME)) {
        db.createObjectStore(STORE_NAME, { keyPath: "keyId" });
      }
    };

    request.onsuccess = () => resolve(request.result);
    request.onerror = () =>
      reject(request.error || new Error("Failed to open IndexedDB key store."));
  });
}

/**
 * Run a single-store IndexedDB transaction and close the DB connection when done.
 * @template T
 * @param {"readonly" | "readwrite"} mode
 * @param {(store: IDBObjectStore) => IDBRequest<T>} operation
 * @returns {Promise<T>}
 */
async function withStore(mode, operation) {
  const db = await openKeyDb();
  return new Promise((resolve, reject) => {
    const tx = db.transaction(STORE_NAME, mode);
    const store = tx.objectStore(STORE_NAME);
    const request = operation(store);

    let result;
    request.onsuccess = () => {
      result = request.result;
    };
    request.onerror = () => {
      reject(request.error || new Error("IndexedDB operation failed."));
    };

    tx.oncomplete = () => {
      db.close();
      resolve(result);
    };
    tx.onerror = () => {
      db.close();
      reject(tx.error || new Error("IndexedDB transaction failed."));
    };
    tx.onabort = () => {
      db.close();
      reject(tx.error || new Error("IndexedDB transaction aborted."));
    };
  });
}

/**
 * Store a non-extractable private CryptoKey in IndexedDB.
 * @param {string} keyId
 * @param {CryptoKey} privateKey
 * @param {object} [metadata]
 * @returns {Promise<void>}
 */
export async function savePrivateKey(keyId, privateKey, metadata = {}) {
  if (!keyId) throw new Error("keyId is required.");
  if (!privateKey) throw new Error("privateKey is required.");

  await withStore("readwrite", (store) =>
    store.put({
      keyId,
      privateKey,
      metadata,
      updatedAt: new Date().toISOString(),
    })
  );
}

/**
 * Retrieve a stored private CryptoKey from IndexedDB.
 * @param {string} keyId
 * @returns {Promise<{ privateKey: CryptoKey, metadata: object } | null>}
 */
export async function getPrivateKey(keyId) {
  if (!keyId) return null;
  const record = await withStore("readonly", (store) => store.get(keyId));
  if (!record) return null;
  return {
    privateKey: record.privateKey,
    metadata: record.metadata || {},
  };
}

/**
 * Check whether a private key exists in IndexedDB.
 * @param {string} keyId
 * @returns {Promise<boolean>}
 */
export async function hasPrivateKey(keyId) {
  const record = await getPrivateKey(keyId);
  return Boolean(record?.privateKey);
}

/**
 * Delete a private key from IndexedDB.
 * @param {string} keyId
 * @returns {Promise<void>}
 */
export async function deletePrivateKey(keyId) {
  if (!keyId) return;
  await withStore("readwrite", (store) => store.delete(keyId));
}
