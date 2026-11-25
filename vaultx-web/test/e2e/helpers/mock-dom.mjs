/**
 * test/e2e/helpers/mock-dom.mjs
 * In-memory DOM, Location, Storage, IndexedDB, and Headless React Hook Runner for Node.js 22.
 */
import React from 'react';
export { waitFor } from './test-runner-core.mjs';

// ==========================================
// 1. Storage Mock (localStorage / sessionStorage)
// ==========================================
export class MockStorage {
  constructor() {
    this._store = new Map();
  }
  getItem(key) {
    const k = String(key);
    return this._store.has(k) ? this._store.get(k) : null;
  }
  setItem(key, value) {
    this._store.set(String(key), String(value));
  }
  removeItem(key) {
    this._store.delete(String(key));
  }
  clear() {
    this._store.clear();
  }
  key(index) {
    const keys = Array.from(this._store.keys());
    return keys[index] ?? null;
  }
  get length() {
    return this._store.size;
  }
}

// ==========================================
// 2. Location Mock (window.location.hash)
// ==========================================
export class MockLocation {
  constructor(initialUrl = 'http://localhost:3000/') {
    this._url = new URL(initialUrl);
  }
  get href() {
    return this._url.href;
  }
  set href(val) {
    this._url = new URL(val, this._url.origin);
  }
  get origin() {
    return this._url.origin;
  }
  get protocol() {
    return this._url.protocol;
  }
  get host() {
    return this._url.host;
  }
  get hostname() {
    return this._url.hostname;
  }
  get port() {
    return this._url.port;
  }
  get pathname() {
    return this._url.pathname;
  }
  set pathname(val) {
    this._url.pathname = val;
  }
  get search() {
    return this._url.search;
  }
  set search(val) {
    this._url.search = val;
  }
  get hash() {
    return this._url.hash;
  }
  set hash(val) {
    const oldHash = this._url.hash;
    const newHash = val.startsWith('#') || val === '' ? val : `#${val}`;
    this._url.hash = newHash;
    if (oldHash !== newHash && globalThis.window) {
      if (typeof globalThis.CustomEvent === 'function') {
        globalThis.window.dispatchEvent(
          new CustomEvent('hashchange', {
            detail: { oldURL: this._url.href, newURL: this._url.href },
          })
        );
      } else {
        globalThis.window.dispatchEvent({
          type: 'hashchange',
          oldURL: this._url.href,
          newURL: this._url.href,
        });
      }
    }
  }
  assign(url) {
    this.href = url;
  }
  replace(url) {
    this.href = url;
  }
}

// ==========================================
// 3. Blob URL Tracker (URL.createObjectURL)
// ==========================================
export class BlobUrlTracker {
  constructor() {
    this.createdUrls = new Map();
    this.revokedUrls = new Set();
    this.counter = 0;
  }

  createObjectURL(blob) {
    const id = ++this.counter;
    const url = `blob:http://localhost:3000/mock-uuid-${id}`;
    this.createdUrls.set(url, blob);
    return url;
  }

  revokeObjectURL(url) {
    if (this.createdUrls.has(url)) {
      this.revokedUrls.add(url);
    }
  }

  getActiveUrls() {
    const active = [];
    for (const url of this.createdUrls.keys()) {
      if (!this.revokedUrls.has(url)) {
        active.push(url);
      }
    }
    return active;
  }

  reset() {
    this.createdUrls.clear();
    this.revokedUrls.clear();
    this.counter = 0;
  }
}

// ==========================================
// 4. In-Memory IndexedDB Simulation
// ==========================================
class MockIDBRequest {
  constructor() {
    this.result = undefined;
    this.error = null;
    this.onsuccess = null;
    this.onerror = null;
    this.onupgradeneeded = null;
  }
  _triggerSuccess(res) {
    this.result = res;
    queueMicrotask(() => {
      if (this.onsuccess) this.onsuccess({ target: this });
    });
  }
  _triggerError(err) {
    this.error = err;
    queueMicrotask(() => {
      if (this.onerror) this.onerror({ target: this });
    });
  }
}

class MockObjectStore {
  constructor(name, keyPath, storeMap) {
    this.name = name;
    this.keyPath = keyPath;
    this.storeMap = storeMap;
  }
  put(value, key) {
    const actualKey = key !== undefined ? key : this.keyPath && value ? value[this.keyPath] : undefined;
    this.storeMap.set(actualKey, value);
    const req = new MockIDBRequest();
    req._triggerSuccess(actualKey);
    return req;
  }
  get(key) {
    const req = new MockIDBRequest();
    const val = this.storeMap.get(key);
    req._triggerSuccess(val !== undefined ? val : undefined);
    return req;
  }
  getAll() {
    const req = new MockIDBRequest();
    req._triggerSuccess(Array.from(this.storeMap.values()));
    return req;
  }
  delete(key) {
    this.storeMap.delete(key);
    const req = new MockIDBRequest();
    req._triggerSuccess(undefined);
    return req;
  }
  clear() {
    this.storeMap.clear();
    const req = new MockIDBRequest();
    req._triggerSuccess(undefined);
    return req;
  }
}

class MockTransaction {
  constructor(storeNames, mode, stores) {
    this.storeNames = Array.isArray(storeNames) ? storeNames : [storeNames];
    this.mode = mode;
    this.stores = stores;
    this.oncomplete = null;
    this.onerror = null;
    queueMicrotask(() => {
      if (this.oncomplete) this.oncomplete({ target: this });
    });
  }
  objectStore(name) {
    const store = this.stores.get(name);
    if (!store) throw new Error(`NotFoundError: Object store "${name}" not found`);
    return store;
  }
}

class MockIDBDatabase {
  constructor(name, version) {
    this.name = name;
    this.version = version;
    this.objectStores = new Map();
    this.objectStoreNames = {
      contains: (s) => this.objectStores.has(s),
    };
  }
  createObjectStore(name, options = {}) {
    const store = new MockObjectStore(name, options.keyPath, new Map());
    this.objectStores.set(name, store);
    return store;
  }
  transaction(storeNames, mode = 'readonly') {
    return new MockTransaction(storeNames, mode, this.objectStores);
  }
  close() {}
}

export class MockIndexedDBFactory {
  constructor() {
    this.databases = new Map();
    this.failNext = false;
  }
  open(name, version = 1) {
    const req = new MockIDBRequest();
    if (this.failNext) {
      req._triggerError(new Error('IndexedDBBlockedError: Database open denied'));
      return req;
    }
    let db = this.databases.get(name);
    const isNew = !db;
    if (isNew) {
      db = new MockIDBDatabase(name, version);
      this.databases.set(name, db);
    }
    queueMicrotask(() => {
      if (isNew && req.onupgradeneeded) {
        req.result = db;
        req.onupgradeneeded({ target: req, oldVersion: 0, newVersion: version });
      }
      req._triggerSuccess(db);
    });
    return req;
  }
  deleteDatabase(name) {
    this.databases.delete(name);
    const req = new MockIDBRequest();
    req._triggerSuccess(undefined);
    return req;
  }
  setFailNext(flag) {
    this.failNext = !!flag;
  }
  clear() {
    this.databases.clear();
    this.failNext = false;
  }
}

// ==========================================
// 5. Headless React Hook Runner
// ==========================================
export function renderHook(hookFn, initialProps = {}) {
  let hookIndex = 0;
  const states = [];
  const effects = [];
  let isMounting = true;
  let currentProps = initialProps;
  const resultRef = { current: null };

  const dispatcher = {
    useState(initial) {
      const idx = hookIndex++;
      if (isMounting) {
        states[idx] = typeof initial === 'function' ? initial() : initial;
      }
      const setState = (next) => {
        states[idx] = typeof next === 'function' ? next(states[idx]) : next;
        rerender(currentProps);
      };
      return [states[idx], setState];
    },
    useRef(initial) {
      const idx = hookIndex++;
      if (isMounting) {
        states[idx] = { current: initial };
      }
      return states[idx];
    },
    useEffect(effect, deps) {
      const idx = hookIndex++;
      effects[idx] = {
        effect,
        deps,
        prevDeps: isMounting ? undefined : effects[idx]?.deps,
        cleanup: effects[idx]?.cleanup,
      };
    },
    useLayoutEffect(effect, deps) {
      return this.useEffect(effect, deps);
    },
    useCallback(fn, deps) {
      const idx = hookIndex++;
      if (isMounting) {
        states[idx] = { fn, deps };
        return fn;
      }
      const prev = states[idx];
      const hasChanged = !deps || !prev?.deps || deps.some((d, i) => d !== prev.deps[i]);
      if (hasChanged) {
        states[idx] = { fn, deps };
        return fn;
      }
      return prev.fn;
    },
    useMemo(fn, deps) {
      const idx = hookIndex++;
      if (isMounting) {
        const val = fn();
        states[idx] = { val, deps };
        return val;
      }
      const prev = states[idx];
      const hasChanged = !deps || !prev?.deps || deps.some((d, i) => d !== prev.deps[i]);
      if (hasChanged) {
        const val = fn();
        states[idx] = { val, deps };
        return val;
      }
      return prev.val;
    },
  };

  function rerender(newProps) {
    currentProps = newProps !== undefined ? newProps : currentProps;
    hookIndex = 0;
    const prevDispatcher =
      React.__SECRET_INTERNALS_DO_NOT_USE_OR_YOU_WILL_BE_FIRED?.ReactCurrentDispatcher?.current;
    if (React.__SECRET_INTERNALS_DO_NOT_USE_OR_YOU_WILL_BE_FIRED?.ReactCurrentDispatcher) {
      React.__SECRET_INTERNALS_DO_NOT_USE_OR_YOU_WILL_BE_FIRED.ReactCurrentDispatcher.current = dispatcher;
    }
    try {
      resultRef.current = hookFn(currentProps);
    } finally {
      if (React.__SECRET_INTERNALS_DO_NOT_USE_OR_YOU_WILL_BE_FIRED?.ReactCurrentDispatcher) {
        React.__SECRET_INTERNALS_DO_NOT_USE_OR_YOU_WILL_BE_FIRED.ReactCurrentDispatcher.current = prevDispatcher;
      }
    }
    isMounting = false;

    // Execute effect callbacks
    for (const item of effects) {
      if (!item) continue;
      const shouldRun =
        !item.prevDeps ||
        !item.deps ||
        item.deps.some((dep, i) => dep !== item.prevDeps[i]);

      if (shouldRun) {
        if (typeof item.cleanup === 'function') {
          item.cleanup();
        }
        const cleanup = item.effect();
        if (typeof cleanup === 'function') {
          item.cleanup = cleanup;
        }
        item.prevDeps = item.deps ? [...item.deps] : undefined;
      }
    }
  }

  // Initial mount
  rerender(initialProps);

  return {
    result: resultRef,
    rerender,
    unmount() {
      for (const item of effects) {
        if (item && typeof item.cleanup === 'function') {
          item.cleanup();
          item.cleanup = null;
        }
      }
    },
  };
}

// ==========================================
// 6. Global DOM Environment Manager
// ==========================================
let originalGlobals = null;
export const blobTracker = new BlobUrlTracker();
export const mockIndexedDB = new MockIndexedDBFactory();
export const mockLocalStorage = new MockStorage();
export const mockSessionStorage = new MockStorage();

export function setupMockDOM(initialUrl = 'http://localhost:3000/') {
  if (originalGlobals) return;

  originalGlobals = {
    window: globalThis.window,
    document: globalThis.document,
    location: globalThis.location,
    localStorage: globalThis.localStorage,
    sessionStorage: globalThis.sessionStorage,
    indexedDB: globalThis.indexedDB,
    createObjectURL: URL.createObjectURL,
    revokeObjectURL: URL.revokeObjectURL,
  };

  const listeners = new Map();
  const mockLocation = new MockLocation(initialUrl);

  const mockWindow = {
    location: mockLocation,
    localStorage: mockLocalStorage,
    sessionStorage: mockSessionStorage,
    indexedDB: mockIndexedDB,
    addEventListener(type, listener) {
      if (!listeners.has(type)) listeners.set(type, new Set());
      listeners.get(type).add(listener);
    },
    removeEventListener(type, listener) {
      if (listeners.has(type)) listeners.get(type).delete(listener);
    },
    dispatchEvent(event) {
      const type = typeof event === 'string' ? event : event.type;
      const set = listeners.get(type);
      if (set) {
        for (const fn of set) {
          try {
            fn(event);
          } catch (e) {
            console.error('Error in window event listener:', e);
          }
        }
      }
      return true;
    },
  };

  globalThis.window = mockWindow;
  globalThis.document = {
    title: 'VaultX',
    createElement: (tag) => ({
      tagName: tag.toUpperCase(),
      appendChild: () => {},
      click: () => {},
    }),
  };
  globalThis.location = mockLocation;
  globalThis.localStorage = mockLocalStorage;
  globalThis.sessionStorage = mockSessionStorage;
  globalThis.indexedDB = mockIndexedDB;

  // Wrap Blob URLs
  URL.createObjectURL = (blob) => blobTracker.createObjectURL(blob);
  URL.revokeObjectURL = (url) => blobTracker.revokeObjectURL(url);
}

export function teardownMockDOM() {
  if (!originalGlobals) return;

  globalThis.window = originalGlobals.window;
  globalThis.document = originalGlobals.document;
  globalThis.location = originalGlobals.location;
  globalThis.localStorage = originalGlobals.localStorage;
  globalThis.sessionStorage = originalGlobals.sessionStorage;
  globalThis.indexedDB = originalGlobals.indexedDB;
  URL.createObjectURL = originalGlobals.createObjectURL;
  URL.revokeObjectURL = originalGlobals.revokeObjectURL;

  originalGlobals = null;
  resetMockDOM();
}

export function resetMockDOM(url = 'http://localhost:3000/') {
  mockLocalStorage.clear();
  mockSessionStorage.clear();
  mockIndexedDB.clear();
  blobTracker.reset();
  if (globalThis.location) {
    globalThis.location.href = url;
  }
}
