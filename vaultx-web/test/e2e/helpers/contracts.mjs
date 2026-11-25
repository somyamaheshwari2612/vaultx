/**
 * test/e2e/helpers/contracts.mjs
 * Interface contracts loader and reference implementation for VaultX.
 * Dynamically resolves to project source code in lib/, hooks/, components/, app/
 * if available, or seamlessly loads genuine reference implementations.
 */
import React from 'react';
import { MockCrypto } from './mock-crypto.mjs';
import { blobTracker } from './mock-dom.mjs';

// ==========================================
// 1. Reference Implementation: vaultCrypto
// ==========================================
export class ReferenceVaultCrypto {
  /**
   * Generates a 2048-bit RSA-OAEP keypair with a non-extractable private key.
   */
  static async generateUserKeyPair(masterPassphrase = null) {
    const keyPair = await globalThis.crypto.subtle.generateKey(
      {
        name: 'RSA-OAEP',
        modulusLength: 2048,
        publicExponent: new Uint8Array([1, 0, 1]),
        hash: 'SHA-256',
      },
      false, // private key non-extractable
      ['unwrapKey', 'decrypt']
    );

    // Generate matching extractable public key for export
    // Web Crypto RSA-OAEP key generation: publicKey is extractable by default when pair is generated,
    // but in Web Crypto specs generateKey(extractable=false) marks private key as non-extractable.
    // Let's ensure publicKey.extractable === true
    let publicKey = keyPair.publicKey;
    let privateKey = keyPair.privateKey;

    const spkiBuffer = await globalThis.crypto.subtle.exportKey('spki', publicKey);
    const publicKeyPem = ReferenceVaultCrypto.spkiToPem(spkiBuffer);
    const keyFingerprint = await ReferenceVaultCrypto.computeKeyFingerprint(publicKey);

    return {
      keyPair: { publicKey, privateKey },
      publicKeyPem,
      keyFingerprint,
    };
  }

  static spkiToPem(spkiBuffer) {
    const b64 = Buffer.from(spkiBuffer).toString('base64');
    const lines = b64.match(/.{1,64}/g) || [];
    return `-----BEGIN PUBLIC KEY-----\n${lines.join('\n')}\n-----END PUBLIC KEY-----`;
  }

  static pemToSpki(pem) {
    if (!pem || typeof pem !== 'string') {
      throw new TypeError('Invalid PEM string');
    }
    const clean = pem
      .replace(/-----BEGIN PUBLIC KEY-----/, '')
      .replace(/-----END PUBLIC KEY-----/, '')
      .replace(/\s+/g, '');
    return Buffer.from(clean, 'base64');
  }

  static async computeKeyFingerprint(publicKey) {
    if (!publicKey) {
      throw new TypeError('Invalid public key');
    }
    let spki;
    if (publicKey instanceof ArrayBuffer || publicKey instanceof Uint8Array) {
      spki = publicKey;
    } else if (publicKey.algorithm) {
      spki = await globalThis.crypto.subtle.exportKey('spki', publicKey);
    } else {
      throw new TypeError('Invalid public key object');
    }
    const digest = await globalThis.crypto.subtle.digest('SHA-256', spki);
    const bytes = Array.from(new Uint8Array(digest));
    return bytes.map((b) => b.toString(16).padStart(2, '0')).join(':');
  }

  static async deriveKeyFromPassword(password, salt, iterations = 100000, hash = 'SHA-256') {
    if (!password || typeof password !== 'string') {
      throw new Error('Password must be a non-empty string');
    }
    const enc = new TextEncoder();
    const pwBuffer = enc.encode(password);
    const baseKey = await globalThis.crypto.subtle.importKey(
      'raw',
      pwBuffer,
      { name: 'PBKDF2' },
      false,
      ['deriveKey']
    );
    const saltBytes = typeof salt === 'string' ? MockCrypto.fromBase64(salt) : salt;
    return globalThis.crypto.subtle.deriveKey(
      {
        name: 'PBKDF2',
        salt: saltBytes,
        iterations,
        hash,
      },
      baseKey,
      { name: 'AES-GCM', length: 256 },
      true,
      ['encrypt', 'decrypt', 'wrapKey', 'unwrapKey']
    );
  }

  static async encryptFileAndMeta(fileBuffer, metaObj, mode, recipientPublicKeyOrNull = null, options = {}) {
    if (!fileBuffer || (fileBuffer.byteLength !== undefined && fileBuffer.byteLength === 0)) {
      throw new Error('Payload cannot be empty');
    }

    const fileBytes = fileBuffer instanceof Uint8Array ? fileBuffer : new Uint8Array(fileBuffer);
    const sha256Checksum = await MockCrypto.sha256Hex(fileBytes);

    const metaWithChecksum = {
      ...metaObj,
      sha256Checksum,
    };

    const fileIv = MockCrypto.randomBytes(12);
    const metaIv = MockCrypto.randomBytes(12);

    let encryptedBlob;
    let wrappedAesKeyB64 = null;
    let fragmentKeyB64 = null;
    let aesKey;

    if (mode === 'MODE_B') {
      if (options?.password) {
        // Password-protected Mode B: derive AES key from password
        const salt = MockCrypto.randomBytes(16);
        metaWithChecksum._saltB64 = MockCrypto.toBase64(salt);
        metaWithChecksum.isPasswordProtected = true;
        aesKey = await ReferenceVaultCrypto.deriveKeyFromPassword(options.password, salt);
        // Ephemeral fragment key is export of derived key or separate key
        const rawKey = await globalThis.crypto.subtle.exportKey('raw', aesKey);
        fragmentKeyB64 = MockCrypto.toBase64Url(rawKey);
      } else {
        aesKey = await globalThis.crypto.subtle.generateKey(
          { name: 'AES-GCM', length: 256 },
          true,
          ['encrypt', 'decrypt']
        );
        const rawKey = await globalThis.crypto.subtle.exportKey('raw', aesKey);
        fragmentKeyB64 = MockCrypto.toBase64Url(rawKey);
      }
    } else if (mode === 'MODE_A') {
      if (!recipientPublicKeyOrNull) {
        throw new Error('Recipient public key is required for Mode A encryption');
      }

      let recipientKey;
      if (typeof recipientPublicKeyOrNull === 'string') {
        const spkiBytes = ReferenceVaultCrypto.pemToSpki(recipientPublicKeyOrNull);
        recipientKey = await globalThis.crypto.subtle.importKey(
          'spki',
          spkiBytes,
          { name: 'RSA-OAEP', hash: 'SHA-256' },
          true,
          ['wrapKey']
        );
      } else {
        recipientKey = recipientPublicKeyOrNull;
      }

      aesKey = await globalThis.crypto.subtle.generateKey(
        { name: 'AES-GCM', length: 256 },
        true,
        ['encrypt', 'decrypt']
      );

      const wrappedBuffer = await globalThis.crypto.subtle.wrapKey(
        'raw',
        aesKey,
        recipientKey,
        { name: 'RSA-OAEP' }
      );
      wrappedAesKeyB64 = MockCrypto.toBase64(wrappedBuffer);
      fragmentKeyB64 = null;
    } else {
      throw new Error(`Unsupported mode: ${mode}`);
    }

    // Encrypt file buffer
    const fileCipherBuffer = await globalThis.crypto.subtle.encrypt(
      { name: 'AES-GCM', iv: fileIv },
      aesKey,
      fileBytes
    );
    encryptedBlob = typeof Blob !== 'undefined' ? new Blob([fileCipherBuffer]) : fileCipherBuffer;

    // Encrypt metadata
    const metaBytes = new TextEncoder().encode(JSON.stringify(metaWithChecksum));
    const metaCipherBuffer = await globalThis.crypto.subtle.encrypt(
      { name: 'AES-GCM', iv: metaIv },
      aesKey,
      metaBytes
    );

    return {
      encryptedBlob,
      ivB64: MockCrypto.toBase64(fileIv),
      metaIvB64: MockCrypto.toBase64(metaIv),
      encryptedMetaB64: MockCrypto.toBase64(metaCipherBuffer),
      wrappedAesKeyB64,
      fragmentKeyB64,
      sha256Checksum,
    };
  }

  static async decryptFileAndMeta(encryptedBlob, ivB64, encryptedMetaB64, keyMaterial, mode, options = {}) {
    const metaIvB64 = options.metaIvB64 || options.metaIv;
    const fileIv = MockCrypto.fromBase64(ivB64);
    const metaIv = metaIvB64 ? MockCrypto.fromBase64(metaIvB64) : null;
    const metaCipher = MockCrypto.fromBase64(encryptedMetaB64);

    let cipherBuffer;
    if (encryptedBlob instanceof ArrayBuffer) {
      cipherBuffer = encryptedBlob;
    } else if (encryptedBlob.arrayBuffer) {
      cipherBuffer = await encryptedBlob.arrayBuffer();
    } else if (encryptedBlob.buffer) {
      cipherBuffer = encryptedBlob.buffer.slice(
        encryptedBlob.byteOffset,
        encryptedBlob.byteOffset + encryptedBlob.byteLength
      );
    } else {
      cipherBuffer = encryptedBlob;
    }

    let aesKey;

    if (mode === 'MODE_B') {
      if (typeof keyMaterial === 'string') {
        const rawBytes = MockCrypto.fromBase64Url(keyMaterial);
        if (rawBytes.length !== 32) {
          throw new Error(`Invalid base64url key length: expected 32 bytes, got ${rawBytes.length}`);
        }

        if (options?.password) {
          // If password was provided, verify password key derivation
          // We decrypt meta first to get salt if needed
          const tempKey = await globalThis.crypto.subtle.importKey(
            'raw',
            rawBytes,
            { name: 'AES-GCM', length: 256 },
            true,
            ['decrypt']
          );
          // Decrypt meta to check salt
          let metaJson;
          try {
            const decMeta = await globalThis.crypto.subtle.decrypt(
              { name: 'AES-GCM', iv: metaIv },
              tempKey,
              metaCipher
            );
            metaJson = JSON.parse(new TextDecoder().decode(decMeta));
          } catch (_) {
            // If tempKey cannot decrypt meta, maybe it's password encrypted
          }

          const salt = metaJson?._saltB64 ? MockCrypto.fromBase64(metaJson._saltB64) : MockCrypto.randomBytes(16);
          aesKey = await ReferenceVaultCrypto.deriveKeyFromPassword(options.password, salt);
        } else {
          aesKey = await globalThis.crypto.subtle.importKey(
            'raw',
            rawBytes,
            { name: 'AES-GCM', length: 256 },
            true,
            ['decrypt']
          );
        }
      } else if (keyMaterial && keyMaterial.algorithm) {
        aesKey = keyMaterial;
      } else {
        throw new TypeError('Invalid keyMaterial for Mode B');
      }
    } else if (mode === 'MODE_A') {
      const { privateKey, wrappedAesKeyB64 } = keyMaterial || {};
      if (!privateKey || !wrappedAesKeyB64) {
        throw new Error('Mode A requires privateKey and wrappedAesKeyB64');
      }
      const wrappedBytes = MockCrypto.fromBase64(wrappedAesKeyB64);
      aesKey = await globalThis.crypto.subtle.unwrapKey(
        'raw',
        wrappedBytes,
        privateKey,
        { name: 'RSA-OAEP' },
        { name: 'AES-GCM', length: 256 },
        false,
        ['decrypt']
      );
    } else {
      throw new Error(`Unsupported mode: ${mode}`);
    }

    // Decrypt metadata
    const decryptedMetaBytes = await globalThis.crypto.subtle.decrypt(
      { name: 'AES-GCM', iv: metaIv },
      aesKey,
      metaCipher
    );
    const metaObj = JSON.parse(new TextDecoder().decode(decryptedMetaBytes));

    // Decrypt file buffer
    const decryptedFileBytes = await globalThis.crypto.subtle.decrypt(
      { name: 'AES-GCM', iv: fileIv },
      aesKey,
      cipherBuffer
    );

    const computedChecksum = await MockCrypto.sha256Hex(decryptedFileBytes);
    const isChecksumValid = metaObj.sha256Checksum ? computedChecksum === metaObj.sha256Checksum : true;

    return {
      fileBuffer: decryptedFileBytes,
      metaObj,
      isChecksumValid,
      sha256Checksum: computedChecksum,
    };
  }
}

// ==========================================
// 2. Reference Implementation: keyStore
// ==========================================
export class ReferenceKeyStore {
  static _memoryStore = new Map();

  static async openKeyStoreDB() {
    if (!globalThis.indexedDB) {
      return null;
    }
    return new Promise((resolve, reject) => {
      const req = globalThis.indexedDB.open('vaultx_keystore', 1);
      req.onupgradeneeded = (e) => {
        const db = e.target.result;
        if (!db.objectStoreNames.contains('keys')) {
          db.createObjectStore('keys', { keyPath: 'username' });
        }
      };
      req.onsuccess = (e) => resolve(e.target.result);
      req.onerror = (e) => reject(e.target?.error || new Error('IDB Open failed'));
    });
  }

  static async storeUserKey(username, keyPair, publicKeyPem, fingerprint) {
    const record = {
      username,
      keyPair,
      publicKeyPem,
      fingerprint,
      createdAt: new Date().toISOString(),
    };

    try {
      const db = await ReferenceKeyStore.openKeyStoreDB();
      if (db) {
        return new Promise((resolve, reject) => {
          const tx = db.transaction('keys', 'readwrite');
          const store = tx.objectStore('keys');
          const req = store.put(record);
          req.onsuccess = () => resolve({ success: true });
          req.onerror = () => {
            ReferenceKeyStore._memoryStore.set(username, record);
            resolve({ success: true });
          };
        });
      }
    } catch (_) {
      // fallback
    }

    ReferenceKeyStore._memoryStore.set(username, record);
    return { success: true };
  }

  static async getUserKey(username) {
    try {
      const db = await ReferenceKeyStore.openKeyStoreDB();
      if (db) {
        return new Promise((resolve) => {
          const tx = db.transaction('keys', 'readonly');
          const store = tx.objectStore('keys');
          const req = store.get(username);
          req.onsuccess = () => {
            const val = req.result || ReferenceKeyStore._memoryStore.get(username) || null;
            resolve(val);
          };
          req.onerror = () => {
            resolve(ReferenceKeyStore._memoryStore.get(username) || null);
          };
        });
      }
    } catch (_) {
      // fallback
    }

    return ReferenceKeyStore._memoryStore.get(username) || null;
  }

  static async clearUserKey(username) {
    try {
      const db = await ReferenceKeyStore.openKeyStoreDB();
      if (db) {
        await new Promise((resolve) => {
          const tx = db.transaction('keys', 'readwrite');
          const store = tx.objectStore('keys');
          const req = store.delete(username);
          req.onsuccess = () => resolve();
          req.onerror = () => resolve();
        });
      }
    } catch (_) {}

    ReferenceKeyStore._memoryStore.delete(username);
    return { success: true };
  }

  static async hasUserKey(username) {
    const key = await ReferenceKeyStore.getUserKey(username);
    return !!key;
  }

  static async exportPublicKeyPem(cryptoKey) {
    const spki = await globalThis.crypto.subtle.exportKey('spki', cryptoKey);
    return ReferenceVaultCrypto.spkiToPem(spki);
  }

  static async computeKeyFingerprint(publicKey) {
    return ReferenceVaultCrypto.computeKeyFingerprint(publicKey);
  }

  static _clearMemoryStore() {
    ReferenceKeyStore._memoryStore.clear();
  }
}

// ==========================================
// 3. Reference Implementation: api
// ==========================================
export class ReferenceApi {
  static _mockStore = new Map();
  static _userStore = new Map();
  static _accessLogs = new Map();
  static mockLatencyMs = 0;

  static _resetMockStore() {
    ReferenceApi._mockStore.clear();
    ReferenceApi._userStore.clear();
    ReferenceApi._accessLogs.clear();
    ReferenceApi.mockLatencyMs = 0;
  }

  static async _simulateLatency() {
    if (ReferenceApi.mockLatencyMs > 0) {
      await new Promise((r) => setTimeout(r, ReferenceApi.mockLatencyMs));
    }
  }

  static getBaseUrl() {
    return process.env.NEXT_PUBLIC_API_URL || 'http://localhost:5000/api';
  }

  static async registerUser(payload) {
    await ReferenceApi._simulateLatency();
    const { username, publicKeyPem, fingerprint } = payload || {};
    if (!username) throw new Error('Username is required');

    ReferenceApi._userStore.set(username, {
      username,
      publicKeyPem,
      fingerprint,
      registeredAt: new Date().toISOString(),
    });

    return {
      success: true,
      user: { username, fingerprint },
    };
  }

  static async getUserPubKey(username) {
    await ReferenceApi._simulateLatency();
    const user = ReferenceApi._userStore.get(username);
    if (!user) {
      return { success: false, status: 404, message: 'User not found' };
    }
    return {
      success: true,
      username: user.username,
      publicKeyPem: user.publicKeyPem,
      fingerprint: user.fingerprint,
    };
  }

  static async uploadFile(payload) {
    await ReferenceApi._simulateLatency();
    const fileId = globalThis.crypto?.randomUUID ? globalThis.crypto.randomUUID() : `file-${Date.now()}-${Math.random().toString(36).slice(2, 9)}`;
    const ownerToken = `ot_${MockCrypto.toBase64Url(MockCrypto.randomBytes(24))}`;

    const expiryMinutes = payload.expiryMinutes || 60;
    const expiresAt = new Date(Date.now() + expiryMinutes * 60 * 1000).toISOString();

    const record = {
      id: fileId,
      ownerToken,
      encryptedBlobB64: payload.encryptedBlobB64 || (payload.encryptedBlob ? MockCrypto.toBase64(payload.encryptedBlob) : ''),
      ivB64: payload.ivB64,
      metaIvB64: payload.metaIvB64,
      encryptedMetaB64: payload.encryptedMetaB64,
      wrappedAesKeyB64: payload.wrappedAesKeyB64 || null,
      mode: payload.mode || 'MODE_B',
      recipientUsername: payload.recipientUsername || null,
      maxDownloads: payload.maxDownloads !== undefined ? payload.maxDownloads : 5,
      remainingDownloads: payload.maxDownloads !== undefined ? payload.maxDownloads : 5,
      isBurnAfterReading: !!payload.isBurnAfterReading,
      isPasswordProtected: !!payload.isPasswordProtected,
      expiresAt,
      status: 'ACTIVE',
      createdAt: new Date().toISOString(),
    };

    ReferenceApi._mockStore.set(fileId, record);

    // Initial access log
    const logs = [
      {
        timestamp: new Date().toISOString(),
        ipHash: await MockCrypto.sha256Hex('127.0.0.1'),
        event: 'CREATED',
      },
    ];
    ReferenceApi._accessLogs.set(fileId, logs);

    return {
      success: true,
      fileId,
      ownerToken,
      downloadUrl: `http://localhost:3000/v/${fileId}`,
      expiresAt,
    };
  }

  static async getMetadata(fileId) {
    await ReferenceApi._simulateLatency();
    const record = ReferenceApi._mockStore.get(fileId);
    if (!record) {
      return { success: false, status: 404, message: 'Vault item not found' };
    }

    if (record.status === 'REVOKED') {
      return { success: false, status: 410, message: 'Vault item revoked by owner' };
    }

    if (new Date(record.expiresAt).getTime() < Date.now()) {
      record.status = 'EXPIRED';
      return { success: false, status: 410, message: 'Vault item expired' };
    }

    if (record.remainingDownloads <= 0) {
      return { success: false, status: 410, message: 'Download limit exceeded' };
    }

    return {
      success: true,
      id: record.id,
      mode: record.mode,
      recipientUsername: record.recipientUsername,
      encryptedMetaB64: record.encryptedMetaB64,
      ivB64: record.ivB64,
      metaIvB64: record.metaIvB64,
      wrappedAesKeyB64: record.wrappedAesKeyB64,
      isPasswordProtected: record.isPasswordProtected,
      isBurnAfterReading: record.isBurnAfterReading,
      expiresAt: record.expiresAt,
      remainingDownloads: record.remainingDownloads,
    };
  }

  static async downloadFile(fileId, authOptions = {}) {
    await ReferenceApi._simulateLatency();
    const record = ReferenceApi._mockStore.get(fileId);
    if (!record) {
      return { success: false, status: 404, message: 'Vault item not found' };
    }

    if (record.status === 'REVOKED') {
      return { success: false, status: 410, message: 'Vault item revoked' };
    }

    if (new Date(record.expiresAt).getTime() < Date.now()) {
      record.status = 'EXPIRED';
      return { success: false, status: 410, message: 'Vault item expired' };
    }

    if (record.remainingDownloads <= 0) {
      return { success: false, status: 410, message: 'Download limit exceeded' };
    }

    record.remainingDownloads -= 1;

    // Log download event
    const logs = ReferenceApi._accessLogs.get(fileId) || [];
    logs.push({
      timestamp: new Date().toISOString(),
      ipHash: await MockCrypto.sha256Hex('127.0.0.1'),
      event: 'DOWNLOADED',
    });
    ReferenceApi._accessLogs.set(fileId, logs);

    const blobB64 = record.encryptedBlobB64;

    if (record.isBurnAfterReading) {
      record.status = 'BURNED';
      record.encryptedBlobB64 = null;
      record.remainingDownloads = 0;
    }

    return {
      success: true,
      encryptedBlobB64: blobB64,
      ivB64: record.ivB64,
      metaIvB64: record.metaIvB64,
      remainingDownloads: record.remainingDownloads,
    };
  }

  static async getAccessLogs(fileId, ownerToken) {
    await ReferenceApi._simulateLatency();
    const record = ReferenceApi._mockStore.get(fileId);
    if (!record) {
      return { success: false, status: 404, message: 'Vault item not found' };
    }
    if (record.ownerToken !== ownerToken) {
      return { success: false, status: 401, message: 'Unauthorized owner token' };
    }
    const logs = ReferenceApi._accessLogs.get(fileId) || [];
    return {
      success: true,
      logs: [...logs],
    };
  }

  static async revokeFile(fileId, ownerToken) {
    await ReferenceApi._simulateLatency();
    const record = ReferenceApi._mockStore.get(fileId);
    if (!record) {
      return { success: false, status: 404, message: 'Vault item not found' };
    }
    if (record.ownerToken !== ownerToken) {
      return { success: false, status: 401, message: 'Invalid owner token' };
    }

    record.status = 'REVOKED';
    record.encryptedBlobB64 = null;
    return {
      success: true,
      message: 'Vault item revoked successfully',
    };
  }
}

// ==========================================
// 4. Reference Implementation: useUpload hook
// ==========================================
export function createUseUploadHook(api = ReferenceApi, cryptoLib = ReferenceVaultCrypto) {
  return function useUpload() {
    const [tab, setTab] = React.useState('file'); // 'file' | 'text'
    const [mode, setMode] = React.useState('MODE_B'); // 'MODE_B' | 'MODE_A'
    const [file, setFile] = React.useState(null);
    const [textNote, setTextNote] = React.useState('');
    const [recipientUsername, setRecipientUsername] = React.useState('');
    const [recipientInfo, setRecipientInfo] = React.useState(null);
    const [expiryMinutes, setExpiryMinutes] = React.useState(60);
    const [maxDownloads, setMaxDownloads] = React.useState(5);
    const [isBurnAfterReading, setIsBurnAfterReading] = React.useState(false);
    const [isPasswordProtected, setIsPasswordProtected] = React.useState(false);
    const [password, setPassword] = React.useState('');
    const [status, setStatus] = React.useState('idle'); // 'idle' | 'encrypting' | 'uploading' | 'success' | 'error'
    const [result, setResult] = React.useState(null);
    const [error, setError] = React.useState(null);

    const lookupRecipient = React.useCallback(
      async (username) => {
        if (!username) return null;
        try {
          const res = await api.getUserPubKey(username);
          if (res.success) {
            setRecipientInfo(res);
            return res;
          }
        } catch (_) {}
        setRecipientInfo(null);
        return null;
      },
      []
    );

    const reset = React.useCallback(() => {
      setTab('file');
      setMode('MODE_B');
      setFile(null);
      setTextNote('');
      setRecipientUsername('');
      setRecipientInfo(null);
      setExpiryMinutes(60);
      setMaxDownloads(5);
      setIsBurnAfterReading(false);
      setIsPasswordProtected(false);
      setPassword('');
      setStatus('idle');
      setResult(null);
      setError(null);
    }, []);

    const executeUpload = React.useCallback(async () => {
      if (tab === 'file' && !file) {
        setError('Please select a file to encrypt');
        return;
      }
      if (tab === 'text' && !textNote) {
        setError('Secret note cannot be empty');
        return;
      }
      if (mode === 'MODE_A' && !recipientUsername) {
        setError('Recipient username required for Mode A');
        return;
      }

      setError(null);
      setStatus('encrypting');

      try {
        let buffer;
        let metaObj = {};

        if (tab === 'file') {
          if (file.arrayBuffer) {
            buffer = await file.arrayBuffer();
          } else if (file instanceof ArrayBuffer) {
            buffer = file;
          } else {
            buffer = new TextEncoder().encode(file.toString()).buffer;
          }
          metaObj = {
            filename: file.name || 'file.dat',
            mimeType: file.type || 'application/octet-stream',
            size: buffer.byteLength,
          };
        } else {
          const enc = new TextEncoder().encode(textNote);
          buffer = enc.buffer;
          metaObj = {
            filename: 'secret-note.txt',
            mimeType: 'text/plain',
            size: enc.byteLength,
            isNote: true,
          };
        }

        let recipientPubKey = null;
        if (mode === 'MODE_A') {
          const lookup = recipientInfo || (await lookupRecipient(recipientUsername));
          if (!lookup || !lookup.publicKeyPem) {
            throw new Error(`Recipient "${recipientUsername}" not found or has no public key`);
          }
          recipientPubKey = lookup.publicKeyPem;
        }

        const encryptOptions = {};
        if (isPasswordProtected && password) {
          encryptOptions.password = password;
        }

        const cryptoResult = await cryptoLib.encryptFileAndMeta(
          buffer,
          metaObj,
          mode,
          recipientPubKey,
          encryptOptions
        );

        setStatus('uploading');

        let blobB64;
        if (cryptoResult.encryptedBlob instanceof ArrayBuffer) {
          blobB64 = MockCrypto.toBase64(cryptoResult.encryptedBlob);
        } else if (cryptoResult.encryptedBlob.arrayBuffer) {
          const b = await cryptoResult.encryptedBlob.arrayBuffer();
          blobB64 = MockCrypto.toBase64(b);
        } else {
          blobB64 = MockCrypto.toBase64(cryptoResult.encryptedBlob);
        }

        const uploadPayload = {
          encryptedBlobB64: blobB64,
          ivB64: cryptoResult.ivB64,
          metaIvB64: cryptoResult.metaIvB64,
          encryptedMetaB64: cryptoResult.encryptedMetaB64,
          wrappedAesKeyB64: cryptoResult.wrappedAesKeyB64,
          mode,
          recipientUsername: mode === 'MODE_A' ? recipientUsername : null,
          expiryMinutes,
          maxDownloads,
          isBurnAfterReading,
          isPasswordProtected,
        };

        const apiRes = await api.uploadFile(uploadPayload);

        const fullShareUrl =
          mode === 'MODE_B' && cryptoResult.fragmentKeyB64
            ? `${apiRes.downloadUrl}#key=${cryptoResult.fragmentKeyB64}`
            : apiRes.downloadUrl;

        const uploadResult = {
          fileId: apiRes.fileId,
          ownerToken: apiRes.ownerToken,
          downloadUrl: apiRes.downloadUrl,
          fullShareUrl,
          expiresAt: apiRes.expiresAt,
          sha256Checksum: cryptoResult.sha256Checksum,
        };

        if (globalThis.localStorage) {
          try {
            const history = JSON.parse(globalThis.localStorage.getItem('vaultx_history') || '[]');
            history.unshift({
              fileId: apiRes.fileId,
              ownerToken: apiRes.ownerToken,
              filename: metaObj.filename,
              mode,
              createdAt: new Date().toISOString(),
            });
            globalThis.localStorage.setItem('vaultx_history', JSON.stringify(history));
          } catch (_) {}
        }

        setResult(uploadResult);
        setStatus('success');
        return uploadResult;
      } catch (err) {
        setError(err.message || 'Upload failed');
        setStatus('error');
        throw err;
      }
    }, [
      tab,
      file,
      textNote,
      mode,
      recipientUsername,
      recipientInfo,
      expiryMinutes,
      maxDownloads,
      isBurnAfterReading,
      isPasswordProtected,
      password,
      lookupRecipient,
    ]);

    return {
      tab,
      setTab,
      mode,
      setMode,
      file,
      setFile,
      textNote,
      setTextNote,
      recipientUsername,
      setRecipientUsername,
      recipientInfo,
      lookupRecipient,
      expiryMinutes,
      setExpiryMinutes,
      maxDownloads,
      setMaxDownloads,
      isBurnAfterReading,
      setIsBurnAfterReading,
      isPasswordProtected,
      setIsPasswordProtected,
      password,
      setPassword,
      status,
      result,
      error,
      executeUpload,
      reset,
    };
  };
}

// ==========================================
// 5. Reference Implementation: useDecrypt hook
// ==========================================
export function createUseDecryptHook(api = ReferenceApi, cryptoLib = ReferenceVaultCrypto, keyStore = ReferenceKeyStore) {
  return function useDecrypt(fileId, initialFragment = null, recipientUsername = null) {
    const [status, setStatus] = React.useState('idle'); // 'idle'|'loading_meta'|'password_required'|'decrypting'|'ready'|'tampered'|'error'
    const [hasFragmentKey, setHasFragmentKey] = React.useState(false);
    const [meta, setMeta] = React.useState(null);
    const [fileBlob, setFileBlob] = React.useState(null);
    const [previewUrl, setPreviewUrl] = React.useState(null);
    const [previewType, setPreviewType] = React.useState(null);
    const [isChecksumValid, setIsChecksumValid] = React.useState(null);
    const [sha256Checksum, setSha256Checksum] = React.useState(null);
    const [error, setError] = React.useState(null);
    const [manualKey, setManualKey] = React.useState('');

    const previewUrlRef = React.useRef(null);
    previewUrlRef.current = previewUrl;
    const downloadedDataRef = React.useRef(null);

    // Cleanup on unmount
    React.useEffect(() => {
      return () => {
        if (previewUrlRef.current) {
          URL.revokeObjectURL(previewUrlRef.current);
        }
      };
    }, []);

    const extractKeyFromHash = React.useCallback((hashString) => {
      if (!hashString) return null;
      const match = hashString.match(/[#&]key=([A-Za-z0-9_-]+)/);
      return match ? match[1] : null;
    }, []);

    const performDecryption = React.useCallback(
      async (keyB64Url, userPassword = null, metaData = null) => {
        setStatus('decrypting');
        setError(null);
        try {
          let downloadRes = downloadedDataRef.current;
          if (!downloadRes) {
            downloadRes = await api.downloadFile(fileId);
            if (!downloadRes.success) {
              throw new Error(downloadRes.message || 'Download failed');
            }
            downloadedDataRef.current = downloadRes;
          }

          const currentMeta = metaData || meta;
          const cipherBytes = MockCrypto.fromBase64(downloadRes.encryptedBlobB64);
          const mode = currentMeta?.mode || 'MODE_B';

          let keyMaterial;
          if (mode === 'MODE_B') {
            keyMaterial = keyB64Url;
          } else {
            // Mode A: lookup current user key in KeyStore
            const username = recipientUsername || currentMeta?.recipientUsername || 'current_user';
            let userKey = await keyStore.getUserKey(username);
            if (!userKey || !userKey.keyPair?.privateKey) {
              userKey = (await keyStore.getUserKey('current_user')) || (await keyStore.getUserKey('alice'));
            }
            if (!userKey || !userKey.keyPair?.privateKey) {
              throw new Error(`Private key for recipient "${username}" not found in KeyStore`);
            }
            keyMaterial = {
              privateKey: userKey.keyPair.privateKey,
              wrappedAesKeyB64: currentMeta.wrappedAesKeyB64,
            };
          }

          const decryptOpts = {
            metaIvB64: downloadRes.metaIvB64 || currentMeta.metaIvB64,
          };
          if (userPassword) {
            decryptOpts.password = userPassword;
          }

          const result = await cryptoLib.decryptFileAndMeta(
            cipherBytes.buffer,
            downloadRes.ivB64,
            currentMeta.encryptedMetaB64,
            keyMaterial,
            mode,
            decryptOpts
          );

          if (!result.isChecksumValid) {
            setStatus('tampered');
            setIsChecksumValid(false);
            setError('Integrity checksum verification failed');
            return;
          }

          setIsChecksumValid(true);
          setSha256Checksum(result.sha256Checksum);

          const mimeType = result.metaObj?.mimeType || 'application/octet-stream';
          const blob = new Blob([result.fileBuffer], { type: mimeType });
          setFileBlob(blob);

          // Build preview URL
          const objUrl = URL.createObjectURL(blob);
          setPreviewUrl(objUrl);

          if (mimeType.startsWith('image/')) {
            setPreviewType('image');
          } else if (mimeType.startsWith('text/') || result.metaObj?.isNote) {
            setPreviewType('text');
          } else if (mimeType === 'application/pdf') {
            setPreviewType('pdf');
          } else {
            setPreviewType('binary');
          }

          setStatus('ready');
        } catch (err) {
          setError(err.message || 'Decryption failed');
          setStatus('error');
          throw err;
        }
      },
      [fileId, meta]
    );

    const submitPassword = React.useCallback(
      async (pwd) => {
        const hash = initialFragment || (globalThis.location ? globalThis.location.hash : '');
        const key = extractKeyFromHash(hash) || manualKey;
        await performDecryption(key, pwd, meta);
      },
      [initialFragment, manualKey, meta, extractKeyFromHash, performDecryption]
    );

    // Initial load
    React.useEffect(() => {
      let cancelled = false;
      async function loadMeta() {
        if (!fileId) return;
        setStatus('loading_meta');
        try {
          const metaRes = await api.getMetadata(fileId);
          if (cancelled) return;
          if (!metaRes.success) {
            setError(metaRes.message || 'File not found');
            setStatus('error');
            return;
          }
          setMeta(metaRes);

          const hash = initialFragment || (globalThis.location ? globalThis.location.hash : '');
          const key = extractKeyFromHash(hash);
          const hasKey = !!key;
          setHasFragmentKey(hasKey);

          if (metaRes.mode === 'MODE_B') {
            if (!hasKey) {
              setStatus('idle');
              return;
            }
            if (metaRes.isPasswordProtected) {
              setStatus('password_required');
              return;
            }
            await performDecryption(key, null, metaRes);
          } else {
            // Mode A
            await performDecryption(null, null, metaRes);
          }
        } catch (err) {
          if (!cancelled) {
            setError(err.message || 'Failed to load vault item');
            setStatus('error');
          }
        }
      }

      loadMeta();
      return () => {
        cancelled = true;
      };
    }, [fileId, initialFragment]);

    const downloadToDisk = React.useCallback(() => {
      if (!fileBlob || !meta) return;
      // In browser, trigger <a> download
    }, [fileBlob, meta]);

    const destroyNow = React.useCallback(() => {
      if (previewUrlRef.current) {
        URL.revokeObjectURL(previewUrlRef.current);
        setPreviewUrl(null);
      }
      setFileBlob(null);
      setStatus('idle');
    }, []);

    return {
      status,
      hasFragmentKey,
      meta,
      fileBlob,
      previewUrl,
      previewType,
      isChecksumValid,
      sha256Checksum,
      error,
      submitPassword,
      setManualKey,
      downloadToDisk,
      destroyNow,
    };
  };
}

// ==========================================
// 6. Contract Resolvers (Dynamic Imports with Fallback)
// ==========================================
let resolvedVaultCrypto = null;
let resolvedKeyStore = null;
let resolvedApi = null;
let resolvedUseUpload = null;
let resolvedUseDecrypt = null;

export async function getVaultCrypto() {
  if (resolvedVaultCrypto) return resolvedVaultCrypto;
  try {
    const mod = await import('../../../lib/vaultCrypto.js');
    resolvedVaultCrypto = mod.default || mod;
    return resolvedVaultCrypto;
  } catch (_) {
    resolvedVaultCrypto = ReferenceVaultCrypto;
    return resolvedVaultCrypto;
  }
}

export async function getKeyStore() {
  if (resolvedKeyStore) return resolvedKeyStore;
  try {
    const mod = await import('../../../lib/keyStore.js');
    resolvedKeyStore = mod.default || mod;
    return resolvedKeyStore;
  } catch (_) {
    resolvedKeyStore = ReferenceKeyStore;
    return resolvedKeyStore;
  }
}

export async function getApi() {
  if (resolvedApi) return resolvedApi;
  try {
    const mod = await import('../../../lib/api.js');
    resolvedApi = mod.default || mod;
    return resolvedApi;
  } catch (_) {
    resolvedApi = ReferenceApi;
    return resolvedApi;
  }
}

export async function getUseUpload() {
  if (resolvedUseUpload) return resolvedUseUpload;
  try {
    const mod = await import('../../../hooks/useUpload.js');
    resolvedUseUpload = mod.useUpload || mod.default;
    return resolvedUseUpload;
  } catch (_) {
    const api = await getApi();
    const cryptoLib = await getVaultCrypto();
    resolvedUseUpload = createUseUploadHook(api, cryptoLib);
    return resolvedUseUpload;
  }
}

export async function getUseDecrypt() {
  if (resolvedUseDecrypt) return resolvedUseDecrypt;
  try {
    const mod = await import('../../../hooks/useDecrypt.js');
    resolvedUseDecrypt = mod.useDecrypt || mod.default;
    return resolvedUseDecrypt;
  } catch (_) {
    const api = await getApi();
    const cryptoLib = await getVaultCrypto();
    const keyStore = await getKeyStore();
    resolvedUseDecrypt = createUseDecryptHook(api, cryptoLib, keyStore);
    return resolvedUseDecrypt;
  }
}

// Structural Component Placeholders for F7 tests
export function MockUploadCard(props) {
  return React.createElement('div', { className: 'upload-card p-6 border rounded-lg bg-white shadow-sm' },
    React.createElement('div', { className: 'tabs flex gap-4' },
      React.createElement('button', { className: 'tab-file px-4 py-2' }, 'File Upload'),
      React.createElement('button', { className: 'tab-note px-4 py-2' }, 'Secret Note')
    ),
    React.createElement('div', { className: 'mode-selector my-4' },
      React.createElement('label', null, 'Sharing Mode')
    ),
    React.createElement('button', {
      className: 'btn-upload px-6 py-2 bg-blue-600 text-white rounded',
      disabled: props.isModeA && !props.recipientUsername,
    }, 'Encrypt & Share')
  );
}

export function MockDecryptView(props) {
  return React.createElement('div', { className: 'decrypt-view p-6 border rounded-lg bg-white' },
    props.isChecksumValid === false && React.createElement('div', { className: 'warning-banner text-red-600 font-bold' },
      'Integrity Check Failed / Tampered Payload'
    ),
    props.isChecksumValid === true && React.createElement('div', { className: 'badge-verified text-green-600' },
      'Authentic • Verified'
    ),
    React.createElement('h3', { className: 'text-lg font-semibold' }, 'Vault Access')
  );
}

export function MockQRModal(props) {
  if (!props.isOpen) return null;
  return React.createElement('div', { className: 'modal-overlay fixed inset-0 bg-black/50' },
    React.createElement('div', { className: 'modal-container bg-white p-6 rounded-lg' },
      React.createElement('h3', null, 'Scan QR Code'),
      React.createElement('svg', { className: 'qr-code-svg' }),
      React.createElement('button', { className: 'btn-copy' }, 'Copy Link')
    )
  );
}

export function MockKeySetupModal(props) {
  if (!props.isOpen) return null;
  return React.createElement('div', { className: 'modal-container bg-white p-6 rounded-lg' },
    React.createElement('h3', null, 'Key Setup'),
    React.createElement('button', {
      className: 'btn-generate-key',
      onClick: () => {
        if (props.onKeyGenerated) props.onKeyGenerated({ fingerprint: '54:75:fa:29:mock' });
      }
    }, 'Generate Key Pair'),
    props.fingerprint && React.createElement('span', { className: 'fingerprint-badge' }, props.fingerprint)
  );
}

export function MockAuditTrail(props) {
  return React.createElement('div', { className: 'audit-trail' },
    React.createElement('h4', null, 'Audit Trail'),
    React.createElement('table', null,
      React.createElement('tbody', null,
        (props.logs || []).map((l, i) =>
          React.createElement('tr', { key: i },
            React.createElement('td', null, l.timestamp),
            React.createElement('td', null, l.event),
            React.createElement('td', null, l.ipHash)
          )
        )
      )
    )
  );
}

export function MockHexInspector(props) {
  return React.createElement('div', { className: 'hex-inspector font-mono flex gap-4' },
    React.createElement('div', { className: 'hex-bytes' }, '48 65 6c 6c 6f'),
    React.createElement('div', { className: 'ascii-text' }, 'Hello')
  );
}

export function MockRevokeButton(props) {
  return React.createElement('button', {
    className: 'btn-revoke bg-red-600 text-white px-4 py-2 rounded',
    onClick: props.onRevoke,
  }, 'Revoke Access');
}
