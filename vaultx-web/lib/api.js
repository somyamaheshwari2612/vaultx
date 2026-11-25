/**
 * VaultX REST API Client
 * Connects to live backend with seamless offline mock store fallback.
 */

import { bufferToBase64 } from './vaultCrypto.js';

export class ApiError extends Error {
  constructor(message, status = 500, data = null) {
    super(message);
    this.name = 'ApiError';
    this.status = status;
    this.data = data;
  }
}

const BASE_URL = (typeof process !== 'undefined' && process.env?.NEXT_PUBLIC_API_URL) || 'http://localhost:5000/api';
const FORCE_MOCK = typeof process !== 'undefined' && process.env?.NEXT_PUBLIC_MOCK_BACKEND === 'true';

// ==========================================
// Offline Mock Store State
// ==========================================

const mockUsers = new Map();
const mockVaults = new Map();

function initMockData() {
  if (typeof window !== 'undefined' && window.localStorage) {
    try {
      const storedUsers = localStorage.getItem('vaultx_mock_users');
      if (storedUsers) {
        const parsed = JSON.parse(storedUsers);
        for (const [k, v] of Object.entries(parsed)) {
          mockUsers.set(k, v);
        }
      }
      const storedVaults = localStorage.getItem('vaultx_mock_vaults');
      if (storedVaults) {
        const parsed = JSON.parse(storedVaults);
        for (const [k, v] of Object.entries(parsed)) {
          mockVaults.set(k, v);
        }
      }
    } catch (err) {
      // Ignore localStorage read errors
    }
  }
}

function persistMockData() {
  if (typeof window !== 'undefined' && window.localStorage) {
    try {
      const uObj = Object.fromEntries(mockUsers.entries());
      localStorage.setItem('vaultx_mock_users', JSON.stringify(uObj));
      const vObj = Object.fromEntries(mockVaults.entries());
      localStorage.setItem('vaultx_mock_vaults', JSON.stringify(vObj));
    } catch (err) {
      // Ignore localStorage write errors
    }
  }
}

initMockData();

function generateRandomHex(byteCount) {
  const bytes = new Uint8Array(byteCount);
  if (typeof globalThis !== 'undefined' && globalThis.crypto) {
    globalThis.crypto.getRandomValues(bytes);
  } else {
    for (let i = 0; i < byteCount; i++) {
      bytes[i] = Math.floor(Math.random() * 256);
    }
  }
  return Array.from(bytes).map((b) => b.toString(16).padStart(2, '0')).join('');
}

// ==========================================
// API Operations
// ==========================================

/**
 * Registers a user with their public key PEM and SHA-256 fingerprint.
 */
export async function registerUser({ username, publicKeyPem, fingerprint }) {
  if (!username || !publicKeyPem) {
    throw new ApiError('Username and publicKeyPem are required', 400);
  }

  if (!FORCE_MOCK) {
    try {
      const res = await fetch(`${BASE_URL}/users/register`, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ username, publicKeyPem, fingerprint })
      });

      if (!res.ok) {
        const errJson = await res.json().catch(() => ({}));
        throw new ApiError(errJson.message || `HTTP ${res.status}: Registration failed`, res.status, errJson);
      }

      return await res.json();
    } catch (err) {
      if (err instanceof ApiError) throw err;
      // Network failure: fallback to mock store
    }
  }

  // Mock Store Implementation
  initMockData();
  if (mockUsers.has(username)) {
    throw new ApiError('Username is already registered', 409);
  }

  const record = {
    username,
    publicKeyPem,
    fingerprint: fingerprint || '00:00:00',
    createdAt: new Date().toISOString()
  };
  mockUsers.set(username, record);
  persistMockData();

  return {
    success: true,
    user: {
      username: record.username,
      fingerprint: record.fingerprint
    }
  };
}

/**
 * Retrieves a user's public key PEM and fingerprint by username (Mode A lookup).
 */
export async function getUserPubKey(username) {
  if (!username) {
    throw new ApiError('Username is required', 400);
  }

  if (!FORCE_MOCK) {
    try {
      const res = await fetch(`${BASE_URL}/users/${encodeURIComponent(username)}/pubkey`, {
        method: 'GET',
        headers: { Accept: 'application/json' }
      });

      if (!res.ok) {
        const errJson = await res.json().catch(() => ({}));
        throw new ApiError(errJson.message || `HTTP ${res.status}: User not found`, res.status, errJson);
      }

      return await res.json();
    } catch (err) {
      if (err instanceof ApiError) throw err;
      // Network failure: fallback to mock store
    }
  }

  // Mock Store Implementation
  initMockData();
  const user = mockUsers.get(username);
  if (!user) {
    throw new ApiError(`User '${username}' not found`, 404);
  }

  return {
    success: true,
    username: user.username,
    publicKeyPem: user.publicKeyPem,
    fingerprint: user.fingerprint
  };
}

/**
 * Uploads an encrypted file payload and associated ciphertext metadata.
 */
export async function uploadFile(payload) {
  if (!payload || !payload.encryptedMetaB64 || !payload.ivB64) {
    throw new ApiError('Invalid upload payload: ciphertext and IV required', 400);
  }

  // Normalize encryptedBlob to base64 string
  let blobB64 = payload.encryptedBlobB64 || '';
  if (!blobB64 && payload.encryptedBlob) {
    blobB64 = bufferToBase64(payload.encryptedBlob);
  }

  const requestBody = {
    encryptedBlobB64: blobB64,
    ivB64: payload.ivB64,
    metaIvB64: payload.metaIvB64 || payload.ivB64,
    encryptedMetaB64: payload.encryptedMetaB64,
    wrappedAesKeyB64: payload.wrappedAesKeyB64 || null,
    mode: payload.mode || 'MODE_B',
    isPasswordProtected: Boolean(payload.isPasswordProtected),
    isBurnAfterReading: Boolean(payload.isBurnAfterReading),
    expiryMinutes: payload.expiryMinutes || 60,
    maxDownloads: payload.maxDownloads || 1,
    recipientUsername: payload.recipientUsername || null
  };

  if (!FORCE_MOCK) {
    try {
      const res = await fetch(`${BASE_URL}/vault/upload`, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify(requestBody)
      });

      if (!res.ok) {
        const errJson = await res.json().catch(() => ({}));
        throw new ApiError(errJson.message || `HTTP ${res.status}: Upload failed`, res.status, errJson);
      }

      return await res.json();
    } catch (err) {
      if (err instanceof ApiError) throw err;
      // Network failure: fallback to mock store
    }
  }

  // Mock Store Implementation
  initMockData();
  const fileId = generateRandomHex(8);
  const ownerToken = generateRandomHex(16);
  const expiryMs = (requestBody.expiryMinutes || 60) * 60 * 1000;
  const expiresAt = new Date(Date.now() + expiryMs).toISOString();

  const vaultRecord = {
    id: fileId,
    ownerToken,
    mode: requestBody.mode,
    recipientUsername: requestBody.recipientUsername || null,
    encryptedBlobB64: requestBody.encryptedBlobB64,
    ivB64: requestBody.ivB64,
    metaIvB64: requestBody.metaIvB64,
    encryptedMetaB64: requestBody.encryptedMetaB64,
    wrappedAesKeyB64: requestBody.wrappedAesKeyB64,
    isPasswordProtected: requestBody.isPasswordProtected,
    isBurnAfterReading: requestBody.isBurnAfterReading,
    maxDownloads: requestBody.maxDownloads,
    remainingDownloads: requestBody.maxDownloads,
    expiresAt,
    createdAt: new Date().toISOString(),
    revoked: false,
    burned: false,
    logs: [
      {
        timestamp: new Date().toISOString(),
        ipHash: 'mock-owner',
        event: 'CREATED'
      }
    ]
  };

  mockVaults.set(fileId, vaultRecord);
  persistMockData();

  return {
    success: true,
    fileId,
    ownerToken,
    downloadUrl: `/v/${fileId}`,
    expiresAt
  };
}

/**
 * Retrieves public metadata and encrypted headers for a vault item.
 */
export async function getMetadata(id) {
  if (!id) {
    throw new ApiError('Vault ID is required', 400);
  }

  if (!FORCE_MOCK) {
    try {
      const res = await fetch(`${BASE_URL}/vault/${encodeURIComponent(id)}/meta`, {
        method: 'GET',
        headers: { Accept: 'application/json' }
      });

      if (!res.ok) {
        const errJson = await res.json().catch(() => ({}));
        throw new ApiError(errJson.message || `HTTP ${res.status}: Metadata retrieval failed`, res.status, errJson);
      }

      return await res.json();
    } catch (err) {
      if (err instanceof ApiError) throw err;
      // Network failure: fallback to mock store
    }
  }

  // Mock Store Implementation
  initMockData();
  const vault = mockVaults.get(id);
  if (!vault) {
    throw new ApiError(`Vault '${id}' not found`, 404);
  }

  if (vault.revoked) {
    throw new ApiError('Vault has been revoked by owner', 410);
  }

  if (vault.burned) {
    throw new ApiError('Vault has been burned or exceeded download limit', 410);
  }

  if (new Date(vault.expiresAt).getTime() <= Date.now()) {
    vault.burned = true;
    persistMockData();
    throw new ApiError('Vault has expired', 410);
  }

  if (vault.remainingDownloads <= 0) {
    vault.burned = true;
    persistMockData();
    throw new ApiError('Vault download limit reached', 410);
  }

  return {
    success: true,
    id: vault.id,
    mode: vault.mode,
    recipientUsername: vault.recipientUsername || null,
    encryptedMetaB64: vault.encryptedMetaB64,
    ivB64: vault.ivB64,
    metaIvB64: vault.metaIvB64,
    wrappedAesKeyB64: vault.wrappedAesKeyB64,
    isPasswordProtected: vault.isPasswordProtected,
    isBurnAfterReading: vault.isBurnAfterReading,
    maxDownloads: vault.maxDownloads,
    remainingDownloads: vault.remainingDownloads,
    expiresAt: vault.expiresAt
  };
}

/**
 * Downloads the encrypted file payload, decrementing remaining downloads.
 */
export async function downloadFile(id, authOptions = {}) {
  if (!id) {
    throw new ApiError('Vault ID is required', 400);
  }

  if (!FORCE_MOCK) {
    try {
      const res = await fetch(`${BASE_URL}/vault/${encodeURIComponent(id)}/download`, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify(authOptions || {})
      });

      if (!res.ok) {
        const errJson = await res.json().catch(() => ({}));
        throw new ApiError(errJson.message || `HTTP ${res.status}: Download failed`, res.status, errJson);
      }

      return await res.json();
    } catch (err) {
      if (err instanceof ApiError) throw err;
      // Network failure: fallback to mock store
    }
  }

  // Mock Store Implementation
  initMockData();
  const vault = mockVaults.get(id);
  if (!vault) {
    throw new ApiError(`Vault '${id}' not found`, 404);
  }

  if (vault.revoked) {
    throw new ApiError('Vault has been revoked by owner', 410);
  }

  if (vault.burned) {
    throw new ApiError('Vault has been burned or exceeded download limit', 410);
  }

  if (new Date(vault.expiresAt).getTime() <= Date.now()) {
    vault.burned = true;
    persistMockData();
    throw new ApiError('Vault has expired', 410);
  }

  if (vault.remainingDownloads <= 0) {
    vault.burned = true;
    persistMockData();
    throw new ApiError('Vault download limit reached', 410);
  }

  // Decrement download count and append audit log
  vault.remainingDownloads -= 1;
  vault.logs.push({
    timestamp: new Date().toISOString(),
    ipHash: 'mock-recipient',
    event: 'DOWNLOAD'
  });

  // Check burn after reading or download exhaustion
  if (vault.isBurnAfterReading || vault.remainingDownloads <= 0) {
    vault.burned = true;
    vault.logs.push({
      timestamp: new Date().toISOString(),
      ipHash: 'system',
      event: 'BURNED'
    });
  }

  persistMockData();

  return {
    success: true,
    encryptedBlobB64: vault.encryptedBlobB64,
    ivB64: vault.ivB64,
    metaIvB64: vault.metaIvB64,
    remainingDownloads: vault.remainingDownloads
  };
}

/**
 * Retrieves the access audit trail logs for an owned vault item.
 */
export async function getAccessLogs(id, ownerToken) {
  if (!id || !ownerToken) {
    throw new ApiError('Vault ID and ownerToken are required', 400);
  }

  if (!FORCE_MOCK) {
    try {
      const res = await fetch(`${BASE_URL}/vault/${encodeURIComponent(id)}/logs`, {
        method: 'GET',
        headers: {
          Accept: 'application/json',
          'x-owner-token': ownerToken
        }
      });

      if (!res.ok) {
        const errJson = await res.json().catch(() => ({}));
        throw new ApiError(errJson.message || `HTTP ${res.status}: Access logs failed`, res.status, errJson);
      }

      return await res.json();
    } catch (err) {
      if (err instanceof ApiError) throw err;
      // Network failure: fallback to mock store
    }
  }

  // Mock Store Implementation
  initMockData();
  const vault = mockVaults.get(id);
  if (!vault) {
    throw new ApiError(`Vault '${id}' not found`, 404);
  }

  if (vault.ownerToken !== ownerToken) {
    throw new ApiError('Unauthorized: invalid owner token', 401);
  }

  return {
    success: true,
    logs: [...vault.logs]
  };
}

/**
 * Revokes a vault item immediately (kill-switch deletion).
 */
export async function revokeFile(id, ownerToken) {
  if (!id || !ownerToken) {
    throw new ApiError('Vault ID and ownerToken are required', 400);
  }

  if (!FORCE_MOCK) {
    try {
      const res = await fetch(`${BASE_URL}/vault/${encodeURIComponent(id)}/revoke`, {
        method: 'POST',
        headers: {
          'Content-Type': 'application/json',
          'x-owner-token': ownerToken
        }
      });

      if (!res.ok) {
        const errJson = await res.json().catch(() => ({}));
        throw new ApiError(errJson.message || `HTTP ${res.status}: Revocation failed`, res.status, errJson);
      }

      return await res.json();
    } catch (err) {
      if (err instanceof ApiError) throw err;
      // Network failure: fallback to mock store
    }
  }

  // Mock Store Implementation
  initMockData();
  const vault = mockVaults.get(id);
  if (!vault) {
    throw new ApiError(`Vault '${id}' not found`, 404);
  }

  if (vault.ownerToken !== ownerToken) {
    throw new ApiError('Unauthorized: invalid owner token', 401);
  }

  vault.revoked = true;
  vault.burned = true;
  vault.logs.push({
    timestamp: new Date().toISOString(),
    ipHash: 'mock-owner',
    event: 'REVOKED'
  });

  persistMockData();

  return {
    success: true,
    message: 'Revoked'
  };
}
