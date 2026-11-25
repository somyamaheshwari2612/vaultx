/**
 * VaultX Client Crypto Engine (Dual-Mode Web Crypto API)
 * Pure ES module using native window.crypto.subtle + keyStore.js.
 * Zero external cryptographic dependencies.
 */

import { savePrivateKey, getPrivateKey } from "./keyStore.js";

const AES_KEY_LENGTH = 256;
const GCM_IV_BYTES = 12;
const RSA_MODULUS_BITS = 2048;
const PBKDF2_ITERATIONS = 250_000;
const DEFAULT_KEY_ID = "default";

// ============================================================================
// Locked Integration Contracts (Imported by Person 3's vaultx-web/lib/)
// ============================================================================

/**
 * Generate an RSA-OAEP keypair, store the private key in IndexedDB
 * (extractable: false), and return the PEM public key + fingerprint.
 * @param {string} [masterPassphrase]
 * @returns {Promise<{ publicKeyPem: string, keyFingerprint: string }>}
 */
export async function generateUserKeyPair(masterPassphrase = "") {
  const keyPair = await crypto.subtle.generateKey(
    {
      name: "RSA-OAEP",
      modulusLength: RSA_MODULUS_BITS,
      publicExponent: new Uint8Array([1, 0, 1]),
      hash: "SHA-256",
    },
    false, // Private key is non-extractable
    ["unwrapKey", "decrypt"]
  );

  const spkiBuffer = await crypto.subtle.exportKey("spki", keyPair.publicKey);
  const publicKeyPem = await exportPublicKeyPem(keyPair.publicKey);
  const keyFingerprint = await computeKeyFingerprint(spkiBuffer);

  await savePrivateKey(DEFAULT_KEY_ID, keyPair.privateKey, {
    keyFingerprint,
    createdAt: new Date().toISOString(),
    hasPassphrase: Boolean(masterPassphrase),
  });

  return { publicKeyPem, keyFingerprint };
}

/**
 * Encrypt fileBuffer and metaObj with AES-256-GCM (12-byte IV) and SHA-256 checksum.
 * Supports Mode A (registered user RSA-OAEP key wrapping) and Mode B (#fragment key export).
 * @param {ArrayBuffer | Uint8Array | Blob} fileBuffer
 * @param {object} metaObj
 * @param {"registered" | "link" | "A" | "B"} mode
 * @param {string | null} recipientPublicKeyOrNull
 * @returns {Promise<{
 *   encryptedBlob: Blob,
 *   ivB64: string,
 *   encryptedMetaB64: string,
 *   wrappedAesKeyB64: string | null,
 *   fragmentKeyB64: string | null,
 *   sha256Checksum: string
 * }>}
 */
export async function encryptFileAndMeta(
  fileBuffer,
  metaObj,
  mode,
  recipientPublicKeyOrNull = null
) {
  const normalizedMode = normalizeMode(mode);
  const plainBytes = await toUint8Array(fileBuffer);

  // 1. Compute SHA-256 checksum of plaintext for integrity verification
  const sha256Checksum = await computeSha256(plainBytes);

  // 2. Generate a fresh 256-bit AES-GCM key for this file
  const aesKey = await crypto.subtle.generateKey(
    { name: "AES-GCM", length: AES_KEY_LENGTH },
    true,
    ["encrypt", "decrypt"]
  );

  // 3. Encrypt file bytes with a random 12-byte IV
  const fileIv = crypto.getRandomValues(new Uint8Array(GCM_IV_BYTES));
  const encryptedFileBuffer = await crypto.subtle.encrypt(
    { name: "AES-GCM", iv: fileIv },
    aesKey,
    plainBytes
  );
  const encryptedBlob = new Blob([encryptedFileBuffer], {
    type: "application/octet-stream",
  });
  const ivB64 = toBase64(fileIv);

  // 4. Encrypt metadata with a separate 12-byte IV (never reuse key+IV in GCM)
  const metaIv = crypto.getRandomValues(new Uint8Array(GCM_IV_BYTES));
  const metaPayload = new TextEncoder().encode(
    JSON.stringify({ ...(metaObj || {}), _sha256: sha256Checksum })
  );
  const encryptedMetaCipher = new Uint8Array(
    await crypto.subtle.encrypt({ name: "AES-GCM", iv: metaIv }, aesKey, metaPayload)
  );
  const packedMeta = new Uint8Array(GCM_IV_BYTES + encryptedMetaCipher.length);
  packedMeta.set(metaIv, 0);
  packedMeta.set(encryptedMetaCipher, GCM_IV_BYTES);
  const encryptedMetaB64 = toBase64(packedMeta);

  // 5. Key delivery per mode
  let wrappedAesKeyB64 = null;
  let fragmentKeyB64 = null;

  if (normalizedMode === "A") {
    if (!recipientPublicKeyOrNull) {
      throw new Error("Mode A (registered user) requires recipientPublicKeyOrNull.");
    }
    wrappedAesKeyB64 = await wrapAesKeyWithPublicKey(aesKey, recipientPublicKeyOrNull);
  } else {
    const rawAesKey = await crypto.subtle.exportKey("raw", aesKey);
    fragmentKeyB64 = toBase64Url(rawAesKey);
  }

  return {
    encryptedBlob,
    ivB64,
    encryptedMetaB64,
    wrappedAesKeyB64,
    fragmentKeyB64,
    sha256Checksum,
  };
}

/**
 * Decrypt file and metadata and verify SHA-256 integrity checksum.
 * @param {Blob | ArrayBuffer | Uint8Array} encryptedBlob
 * @param {string} ivB64
 * @param {string} encryptedMetaB64
 * @param {string | CryptoKey | { wrappedAesKeyB64: string, keyId?: string }} keyMaterial
 * @param {"registered" | "link" | "A" | "B"} mode
 * @returns {Promise<{
 *   fileBuffer: ArrayBuffer,
 *   metaObj: object,
 *   isChecksumValid: boolean
 * }>}
 */
export async function decryptFileAndMeta(
  encryptedBlob,
  ivB64,
  encryptedMetaB64,
  keyMaterial,
  mode
) {
  const normalizedMode = normalizeMode(mode);
  const encryptedBytes = await toUint8Array(encryptedBlob);
  const fileIv = fromBase64(ivB64);

  // 1. Recover AES-GCM CryptoKey
  let aesKey;
  if (normalizedMode === "A") {
    const wrappedKeyB64 =
      typeof keyMaterial === "string" ? keyMaterial : keyMaterial?.wrappedAesKeyB64;
    const keyId =
      typeof keyMaterial === "object" && keyMaterial?.keyId
        ? keyMaterial.keyId
        : DEFAULT_KEY_ID;

    if (!wrappedKeyB64) {
      throw new Error("Mode A decryption requires wrappedAesKeyB64.");
    }

    const stored = await getPrivateKey(keyId);
    if (!stored?.privateKey) {
      throw new Error("No private key found in browser IndexedDB for this account.");
    }
    aesKey = await unwrapAesKeyWithPrivateKey(wrappedKeyB64, stored.privateKey);
  } else {
    if (keyMaterial instanceof CryptoKey) {
      aesKey = keyMaterial;
    } else if (typeof keyMaterial === "string" && keyMaterial.length > 0) {
      const rawKeyBytes = fromBase64Url(keyMaterial);
      aesKey = await crypto.subtle.importKey(
        "raw",
        rawKeyBytes,
        { name: "AES-GCM", length: AES_KEY_LENGTH },
        false,
        ["decrypt"]
      );
    } else {
      throw new Error("Mode B decryption requires a fragmentKeyB64 string or CryptoKey.");
    }
  }

  // 2. Decrypt file buffer
  const fileBuffer = await crypto.subtle.decrypt(
    { name: "AES-GCM", iv: fileIv },
    aesKey,
    encryptedBytes
  );

  // 3. Decrypt metadata (12-byte IV prefix + ciphertext)
  const packedMeta = fromBase64(encryptedMetaB64);
  if (packedMeta.length <= GCM_IV_BYTES) {
    throw new Error("Invalid encrypted metadata payload.");
  }
  const metaIv = packedMeta.slice(0, GCM_IV_BYTES);
  const metaCipher = packedMeta.slice(GCM_IV_BYTES);
  const decryptedMetaBuffer = await crypto.subtle.decrypt(
    { name: "AES-GCM", iv: metaIv },
    aesKey,
    metaCipher
  );

  const parsedMeta = JSON.parse(new TextDecoder().decode(decryptedMetaBuffer));
  const { _sha256: expectedSha256, ...metaObj } = parsedMeta;

  // 4. Verify SHA-256 checksum against decrypted file bytes
  const actualSha256 = await computeSha256(fileBuffer);
  const isChecksumValid = Boolean(expectedSha256 && actualSha256 === expectedSha256);

  return {
    fileBuffer,
    metaObj,
    isChecksumValid,
  };
}

// ============================================================================
// Internal Crypto & Encoding Helpers
// ============================================================================

/**
 * Compute hex-encoded SHA-256 digest of binary data.
 * @param {ArrayBuffer | Uint8Array} data
 * @returns {Promise<string>}
 */
export async function computeSha256(data) {
  const bytes = data instanceof Uint8Array ? data : new Uint8Array(data);
  const digest = await crypto.subtle.digest("SHA-256", bytes);
  return Array.from(new Uint8Array(digest))
    .map((b) => b.toString(16).padStart(2, "0"))
    .join("");
}

/**
 * Compute a short human-verifiable fingerprint from an exported SPKI public key.
 * @param {ArrayBuffer} publicKeyBuffer
 * @returns {Promise<string>}
 */
export async function computeKeyFingerprint(publicKeyBuffer) {
  const hex = await computeSha256(publicKeyBuffer);
  // Format first 16 hex chars (64 bits) as 4 groups: XXXX-XXXX-XXXX-XXXX
  return hex.slice(0, 16).toUpperCase().match(/.{1,4}/g).join("-");
}

/**
 * Export an RSA-OAEP CryptoKey public key to PEM format.
 * @param {CryptoKey} publicKey
 * @returns {Promise<string>}
 */
export async function exportPublicKeyPem(publicKey) {
  const spki = await crypto.subtle.exportKey("spki", publicKey);
  const b64 = toBase64(spki);
  const lines = b64.match(/.{1,64}/g)?.join("\n") ?? b64;
  return `-----BEGIN PUBLIC KEY-----\n${lines}\n-----END PUBLIC KEY-----`;
}

/**
 * Import a PEM-encoded RSA-OAEP public key into a CryptoKey.
 * @param {string} pem
 * @returns {Promise<CryptoKey>}
 */
export async function importPublicKeyPem(pem) {
  const cleanB64 = pem
    .replace(/-----BEGIN PUBLIC KEY-----/g, "")
    .replace(/-----END PUBLIC KEY-----/g, "")
    .replace(/\s+/g, "");
  const derBytes = fromBase64(cleanB64);

  return crypto.subtle.importKey(
    "spki",
    derBytes,
    { name: "RSA-OAEP", hash: "SHA-256" },
    true,
    ["wrapKey", "encrypt"]
  );
}

/**
 * Derive an AES-GCM key from a user passphrase and salt using PBKDF2.
 * @param {string} passphrase
 * @param {Uint8Array} salt
 * @returns {Promise<CryptoKey>}
 */
export async function deriveKeyFromPassphrase(passphrase, salt) {
  const baseKey = await crypto.subtle.importKey(
    "raw",
    new TextEncoder().encode(passphrase),
    "PBKDF2",
    false,
    ["deriveKey"]
  );

  return crypto.subtle.deriveKey(
    {
      name: "PBKDF2",
      salt,
      iterations: PBKDF2_ITERATIONS,
      hash: "SHA-256",
    },
    baseKey,
    { name: "AES-GCM", length: AES_KEY_LENGTH },
    false,
    ["encrypt", "decrypt", "wrapKey", "unwrapKey"]
  );
}

/**
 * Wrap an AES-GCM CryptoKey using a recipient's RSA-OAEP public key.
 * @param {CryptoKey} aesKey
 * @param {string} recipientPublicKeyPem
 * @returns {Promise<string>} Base64-encoded wrapped key
 */
export async function wrapAesKeyWithPublicKey(aesKey, recipientPublicKeyPem) {
  const publicKey = await importPublicKeyPem(recipientPublicKeyPem);
  const wrapped = await crypto.subtle.wrapKey("raw", aesKey, publicKey, {
    name: "RSA-OAEP",
  });
  return toBase64(wrapped);
}

/**
 * Unwrap an AES-GCM CryptoKey using the recipient's non-extractable private key.
 * @param {string} wrappedAesKeyB64
 * @param {CryptoKey} privateKey
 * @returns {Promise<CryptoKey>}
 */
export async function unwrapAesKeyWithPrivateKey(wrappedAesKeyB64, privateKey) {
  const wrappedBytes = fromBase64(wrappedAesKeyB64);
  return crypto.subtle.unwrapKey(
    "raw",
    wrappedBytes,
    privateKey,
    { name: "RSA-OAEP" },
    { name: "AES-GCM", length: AES_KEY_LENGTH },
    false,
    ["decrypt"]
  );
}

/**
 * Convert ArrayBuffer/Uint8Array to standard Base64 string (chunk-safe for 10MB+ files).
 * @param {ArrayBuffer | Uint8Array} buffer
 * @returns {string}
 */
export function toBase64(buffer) {
  const bytes = buffer instanceof Uint8Array ? buffer : new Uint8Array(buffer);
  const chunkSize = 0x8000;
  let binary = "";
  for (let i = 0; i < bytes.length; i += chunkSize) {
    binary += String.fromCharCode(...bytes.subarray(i, i + chunkSize));
  }
  return btoa(binary);
}

/**
 * Convert standard Base64 string to Uint8Array.
 * @param {string} b64
 * @returns {Uint8Array}
 */
export function fromBase64(b64) {
  const binary = atob(b64);
  const bytes = new Uint8Array(binary.length);
  for (let i = 0; i < binary.length; i++) {
    bytes[i] = binary.charCodeAt(i);
  }
  return bytes;
}

/**
 * Convert ArrayBuffer/Uint8Array to URL-safe Base64URL string (no padding).
 * @param {ArrayBuffer | Uint8Array} buffer
 * @returns {string}
 */
export function toBase64Url(buffer) {
  return toBase64(buffer).replace(/\+/g, "-").replace(/\//g, "_").replace(/=+$/, "");
}

/**
 * Convert URL-safe Base64URL string to Uint8Array.
 * @param {string} b64Url
 * @returns {Uint8Array}
 */
export function fromBase64Url(b64Url) {
  let b64 = b64Url.replace(/-/g, "+").replace(/_/g, "/");
  while (b64.length % 4 !== 0) {
    b64 += "=";
  }
  return fromBase64(b64);
}

// ============================================================================
// Private Utilities
// ============================================================================

function normalizeMode(mode) {
  const m = String(mode || "").trim().toLowerCase();
  if (m === "a" || m === "registered" || m === "modea") return "A";
  if (m === "b" || m === "link" || m === "anyone" || m === "modeb") return "B";
  throw new Error(`Unsupported encryption mode: "${mode}". Expected "A" or "B".`);
}

async function toUint8Array(input) {
  if (input instanceof Uint8Array) return input;
  if (input instanceof ArrayBuffer) return new Uint8Array(input);
  if (typeof Blob !== "undefined" && input instanceof Blob) {
    return new Uint8Array(await input.arrayBuffer());
  }
  throw new Error("Expected ArrayBuffer, Uint8Array, or Blob.");
}
