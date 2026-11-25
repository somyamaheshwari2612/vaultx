/**
 * VaultX Client Web Crypto Engine
 * Zero-Knowledge cryptographic primitives using native Web Crypto API.
 */

// Global crypto reference (works in Node.js 22+ and modern browsers)
const webCrypto = typeof globalThis !== 'undefined' && globalThis.crypto ? globalThis.crypto : null;

if (!webCrypto || !webCrypto.subtle) {
  console.warn('[vaultCrypto] Web Crypto API (crypto.subtle) is not available in this environment.');
}

// ==========================================
// Base64 & Base64URL Conversion Utilities
// ==========================================

/**
 * Converts ArrayBuffer or Uint8Array to standard Base64 string.
 */
export function bufferToBase64(buffer) {
  if (!buffer) return '';
  const bytes = buffer instanceof Uint8Array ? buffer : new Uint8Array(buffer);

  if (typeof Buffer !== 'undefined') {
    return Buffer.from(bytes.buffer, bytes.byteOffset, bytes.byteLength).toString('base64');
  }

  let binary = '';
  const len = bytes.byteLength;
  const chunkSize = 0x8000;
  for (let i = 0; i < len; i += chunkSize) {
    binary += String.fromCharCode.apply(null, bytes.subarray(i, Math.min(i + chunkSize, len)));
  }
  return btoa(binary);
}

/**
 * Converts standard Base64 string to Uint8Array.
 */
export function base64ToBuffer(b64) {
  if (!b64 || typeof b64 !== 'string') return new Uint8Array(0);

  if (typeof Buffer !== 'undefined') {
    const buf = Buffer.from(b64, 'base64');
    return new Uint8Array(buf.buffer, buf.byteOffset, buf.byteLength);
  }

  const binary = atob(b64);
  const bytes = new Uint8Array(binary.length);
  for (let i = 0; i < binary.length; i++) {
    bytes[i] = binary.charCodeAt(i);
  }
  return bytes;
}

/**
 * Converts ArrayBuffer or Uint8Array to RFC 4648 Base64URL string (no padding).
 */
export function bufferToBase64Url(buffer) {
  const b64 = bufferToBase64(buffer);
  return b64.replace(/\+/g, '-').replace(/\//g, '_').replace(/=+$/, '');
}

/**
 * Converts RFC 4648 Base64URL string to Uint8Array.
 */
export function base64UrlToBuffer(b64url) {
  if (!b64url || typeof b64url !== 'string') return new Uint8Array(0);
  let b64 = b64url.replace(/-/g, '+').replace(/_/g, '/');
  while (b64.length % 4 !== 0) {
    b64 += '=';
  }
  return base64ToBuffer(b64);
}

// ==========================================
// Checksum & Fingerprint Utilities
// ==========================================

/**
 * Computes lowercase hex SHA-256 checksum of an ArrayBuffer or Uint8Array.
 */
export async function computeSha256Checksum(buffer) {
  const bytes = buffer instanceof Uint8Array ? buffer : new Uint8Array(buffer);
  const hashBuffer = await webCrypto.subtle.digest('SHA-256', bytes);
  return Array.from(new Uint8Array(hashBuffer))
    .map((b) => b.toString(16).padStart(2, '0'))
    .join('');
}

/**
 * Computes uppercase colon-separated hex SHA-256 fingerprint from SPKI bytes or CryptoKey.
 */
export async function computeKeyFingerprint(publicKeyOrSpki) {
  let spkiBytes;
  if (publicKeyOrSpki instanceof Uint8Array) {
    spkiBytes = publicKeyOrSpki;
  } else if (publicKeyOrSpki instanceof ArrayBuffer) {
    spkiBytes = new Uint8Array(publicKeyOrSpki);
  } else if (typeof publicKeyOrSpki === 'string') {
    const cleanB64 = publicKeyOrSpki.replace(/-----[^\n\r]+-----/g, '').replace(/\s+/g, '');
    spkiBytes = base64ToBuffer(cleanB64);
  } else if (publicKeyOrSpki && typeof publicKeyOrSpki === 'object' && publicKeyOrSpki.type === 'public') {
    const exported = await webCrypto.subtle.exportKey('spki', publicKeyOrSpki);
    spkiBytes = new Uint8Array(exported);
  } else {
    throw new Error('Invalid public key input for fingerprint computation');
  }

  const hashBuffer = await webCrypto.subtle.digest('SHA-256', spkiBytes);
  return Array.from(new Uint8Array(hashBuffer))
    .map((b) => b.toString(16).padStart(2, '0').toUpperCase())
    .join(':');
}

/**
 * Exports an RSA-OAEP public CryptoKey to standard PEM string.
 */
export async function exportPublicKeyPem(cryptoKey) {
  if (!cryptoKey || cryptoKey.type !== 'public') {
    throw new Error('Key must be a valid public CryptoKey');
  }
  const spki = await webCrypto.subtle.exportKey('spki', cryptoKey);
  const b64 = bufferToBase64(spki);
  const chunks = b64.match(/.{1,64}/g) || [];
  return `-----BEGIN PUBLIC KEY-----\n${chunks.join('\n')}\n-----END PUBLIC KEY-----`;
}

/**
 * Imports an RSA-OAEP public key from PEM string or SPKI bytes.
 */
export async function importPublicKey(pemOrSpki) {
  let spkiBytes;
  if (typeof pemOrSpki === 'string') {
    const cleanB64 = pemOrSpki.replace(/-----[^\n\r]+-----/g, '').replace(/\s+/g, '');
    spkiBytes = base64ToBuffer(cleanB64);
  } else if (pemOrSpki instanceof Uint8Array || pemOrSpki instanceof ArrayBuffer) {
    spkiBytes = pemOrSpki;
  } else if (pemOrSpki && typeof pemOrSpki === 'object' && pemOrSpki.algorithm) {
    return pemOrSpki;
  } else {
    throw new Error('Invalid recipient public key format');
  }

  return await webCrypto.subtle.importKey(
    'spki',
    spkiBytes,
    { name: 'RSA-OAEP', hash: 'SHA-256' },
    true,
    ['wrapKey']
  );
}

// ==========================================
// Key Pair Generation (Mode A)
// ==========================================

/**
 * Generates an RSA-OAEP 2048-bit keypair for Mode A sharing.
 * Private key is non-extractable (extractable: false).
 * Public key is exported to standard PEM and fingerprint is computed.
 */
export async function generateUserKeyPair(masterPassphrase = null) {
  const keyPair = await webCrypto.subtle.generateKey(
    {
      name: 'RSA-OAEP',
      modulusLength: 2048,
      publicExponent: new Uint8Array([1, 0, 1]),
      hash: 'SHA-256'
    },
    false, // Makes privateKey non-extractable; publicKey remains extractable
    ['wrapKey', 'unwrapKey']
  );

  const publicKeyPem = await exportPublicKeyPem(keyPair.publicKey);
  const keyFingerprint = await computeKeyFingerprint(keyPair.publicKey);

  return {
    keyPair: {
      publicKey: keyPair.publicKey,
      privateKey: keyPair.privateKey
    },
    publicKeyPem,
    keyFingerprint
  };
}

// ==========================================
// Encryption (Mode A & Mode B)
// ==========================================

/**
 * Encrypts a file buffer and its associated metadata using AES-256-GCM.
 * Computes plaintext SHA-256 checksum and embeds it in metadata.
 * In Mode B: exports raw AES key as base64url fragment key (optional PBKDF2 wrap if password provided).
 * In Mode A: wraps AES key with recipient's RSA-OAEP public key.
 */
export async function encryptFileAndMeta(
  fileBuffer,
  metaObj = {},
  mode = 'MODE_B',
  recipientPublicKeyOrNull = null,
  options = {}
) {
  // 1. Normalize and validate fileBuffer
  let fileBytes;
  if (typeof Blob !== 'undefined' && fileBuffer instanceof Blob) {
    const ab = await fileBuffer.arrayBuffer();
    fileBytes = new Uint8Array(ab);
  } else if (fileBuffer instanceof Uint8Array) {
    fileBytes = fileBuffer;
  } else if (fileBuffer instanceof ArrayBuffer) {
    fileBytes = new Uint8Array(fileBuffer);
  } else if (typeof Buffer !== 'undefined' && Buffer.isBuffer(fileBuffer)) {
    fileBytes = new Uint8Array(fileBuffer.buffer, fileBuffer.byteOffset, fileBuffer.byteLength);
  } else {
    throw new Error('Payload cannot be empty');
  }

  if (!fileBytes || fileBytes.byteLength === 0) {
    throw new Error('Payload cannot be empty');
  }

  // 2. Compute plaintext SHA-256 checksum
  const sha256Checksum = await computeSha256Checksum(fileBytes);

  // 3. Embed checksum into deep copy of metaObj and serialize to UTF-8
  const metaWithChecksum = {
    ...JSON.parse(JSON.stringify(metaObj || {})),
    checksum: sha256Checksum
  };
  const metaBytes = new TextEncoder().encode(JSON.stringify(metaWithChecksum));

  // 4. Generate random 256-bit AES-GCM symmetric key
  const aesKey = await webCrypto.subtle.generateKey(
    { name: 'AES-GCM', length: 256 },
    true,
    ['encrypt', 'decrypt', 'wrapKey', 'unwrapKey']
  );

  // 5. Generate random 12-byte IVs for file and metadata
  const fileIv = webCrypto.getRandomValues(new Uint8Array(12));
  const metaIv = webCrypto.getRandomValues(new Uint8Array(12));

  // 6. Encrypt file and metadata with AES-GCM
  const encryptedFileBuf = await webCrypto.subtle.encrypt(
    { name: 'AES-GCM', iv: fileIv },
    aesKey,
    fileBytes
  );

  const encryptedMetaBuf = await webCrypto.subtle.encrypt(
    { name: 'AES-GCM', iv: metaIv },
    aesKey,
    metaBytes
  );

  const encryptedBlob = encryptedFileBuf;
  const ivB64 = bufferToBase64(fileIv);
  const metaIvB64 = bufferToBase64(metaIv);
  const encryptedMetaB64 = bufferToBase64(encryptedMetaBuf);

  let fragmentKeyB64 = null;
  let wrappedAesKeyB64 = null;

  // 7. Mode-specific key packaging
  if (mode === 'MODE_B') {
    const rawAesKey = await webCrypto.subtle.exportKey('raw', aesKey);
    const rawKeyBytes = new Uint8Array(rawAesKey);

    if (options && options.password) {
      // Derive key via PBKDF2 with 16-byte random salt and 100,000 iterations
      const salt = webCrypto.getRandomValues(new Uint8Array(16));
      const keyIv = webCrypto.getRandomValues(new Uint8Array(12));

      const passwordBytes = new TextEncoder().encode(options.password);
      const baseKey = await webCrypto.subtle.importKey(
        'raw',
        passwordBytes,
        'PBKDF2',
        false,
        ['deriveKey']
      );

      const pbkdf2Key = await webCrypto.subtle.deriveKey(
        {
          name: 'PBKDF2',
          salt,
          iterations: 100000,
          hash: 'SHA-256'
        },
        baseKey,
        { name: 'AES-GCM', length: 256 },
        false,
        ['encrypt']
      );

      // Encrypt raw AES key with derived key
      const encKeyBuf = await webCrypto.subtle.encrypt(
        { name: 'AES-GCM', iv: keyIv },
        pbkdf2Key,
        rawKeyBytes
      );

      // Pack salt (16 bytes) + IV (12 bytes) + ciphertext (48 bytes)
      const packed = new Uint8Array(16 + 12 + encKeyBuf.byteLength);
      packed.set(salt, 0);
      packed.set(keyIv, 16);
      packed.set(new Uint8Array(encKeyBuf), 28);

      fragmentKeyB64 = bufferToBase64Url(packed);
    } else {
      fragmentKeyB64 = bufferToBase64Url(rawKeyBytes);
    }
  } else if (mode === 'MODE_A') {
    if (!recipientPublicKeyOrNull) {
      throw new Error('Recipient public key is required for Mode A');
    }

    const recipientKey = await importPublicKey(recipientPublicKeyOrNull);

    const wrappedKeyBuf = await webCrypto.subtle.wrapKey(
      'raw',
      aesKey,
      recipientKey,
      { name: 'RSA-OAEP' }
    );

    wrappedAesKeyB64 = bufferToBase64(wrappedKeyBuf);
  } else {
    throw new Error(`Unsupported mode: ${mode}`);
  }

  return {
    encryptedBlob,
    ivB64,
    metaIvB64,
    encryptedMetaB64,
    wrappedAesKeyB64,
    fragmentKeyB64,
    sha256Checksum
  };
}

// ==========================================
// Decryption (Mode A & Mode B)
// ==========================================

/**
 * Decrypts file payload and metadata, verifying SHA-256 checksum and AES-GCM authentication.
 */
export async function decryptFileAndMeta(
  encryptedBlob,
  ivB64,
  encryptedMetaB64,
  keyMaterial,
  mode = 'MODE_B',
  options = {}
) {
  // Support flexible argument passing (metaIv in options or 7-parameter convention)
  let actualIvB64 = ivB64;
  let actualMetaIvB64 = options?.metaIvB64 || options?.metaIv;
  let actualEncryptedMetaB64 = encryptedMetaB64;
  let actualKeyMaterial = keyMaterial;
  let actualMode = mode;
  let actualOptions = typeof options === 'object' && options !== null ? options : {};

  // Detect 7-parameter convention: (blob, iv, metaIv, encMeta, keyMat, mode, options)
  if (arguments.length >= 6 && (arguments[5] === 'MODE_A' || arguments[5] === 'MODE_B')) {
    actualIvB64 = arguments[1];
    actualMetaIvB64 = arguments[2];
    actualEncryptedMetaB64 = arguments[3];
    actualKeyMaterial = arguments[4];
    actualMode = arguments[5];
    actualOptions = arguments[6] || {};
  } else if (!actualMetaIvB64) {
    actualMetaIvB64 = actualIvB64;
  }

  // 1. Reconstruct / Unwrap AES-256-GCM Key
  let aesKey;

  if (actualMode === 'MODE_B') {
    if (!actualKeyMaterial) {
      throw new Error('Key material is required for Mode B decryption');
    }

    const keyBytes = typeof actualKeyMaterial === 'string'
      ? base64UrlToBuffer(actualKeyMaterial)
      : (actualKeyMaterial instanceof Uint8Array ? actualKeyMaterial : new Uint8Array(actualKeyMaterial));

    if (keyBytes.byteLength === 32) {
      // Unprotected raw AES-256 key
      aesKey = await webCrypto.subtle.importKey(
        'raw',
        keyBytes,
        { name: 'AES-GCM' },
        false,
        ['decrypt']
      );
    } else if (keyBytes.byteLength > 32) {
      // Password-protected AES key (salt: 16, iv: 12, ct: 48)
      if (!actualOptions || !actualOptions.password) {
        const err = new Error('Password required for decryption');
        err.code = 'PASSWORD_REQUIRED';
        throw err;
      }

      const salt = keyBytes.subarray(0, 16);
      const keyIv = keyBytes.subarray(16, 28);
      const keyCt = keyBytes.subarray(28);

      const passwordBytes = new TextEncoder().encode(actualOptions.password);
      const baseKey = await webCrypto.subtle.importKey(
        'raw',
        passwordBytes,
        'PBKDF2',
        false,
        ['deriveKey']
      );

      const pbkdf2Key = await webCrypto.subtle.deriveKey(
        {
          name: 'PBKDF2',
          salt,
          iterations: 100000,
          hash: 'SHA-256'
        },
        baseKey,
        { name: 'AES-GCM', length: 256 },
        false,
        ['decrypt']
      );

      let rawKeyBuf;
      try {
        rawKeyBuf = await webCrypto.subtle.decrypt(
          { name: 'AES-GCM', iv: keyIv },
          pbkdf2Key,
          keyCt
        );
      } catch (err) {
        const error = new Error('Incorrect password or corrupted key material');
        error.code = 'INVALID_PASSWORD';
        throw error;
      }

      aesKey = await webCrypto.subtle.importKey(
        'raw',
        rawKeyBuf,
        { name: 'AES-GCM' },
        false,
        ['decrypt']
      );
    } else {
      throw new Error(`Invalid keyMaterial length for Mode B (${keyBytes.byteLength} bytes)`);
    }
  } else if (actualMode === 'MODE_A') {
    if (!actualKeyMaterial || !actualKeyMaterial.privateKey || !actualKeyMaterial.wrappedAesKeyB64) {
      throw new Error('Mode A requires keyMaterial to contain { privateKey, wrappedAesKeyB64 }');
    }

    const wrappedBytes = base64ToBuffer(actualKeyMaterial.wrappedAesKeyB64);

    aesKey = await webCrypto.subtle.unwrapKey(
      'raw',
      wrappedBytes,
      actualKeyMaterial.privateKey,
      { name: 'RSA-OAEP' },
      { name: 'AES-GCM', length: 256 },
      false,
      ['decrypt']
    );
  } else {
    throw new Error(`Unsupported mode: ${actualMode}`);
  }

  // 2. Decrypt metadata
  const metaIvBytes = base64ToBuffer(actualMetaIvB64);
  const encMetaBytes = base64ToBuffer(actualEncryptedMetaB64);

  const metaDecryptedBuf = await webCrypto.subtle.decrypt(
    { name: 'AES-GCM', iv: metaIvBytes },
    aesKey,
    encMetaBytes
  );

  const metaObj = JSON.parse(new TextDecoder().decode(metaDecryptedBuf));

  // 3. Decrypt file payload
  let encFileBuf;
  if (typeof Blob !== 'undefined' && encryptedBlob instanceof Blob) {
    encFileBuf = await encryptedBlob.arrayBuffer();
  } else if (encryptedBlob instanceof Uint8Array) {
    encFileBuf = encryptedBlob.buffer.slice(
      encryptedBlob.byteOffset,
      encryptedBlob.byteOffset + encryptedBlob.byteLength
    );
  } else if (encryptedBlob instanceof ArrayBuffer) {
    encFileBuf = encryptedBlob;
  } else if (typeof Buffer !== 'undefined' && Buffer.isBuffer(encryptedBlob)) {
    encFileBuf = encryptedBlob.buffer.slice(
      encryptedBlob.byteOffset,
      encryptedBlob.byteOffset + encryptedBlob.byteLength
    );
  } else {
    throw new Error('Invalid encryptedBlob input');
  }

  const fileIvBytes = base64ToBuffer(actualIvB64);

  const fileBuffer = await webCrypto.subtle.decrypt(
    { name: 'AES-GCM', iv: fileIvBytes },
    aesKey,
    encFileBuf
  );

  // 4. Verify plaintext checksum
  const computedChecksum = await computeSha256Checksum(fileBuffer);
  const isChecksumValid = Boolean(metaObj?.checksum && metaObj.checksum.toLowerCase() === computedChecksum.toLowerCase());

  return {
    fileBuffer,
    metaObj,
    isChecksumValid,
    sha256Checksum: computedChecksum
  };
}
