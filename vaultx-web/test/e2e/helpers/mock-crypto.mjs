/**
 * test/e2e/helpers/mock-crypto.mjs
 * Cryptographic fixtures, fault injection, bit-flipping, and Base64URL utilities for VaultX tests.
 */
export class MockCrypto {
  static _cachedRsaPair = null;

  /**
   * Generates or returns a cached RSA-OAEP 2048-bit keypair for test speed.
   */
  static async getTestRsaKeyPair() {
    if (!MockCrypto._cachedRsaPair) {
      MockCrypto._cachedRsaPair = await globalThis.crypto.subtle.generateKey(
        {
          name: 'RSA-OAEP',
          modulusLength: 2048,
          publicExponent: new Uint8Array([1, 0, 1]),
          hash: 'SHA-256',
        },
        true,
        ['wrapKey', 'unwrapKey']
      );
    }
    return MockCrypto._cachedRsaPair;
  }

  /**
   * Flips exactly 1 bit in a Buffer, ArrayBuffer, Uint8Array, or Blob.
   */
  static async flipBit(buffer, byteIndex = 0, bitOffset = 0) {
    let bytes;
    if (typeof Blob !== 'undefined' && buffer instanceof Blob) {
      bytes = new Uint8Array(await buffer.arrayBuffer());
    } else if (buffer instanceof ArrayBuffer) {
      bytes = new Uint8Array(buffer.slice(0));
    } else if (ArrayBuffer.isView(buffer)) {
      bytes = new Uint8Array(buffer.buffer.slice(buffer.byteOffset, buffer.byteOffset + buffer.byteLength));
    } else {
      bytes = new Uint8Array(buffer);
    }
    if (byteIndex >= bytes.length) {
      throw new Error(`flipBit: byteIndex ${byteIndex} out of range (length: ${bytes.length})`);
    }
    bytes[byteIndex] ^= 1 << bitOffset;
    return bytes.buffer;
  }

  /**
   * Corrupts the 16-byte AES-GCM authentication tag at the end of ciphertext.
   */
  static corruptAuthTag(cipherBuffer) {
    const bytes = new Uint8Array(
      cipherBuffer instanceof ArrayBuffer
        ? cipherBuffer.slice(0)
        : cipherBuffer.buffer
        ? cipherBuffer.buffer.slice(cipherBuffer.byteOffset, cipherBuffer.byteOffset + cipherBuffer.byteLength)
        : cipherBuffer
    );
    if (bytes.length < 16) throw new Error('Ciphertext too short for GCM tag');
    bytes[bytes.length - 1] ^= 0x01;
    return bytes.buffer;
  }

  /**
   * Encodes ArrayBuffer or Uint8Array to RFC 4648 Base64URL string without padding.
   */
  static toBase64Url(buffer) {
    const bytes = buffer instanceof Uint8Array ? buffer : new Uint8Array(buffer);
    return Buffer.from(bytes)
      .toString('base64')
      .replace(/\+/g, '-')
      .replace(/\//g, '_')
      .replace(/=+$/, '');
  }

  /**
   * Decodes Base64URL string to Uint8Array.
   */
  static fromBase64Url(str) {
    if (typeof str !== 'string') {
      throw new TypeError('Expected string for fromBase64Url');
    }
    let base64 = str.replace(/-/g, '+').replace(/_/g, '/');
    while (base64.length % 4) {
      base64 += '=';
    }
    return new Uint8Array(Buffer.from(base64, 'base64'));
  }

  /**
   * Standard Base64 encoder.
   */
  static toBase64(buffer) {
    if (typeof Blob !== 'undefined' && buffer instanceof Blob) {
      // For synchronous Blob conversion if possible, or ArrayBuffer
      throw new TypeError('MockCrypto.toBase64 requires ArrayBuffer or Uint8Array. Use await blob.arrayBuffer() first.');
    }
    const bytes = buffer instanceof Uint8Array ? buffer : new Uint8Array(buffer);
    return Buffer.from(bytes).toString('base64');
  }

  /**
   * Standard Base64 decoder.
   */
  static fromBase64(str) {
    return new Uint8Array(Buffer.from(str, 'base64'));
  }

  /**
   * Computes SHA-256 hex digest of a string or buffer.
   */
  static async sha256Hex(data) {
    const buffer = typeof data === 'string' ? new TextEncoder().encode(data) : data;
    const digest = await globalThis.crypto.subtle.digest('SHA-256', buffer);
    return Array.from(new Uint8Array(digest))
      .map((b) => b.toString(16).padStart(2, '0'))
      .join('');
  }

  /**
   * Generates cryptographically secure random bytes in chunks up to 65536 bytes.
   */
  static randomBytes(length) {
    const bytes = new Uint8Array(length);
    const MAX_CHUNK = 65536;
    for (let offset = 0; offset < length; offset += MAX_CHUNK) {
      const chunk = Math.min(length - offset, MAX_CHUNK);
      globalThis.crypto.getRandomValues(bytes.subarray(offset, offset + chunk));
    }
    return bytes;
  }
}
