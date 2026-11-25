/**
 * VaultX Hex Utilities
 * Conversion and display helpers for the HexInspector component.
 * Person 4 — utility module.
 */

/**
 * Converts an ArrayBuffer or Uint8Array to a formatted hex string.
 * Each byte becomes two lowercase hex characters (e.g. 0x0A → "0a").
 *
 * @param {ArrayBuffer|Uint8Array} buffer - The binary data to convert.
 * @returns {string} Hex string representation.
 */
export function bufferToHex(buffer) {
  const bytes = buffer instanceof Uint8Array ? buffer : new Uint8Array(buffer);
  return Array.from(bytes)
    .map((b) => b.toString(16).padStart(2, '0'))
    .join('');
}

/**
 * Converts a hex string back to a Uint8Array.
 *
 * @param {string} hex - Hex string (e.g. "0a1b2c").
 * @returns {Uint8Array} Binary data.
 */
export function hexToBuffer(hex) {
  if (!hex || typeof hex !== 'string') return new Uint8Array(0);
  const clean = hex.replace(/\s+/g, '');
  const bytes = new Uint8Array(clean.length / 2);
  for (let i = 0; i < bytes.length; i++) {
    bytes[i] = parseInt(clean.substring(i * 2, i * 2 + 2), 16);
  }
  return bytes;
}

/**
 * Formats raw bytes into hex-dump rows, each with:
 *   - offset  (8-char hex address)
 *   - hex     (space-separated hex pairs, 16 per row)
 *   - ascii   (printable ASCII or '.' for non-printable)
 *
 * @param {Uint8Array} bytes    - The bytes to format.
 * @param {number}     maxBytes - Maximum bytes to process (default 512).
 * @returns {{ rows: Array<{offset:string, hex:string, ascii:string}>, totalBytes: number }}
 */
export function formatHexRows(bytes, maxBytes = 512) {
  if (!bytes || bytes.length === 0) {
    return { rows: [], totalBytes: 0 };
  }

  const slice = bytes.subarray(0, maxBytes);
  const rows = [];

  for (let offset = 0; offset < slice.length; offset += 16) {
    const chunk = slice.subarray(offset, offset + 16);
    const hexParts = [];
    let ascii = '';

    for (let i = 0; i < 16; i++) {
      if (i < chunk.length) {
        const b = chunk[i];
        hexParts.push(b.toString(16).padStart(2, '0'));
        // Printable ASCII range: 0x20 (space) to 0x7E (~)
        ascii += b >= 0x20 && b <= 0x7e ? String.fromCharCode(b) : '.';
      } else {
        hexParts.push('  ');
      }
    }

    rows.push({
      offset: offset.toString(16).padStart(8, '0'),
      hex: hexParts.join(' '),
      ascii,
    });
  }

  return { rows, totalBytes: bytes.byteLength };
}

/**
 * Extracts the IV (Initialization Vector) from the beginning of a ciphertext buffer.
 * AES-GCM uses a 12-byte IV (96 bits) by convention.
 *
 * @param {Uint8Array} cipherBytes - Full ciphertext (IV prepended).
 * @param {number}     ivLength    - Length of IV in bytes (default 12 for AES-GCM).
 * @returns {{ iv: string, ivBytes: Uint8Array }}
 */
export function extractIV(cipherBytes, ivLength = 12) {
  if (!cipherBytes || cipherBytes.length < ivLength) {
    return { iv: '', ivBytes: new Uint8Array(0) };
  }
  const ivBytes = cipherBytes.subarray(0, ivLength);
  const iv = bufferToHex(ivBytes);
  return { iv, ivBytes };
}

/**
 * Formats a byte count into a human-readable file size string.
 * e.g. 2457600 → "2.34 MB"
 *
 * @param {number} bytes - Number of bytes.
 * @returns {string} Human-readable size.
 */
export function formatFileSize(bytes) {
  if (bytes === 0) return '0 B';
  const units = ['B', 'KB', 'MB', 'GB', 'TB'];
  const i = Math.floor(Math.log(bytes) / Math.log(1024));
  const size = (bytes / Math.pow(1024, i)).toFixed(i > 0 ? 2 : 0);
  return `${size} ${units[i]}`;
}

/**
 * Copies text to the clipboard using the modern Clipboard API.
 * Falls back gracefully if unavailable.
 *
 * @param {string} text - Text to copy.
 * @returns {Promise<boolean>} Whether the copy succeeded.
 */
export async function copyToClipboard(text) {
  try {
    if (navigator?.clipboard?.writeText) {
      await navigator.clipboard.writeText(text);
      return true;
    }
    // Fallback for older browsers
    const textarea = document.createElement('textarea');
    textarea.value = text;
    textarea.style.position = 'fixed';
    textarea.style.opacity = '0';
    document.body.appendChild(textarea);
    textarea.select();
    const ok = document.execCommand('copy');
    document.body.removeChild(textarea);
    return ok;
  } catch {
    return false;
  }
}
