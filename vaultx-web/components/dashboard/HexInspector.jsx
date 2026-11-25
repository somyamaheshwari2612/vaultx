'use client';

import React, { useMemo } from 'react';
import { Binary } from 'lucide-react';
import { base64ToBuffer } from '../../lib/vaultCrypto.js';

/**
 * HexInspector
 * Person 4 dashboard slot: matte charcoal (#0B0C10) split hex / ASCII inspector.
 */
export function HexInspector({ fileId, encryptedBlobB64 = '', bytes = null, label = 'Ciphertext Inspector', maxBytes = 256 }) {
  const rows = useMemo(() => {
    let rawBytes = new Uint8Array(0);
    if (bytes instanceof Uint8Array) {
      rawBytes = bytes;
    } else if (bytes instanceof ArrayBuffer) {
      rawBytes = new Uint8Array(bytes);
    } else if (encryptedBlobB64 && typeof encryptedBlobB64 === 'string') {
      try {
        rawBytes = base64ToBuffer(encryptedBlobB64);
      } catch (_) {
        rawBytes = new Uint8Array(0);
      }
    }

    const slice = rawBytes.subarray(0, maxBytes);
    const result = [];
    for (let offset = 0; offset < slice.length; offset += 16) {
      const chunk = slice.subarray(offset, offset + 16);
      const hexParts = [];
      let ascii = '';
      for (let i = 0; i < 16; i++) {
        if (i < chunk.length) {
          const b = chunk[i];
          hexParts.push(b.toString(16).padStart(2, '0'));
          ascii += b >= 32 && b <= 126 ? String.fromCharCode(b) : '.';
        } else {
          hexParts.push('  ');
        }
      }
      result.push({
        offset: offset.toString(16).padStart(8, '0'),
        hex: hexParts.join(' '),
        ascii,
      });
    }

    return { rows: result, totalBytes: rawBytes.byteLength };
  }, [encryptedBlobB64, bytes, maxBytes]);

  return (
    <div className="hex-inspector hud-glass rounded-xl border border-white/10 p-4">
      <div className="mb-3 flex items-center justify-between border-b border-white/10 pb-2.5">
        <div className="flex items-center gap-2">
          <Binary className="h-4 w-4 text-[#A1A1AA]" />
          <h4 className="font-mono text-sm font-semibold text-[#FAFAFA]">{label}</h4>
        </div>
        <span className="font-mono text-xs text-[#71717A]">
          {fileId ? `ID: ${fileId} • ` : ''}
          {rows.totalBytes} bytes
        </span>
      </div>

      {rows.rows.length === 0 ? (
        <div className="hud-well rounded-lg border border-dashed border-white/10 p-4 text-center font-mono text-xs text-[#71717A]">
          No raw ciphertext bytes loaded for inspection.
        </div>
      ) : (
        <div className="hud-well overflow-x-auto rounded-lg border border-white/10 p-3 font-mono text-xs">
          <div className="space-y-1">
            {rows.rows.map((row) => (
              <div key={row.offset} className="flex items-center gap-4 whitespace-pre">
                <span className="text-[#71717A] select-none">{row.offset}</span>
                <span className="hex-bytes text-zinc-200">{row.hex}</span>
                <span className="ascii-text border-l border-white/10 pl-3 text-[#71717A]">
                  {row.ascii}
                </span>
              </div>
            ))}
          </div>
          {rows.totalBytes > maxBytes && (
            <p className="mt-2 border-t border-white/10 pt-2 text-[11px] text-[#71717A]">
              Showing first {maxBytes} of {rows.totalBytes} encrypted bytes.
            </p>
          )}
        </div>
      )}
    </div>
  );
}

export default HexInspector;
