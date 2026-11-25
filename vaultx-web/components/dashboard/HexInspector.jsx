'use client';

import React, { useMemo, useState, useCallback } from 'react';
import { Binary, Copy, Check, Info, ChevronDown, ChevronUp } from 'lucide-react';
import { base64ToBuffer } from '../../lib/vaultCrypto.js';
import { formatHexRows, bufferToHex, formatFileSize, copyToClipboard } from '../../utils/hexUtils.js';

/**
 * HexInspector — Enhanced Version
 * ────────────────────────────────
 * Person 4 dashboard component: displays raw encrypted ciphertext in a
 * classic hex-editor format with:
 *   • Offset | Hex | ASCII columns (16 bytes per row)
 *   • IV extraction and display
 *   • Metadata panel (file size, algorithm, encrypted size)
 *   • Copy-to-clipboard for hex dump and IV
 *   • Expandable rows (show more / show less)
 *   • Large-file handling with byte-limit slider
 *
 * Props:
 *   fileId           — Vault identifier (displayed in header)
 *   encryptedBlobB64 — Base64-encoded ciphertext string
 *   bytes            — Alternative: direct Uint8Array or ArrayBuffer
 *   label            — Header title text
 *   maxBytes         — Initial max bytes to show (default 256)
 *   meta             — Optional metadata object { algorithm, fileSize, encryptedSize, ivB64, ... }
 */
export function HexInspector({
  fileId,
  encryptedBlobB64 = '',
  bytes = null,
  label = 'Ciphertext Inspector',
  maxBytes = 256,
  meta = null,
}) {
  const [displayMax, setDisplayMax] = useState(maxBytes);
  const [copiedHex, setCopiedHex] = useState(false);
  const [copiedIV, setCopiedIV] = useState(false);
  const [showMeta, setShowMeta] = useState(true);

  // ── Decode raw bytes from props ────────────────────────────────
  const rawBytes = useMemo(() => {
    if (bytes instanceof Uint8Array) return bytes;
    if (bytes instanceof ArrayBuffer) return new Uint8Array(bytes);
    if (encryptedBlobB64 && typeof encryptedBlobB64 === 'string') {
      try {
        return base64ToBuffer(encryptedBlobB64);
      } catch {
        return new Uint8Array(0);
      }
    }
    return new Uint8Array(0);
  }, [encryptedBlobB64, bytes]);

  // ── Format hex rows ────────────────────────────────────────────
  const { rows, totalBytes } = useMemo(
    () => formatHexRows(rawBytes, displayMax),
    [rawBytes, displayMax]
  );

  // ── Extract IV from the first 12 bytes (AES-GCM convention) ───
  const ivHex = useMemo(() => {
    // Prefer the IV from metadata if provided
    if (meta?.ivB64) {
      try {
        const ivBytes = base64ToBuffer(meta.ivB64);
        return bufferToHex(ivBytes);
      } catch { /* fall through */ }
    }
    // Otherwise extract from ciphertext prefix
    if (rawBytes.length >= 12) {
      return bufferToHex(rawBytes.subarray(0, 12));
    }
    return '';
  }, [rawBytes, meta]);

  // ── Copy handlers ──────────────────────────────────────────────
  const handleCopyHex = useCallback(async () => {
    const hexStr = rows.map((r) => `${r.offset}  ${r.hex}  |${r.ascii}|`).join('\n');
    const ok = await copyToClipboard(hexStr);
    if (ok) {
      setCopiedHex(true);
      setTimeout(() => setCopiedHex(false), 2000);
    }
  }, [rows]);

  const handleCopyIV = useCallback(async () => {
    if (!ivHex) return;
    const ok = await copyToClipboard(ivHex);
    if (ok) {
      setCopiedIV(true);
      setTimeout(() => setCopiedIV(false), 2000);
    }
  }, [ivHex]);

  // ── Show-more / show-less ──────────────────────────────────────
  const canExpand = totalBytes > displayMax;
  const isExpanded = displayMax >= totalBytes;

  return (
    <div className="hex-inspector hud-glass rounded-xl border border-white/10 p-4">
      {/* ─── Header ────────────────────────────────────────────── */}
      <div className="mb-3 flex items-center justify-between border-b border-white/10 pb-2.5">
        <div className="flex items-center gap-2">
          <Binary className="h-4 w-4 text-[#A1A1AA]" />
          <h4 className="font-mono text-sm font-semibold text-[#FAFAFA]">{label}</h4>
        </div>
        <div className="flex items-center gap-2">
          {/* Copy hex dump button */}
          {rows.length > 0 && (
            <button
              type="button"
              onClick={handleCopyHex}
              className="inline-flex items-center gap-1 rounded border border-white/10 bg-white/5 px-2 py-1 font-mono text-[10px] font-medium text-zinc-300 hover:bg-white/10 transition-colors"
              title="Copy hex dump to clipboard"
            >
              {copiedHex ? <Check className="h-3 w-3 text-emerald-400" /> : <Copy className="h-3 w-3" />}
              <span>{copiedHex ? 'Copied' : 'Copy Hex'}</span>
            </button>
          )}
          <span className="font-mono text-xs text-[#71717A]">
            {fileId ? `ID: ${fileId} · ` : ''}{totalBytes} bytes
          </span>
        </div>
      </div>

      {/* ─── Metadata Panel ─────────────────────────────────────── */}
      {(meta || ivHex) && (
        <div className="mb-3">
          <button
            type="button"
            onClick={() => setShowMeta((v) => !v)}
            className="mb-2 inline-flex items-center gap-1 font-mono text-[11px] text-[#71717A] hover:text-zinc-300 transition-colors"
          >
            <Info className="h-3 w-3" />
            <span>Metadata</span>
            {showMeta ? <ChevronUp className="h-3 w-3" /> : <ChevronDown className="h-3 w-3" />}
          </button>

          {showMeta && (
            <div className="hud-well grid grid-cols-2 gap-x-6 gap-y-1.5 rounded-lg border border-white/10 p-3 font-mono text-[11px]">
              {/* IV */}
              {ivHex && (
                <div className="col-span-2 flex items-center gap-2">
                  <span className="text-[#71717A]">IV (12 B):</span>
                  <code className="flex-1 truncate text-amber-400/90">{ivHex}</code>
                  <button
                    type="button"
                    onClick={handleCopyIV}
                    className="shrink-0 rounded border border-white/10 bg-white/5 p-0.5 hover:bg-white/10 transition-colors"
                    title="Copy IV"
                  >
                    {copiedIV ? <Check className="h-3 w-3 text-emerald-400" /> : <Copy className="h-3 w-3 text-zinc-400" />}
                  </button>
                </div>
              )}
              {meta?.algorithm && (
                <div>
                  <span className="text-[#71717A]">Algorithm: </span>
                  <span className="text-zinc-200">{meta.algorithm}</span>
                </div>
              )}
              {meta?.fileSize != null && (
                <div>
                  <span className="text-[#71717A]">Original: </span>
                  <span className="text-zinc-200">{formatFileSize(meta.fileSize)}</span>
                </div>
              )}
              {meta?.encryptedSize != null && (
                <div>
                  <span className="text-[#71717A]">Encrypted: </span>
                  <span className="text-zinc-200">{formatFileSize(meta.encryptedSize)}</span>
                </div>
              )}
              {totalBytes > 0 && (
                <div>
                  <span className="text-[#71717A]">Loaded: </span>
                  <span className="text-zinc-200">{formatFileSize(totalBytes)}</span>
                </div>
              )}
            </div>
          )}
        </div>
      )}

      {/* ─── Hex Dump ───────────────────────────────────────────── */}
      {rows.length === 0 ? (
        <div className="hud-well rounded-lg border border-dashed border-white/10 p-4 text-center font-mono text-xs text-[#71717A]">
          No raw ciphertext bytes loaded for inspection.
        </div>
      ) : (
        <div className="hud-well overflow-x-auto rounded-lg border border-white/10 p-3 font-mono text-xs">
          {/* Column headers */}
          <div className="mb-1 flex items-center gap-4 whitespace-pre text-[10px] text-[#71717A] select-none">
            <span className="w-[72px]">Offset</span>
            <span className="flex-1">Hex</span>
            <span className="border-l border-white/10 pl-3">ASCII</span>
          </div>

          <div className="space-y-0.5">
            {rows.map((row) => (
              <div key={row.offset} className="flex items-center gap-4 whitespace-pre hover:bg-white/[0.02] rounded transition-colors">
                <span className="text-[#71717A] select-none w-[72px]">{row.offset}</span>
                <span className="hex-bytes text-zinc-200 flex-1">{row.hex}</span>
                <span className="ascii-text border-l border-white/10 pl-3 text-[#71717A]">
                  {row.ascii}
                </span>
              </div>
            ))}
          </div>

          {/* Expand / Collapse controls */}
          <div className="mt-2 flex items-center justify-between border-t border-white/10 pt-2">
            <p className="text-[11px] text-[#71717A]">
              Showing {Math.min(displayMax, totalBytes)} of {totalBytes} bytes
            </p>
            <div className="flex gap-2">
              {canExpand && !isExpanded && (
                <button
                  type="button"
                  onClick={() => setDisplayMax((v) => Math.min(v + 256, totalBytes))}
                  className="rounded border border-white/10 bg-white/5 px-2 py-0.5 font-mono text-[10px] text-zinc-300 hover:bg-white/10 transition-colors"
                >
                  Show +256 bytes
                </button>
              )}
              {displayMax > maxBytes && (
                <button
                  type="button"
                  onClick={() => setDisplayMax(maxBytes)}
                  className="rounded border border-white/10 bg-white/5 px-2 py-0.5 font-mono text-[10px] text-zinc-300 hover:bg-white/10 transition-colors"
                >
                  Collapse
                </button>
              )}
            </div>
          </div>
        </div>
      )}
    </div>
  );
}

export default HexInspector;
