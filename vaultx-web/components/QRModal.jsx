'use client';

import React, { useState, useEffect } from 'react';
import { QRCodeSVG } from 'qrcode.react';
import { X, Copy, Check, QrCode, ShieldCheck } from 'lucide-react';

/**
 * QRModal
 * Displays the generated zero-knowledge shareable URL (including #key=... fragment)
 * inside a matte charcoal (#0B0C10) modal with razor-thin border-white/10.
 */
export function QRModal({ isOpen, onClose, shareUrl, url, title = 'Zero-Knowledge Share QR' }) {
  const [copied, setCopied] = useState(false);
  const targetUrl = shareUrl || url || '';

  useEffect(() => {
    if (!isOpen) {
      setCopied(false);
      return;
    }

    const handleKeyDown = (e) => {
      if (e.key === 'Escape' && onClose) {
        onClose();
      }
    };
    window.addEventListener('keydown', handleKeyDown);
    return () => window.removeEventListener('keydown', handleKeyDown);
  }, [isOpen, onClose]);

  if (!isOpen) return null;

  const handleCopy = async () => {
    if (!targetUrl) return;
    try {
      await navigator.clipboard.writeText(targetUrl);
      setCopied(true);
      setTimeout(() => setCopied(false), 2000);
    } catch (_) {
      // Clipboard fallback ignored if blocked
    }
  };

  return (
    <div
      className="modal-overlay fixed inset-0 z-50 flex items-center justify-center bg-black/80 backdrop-blur-sm p-4"
      role="dialog"
      aria-modal="true"
      aria-labelledby="qr-modal-title"
      onClick={(e) => {
        if (e.target === e.currentTarget && onClose) {
          onClose();
        }
      }}
    >
      <div className="modal-container hud-glass w-full max-w-md overflow-hidden rounded-xl border border-white/10">
        <div className="flex items-center justify-between border-b border-white/10 bg-[#0B0C10] px-4 py-2.5">
          <div className="flex items-center gap-2">
            <QrCode className="h-4 w-4 text-[#A1A1AA]" />
            <h3 id="qr-modal-title" className="font-mono text-sm font-semibold text-[#FAFAFA]">
              {title}
            </h3>
          </div>
          <button
            type="button"
            onClick={onClose}
            className="btn-close rounded p-1 text-[#71717A] hover:bg-white/5 hover:text-[#FAFAFA]"
            aria-label="Close modal"
          >
            <X className="h-4 w-4" />
          </button>
        </div>

        <div className="flex flex-col items-center gap-4 p-5">
          <div className="rounded-xl border border-white/10 bg-white p-4">
            {targetUrl ? (
              <QRCodeSVG
                value={targetUrl}
                size={200}
                level="M"
                includeMargin={false}
                className="qr-code-svg"
              />
            ) : (
              <div className="flex h-[200px] w-[200px] items-center justify-center bg-zinc-100 font-mono text-xs text-zinc-600">
                No URL available
              </div>
            )}
          </div>

          <div className="hud-well w-full rounded-lg border border-white/10 p-3">
            <p className="mb-1 font-mono text-[11px] font-medium text-[#71717A]">Shareable Link</p>
            <p className="break-all font-mono text-xs text-zinc-200 select-all">
              {targetUrl}
            </p>
          </div>

          <div className="flex w-full items-start gap-2 rounded-lg border border-white/10 bg-white/5 p-2.5 text-xs text-[#A1A1AA]">
            <ShieldCheck className="mt-0.5 h-4 w-4 shrink-0 text-emerald-400" />
            <span>
              The decryption key remains in the URL fragment (
              <code className="rounded border border-white/10 bg-white/5 px-1 py-0.5 text-zinc-200">#key=...</code>
              ) and is never sent to the server.
            </span>
          </div>
        </div>

        <div className="flex items-center justify-end gap-2 border-t border-white/10 bg-[#07080B] px-5 py-3.5">
          <button
            type="button"
            onClick={handleCopy}
            disabled={!targetUrl}
            className="btn-copy inline-flex items-center gap-1.5 rounded-md bg-[#7C3AED] px-4 py-2 font-mono text-xs font-semibold text-white shadow-lg shadow-violet-600/25 hover:bg-[#6D28D9] disabled:opacity-50"
          >
            {copied ? <Check className="h-4 w-4" /> : <Copy className="h-4 w-4" />}
            <span>{copied ? 'Copied' : 'Copy Link'}</span>
          </button>
          <button
            type="button"
            onClick={onClose}
            className="btn-close rounded-md border border-white/10 bg-white/5 px-4 py-2 font-mono text-xs font-medium text-zinc-200 hover:bg-white/10"
          >
            Close
          </button>
        </div>
      </div>
    </div>
  );
}

export default QRModal;
