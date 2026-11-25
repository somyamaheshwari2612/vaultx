'use client';

import React, { useState, useCallback } from 'react';
import { Trash2, Check, AlertCircle, ShieldAlert, X, Loader2 } from 'lucide-react';
import { revokeFile } from '../../lib/api.js';

/**
 * RevokeButton — Enhanced Version with Confirmation Modal
 * ────────────────────────────────────────────────────────
 * Person 4 dashboard component: Tactical Crimson kill-switch button with:
 *   • Two-step confirmation modal to prevent accidental revocation
 *   • Loading spinner during API call
 *   • Success animation
 *   • Error display with dismiss
 *   • Disabled state when already revoked
 *
 * Props:
 *   fileId     — Vault ID to revoke
 *   ownerToken — Authentication token for the owner
 *   disabled   — External disable flag
 *   isRevoked  — Whether the vault is already revoked
 *   onRevoked  — Callback fired after successful revocation
 *   onRevoke   — Alternative callback (for mock/offline mode)
 */
export function RevokeButton({
  fileId,
  ownerToken,
  disabled = false,
  isRevoked = false,
  onRevoked,
  onRevoke,
}) {
  const [status, setStatus] = useState(isRevoked ? 'revoked' : 'idle');
  const [error, setError] = useState(null);
  const [showConfirm, setShowConfirm] = useState(false);

  // ── Open confirmation modal ────────────────────────────────────
  const handleClick = useCallback(() => {
    if (disabled || status === 'revoking' || status === 'revoked') return;

    // If no fileId/ownerToken (mock mode), fire callback directly
    if (!fileId || !ownerToken) {
      if (onRevoke) onRevoke();
      return;
    }

    // Show confirmation modal
    setShowConfirm(true);
  }, [disabled, status, fileId, ownerToken, onRevoke]);

  // ── Execute revocation ─────────────────────────────────────────
  const executeRevoke = useCallback(async () => {
    setShowConfirm(false);
    setStatus('revoking');
    setError(null);

    try {
      const res = await revokeFile(fileId, ownerToken);
      setStatus('revoked');
      if (onRevoked) onRevoked(res);
      if (onRevoke) onRevoke(res);
    } catch (err) {
      setError(err.message || 'Revocation failed');
      setStatus('error');
    }
  }, [fileId, ownerToken, onRevoked, onRevoke]);

  // ── Cancel ─────────────────────────────────────────────────────
  const cancelRevoke = useCallback(() => {
    setShowConfirm(false);
  }, []);

  // ── Dismiss error ──────────────────────────────────────────────
  const dismissError = useCallback(() => {
    setError(null);
    setStatus('idle');
  }, []);

  // ── Button visual states ───────────────────────────────────────
  const isDisabled = disabled || status === 'revoking' || status === 'revoked' || isRevoked;

  const buttonClasses = (() => {
    if (status === 'revoked' || isRevoked) {
      return 'border-white/10 bg-white/5 text-[#71717A] cursor-not-allowed';
    }
    if (status === 'revoking') {
      return 'border-red-500/40 bg-red-500/10 text-red-400 cursor-wait opacity-75';
    }
    if (status === 'error') {
      return 'border-red-500/40 bg-red-500/10 text-red-400 hover:bg-red-500/20';
    }
    return 'border-red-500/40 bg-red-500/10 text-red-400 hover:bg-red-500/20 disabled:opacity-50';
  })();

  return (
    <>
      <div className="inline-flex flex-col items-start gap-1">
        {/* ─── Main Button ────────────────────────────────────── */}
        <button
          type="button"
          onClick={handleClick}
          disabled={isDisabled}
          className={`btn-revoke inline-flex items-center gap-1.5 rounded-md border px-3 py-1.5 font-mono text-xs font-semibold transition-all ${buttonClasses}`}
        >
          {status === 'revoked' || isRevoked ? (
            <>
              <Check className="h-3.5 w-3.5" />
              <span>Revoked</span>
            </>
          ) : status === 'revoking' ? (
            <>
              <Loader2 className="h-3.5 w-3.5 animate-spin" />
              <span>Revoking…</span>
            </>
          ) : (
            <>
              <Trash2 className="h-3.5 w-3.5" />
              <span>Revoke Access</span>
            </>
          )}
        </button>

        {/* ─── Error display ──────────────────────────────────── */}
        {error && (
          <div className="inline-flex items-center gap-1 font-mono text-[11px] text-red-400">
            <AlertCircle className="h-3 w-3 shrink-0" />
            <span>{error}</span>
            <button
              type="button"
              onClick={dismissError}
              className="ml-1 rounded p-0.5 hover:bg-red-500/10"
              title="Dismiss"
            >
              <X className="h-3 w-3" />
            </button>
          </div>
        )}
      </div>

      {/* ─── Confirmation Modal ───────────────────────────────── */}
      {showConfirm && (
        <div className="fixed inset-0 z-50 flex items-center justify-center p-4">
          {/* Backdrop */}
          <div
            className="absolute inset-0 bg-black/70 backdrop-blur-sm"
            onClick={cancelRevoke}
          />

          {/* Modal card */}
          <div className="relative z-10 w-full max-w-sm rounded-xl border border-red-500/30 bg-[#0B0C10] p-6 shadow-2xl shadow-red-900/20">
            {/* Icon */}
            <div className="mx-auto mb-4 flex h-12 w-12 items-center justify-center rounded-full border border-red-500/30 bg-red-500/10">
              <ShieldAlert className="h-6 w-6 text-red-400" />
            </div>

            {/* Title & description */}
            <h3 className="mb-1 text-center font-mono text-sm font-bold text-[#FAFAFA]">
              Revoke Access?
            </h3>
            <p className="mb-6 text-center text-xs text-[#A1A1AA]">
              This will <strong className="text-red-400">permanently</strong> disable
              all sharing links for this vault. Recipients will no longer be
              able to download or view the file. This action cannot be undone.
            </p>

            {/* Vault ID indicator */}
            <div className="mb-5 rounded-lg border border-white/10 bg-[#07080B] px-3 py-2 text-center font-mono text-[11px] text-[#71717A]">
              Vault ID: <span className="text-zinc-300">{fileId}</span>
            </div>

            {/* Action buttons */}
            <div className="flex gap-3">
              <button
                type="button"
                onClick={cancelRevoke}
                className="flex-1 rounded-lg border border-white/10 bg-white/5 px-4 py-2 font-mono text-xs font-medium text-zinc-300 transition-colors hover:bg-white/10"
              >
                Cancel
              </button>
              <button
                type="button"
                onClick={executeRevoke}
                className="flex-1 rounded-lg border border-red-500/40 bg-red-500/20 px-4 py-2 font-mono text-xs font-bold text-red-400 transition-colors hover:bg-red-500/30"
              >
                Yes, Revoke
              </button>
            </div>
          </div>
        </div>
      )}
    </>
  );
}

export default RevokeButton;
