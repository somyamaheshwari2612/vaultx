'use client';

import React, { useState } from 'react';
import { Trash2, Check, AlertCircle } from 'lucide-react';
import { revokeFile } from '../../lib/api.js';

/**
 * RevokeButton
 * Person 4 dashboard slot: Tactical Crimson Red kill-switch button.
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

  const handleClick = async () => {
    if (disabled || status === 'revoking' || status === 'revoked') return;

    if (!fileId || !ownerToken) {
      if (onRevoke) {
        onRevoke();
      }
      return;
    }

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
  };

  return (
    <div className="inline-flex flex-col items-start gap-1">
      <button
        type="button"
        onClick={handleClick}
        disabled={disabled || status === 'revoking' || status === 'revoked' || isRevoked}
        className={`btn-revoke inline-flex items-center gap-1.5 rounded-md border px-3 py-1.5 font-mono text-xs font-semibold transition-colors ${
          status === 'revoked' || isRevoked
            ? 'border-white/10 bg-white/5 text-[#71717A] cursor-not-allowed'
            : 'border-red-500/40 bg-red-500/10 text-red-400 hover:bg-red-500/20 disabled:opacity-50'
        }`}
      >
        {status === 'revoked' || isRevoked ? (
          <>
            <Check className="h-3.5 w-3.5" />
            <span>Revoked</span>
          </>
        ) : (
          <>
            <Trash2 className="h-3.5 w-3.5" />
            <span>{status === 'revoking' ? 'Revoking...' : 'Revoke Access'}</span>
          </>
        )}
      </button>

      {error && (
        <span className="inline-flex items-center gap-1 font-mono text-[11px] text-red-400">
          <AlertCircle className="h-3 w-3" />
          <span>{error}</span>
        </span>
      )}
    </div>
  );
}

export default RevokeButton;
