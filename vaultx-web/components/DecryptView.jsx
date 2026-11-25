'use client';

import React, { useState, useEffect } from 'react';
import Link from 'next/link';
import {
  ShieldCheck,
  ShieldAlert,
  Lock,
  Key,
  Download,
  Trash2,
  Copy,
  Check,
  File,
  AlertCircle,
  Loader2,
} from 'lucide-react';
import { useDecrypt } from '../hooks/useDecrypt.js';
import { TerminalWindow } from './TerminalWindow.jsx';

function formatBytes(bytes) {
  if (!bytes && bytes !== 0) return '0 B';
  if (bytes < 1024) return `${bytes} B`;
  if (bytes < 1024 * 1024) return `${(bytes / 1024).toFixed(1)} KB`;
  return `${(bytes / (1024 * 1024)).toFixed(2)} MB`;
}

/**
 * DecryptView
 * Matte charcoal (#0B0C10) recipient decrypt view mounted at /v/[id].
 */
export function DecryptView({ fileId }) {
  const [activeUsername, setActiveUsername] = useState(null);
  const [storedOwnerToken, setStoredOwnerToken] = useState('');

  useEffect(() => {
    if (typeof window !== 'undefined' && window.localStorage) {
      try {
        const savedUser = window.localStorage.getItem('vaultx_active_username');
        if (savedUser) setActiveUsername(savedUser);

        const rawSent = window.localStorage.getItem('vaultx_sent_vaults');
        if (rawSent && fileId) {
          const list = JSON.parse(rawSent);
          const match = list.find((item) => item.fileId === fileId || item.id === fileId);
          if (match?.ownerToken) {
            setStoredOwnerToken(match.ownerToken);
          }
        }
      } catch (_) {}
    }
  }, [fileId]);

  const {
    status,
    hasFragmentKey,
    meta,
    decryptedMeta,
    fileBlob,
    previewUrl,
    previewType,
    textContent,
    isChecksumValid,
    sha256Checksum,
    error,
    submitPassword,
    setManualKey,
    downloadToDisk,
    destroyNow,
  } = useDecrypt(fileId, null, activeUsername);

  const [manualKeyInput, setManualKeyInput] = useState('');
  const [passwordInput, setPasswordInput] = useState('');
  const [ownerTokenInput, setOwnerTokenInput] = useState('');
  const [showDestroyPrompt, setShowDestroyPrompt] = useState(false);
  const [copiedNote, setCopiedNote] = useState(false);
  const [destroyedNotice, setDestroyedNotice] = useState(false);

  const usedManualKey = Boolean(manualKeyInput.trim());

  const handleManualKeySubmit = (e) => {
    e.preventDefault();
    if (manualKeyInput.trim()) {
      setManualKey(manualKeyInput.trim());
    }
  };

  const handlePasswordSubmit = async (e) => {
    e.preventDefault();
    if (!passwordInput) return;
    try {
      await submitPassword(passwordInput);
    } catch (_) {
      // Error surfaced via useDecrypt
    }
  };

  const handleCopyNote = async () => {
    if (!textContent) return;
    try {
      await navigator.clipboard.writeText(textContent);
      setCopiedNote(true);
      setTimeout(() => setCopiedNote(false), 2000);
    } catch (_) {}
  };

  const handleDestroy = async () => {
    const tokenToUse = ownerTokenInput.trim() || storedOwnerToken || null;
    await destroyNow(tokenToUse);
    setDestroyedNotice(true);
    setShowDestroyPrompt(false);
  };

  const renderKeyDetectionBadge = () => {
    if (!meta) return null;
    if (meta.mode === 'MODE_A') {
      return (
        <span className="key-badge inline-flex items-center gap-1.5 rounded-md border border-white/10 bg-white/5 px-2.5 py-1 font-mono text-xs font-medium text-zinc-200">
          <Key className="h-3.5 w-3.5 text-[#7C3AED]" />
          <span>Mode A: RSA Private Key (IndexedDB)</span>
        </span>
      );
    }

    return hasFragmentKey ? (
      <span className="key-badge inline-flex items-center gap-1.5 rounded-md border border-white/10 bg-white/5 px-2.5 py-1 font-mono text-xs font-medium text-zinc-200">
        <Key className="h-3.5 w-3.5 text-[#7C3AED]" />
        <span>Key Detected from URL #fragment</span>
      </span>
    ) : (
      <span className="key-badge-missing inline-flex items-center gap-1.5 rounded-md border border-red-500/40 bg-red-500/10 px-2.5 py-1 font-mono text-xs font-medium text-red-400">
        <Key className="h-3.5 w-3.5 text-red-400" />
        <span>No #fragment Key Found (Manual Key Required)</span>
      </span>
    );
  };

  return (
    <section className="decrypt-view">
      <TerminalWindow>
        <div className="p-5 sm:p-6">
          {/* Header & Key Detection Status */}
          <div className="mb-5 flex flex-wrap items-center justify-between gap-3 border-b border-white/10 pb-4">
            <div>
              <h2 className="text-lg font-bold text-[#FAFAFA]">Encrypted Vault Access</h2>
              <p className="font-mono text-xs text-[#71717A]">Vault ID: {fileId}</p>
            </div>

            <div className="flex flex-wrap items-center gap-2">
              {renderKeyDetectionBadge()}

              {isChecksumValid === true && (
                <span className="badge-verified inline-flex items-center gap-1.5 rounded-md border border-emerald-500/40 bg-emerald-950/30 px-2.5 py-1 font-mono text-xs font-bold text-emerald-400">
                  <ShieldCheck className="h-3.5 w-3.5" />
                  <span>Authentic &bull; Verified</span>
                </span>
              )}

              {isChecksumValid === false && (
                <span className="warning-banner inline-flex items-center gap-1.5 rounded-md border border-red-500/40 bg-red-500/10 px-2.5 py-1 font-mono text-xs font-bold text-red-400">
                  <ShieldAlert className="h-3.5 w-3.5" />
                  <span>Tampered &bull; Warning</span>
                </span>
              )}
            </div>
          </div>

          {/* Destroyed / Purged Confirmation */}
          {destroyedNotice && status === 'idle' && (
            <div className="hud-well mb-4 rounded-xl border border-white/10 p-4 text-sm text-zinc-200">
              <p className="font-mono font-bold text-[#FAFAFA]">In-memory payload cleared.</p>
              <p className="mt-1 text-xs text-[#A1A1AA]">
                Preview ObjectURL has been revoked and decrypted bytes have been purged from memory.
              </p>
              <Link
                href="/"
                className="mt-3 inline-block rounded-md border border-white/10 bg-white/5 px-3 py-1.5 font-mono text-xs font-medium text-zinc-200 hover:bg-white/10"
              >
                Return to Upload
              </Link>
            </div>
          )}

          {/* Loading / Decrypting States */}
          {(status === 'loading_meta' || status === 'decrypting') && (
            <div className="hud-well flex items-center gap-3 rounded-xl border border-white/10 p-6 font-mono text-sm text-[#A1A1AA]">
              <Loader2 className="h-5 w-5 animate-spin text-[#7C3AED]" />
              <span>
                {status === 'loading_meta'
                  ? 'Loading encrypted vault metadata...'
                  : 'Decrypting ciphertext and verifying SHA-256 checksum...'}
              </span>
            </div>
          )}

          {/* Missing Fragment Key Manual Input Prompt */}
          {!destroyedNotice &&
            meta?.mode === 'MODE_B' &&
            ((!hasFragmentKey && status === 'idle') ||
              (status === 'error' && (usedManualKey || !hasFragmentKey || error?.includes('Invalid key')))) && (
              <form
                onSubmit={handleManualKeySubmit}
                className="manual-key-prompt hud-well space-y-3 rounded-xl border border-white/10 p-4"
              >
                <p className="font-mono text-sm font-bold text-[#FAFAFA]">
                  {status === 'error' ? 'Retry Decryption Key' : 'Enter Decryption Key'}
                </p>
                <p className="text-xs text-[#A1A1AA]">
                  {status === 'error'
                    ? 'The key provided could not unlock this vault. Check the Base64URL key from the sender and try again.'
                    : (
                      <>
                        The URL fragment (
                        <code className="rounded border border-white/10 bg-white/5 px-1 py-0.5 text-zinc-200">
                          #key=...
                        </code>
                        ) is missing. Paste the Base64URL key provided by the sender to unlock this vault.
                      </>
                    )}
                </p>
                <div className="flex gap-2">
                  <input
                    type="text"
                    value={manualKeyInput}
                    onChange={(e) => setManualKeyInput(e.target.value)}
                    placeholder="Paste Base64URL fragment key..."
                    className="manual-key-input flex-1 rounded-md border border-white/10 bg-[#0B0C10] px-3 py-2 font-mono text-xs text-[#FAFAFA] placeholder-[#71717A] focus:border-[#7C3AED] focus:outline-none"
                  />
                  <button
                    type="submit"
                    disabled={!manualKeyInput.trim()}
                    className="btn-unlock-key rounded-md bg-[#7C3AED] px-4 py-2 font-mono text-xs font-semibold text-white shadow-lg shadow-violet-600/25 hover:bg-[#6D28D9] disabled:opacity-50"
                  >
                    {status === 'error' ? 'Retry Key' : 'Unlock Vault'}
                  </button>
                </div>
              </form>
            )}

          {/* Password Challenge Modal / Panel */}
          {status === 'password_required' && (
            <form
              onSubmit={handlePasswordSubmit}
              className="password-challenge hud-well space-y-3 rounded-xl border border-red-500/40 bg-red-500/5 p-5"
            >
              <div className="flex items-center gap-2 text-red-400">
                <Lock className="h-4 w-4" />
                <h3 className="font-mono text-sm font-bold">Password Required</h3>
              </div>
              <p className="text-xs text-[#A1A1AA]">
                This vault is protected with an additional PBKDF2 password wrapper.
              </p>
              {error && (
                <div className="flex items-center gap-2 rounded-md border border-red-500/40 bg-red-500/10 p-2.5 text-xs text-red-400">
                  <AlertCircle className="h-4 w-4 shrink-0" />
                  <span>{error}</span>
                </div>
              )}
              <div className="flex gap-2">
                <input
                  type="password"
                  value={passwordInput}
                  onChange={(e) => setPasswordInput(e.target.value)}
                  placeholder="Enter vault password..."
                  aria-label="Vault password"
                  className="password-challenge-input flex-1 rounded-md border border-red-500/30 bg-[#0B0C10] px-3 py-2 font-mono text-sm text-[#FAFAFA] placeholder-[#71717A] focus:border-red-500 focus:outline-none"
                />
                <button
                  type="submit"
                  disabled={!passwordInput}
                  className="btn-submit-password rounded-md bg-[#7C3AED] px-4 py-2 font-mono text-xs font-semibold text-white shadow-lg shadow-violet-600/25 hover:bg-[#6D28D9] disabled:opacity-50"
                >
                  Decrypt
                </button>
              </div>
            </form>
          )}

          {/* Tampered Warning Banner */}
          {status === 'tampered' && (
            <div className="warning-banner rounded-xl border border-red-500/40 bg-red-500/10 p-4 text-sm text-red-400">
              <div className="flex items-center gap-2 font-mono font-bold">
                <ShieldAlert className="h-5 w-5" />
                <span>Tampered &bull; Warning: Integrity Verification Failed</span>
              </div>
              <p className="mt-1 text-xs text-red-300/90">
                {error || 'The computed SHA-256 digest does not match the authenticated metadata checksum.'}
              </p>
            </div>
          )}

          {/* General Error Banner */}
          {status === 'error' && (
            <div className="error-banner mt-3 rounded-xl border border-red-500/40 bg-red-500/10 p-4 text-sm text-red-400">
              <div className="flex items-center gap-2 font-mono font-semibold">
                <AlertCircle className="h-4 w-4" />
                <span>Unable to Decrypt Vault</span>
              </div>
              <p className="mt-1 text-xs">{error}</p>
              {meta?.mode === 'MODE_A' && (
                <p className="mt-2 text-xs text-[#A1A1AA]">
                  Mode A requires your recipient private key in IndexedDB. Ensure you generated your keypair on this browser via Key Setup.
                </p>
              )}
            </div>
          )}

          {/* Ready: Metadata + Zero-Footprint In-Memory Previewer + Actions */}
          {status === 'ready' && (
            <div className="space-y-5">
              <div className="meta-summary hud-well grid grid-cols-1 gap-3 rounded-xl border border-white/10 p-3.5 text-xs sm:grid-cols-3">
                <div>
                  <span className="font-mono text-[10px] text-[#71717A]">FILENAME</span>
                  <p className="truncate font-mono font-semibold text-[#FAFAFA]">
                    {decryptedMeta?.filename || 'secret-payload'}
                  </p>
                </div>
                <div>
                  <span className="font-mono text-[10px] text-[#71717A]">SIZE / TYPE</span>
                  <p className="font-mono text-zinc-200">
                    {formatBytes(decryptedMeta?.size ?? fileBlob?.size)} &bull;{' '}
                    {decryptedMeta?.mimeType || 'application/octet-stream'}
                  </p>
                </div>
                <div>
                  <span className="font-mono text-[10px] text-[#71717A]">DOWNLOADS LEFT</span>
                  <p className="font-mono text-emerald-400">
                    {meta?.isBurnAfterReading ? 'Burned after this read' : (meta?.remainingDownloads ?? '-')}
                  </p>
                </div>
              </div>

              {/* Zero-Footprint In-Memory Previewer */}
              <div className="preview-container hud-well rounded-xl border border-white/10 p-4">
                <div className="mb-2.5 flex items-center justify-between">
                  <span className="font-mono text-xs font-semibold uppercase tracking-wider text-[#71717A]">
                    Zero-Footprint In-Memory Preview
                  </span>
                  {previewType === 'text' && (
                    <button
                      type="button"
                      onClick={handleCopyNote}
                      className="btn-copy-note inline-flex items-center gap-1 rounded border border-white/10 bg-white/5 px-2.5 py-1 font-mono text-xs font-medium text-zinc-200 hover:bg-white/10"
                    >
                      {copiedNote ? <Check className="h-3.5 w-3.5" /> : <Copy className="h-3.5 w-3.5" />}
                      <span>{copiedNote ? 'Copied' : 'Copy Note'}</span>
                    </button>
                  )}
                </div>

                {previewType === 'image' && previewUrl && (
                  <div className="flex justify-center rounded-lg border border-white/10 bg-[#050508] p-2">
                    <img
                      src={previewUrl}
                      alt={decryptedMeta?.filename || 'Decrypted image preview'}
                      className="preview-image max-h-[480px] max-w-full object-contain"
                    />
                  </div>
                )}

                {previewType === 'pdf' && previewUrl && (
                  <iframe
                    src={previewUrl}
                    title={decryptedMeta?.filename || 'Decrypted PDF preview'}
                    className="preview-pdf h-[500px] w-full rounded-lg border border-white/10 bg-white"
                  />
                )}

                {previewType === 'text' && (
                  <pre className="preview-text max-h-96 overflow-auto whitespace-pre-wrap break-words rounded-lg border border-white/10 bg-[#050508] p-4 font-mono text-sm text-[#FAFAFA]">
                    {textContent}
                  </pre>
                )}

                {previewType === 'binary' && (
                  <div className="preview-binary flex items-center gap-3 rounded-lg border border-white/10 bg-[#050508] p-4 text-xs text-[#A1A1AA]">
                    <File className="h-6 w-6 text-[#71717A]" />
                    <div>
                      <p className="font-mono font-semibold text-[#FAFAFA]">
                        Binary file decrypted in memory ({formatBytes(fileBlob?.size)})
                      </p>
                      <p>Inline preview is unavailable for this MIME type. Use Download to Disk below.</p>
                    </div>
                  </div>
                )}
              </div>

              {sha256Checksum && (
                <div className="hud-well rounded-lg border border-white/10 px-3 py-2 font-mono text-[11px] text-[#71717A] break-all">
                  SHA-256 Digest: <span className="text-emerald-400">{sha256Checksum}</span>
                </div>
              )}

              {/* Action Buttons */}
              <div className="flex flex-wrap items-center justify-between gap-3 border-t border-white/10 pt-4">
                <button
                  type="button"
                  onClick={downloadToDisk}
                  disabled={!fileBlob}
                  className="btn-download-disk inline-flex items-center gap-2 rounded-lg bg-[#7C3AED] px-4 py-2.5 font-mono text-xs font-semibold text-white shadow-lg shadow-violet-600/25 hover:bg-[#6D28D9] disabled:opacity-50"
                >
                  <Download className="h-4 w-4" />
                  <span>Download to Disk</span>
                </button>

                <button
                  type="button"
                  onClick={() => {
                    if (storedOwnerToken) {
                      handleDestroy();
                    } else {
                      setShowDestroyPrompt((prev) => !prev);
                    }
                  }}
                  className="btn-destroy-revoke inline-flex items-center gap-2 rounded-lg border border-red-500/40 bg-red-500/10 px-4 py-2.5 font-mono text-xs font-semibold text-red-400 hover:bg-red-500/20"
                >
                  <Trash2 className="h-4 w-4" />
                  <span>Destroy / Revoke</span>
                </button>
              </div>

              {showDestroyPrompt && (
                <div className="rounded-xl border border-red-500/40 bg-red-500/10 p-3.5 space-y-2.5">
                  <p className="text-xs font-medium text-red-400">
                    Optional: Enter Owner Revocation Token to also delete server copy, or click Confirm to purge local memory only.
                  </p>
                  <div className="flex gap-2">
                    <input
                      type="text"
                      value={ownerTokenInput}
                      onChange={(e) => setOwnerTokenInput(e.target.value)}
                      placeholder="Owner revocation token (optional)"
                      className="flex-1 rounded-md border border-white/10 bg-[#0B0C10] px-2.5 py-1.5 font-mono text-xs text-[#FAFAFA] placeholder-[#71717A]"
                    />
                    <button
                      type="button"
                      onClick={handleDestroy}
                      className="rounded-md bg-red-600 px-3 py-1.5 font-mono text-xs font-bold text-white hover:bg-red-500"
                    >
                      Confirm Destroy
                    </button>
                  </div>
                </div>
              )}
            </div>
          )}
        </div>
      </TerminalWindow>
    </section>
  );
}

export default DecryptView;
