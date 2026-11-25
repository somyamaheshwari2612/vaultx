'use client';

import React, { useState, useRef } from 'react';
import Link from 'next/link';
import {
  Upload,
  FileText,
  Lock,
  Link2,
  UserCheck,
  QrCode,
  Copy,
  Check,
  AlertCircle,
  Flame,
  ShieldAlert,
  Search,
  X,
  RotateCcw,
} from 'lucide-react';
import { useUpload } from '../hooks/useUpload.js';
import { QRModal } from './QRModal.jsx';
import { TerminalWindow } from './TerminalWindow.jsx';
import { ThemeSelect } from './ThemeSelect.jsx';

function formatBytes(bytes) {
  if (!bytes && bytes !== 0) return '0 B';
  if (bytes < 1024) return `${bytes} B`;
  if (bytes < 1024 * 1024) return `${(bytes / 1024).toFixed(1)} KB`;
  return `${(bytes / (1024 * 1024)).toFixed(2)} MB`;
}

/**
 * UploadCard
 * Obsidian Black (#050508), Matte Charcoal (#0B0C10), Deep Violet (#7C3AED),
 * and Tactical Crimson Red (#EF4444) upload & encryption card.
 */
export function UploadCard() {
  const {
    tab,
    setTab,
    mode,
    setMode,
    file,
    setFile,
    textNote,
    setTextNote,
    recipientUsername,
    setRecipientUsername,
    recipientInfo,
    lookupRecipient,
    expiryMinutes,
    setExpiryMinutes,
    maxDownloads,
    setMaxDownloads,
    isBurnAfterReading,
    setIsBurnAfterReading,
    isPasswordProtected,
    setIsPasswordProtected,
    password,
    setPassword,
    status,
    result,
    error,
    executeUpload,
    reset,
  } = useUpload();

  const [isDragging, setIsDragging] = useState(false);
  const [isQrOpen, setIsQrOpen] = useState(false);
  const [copiedLink, setCopiedLink] = useState(false);
  const [copiedToken, setCopiedToken] = useState(false);
  const [lookupStatus, setLookupStatus] = useState('');
  const fileInputRef = useRef(null);

  const isBusy = status === 'encrypting' || status === 'uploading';

  const handleDragOver = (e) => {
    e.preventDefault();
    e.stopPropagation();
    if (!isDragging) setIsDragging(true);
  };

  const handleDragLeave = (e) => {
    e.preventDefault();
    e.stopPropagation();
    setIsDragging(false);
  };

  const handleDrop = (e) => {
    e.preventDefault();
    e.stopPropagation();
    setIsDragging(false);
    const dropped = e.dataTransfer?.files?.[0];
    if (dropped) {
      setFile(dropped);
    }
  };

  const handleFileChange = (e) => {
    const selected = e.target.files?.[0];
    if (selected) {
      setFile(selected);
    }
  };

  const handleLookupRecipient = async () => {
    const target = recipientUsername.trim();
    if (!target) return;
    setLookupStatus('searching');
    const info = await lookupRecipient(target);
    setLookupStatus(info ? 'found' : 'not_found');
  };

  const handleBurnToggle = (checked) => {
    setIsBurnAfterReading(checked);
    if (checked) {
      setMaxDownloads(1);
    }
  };

  const handleCopyText = async (val, setter) => {
    if (!val) return;
    try {
      await navigator.clipboard.writeText(val);
      setter(true);
      setTimeout(() => setter(false), 2000);
    } catch (_) {}
  };

  const handleSubmit = async (e) => {
    e.preventDefault();
    try {
      await executeUpload();
    } catch (_) {
      // Error state is handled by useUpload
    }
  };

  const handleReset = () => {
    reset();
    setLookupStatus('');
    setCopiedLink(false);
    setCopiedToken(false);
    setIsQrOpen(false);
    if (fileInputRef.current) {
      fileInputRef.current.value = '';
    }
  };

  const getActionLabel = () => {
    if (status === 'encrypting') return 'Encrypting...';
    if (status === 'uploading') return 'Uploading...';
    if (status === 'success') return 'Encrypted & Shared';
    if (status === 'error') return 'Retry Encrypt & Share';
    return 'Encrypt & Share';
  };

  const isSubmitDisabled =
    isBusy ||
    (tab === 'file' && !file) ||
    (tab === 'text' && !textNote.trim()) ||
    (mode === 'MODE_A' && !recipientUsername.trim()) ||
    (isPasswordProtected && !password);

  return (
    <section className="upload-card">
      <TerminalWindow>
        <div className="p-4 sm:p-5">
          {/* Dual Input Tabs */}
          <div className="tabs mb-4 flex gap-2 border-b border-white/10 pb-3" role="tablist">
            <button
              type="button"
              role="tab"
              aria-selected={tab === 'file'}
              onClick={() => setTab('file')}
              disabled={isBusy}
              className={`tab-file inline-flex items-center gap-2 rounded-md border px-3.5 py-1.5 text-xs font-medium transition-all ${
                tab === 'file'
                  ? 'border-[#7C3AED]/60 bg-[#7C3AED]/15 text-white'
                  : 'border-white/10 bg-white/[0.03] text-[#A1A1AA] hover:border-white/20 hover:text-[#FAFAFA]'
              }`}
            >
              <Upload className={`h-3.5 w-3.5 ${tab === 'file' ? 'text-[#7C3AED]' : 'text-[#71717A]'}`} />
              <span>File Upload</span>
            </button>

            <button
              type="button"
              role="tab"
              aria-selected={tab === 'text'}
              onClick={() => setTab('text')}
              disabled={isBusy}
              className={`tab-note inline-flex items-center gap-2 rounded-md border px-3.5 py-1.5 text-xs font-medium transition-all ${
                tab === 'text'
                  ? 'border-[#7C3AED]/60 bg-[#7C3AED]/15 text-white'
                  : 'border-white/10 bg-white/[0.03] text-[#A1A1AA] hover:border-white/20 hover:text-[#FAFAFA]'
              }`}
            >
              <FileText className={`h-3.5 w-3.5 ${tab === 'text' ? 'text-[#7C3AED]' : 'text-[#71717A]'}`} />
              <span>Secret Text Note</span>
            </button>
          </div>

          <form onSubmit={handleSubmit} className="space-y-4">
            {/* Tab Panel: #07080B File Dropzone vs Secret Text Editor */}
            {tab === 'file' ? (
              <div
                onDragOver={handleDragOver}
                onDragLeave={handleDragLeave}
                onDrop={handleDrop}
                onClick={() => !isBusy && fileInputRef.current?.click()}
                className={`dropzone hud-well flex cursor-pointer flex-col items-center justify-center rounded-xl border border-dashed px-6 py-5 text-center transition-all ${
                  isDragging
                    ? 'border-[#7C3AED] bg-[#7C3AED]/10'
                    : 'border-white/15 hover:border-white/30'
                }`}
              >
                <input
                  ref={fileInputRef}
                  type="file"
                  onChange={handleFileChange}
                  disabled={isBusy}
                  className="hidden"
                  aria-label="Select file to encrypt"
                />
                {file ? (
                  <div className="flex w-full max-w-md items-center justify-between rounded-lg border border-white/10 bg-[#0B0C10] px-4 py-3 text-left">
                    <div className="min-w-0 pr-3">
                      <p className="truncate text-sm font-semibold text-[#FAFAFA]">{file.name}</p>
                      <p className="font-mono text-xs text-[#71717A]">
                        {formatBytes(file.size)} &bull; {file.type || 'application/octet-stream'}
                      </p>
                    </div>
                    <button
                      type="button"
                      onClick={(e) => {
                        e.stopPropagation();
                        setFile(null);
                        if (fileInputRef.current) fileInputRef.current.value = '';
                      }}
                      className="rounded p-1 text-[#71717A] hover:bg-white/5 hover:text-[#FAFAFA]"
                      aria-label="Remove selected file"
                    >
                      <X className="h-4 w-4" />
                    </button>
                  </div>
                ) : (
                  <>
                    <div className="mb-2.5 flex h-11 w-11 items-center justify-center rounded-full border border-[#7C3AED]/40 bg-[#7C3AED]/15">
                      <Upload className="h-5 w-5 text-[#7C3AED]" />
                    </div>
                    <p className="text-sm font-medium text-[#FAFAFA]">
                      Drag and drop a file here, or click to browse
                    </p>
                    <p className="mt-1 font-mono text-xs text-[#71717A]">
                      Encrypted locally with AES-256-GCM before leaving your browser
                    </p>
                  </>
                )}
              </div>
            ) : (
              <div className="secret-note-editor">
                <div className="mb-1.5 flex items-center justify-between">
                  <label htmlFor="vaultx-secret-note" className="font-mono text-xs font-medium text-[#A1A1AA]">
                    Secret Text Payload
                  </label>
                  <span className="font-mono text-xs text-[#71717A]">
                    {new TextEncoder().encode(textNote).byteLength} bytes
                  </span>
                </div>
                <textarea
                  id="vaultx-secret-note"
                  rows={6}
                  value={textNote}
                  onChange={(e) => setTextNote(e.target.value)}
                  disabled={isBusy}
                  placeholder="Paste API keys, recovery phrases, or private notes..."
                  className="secret-note-textarea hud-well w-full rounded-xl border border-white/10 p-3.5 font-mono text-sm text-[#FAFAFA] placeholder-[#71717A] focus:border-[#7C3AED] focus:outline-none"
                />
              </div>
            )}

            {/* Mode Selector */}
            <div className="mode-selector rounded-xl border border-white/10 bg-[#07080B] p-3.5">
              <p className="mb-2.5 text-xs font-medium text-[#71717A]">
                Cryptographic Sharing Mode
              </p>
              <div className="grid grid-cols-1 gap-2.5 sm:grid-cols-2">
                <label
                  className={`flex cursor-pointer items-start gap-2.5 rounded-lg border p-3 transition-all ${
                    mode === 'MODE_B'
                      ? 'border-[#7C3AED] bg-[#7C3AED]/10'
                      : 'border-white/10 bg-[#0B0C10] hover:border-white/20'
                  }`}
                >
                  <input
                    type="radio"
                    name="vaultx-mode"
                    value="MODE_B"
                    checked={mode === 'MODE_B'}
                    onChange={() => setMode('MODE_B')}
                    disabled={isBusy}
                    className="mt-0.5 accent-[#7C3AED]"
                  />
                  <div>
                    <div className="flex items-center gap-1.5 font-mono text-xs font-semibold text-[#FAFAFA]">
                      <Link2 className={`h-3.5 w-3.5 ${mode === 'MODE_B' ? 'text-[#7C3AED]' : 'text-[#71717A]'}`} />
                      <span>Mode B: Anonymous Fragment Link</span>
                    </div>
                    <p className="mt-1 text-xs text-[#A1A1AA]">
                      Ephemeral AES key stored only in URL{' '}
                      <code className="rounded border border-white/10 bg-white/5 px-1 py-0.5 text-zinc-200">
                        #key=
                      </code>{' '}
                      fragment.
                    </p>
                  </div>
                </label>

                <label
                  className={`flex cursor-pointer items-start gap-2.5 rounded-lg border p-3 transition-all ${
                    mode === 'MODE_A'
                      ? 'border-[#7C3AED] bg-[#7C3AED]/10'
                      : 'border-white/10 bg-[#0B0C10] hover:border-white/20'
                  }`}
                >
                  <input
                    type="radio"
                    name="vaultx-mode"
                    value="MODE_A"
                    checked={mode === 'MODE_A'}
                    onChange={() => setMode('MODE_A')}
                    disabled={isBusy}
                    className="mt-0.5 accent-[#7C3AED]"
                  />
                  <div>
                    <div className="flex items-center gap-1.5 font-mono text-xs font-semibold text-[#FAFAFA]">
                      <UserCheck className={`h-3.5 w-3.5 ${mode === 'MODE_A' ? 'text-[#7C3AED]' : 'text-[#71717A]'}`} />
                      <span>Mode A: Recipient Public Key</span>
                    </div>
                    <p className="mt-1 text-xs text-[#A1A1AA]">
                      AES key wrapped with recipient RSA-OAEP public key. Zero fragment.
                    </p>
                  </div>
                </label>
              </div>

              {mode === 'MODE_A' && (
                <div className="mt-3.5 space-y-2.5 border-t border-white/10 pt-3.5">
                  <label htmlFor="vaultx-recipient" className="block font-mono text-xs font-medium text-[#A1A1AA]">
                    Recipient Handle &amp; Key Verification
                  </label>
                  <div className="flex gap-2">
                    <input
                      id="vaultx-recipient"
                      type="text"
                      value={recipientUsername}
                      onChange={(e) => {
                        setRecipientUsername(e.target.value);
                        setLookupStatus('');
                      }}
                      disabled={isBusy}
                      placeholder="Enter recipient handle (e.g. alice)"
                      className="recipient-input flex-1 rounded-md border border-white/10 bg-[#0B0C10] px-3 py-1.5 font-mono text-sm text-[#FAFAFA] placeholder-[#71717A] focus:border-[#7C3AED] focus:outline-none"
                    />
                    <button
                      type="button"
                      onClick={handleLookupRecipient}
                      disabled={isBusy || !recipientUsername.trim()}
                      className="btn-lookup-recipient inline-flex items-center gap-1.5 rounded-md border border-white/10 bg-white/5 px-3 py-1.5 font-mono text-xs font-medium text-zinc-200 hover:bg-white/10 disabled:opacity-50"
                    >
                      <Search className="h-3.5 w-3.5" />
                      <span>Verify Key</span>
                    </button>
                  </div>

                  {recipientInfo && (
                    <div className="recipient-fingerprint rounded-lg border border-emerald-500/35 bg-emerald-950/20 p-2.5 text-xs">
                      <p className="font-mono font-semibold text-emerald-400">
                        Verified Key for {recipientInfo.username}
                      </p>
                      <p className="mt-1 break-all font-mono text-[11px] text-[#A1A1AA]">
                        Fingerprint: {recipientInfo.fingerprint}
                      </p>
                    </div>
                  )}

                  {lookupStatus === 'not_found' && !recipientInfo && (
                    <p className="font-mono text-xs text-red-400">
                      Recipient not found. Ask them to generate a keypair via Key Setup first.
                    </p>
                  )}
                </div>
              )}
            </div>

            {/* Expiration, Download Limits & Security Options */}
            <div className="controls-grid grid grid-cols-1 gap-3 rounded-xl border border-white/10 bg-[#07080B] p-3.5 sm:grid-cols-2">
              <div>
                <label htmlFor="vaultx-ttl" className="mb-1 block text-xs font-medium text-[#71717A]">
                  Expiration (TTL)
                </label>
                <ThemeSelect
                  id="vaultx-ttl"
                  value={expiryMinutes}
                  onChange={(val) => setExpiryMinutes(Number(val))}
                  disabled={isBusy}
                  options={[
                    { value: 10, label: '10 Minutes' },
                    { value: 60, label: '1 Hour' },
                    { value: 1440, label: '24 Hours' },
                    { value: 10080, label: '7 Days' },
                  ]}
                />
              </div>

              <div>
                <label htmlFor="vaultx-max-downloads" className="mb-1 block text-xs font-medium text-[#71717A]">
                  Max Downloads
                </label>
                <input
                  id="vaultx-max-downloads"
                  type="number"
                  min={1}
                  max={100}
                  value={maxDownloads}
                  onChange={(e) => setMaxDownloads(Math.max(1, Number(e.target.value) || 1))}
                  disabled={isBusy || isBurnAfterReading}
                  className="max-downloads-input w-full rounded-md border border-white/10 bg-[#0B0C10] px-3 py-1.5 font-mono text-sm text-[#FAFAFA] focus:border-[#7C3AED] focus:outline-none disabled:opacity-50"
                />
              </div>

              {/* Burn After Reading (1 View) — Tactical Crimson Red Accent */}
              <div
                className={`flex items-center justify-between gap-2.5 rounded-lg border px-3 py-2 transition-colors sm:col-span-2 ${
                  isBurnAfterReading
                    ? 'border-red-500/40 bg-red-500/10 text-red-400'
                    : 'border-white/10 bg-[#0B0C10] text-[#A1A1AA]'
                }`}
              >
                <div className="flex items-center gap-2.5">
                  <input
                    id="vaultx-burn"
                    type="checkbox"
                    checked={isBurnAfterReading}
                    onChange={(e) => handleBurnToggle(e.target.checked)}
                    disabled={isBusy}
                    className="burn-checkbox h-4 w-4 rounded border-white/20 bg-[#050508] accent-red-500"
                  />
                  <label htmlFor="vaultx-burn" className="inline-flex cursor-pointer items-center gap-1.5 text-xs font-medium">
                    <Flame className={`h-3.5 w-3.5 ${isBurnAfterReading ? 'text-red-400' : 'text-[#71717A]'}`} />
                    <span>Burn After Reading (1 View)</span>
                  </label>
                </div>
                {isBurnAfterReading && (
                  <span className="rounded border border-red-500/40 bg-red-500/15 px-2 py-0.5 font-mono text-[10px] font-semibold uppercase tracking-wider text-red-400">
                    Self-Destruct Armed
                  </span>
                )}
              </div>

              {/* Password Protection — Tactical Crimson Red Accent when active */}
              <div
                className={`space-y-2.5 rounded-lg border px-3 py-2.5 transition-colors sm:col-span-2 ${
                  isPasswordProtected
                    ? 'border-red-500/40 bg-red-500/10 text-red-400'
                    : 'border-white/10 bg-[#0B0C10] text-[#A1A1AA]'
                }`}
              >
                <div className="flex items-center justify-between gap-2.5">
                  <div className="flex items-center gap-2.5">
                    <input
                      id="vaultx-password-toggle"
                      type="checkbox"
                      checked={isPasswordProtected}
                      onChange={(e) => setIsPasswordProtected(e.target.checked)}
                      disabled={isBusy}
                      className="password-toggle h-4 w-4 rounded border-white/20 bg-[#050508] accent-red-500"
                    />
                    <label htmlFor="vaultx-password-toggle" className="inline-flex cursor-pointer items-center gap-1.5 text-xs font-medium">
                      <Lock className={`h-3.5 w-3.5 ${isPasswordProtected ? 'text-red-400' : 'text-[#71717A]'}`} />
                      <span>Require Additional Password (PBKDF2 key wrapping)</span>
                    </label>
                  </div>
                  {isPasswordProtected && (
                    <span className="rounded border border-red-500/40 bg-red-500/15 px-2 py-0.5 font-mono text-[10px] font-semibold uppercase tracking-wider text-red-400">
                      Locked
                    </span>
                  )}
                </div>

                {isPasswordProtected && (
                  <input
                    type="password"
                    value={password}
                    onChange={(e) => setPassword(e.target.value)}
                    disabled={isBusy}
                    placeholder="Enter link protection password..."
                    aria-label="Vault protection password"
                    className="password-input w-full rounded-md border border-red-500/30 bg-[#050508] px-3 py-1.5 font-mono text-sm text-[#FAFAFA] placeholder-[#71717A] focus:border-red-500 focus:outline-none"
                  />
                )}
              </div>
            </div>

            {/* Error Display */}
            {error && (
              <div className="error-banner flex items-start gap-2 rounded-lg border border-red-500/40 bg-red-500/10 p-3 text-xs text-red-400">
                <AlertCircle className="mt-0.5 h-4 w-4 shrink-0" />
                <span>{error}</span>
              </div>
            )}

            {/* Dynamic Action Button — Solid Deep Violet (#7C3AED) */}
            <div className="flex items-center gap-3">
              <button
                type="submit"
                disabled={isSubmitDisabled}
                className="btn-upload inline-flex flex-1 items-center justify-center gap-2 rounded-lg bg-[#7C3AED] px-5 py-3 font-mono text-sm font-semibold tracking-wide text-white shadow-lg shadow-violet-600/25 transition-all hover:bg-[#6D28D9] disabled:cursor-not-allowed disabled:opacity-40 disabled:shadow-none"
              >
                <Lock className="h-4 w-4" />
                <span>{getActionLabel()}</span>
              </button>

              {(status === 'success' || status === 'error') && (
                <button
                  type="button"
                  onClick={handleReset}
                  className="btn-reset inline-flex items-center gap-1.5 rounded-lg border border-white/10 bg-white/5 px-4 py-3 font-mono text-xs font-semibold text-zinc-200 hover:bg-white/10"
                >
                  <RotateCcw className="h-4 w-4" />
                  <span>Reset</span>
                </button>
              )}
            </div>
          </form>

          {/* Share Output Section */}
          {status === 'success' && result && (
            <div className="share-output hud-well mt-5 space-y-4 rounded-xl border border-emerald-500/35 p-4">
              <div className="flex items-center justify-between border-b border-white/10 pb-2.5">
                <h3 className="font-mono text-sm font-bold text-emerald-400">
                  Vault Ready &amp; Encrypted
                </h3>
                <span className="font-mono text-xs text-[#71717A]">ID: {result.fileId}</span>
              </div>

              {/* Shareable Link */}
              <div>
                <label className="mb-1.5 block font-mono text-xs font-medium text-[#71717A]">
                  Shareable Zero-Knowledge Link
                </label>
                <div className="flex flex-wrap gap-2">
                  <input
                    type="text"
                    readOnly
                    value={result.fullShareUrl}
                    aria-label="Shareable link"
                    className="share-url-input min-w-0 flex-1 rounded-md border border-white/10 bg-[#0B0C10] px-3 py-1.5 font-mono text-xs text-zinc-200 select-all"
                  />
                  <button
                    type="button"
                    onClick={() => handleCopyText(result.fullShareUrl, setCopiedLink)}
                    className="btn-copy-link inline-flex items-center gap-1.5 rounded-md bg-[#7C3AED] px-3 py-1.5 font-mono text-xs font-semibold text-white hover:bg-[#6D28D9]"
                  >
                    {copiedLink ? <Check className="h-3.5 w-3.5" /> : <Copy className="h-3.5 w-3.5" />}
                    <span>{copiedLink ? 'Copied' : 'Copy'}</span>
                  </button>
                  <button
                    type="button"
                    onClick={() => setIsQrOpen(true)}
                    className="btn-open-qr inline-flex items-center gap-1.5 rounded-md border border-white/10 bg-white/5 px-3 py-1.5 font-mono text-xs font-medium text-zinc-200 hover:bg-white/10"
                  >
                    <QrCode className="h-3.5 w-3.5" />
                    <span>QR Code</span>
                  </button>
                </div>
              </div>

              {/* Owner Revocation Token Banner */}
              <div className="owner-token-banner rounded-lg border border-red-500/30 bg-red-500/5 p-3">
                <div className="flex items-start gap-2.5">
                  <ShieldAlert className="mt-0.5 h-4 w-4 shrink-0 text-red-400" />
                  <div className="min-w-0 flex-1">
                    <p className="font-mono text-xs font-bold text-[#FAFAFA]">Owner Revocation Token</p>
                    <p className="mt-0.5 text-xs text-[#A1A1AA]">
                      Save this token to audit access or destroy the vault early from the{' '}
                      <Link href="/dashboard" className="text-zinc-200 underline hover:text-white">
                        Sender Dashboard
                      </Link>
                      .
                    </p>
                    <div className="mt-2 flex items-center gap-2">
                      <code className="flex-1 truncate rounded border border-white/10 bg-[#050508] px-2.5 py-1 font-mono text-xs text-zinc-200 select-all">
                        {result.ownerToken}
                      </code>
                      <button
                        type="button"
                        onClick={() => handleCopyText(result.ownerToken, setCopiedToken)}
                        className="btn-copy-token inline-flex items-center gap-1 rounded border border-white/10 bg-white/5 px-2.5 py-1 font-mono text-xs font-medium text-zinc-200 hover:bg-white/10"
                      >
                        {copiedToken ? <Check className="h-3.5 w-3.5" /> : <Copy className="h-3.5 w-3.5" />}
                        <span>{copiedToken ? 'Copied' : 'Copy'}</span>
                      </button>
                    </div>
                  </div>
                </div>
              </div>

              {result.sha256Checksum && (
                <p className="truncate font-mono text-[11px] text-[#71717A]">
                  Plaintext SHA-256: {result.sha256Checksum}
                </p>
              )}
            </div>
          )}
        </div>
      </TerminalWindow>

      <QRModal
        isOpen={isQrOpen}
        onClose={() => setIsQrOpen(false)}
        shareUrl={result?.fullShareUrl || ''}
      />
    </section>
  );
}

export default UploadCard;
