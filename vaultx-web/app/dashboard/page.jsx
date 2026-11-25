'use client';

import React, { useState, useEffect, useCallback } from 'react';
import Link from 'next/link';
import { Shield, Plus, ExternalLink, RefreshCw, Inbox } from 'lucide-react';
import { AuditTrail } from '../../components/dashboard/AuditTrail.jsx';
import { HexInspector } from '../../components/dashboard/HexInspector.jsx';
import { RevokeButton } from '../../components/dashboard/RevokeButton.jsx';
import { TerminalWindow } from '../../components/TerminalWindow.jsx';
import { getMetadata } from '../../lib/api.js';

/**
 * DashboardPage (/dashboard)
 * Sender dashboard reading sent vaults from localStorage ('vaultx_sent_vaults')
 * and hosting Person 4 components: <AuditTrail />, <HexInspector />, and <RevokeButton />.
 */
export default function DashboardPage() {
  const [sentVaults, setSentVaults] = useState([]);
  const [selectedId, setSelectedId] = useState(null);
  const [inspectedMetaB64, setInspectedMetaB64] = useState('');
  const [inspectStatus, setInspectStatus] = useState('');

  const loadVaults = useCallback(() => {
    if (typeof window === 'undefined' || !window.localStorage) return;
    try {
      const raw = window.localStorage.getItem('vaultx_sent_vaults');
      const list = raw ? JSON.parse(raw) : [];
      const normalized = Array.isArray(list) ? list : [];
      setSentVaults(normalized);
      if (normalized.length > 0 && !selectedId) {
        setSelectedId(normalized[0].fileId || normalized[0].id);
      }
    } catch (_) {
      setSentVaults([]);
    }
  }, [selectedId]);

  useEffect(() => {
    loadVaults();
  }, [loadVaults]);

  const selectedVault =
    sentVaults.find((v) => (v.fileId || v.id) === selectedId) || sentVaults[0] || null;
  const activeFileId = selectedVault?.fileId || selectedVault?.id || null;

  useEffect(() => {
    let cancelled = false;
    async function loadCipherMeta() {
      if (!activeFileId) {
        setInspectedMetaB64('');
        setInspectStatus('');
        return;
      }
      setInspectStatus('Fetching encrypted metadata header...');
      try {
        const meta = await getMetadata(activeFileId);
        if (!cancelled && meta?.encryptedMetaB64) {
          setInspectedMetaB64(meta.encryptedMetaB64);
          setInspectStatus('Encrypted metadata header loaded (0 downloads consumed)');
        }
      } catch (err) {
        if (!cancelled) {
          setInspectedMetaB64('');
          setInspectStatus(err.message || 'Vault unavailable or expired/revoked');
        }
      }
    }
    loadCipherMeta();
    return () => {
      cancelled = true;
    };
  }, [activeFileId]);

  const handleRevoked = (fileId) => {
    setSentVaults((prev) => {
      const updated = prev.map((item) =>
        (item.fileId || item.id) === fileId ? { ...item, revoked: true } : item
      );
      if (typeof window !== 'undefined' && window.localStorage) {
        try {
          window.localStorage.setItem('vaultx_sent_vaults', JSON.stringify(updated));
        } catch (_) {}
      }
      return updated;
    });
    setInspectedMetaB64('');
    setInspectStatus('Vault has been revoked by owner');
  };

  return (
    <div className="relative min-h-screen text-[#FAFAFA]">
      <header className="sticky top-0 z-30 border-b border-white/10 bg-[#050508]/85 backdrop-blur-xl">
        <div className="mx-auto flex max-w-5xl flex-wrap items-center justify-between gap-4 px-4 py-3">
          <Link href="/" className="group flex items-center gap-2.5">
            <div className="flex h-8 w-8 items-center justify-center rounded-lg border border-red-500/40 bg-red-500/10 transition-colors group-hover:border-red-500/60">
              <Shield className="h-4 w-4 text-[#EF4444]" />
            </div>
            <span className="text-base font-bold tracking-tight text-[#FAFAFA]">
              VAULTX
            </span>
          </Link>

          <nav className="flex items-center gap-2">
            <button
              type="button"
              onClick={loadVaults}
              className="inline-flex items-center gap-1.5 rounded-md border border-white/10 bg-white/5 px-3 py-1.5 font-mono text-xs font-medium text-zinc-200 transition-colors hover:border-white/20 hover:bg-white/10"
            >
              <RefreshCw className="h-3.5 w-3.5 text-[#A1A1AA]" />
              <span>Refresh</span>
            </button>

            <Link
              href="/"
              className="inline-flex items-center gap-1.5 rounded-md bg-[#7C3AED] px-3.5 py-1.5 font-mono text-xs font-semibold text-white shadow-lg shadow-violet-600/25 transition-colors hover:bg-[#6D28D9]"
            >
              <Plus className="h-3.5 w-3.5" />
              <span>New Vault</span>
            </Link>
          </nav>
        </div>
      </header>

      <main className="relative z-10 mx-auto max-w-5xl px-4 py-8">
        <div className="mb-6">
          <h2 className="text-2xl font-bold tracking-tight text-[#FAFAFA]">Sent Vaults</h2>
          <p className="mt-1 text-sm text-[#A1A1AA]">
            Locally tracked uploads from this browser. Inspect access logs, raw ciphertext headers, or trigger instant kill-switch revocation.
          </p>
        </div>

        {sentVaults.length === 0 ? (
          <TerminalWindow>
            <div className="p-10 text-center">
              <div className="mx-auto mb-3 flex h-12 w-12 items-center justify-center rounded-xl border border-white/10 bg-[#07080B]">
                <Inbox className="h-6 w-6 text-[#A1A1AA]" />
              </div>
              <h3 className="font-mono text-sm font-semibold text-[#FAFAFA]">No Sent Vaults Found</h3>
              <p className="mt-1 text-xs text-[#71717A]">
                Encrypt and upload a file or secret note to track it here.
              </p>
              <Link
                href="/"
                className="mt-5 inline-flex items-center gap-1.5 rounded-md bg-[#7C3AED] px-4 py-2 font-mono text-xs font-semibold text-white shadow-lg shadow-violet-600/25 hover:bg-[#6D28D9]"
              >
                <Plus className="h-3.5 w-3.5" />
                <span>Create First Vault</span>
              </Link>
            </div>
          </TerminalWindow>
        ) : (
          <div className="grid grid-cols-1 gap-6 lg:grid-cols-12">
            {/* Sent Vaults List */}
            <aside className="lg:col-span-5 space-y-3">
              {sentVaults.map((item) => {
                const itemId = item.fileId || item.id;
                const isSelected = itemId === activeFileId;
                return (
                  <div
                    key={itemId}
                    onClick={() => setSelectedId(itemId)}
                    className={`vault-list-item cursor-pointer rounded-xl border p-4 transition-colors ${
                      isSelected
                        ? 'hud-glass border-[#7C3AED]'
                        : 'hud-glass border-white/10 hover:border-white/20'
                    }`}
                  >
                    <div className="flex items-start justify-between gap-2">
                      <div className="min-w-0">
                        <p className="truncate text-sm font-semibold text-[#FAFAFA]">
                          {item.filename || 'Encrypted Payload'}
                        </p>
                        <p className="mt-0.5 font-mono text-[11px] text-[#71717A]">
                          ID: {itemId} &bull; {item.mode || 'MODE_B'}
                        </p>
                      </div>
                      {item.revoked && (
                        <span className="rounded border border-red-500/40 bg-red-500/10 px-2 py-0.5 font-mono text-[10px] font-bold text-red-400">
                          REVOKED
                        </span>
                      )}
                    </div>

                    <div className="mt-3 flex flex-wrap items-center justify-between gap-2 border-t border-white/10 pt-2.5">
                      <Link
                        href={`/v/${itemId}`}
                        onClick={(e) => e.stopPropagation()}
                        className="inline-flex items-center gap-1 font-mono text-xs font-medium text-[#A1A1AA] hover:text-[#FAFAFA] hover:underline"
                      >
                        <span>Open Route</span>
                        <ExternalLink className="h-3 w-3" />
                      </Link>

                      <div onClick={(e) => e.stopPropagation()}>
                        <RevokeButton
                          fileId={itemId}
                          ownerToken={item.ownerToken}
                          isRevoked={Boolean(item.revoked)}
                          onRevoked={() => handleRevoked(itemId)}
                        />
                      </div>
                    </div>
                  </div>
                );
              })}
            </aside>

            {/* Detail Inspector Slots (AuditTrail + HexInspector) */}
            <section className="lg:col-span-7 space-y-5">
              {selectedVault && (
                <>
                  <div className="hud-glass rounded-xl border border-white/10 p-4">
                    <div className="flex flex-wrap items-center justify-between gap-2">
                      <div>
                        <h3 className="text-sm font-semibold text-[#FAFAFA]">
                          {selectedVault.filename || 'Selected Vault'}
                        </h3>
                        <p className="font-mono text-xs text-[#71717A]">
                          Created:{' '}
                          {selectedVault.createdAt
                            ? new Date(selectedVault.createdAt).toLocaleString()
                            : '-'}
                        </p>
                      </div>
                      <RevokeButton
                        key={`revoke-${activeFileId}`}
                        fileId={activeFileId}
                        ownerToken={selectedVault.ownerToken}
                        isRevoked={Boolean(selectedVault.revoked)}
                        onRevoked={() => handleRevoked(activeFileId)}
                      />
                    </div>
                  </div>

                  <AuditTrail
                    key={`audit-${activeFileId}`}
                    fileId={activeFileId}
                    ownerToken={selectedVault.ownerToken}
                  />

                  <div className="space-y-2">
                    <HexInspector
                      fileId={activeFileId}
                      encryptedBlobB64={inspectedMetaB64}
                      label="Encrypted Metadata Header (Hex/ASCII)"
                    />
                    {inspectStatus && (
                      <p className="font-mono text-[11px] text-[#71717A]">{inspectStatus}</p>
                    )}
                  </div>
                </>
              )}
            </section>
          </div>
        )}
      </main>
    </div>
  );
}
