'use client';

import React, { useState, useEffect } from 'react';
import Link from 'next/link';
import { Shield, Key, LayoutDashboard } from 'lucide-react';
import { UploadCard } from '../components/UploadCard.jsx';
import { KeySetupModal } from '../components/KeySetupModal.jsx';

/**
 * HomePage (/)
 * Sleek Obsidian Black, Deep Violet, and Tactical Crimson Red VaultX upload view.
 */
export default function HomePage() {
  const [isKeyModalOpen, setIsKeyModalOpen] = useState(false);
  const [activeKeyInfo, setActiveKeyInfo] = useState(null);

  useEffect(() => {
    if (typeof window !== 'undefined' && window.localStorage) {
      try {
        const savedUser = window.localStorage.getItem('vaultx_active_username');
        if (savedUser) {
          setActiveKeyInfo({ username: savedUser });
        }
      } catch (_) {}
    }
  }, []);

  return (
    <div className="relative min-h-screen text-[#FAFAFA]">
      <header className="sticky top-0 z-30 border-b border-white/10 bg-[#050508]/85 backdrop-blur-xl">
        <div className="mx-auto flex max-w-5xl items-center justify-between gap-4 px-4 py-3">
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
              onClick={() => setIsKeyModalOpen(true)}
              className="btn-open-key-setup inline-flex items-center gap-1.5 rounded-md border border-white/10 bg-white/5 px-3 py-1.5 text-xs font-medium text-zinc-200 transition-colors hover:border-white/20 hover:bg-white/10"
            >
              <Key className="h-3.5 w-3.5 text-[#A1A1AA]" />
              <span>
                {activeKeyInfo?.username ? `ID: ${activeKeyInfo.username}` : 'Key Setup'}
              </span>
            </button>

            <Link
              href="/dashboard"
              className="nav-dashboard-link inline-flex items-center gap-1.5 rounded-md border border-white/10 bg-white/5 px-3 py-1.5 text-xs font-medium text-zinc-200 transition-colors hover:border-white/20 hover:bg-white/10"
            >
              <LayoutDashboard className="h-3.5 w-3.5 text-[#A1A1AA]" />
              <span>Dashboard</span>
            </Link>
          </nav>
        </div>
      </header>

      <main className="relative z-10 mx-auto max-w-3xl px-4 pt-8 pb-6">
        <div className="mb-5 text-center">
          <h1 className="text-2xl font-bold tracking-tight text-[#FAFAFA] sm:text-3xl">
            Zero-Knowledge File &amp; Secret Sharing
          </h1>
          <p className="mt-1.5 text-sm text-[#A1A1AA]">
            Client-side AES-256-GCM encryption in your browser. Keys stay in URL{' '}
            <code className="rounded border border-white/10 bg-white/5 px-1.5 py-0.5 font-mono text-xs text-zinc-200">
              #fragments
            </code>{' '}
            or RSA-OAEP wraps.
          </p>
        </div>

        <div className="relative">
          <div className="animate-float-slow pointer-events-none absolute -left-52 top-10 hidden w-44 rounded-xl border border-white/10 bg-[#0B0C10]/90 p-3.5 backdrop-blur-xl shadow-[0_20px_50px_rgba(0,0,0,0.85),inset_0_1px_0_rgba(255,255,255,0.06)] xl:block">
            <div className="mb-2 flex items-center justify-between border-b border-white/10 pb-1.5 font-mono text-[10px] text-[#71717A]">
              <span>CLIENT_ISOLATION</span>
              <span className="h-1.5 w-1.5 rounded-full bg-[#7C3AED]" />
            </div>
            <div className="space-y-1 font-mono text-[11px]">
              <div className="flex justify-between">
                <span className="text-[#71717A]">SERVER_BLIND:</span>
                <span className="text-[#FAFAFA]">TRUE</span>
              </div>
              <div className="flex justify-between">
                <span className="text-[#71717A]">IV_NONCE:</span>
                <span className="text-[#A1A1AA]">12-BYTE</span>
              </div>
              <div className="flex justify-between">
                <span className="text-[#71717A]">KEY_EXIT:</span>
                <span className="text-red-400">BLOCKED</span>
              </div>
            </div>
          </div>

          <div
            className="animate-float-slow pointer-events-none absolute -right-52 bottom-12 hidden w-44 rounded-xl border border-white/10 bg-[#0B0C10]/90 p-3.5 backdrop-blur-xl shadow-[0_20px_50px_rgba(0,0,0,0.85),inset_0_1px_0_rgba(255,255,255,0.06)] xl:block"
            style={{ animationDelay: '-2.8s' }}
          >
            <div className="mb-2 flex items-center justify-between border-b border-white/10 pb-1.5 font-mono text-[10px] text-[#71717A]">
              <span>CRYPTO_TELEMETRY</span>
              <span className="h-1.5 w-1.5 rounded-full bg-[#EF4444]" />
            </div>
            <div className="space-y-1 font-mono text-[11px]">
              <div className="flex justify-between">
                <span className="text-[#71717A]">CIPHER:</span>
                <span className="text-[#FAFAFA]">AES-256</span>
              </div>
              <div className="flex justify-between">
                <span className="text-[#71717A]">DIGEST:</span>
                <span className="text-[#A1A1AA]">SHA-256</span>
              </div>
              <div className="flex justify-between">
                <span className="text-[#71717A]">LEAKS:</span>
                <span className="text-[#FAFAFA]">0</span>
              </div>
            </div>
          </div>

          <UploadCard />
        </div>
      </main>

      <KeySetupModal
        isOpen={isKeyModalOpen}
        onClose={() => setIsKeyModalOpen(false)}
        initialUsername={activeKeyInfo?.username || ''}
        onKeyGenerated={(info) => setActiveKeyInfo(info)}
      />
    </div>
  );
}
