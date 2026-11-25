'use client';

import React, { useState, useEffect } from 'react';
import Link from 'next/link';
import { useParams } from 'next/navigation';
import { Shield, ArrowLeft, LayoutDashboard } from 'lucide-react';
import { DecryptView } from '../../../components/DecryptView.jsx';

/**
 * RecipientDecryptPage (/v/[id])
 * Client component dynamic route resolving the vault ID parameter safely
 * and mounting <DecryptView fileId={id} />.
 */
export default function RecipientDecryptPage({ params }) {
  const routeParams = useParams();
  const [resolvedId, setResolvedId] = useState(() => {
    if (params && typeof params.then !== 'function' && params.id) {
      return Array.isArray(params.id) ? params.id[0] : params.id;
    }
    if (routeParams?.id) {
      return Array.isArray(routeParams.id) ? routeParams.id[0] : routeParams.id;
    }
    return '';
  });

  useEffect(() => {
    let cancelled = false;
    if (params && typeof params.then === 'function') {
      params.then((p) => {
        if (!cancelled && p?.id) {
          setResolvedId(Array.isArray(p.id) ? p.id[0] : p.id);
        }
      });
    } else if (routeParams?.id && !resolvedId) {
      setResolvedId(Array.isArray(routeParams.id) ? routeParams.id[0] : routeParams.id);
    }
    return () => {
      cancelled = true;
    };
  }, [params, routeParams, resolvedId]);

  const fileId =
    resolvedId ||
    (routeParams?.id ? (Array.isArray(routeParams.id) ? routeParams.id[0] : routeParams.id) : '');

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
            <Link
              href="/"
              className="inline-flex items-center gap-1.5 rounded-md border border-white/10 bg-white/5 px-3 py-1.5 font-mono text-xs font-medium text-zinc-200 transition-colors hover:border-white/20 hover:bg-white/10"
            >
              <ArrowLeft className="h-3.5 w-3.5 text-[#A1A1AA]" />
              <span>New Upload</span>
            </Link>
            <Link
              href="/dashboard"
              className="inline-flex items-center gap-1.5 rounded-md border border-white/10 bg-white/5 px-3 py-1.5 font-mono text-xs font-medium text-zinc-200 transition-colors hover:border-white/20 hover:bg-white/10"
            >
              <LayoutDashboard className="h-3.5 w-3.5 text-[#A1A1AA]" />
              <span>Dashboard</span>
            </Link>
          </nav>
        </div>
      </header>

      <main className="relative z-10 mx-auto max-w-4xl px-4 py-8">
        {fileId ? (
          <DecryptView fileId={fileId} />
        ) : (
          <div className="hud-glass rounded-xl border border-white/10 p-6 font-mono text-sm text-[#A1A1AA]">
            Resolving vault identifier...
          </div>
        )}
      </main>
    </div>
  );
}
