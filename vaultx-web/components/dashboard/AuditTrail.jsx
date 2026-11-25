'use client';

import React, { useState, useEffect, useCallback, useMemo } from 'react';
import {
  RefreshCw,
  Activity,
  AlertCircle,
  Search,
  Filter,
  Eye,
  Download,
  ShieldAlert,
  KeyRound,
  Plus,
  ChevronDown,
} from 'lucide-react';
import { getAccessLogs } from '../../lib/api.js';

// ─── Event badge config ────────────────────────────────────────────
// Maps each event type to a colour scheme and icon for quick visual scanning.
const EVENT_CONFIG = {
  CREATED:          { color: 'text-emerald-400 bg-emerald-500/10 border-emerald-500/30', icon: Plus },
  VIEWED_META:      { color: 'text-blue-400 bg-blue-500/10 border-blue-500/30',         icon: Eye },
  DOWNLOAD:         { color: 'text-violet-400 bg-violet-500/10 border-violet-500/30',   icon: Download },
  REVOKED:          { color: 'text-red-400 bg-red-500/10 border-red-500/30',             icon: ShieldAlert },
  BURNED:           { color: 'text-orange-400 bg-orange-500/10 border-orange-500/30',    icon: ShieldAlert },
  PASSWORD_ATTEMPT: { color: 'text-amber-400 bg-amber-500/10 border-amber-500/30',      icon: KeyRound },
};

const DEFAULT_EVENT = { color: 'text-zinc-400 bg-white/5 border-white/10', icon: Activity };

// ─── Status dot ────────────────────────────────────────────────────
function StatusDot({ status }) {
  const isSuccess = status === 'success';
  return (
    <span
      className={`inline-block h-2 w-2 rounded-full ${
        isSuccess ? 'bg-emerald-400 shadow-[0_0_6px_rgba(52,211,153,0.5)]' : 'bg-red-400 shadow-[0_0_6px_rgba(248,113,113,0.5)]'
      }`}
      title={isSuccess ? 'Allowed' : 'Denied'}
    />
  );
}

// ─── Loading skeleton row ──────────────────────────────────────────
function SkeletonRow() {
  return (
    <tr className="animate-pulse">
      {[...Array(6)].map((_, i) => (
        <td key={i} className="py-2.5 pr-3">
          <div className="h-3 w-full rounded bg-white/[0.06]" />
        </td>
      ))}
    </tr>
  );
}

/**
 * AuditTrail — Enhanced Version
 * ─────────────────────────────
 * Person 4 dashboard component: displays access logs for a vault item with:
 *   • Search bar to filter by any visible field
 *   • Event-type dropdown filter
 *   • Colour-coded event badges with icons
 *   • Status indicator (success/denied)
 *   • Remaining-views column
 *   • Browser info column
 *   • Loading skeletons
 *   • Auto-refresh toggle (30 s interval)
 *   • Error banner with retry
 *
 * Props:
 *   fileId       — Vault ID to fetch logs for
 *   ownerToken   — Authentication token for the owner
 *   logs         — Optional initial logs array (bypasses fetch)
 */
export function AuditTrail({ fileId, ownerToken, logs: initialLogs = null }) {
  // ── State ──────────────────────────────────────────────────────
  const [logs, setLogs] = useState(Array.isArray(initialLogs) ? initialLogs : []);
  const [loading, setLoading] = useState(false);
  const [error, setError] = useState(null);
  const [searchQuery, setSearchQuery] = useState('');
  const [eventFilter, setEventFilter] = useState('ALL');
  const [autoRefresh, setAutoRefresh] = useState(false);
  const [filterOpen, setFilterOpen] = useState(false);

  // ── Fetch logs from API ────────────────────────────────────────
  const fetchLogs = useCallback(async () => {
    if (!fileId || !ownerToken) return;
    setLoading(true);
    setError(null);
    try {
      const res = await getAccessLogs(fileId, ownerToken);
      if (res && res.success && Array.isArray(res.logs)) {
        setLogs(res.logs);
      } else {
        setError(res?.message || 'Failed to retrieve access logs');
      }
    } catch (err) {
      setError(err.message || 'Failed to retrieve access logs');
    } finally {
      setLoading(false);
    }
  }, [fileId, ownerToken]);

  // ── Initial load ───────────────────────────────────────────────
  useEffect(() => {
    if (Array.isArray(initialLogs)) {
      setLogs(initialLogs);
      return;
    }
    if (fileId && ownerToken) {
      fetchLogs();
    }
  }, [fileId, ownerToken, initialLogs, fetchLogs]);

  // ── Auto-refresh interval (every 30 s) ────────────────────────
  useEffect(() => {
    if (!autoRefresh || !fileId || !ownerToken) return;
    const interval = setInterval(fetchLogs, 30000);
    return () => clearInterval(interval);
  }, [autoRefresh, fileId, ownerToken, fetchLogs]);

  // ── Unique event types for the filter dropdown ─────────────────
  const eventTypes = useMemo(() => {
    const types = new Set(logs.map((l) => l.event || 'UNKNOWN'));
    return ['ALL', ...Array.from(types)];
  }, [logs]);

  // ── Filtered + searched logs ───────────────────────────────────
  const filteredLogs = useMemo(() => {
    let result = logs;

    // Apply event-type filter
    if (eventFilter !== 'ALL') {
      result = result.filter((l) => (l.event || 'UNKNOWN') === eventFilter);
    }

    // Apply search query across all visible fields
    if (searchQuery.trim()) {
      const q = searchQuery.toLowerCase();
      result = result.filter((l) => {
        const timestamp = l.timestamp ? new Date(l.timestamp).toLocaleString() : '';
        const fields = [
          timestamp,
          l.event,
          l.ipHash,
          l.browser,
          l.status,
          l.remainingViews?.toString(),
        ];
        return fields.some((f) => f && f.toLowerCase().includes(q));
      });
    }

    return result;
  }, [logs, eventFilter, searchQuery]);

  // ── Render ─────────────────────────────────────────────────────
  return (
    <div className="audit-trail hud-glass rounded-xl border border-white/10 p-4">
      {/* ─── Header ─────────────────────────────────────────────── */}
      <div className="mb-3 flex items-center justify-between border-b border-white/10 pb-2.5">
        <div className="flex items-center gap-2">
          <Activity className="h-4 w-4 text-[#A1A1AA]" />
          <h4 className="font-mono text-sm font-semibold text-[#FAFAFA]">
            Access Audit Trail
          </h4>
          <span className="rounded-full bg-white/5 px-2 py-0.5 font-mono text-[10px] text-[#71717A]">
            {filteredLogs.length}{filteredLogs.length !== logs.length ? ` / ${logs.length}` : ''} events
          </span>
        </div>

        <div className="flex items-center gap-2">
          {/* Auto-refresh toggle */}
          {fileId && ownerToken && (
            <button
              type="button"
              onClick={() => setAutoRefresh((v) => !v)}
              className={`inline-flex items-center gap-1 rounded border px-2 py-1 font-mono text-[10px] font-medium transition-colors ${
                autoRefresh
                  ? 'border-emerald-500/40 bg-emerald-500/10 text-emerald-400'
                  : 'border-white/10 bg-white/5 text-zinc-400 hover:bg-white/10'
              }`}
              title={autoRefresh ? 'Auto-refresh ON (30s)' : 'Enable auto-refresh'}
            >
              <span className={`inline-block h-1.5 w-1.5 rounded-full ${autoRefresh ? 'bg-emerald-400 animate-pulse' : 'bg-zinc-500'}`} />
              <span>Auto</span>
            </button>
          )}

          {/* Refresh button */}
          {fileId && ownerToken && (
            <button
              type="button"
              onClick={fetchLogs}
              disabled={loading}
              className="btn-refresh-logs inline-flex items-center gap-1 rounded border border-white/10 bg-white/5 px-2.5 py-1 font-mono text-xs font-medium text-zinc-200 hover:bg-white/10 disabled:opacity-50"
            >
              <RefreshCw className={`h-3 w-3 ${loading ? 'animate-spin' : ''}`} />
              <span>Refresh</span>
            </button>
          )}
        </div>
      </div>

      {/* ─── Search & Filter Bar ────────────────────────────────── */}
      <div className="mb-3 flex flex-wrap items-center gap-2">
        {/* Search input */}
        <div className="relative flex-1 min-w-[180px]">
          <Search className="absolute left-2.5 top-1/2 h-3 w-3 -translate-y-1/2 text-[#71717A]" />
          <input
            type="text"
            value={searchQuery}
            onChange={(e) => setSearchQuery(e.target.value)}
            placeholder="Search logs..."
            className="w-full rounded border border-white/10 bg-[#07080B] py-1.5 pl-8 pr-3 font-mono text-xs text-[#FAFAFA] placeholder-[#71717A] outline-none focus:border-[#7C3AED]/50 focus:ring-1 focus:ring-[#7C3AED]/30"
          />
        </div>

        {/* Event filter dropdown */}
        <div className="relative">
          <button
            type="button"
            onClick={() => setFilterOpen((v) => !v)}
            className="inline-flex items-center gap-1.5 rounded border border-white/10 bg-[#07080B] px-3 py-1.5 font-mono text-xs text-zinc-200 hover:border-white/20"
          >
            <Filter className="h-3 w-3 text-[#71717A]" />
            <span>{eventFilter === 'ALL' ? 'All Events' : eventFilter}</span>
            <ChevronDown className="h-3 w-3 text-[#71717A]" />
          </button>

          {filterOpen && (
            <div className="absolute right-0 top-full z-20 mt-1 min-w-[150px] rounded-lg border border-white/10 bg-[#0B0C10] p-1 shadow-xl">
              {eventTypes.map((type) => (
                <button
                  key={type}
                  type="button"
                  onClick={() => { setEventFilter(type); setFilterOpen(false); }}
                  className={`block w-full rounded px-3 py-1.5 text-left font-mono text-xs transition-colors ${
                    eventFilter === type
                      ? 'bg-[#7C3AED]/20 text-[#FAFAFA]'
                      : 'text-zinc-400 hover:bg-white/5 hover:text-zinc-200'
                  }`}
                >
                  {type === 'ALL' ? 'All Events' : type}
                </button>
              ))}
            </div>
          )}
        </div>
      </div>

      {/* ─── Error banner ───────────────────────────────────────── */}
      {error && (
        <div className="mb-3 flex items-center gap-2 rounded-lg border border-red-500/40 bg-red-500/10 p-2.5 text-xs text-red-400">
          <AlertCircle className="h-4 w-4 shrink-0" />
          <span className="flex-1">{error}</span>
          <button
            type="button"
            onClick={fetchLogs}
            className="shrink-0 rounded border border-red-500/40 bg-red-500/10 px-2 py-0.5 font-mono text-[10px] font-medium text-red-300 hover:bg-red-500/20"
          >
            Retry
          </button>
        </div>
      )}

      {/* ─── Table ──────────────────────────────────────────────── */}
      {loading && logs.length === 0 ? (
        /* Loading skeleton when no data yet */
        <div className="hud-well overflow-x-auto rounded-lg border border-white/10 p-2">
          <table className="w-full border-collapse text-left text-xs">
            <thead>
              <tr className="border-b border-white/10 font-mono text-[11px] text-[#71717A]">
                <th className="py-2 pr-3 font-medium">Timestamp</th>
                <th className="py-2 pr-3 font-medium">Event</th>
                <th className="py-2 pr-3 font-medium">Status</th>
                <th className="py-2 pr-3 font-medium">IP Hash</th>
                <th className="py-2 pr-3 font-medium">Browser</th>
                <th className="py-2 font-medium">Views Left</th>
              </tr>
            </thead>
            <tbody>
              {[...Array(4)].map((_, i) => (
                <SkeletonRow key={i} />
              ))}
            </tbody>
          </table>
        </div>
      ) : filteredLogs.length === 0 ? (
        <p className="hud-well rounded-lg border border-white/10 py-5 text-center font-mono text-xs text-[#71717A]">
          {logs.length === 0
            ? 'No audit events recorded for this vault.'
            : 'No logs match your current filters.'}
        </p>
      ) : (
        <div className="hud-well overflow-x-auto rounded-lg border border-white/10 p-2">
          <table className="w-full border-collapse text-left text-xs">
            <thead>
              <tr className="border-b border-white/10 font-mono text-[11px] text-[#71717A]">
                <th className="py-2 pr-3 font-medium">Timestamp</th>
                <th className="py-2 pr-3 font-medium">Event</th>
                <th className="py-2 pr-3 font-medium">Status</th>
                <th className="py-2 pr-3 font-medium">IP Hash</th>
                <th className="py-2 pr-3 font-medium">Browser</th>
                <th className="py-2 font-medium">Views Left</th>
              </tr>
            </thead>
            <tbody className="divide-y divide-white/[0.06] font-mono">
              {filteredLogs.map((entry, idx) => {
                const cfg = EVENT_CONFIG[entry.event] || DEFAULT_EVENT;
                const Icon = cfg.icon;
                return (
                  <tr key={`${entry.timestamp}-${idx}`} className="text-zinc-200 hover:bg-white/[0.02] transition-colors">
                    {/* Timestamp */}
                    <td className="py-2.5 pr-3 whitespace-nowrap text-[#A1A1AA]">
                      {entry.timestamp ? new Date(entry.timestamp).toLocaleString() : '-'}
                    </td>

                    {/* Event badge */}
                    <td className="py-2.5 pr-3">
                      <span className={`inline-flex items-center gap-1 rounded border px-1.5 py-0.5 text-[11px] font-semibold ${cfg.color}`}>
                        <Icon className="h-3 w-3" />
                        {entry.event || 'UNKNOWN'}
                      </span>
                    </td>

                    {/* Status */}
                    <td className="py-2.5 pr-3">
                      <div className="flex items-center gap-1.5">
                        <StatusDot status={entry.status} />
                        <span className="text-[11px] text-[#A1A1AA] capitalize">
                          {entry.status || '-'}
                        </span>
                      </div>
                    </td>

                    {/* IP Hash (anonymized) */}
                    <td
                      className="py-2.5 pr-3 max-w-[140px] truncate text-[#71717A]"
                      title={entry.ipHash}
                    >
                      {entry.ipHash
                        ? `${entry.ipHash.substring(0, 8)}…`
                        : '-'}
                    </td>

                    {/* Browser */}
                    <td className="py-2.5 pr-3 whitespace-nowrap text-[#A1A1AA]">
                      {entry.browser || '-'}
                    </td>

                    {/* Remaining views */}
                    <td className="py-2.5 font-semibold">
                      {entry.remainingViews != null ? (
                        <span className={entry.remainingViews <= 1 ? 'text-amber-400' : 'text-zinc-200'}>
                          {entry.remainingViews}
                        </span>
                      ) : (
                        <span className="text-[#71717A]">-</span>
                      )}
                    </td>
                  </tr>
                );
              })}
            </tbody>
          </table>
        </div>
      )}
    </div>
  );
}

export default AuditTrail;
