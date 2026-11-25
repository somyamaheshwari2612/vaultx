'use client';

import React, { useState, useEffect, useCallback } from 'react';
import { RefreshCw, Activity, AlertCircle } from 'lucide-react';
import { getAccessLogs } from '../../lib/api.js';

/**
 * AuditTrail
 * Person 4 dashboard slot: matte charcoal (#0B0C10) table with razor-thin border-white/10.
 */
export function AuditTrail({ fileId, ownerToken, logs: initialLogs = null }) {
  const [logs, setLogs] = useState(Array.isArray(initialLogs) ? initialLogs : []);
  const [loading, setLoading] = useState(false);
  const [error, setError] = useState(null);

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

  useEffect(() => {
    if (Array.isArray(initialLogs)) {
      setLogs(initialLogs);
      return;
    }
    if (fileId && ownerToken) {
      fetchLogs();
    }
  }, [fileId, ownerToken, initialLogs, fetchLogs]);

  return (
    <div className="audit-trail hud-glass rounded-xl border border-white/10 p-4">
      <div className="mb-3 flex items-center justify-between border-b border-white/10 pb-2.5">
        <div className="flex items-center gap-2">
          <Activity className="h-4 w-4 text-[#A1A1AA]" />
          <h4 className="font-mono text-sm font-semibold text-[#FAFAFA]">Access Audit Trail</h4>
        </div>
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

      {error && (
        <div className="mb-3 flex items-center gap-2 rounded-lg border border-red-500/40 bg-red-500/10 p-2.5 text-xs text-red-400">
          <AlertCircle className="h-4 w-4 shrink-0" />
          <span>{error}</span>
        </div>
      )}

      {logs.length === 0 ? (
        <p className="hud-well rounded-lg border border-white/10 py-5 text-center font-mono text-xs text-[#71717A]">
          {loading ? 'Loading audit logs...' : 'No audit events recorded for this vault.'}
        </p>
      ) : (
        <div className="hud-well overflow-x-auto rounded-lg border border-white/10 p-2">
          <table className="w-full border-collapse text-left text-xs">
            <thead>
              <tr className="border-b border-white/10 font-mono text-[11px] text-[#71717A]">
                <th className="py-2 pr-3 font-medium">Timestamp</th>
                <th className="py-2 pr-3 font-medium">Event</th>
                <th className="py-2 font-medium">IP Hash</th>
              </tr>
            </thead>
            <tbody className="divide-y divide-white/[0.06] font-mono">
              {logs.map((entry, idx) => (
                <tr key={`${entry.timestamp}-${idx}`} className="text-zinc-200">
                  <td className="py-2 pr-3 whitespace-nowrap text-[#A1A1AA]">
                    {entry.timestamp ? new Date(entry.timestamp).toLocaleString() : '-'}
                  </td>
                  <td className="py-2 pr-3">
                    <span className="inline-block rounded border border-white/10 bg-white/5 px-1.5 py-0.5 text-[11px] font-semibold text-zinc-200">
                      {entry.event || 'UNKNOWN'}
                    </span>
                  </td>
                  <td className="py-2 truncate max-w-[180px] text-[#71717A]" title={entry.ipHash}>
                    {entry.ipHash || '-'}
                  </td>
                </tr>
              ))}
            </tbody>
          </table>
        </div>
      )}
    </div>
  );
}

export default AuditTrail;
