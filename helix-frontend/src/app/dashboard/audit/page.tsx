"use client";
import { useEffect, useState, useCallback } from "react";
import { listAuditLog, type AuditLogList } from "@/lib/api";
import Spinner from "@/components/Spinner";

function fmtDate(iso: string) {
  return new Date(iso).toLocaleString("en-GB", {
    day: "2-digit", month: "short", year: "numeric",
    hour: "2-digit", minute: "2-digit", second: "2-digit",
  });
}

const actionLabels: Record<string, string> = {
  login:             "Login",
  create_user:       "Create User",
  create_scan:       "Create Scan",
  view_scan:         "View Scan",
  view_report:       "View Report",
  delete_scan:       "Delete Scan",
  trigger_extract:   "Trigger Extract",
  trigger_decompile: "Trigger Decompile",
};

export default function AuditPage() {
  const [data, setData] = useState<AuditLogList | null>(null);
  const [page, setPage] = useState(1);
  const [actionFilter, setActionFilter] = useState("");
  const [usernameFilter, setUsernameFilter] = useState("");
  const [loading, setLoading] = useState(true);

  const load = useCallback(() => {
    setLoading(true);
    listAuditLog(page, 50, actionFilter || undefined, usernameFilter || undefined)
      .then(setData)
      .catch(console.error)
      .finally(() => setLoading(false));
  }, [page, actionFilter, usernameFilter]);

  useEffect(() => { load(); }, [load]);

  return (
    <div className="">
      <div className="flex items-center justify-between mb-6">
        <div>
          <h1 className="text-xl font-bold text-white">Audit Log</h1>
          {data && <p className="text-slate-500 text-sm mt-0.5">{data.total} entries</p>}
        </div>
        <button
          onClick={load}
          className="border border-slate-700 bg-slate-800 hover:bg-slate-700 text-slate-400 text-sm px-3 py-1.5 rounded-lg transition-colors"
        >
          ↻ Refresh
        </button>
      </div>

      <div className="flex flex-wrap gap-2 mb-4">
        <select
          value={actionFilter}
          onChange={(e) => { setActionFilter(e.target.value); setPage(1); }}
          className="border border-slate-700 bg-slate-900/60 rounded-lg px-3 py-1.5 text-sm text-slate-300 focus:outline-none focus:ring-2 focus:ring-blue-500"
        >
          <option value="">All Actions</option>
          {Object.entries(actionLabels).map(([value, label]) => (
            <option key={value} value={value}>{label}</option>
          ))}
        </select>
        <input
          value={usernameFilter}
          onChange={(e) => { setUsernameFilter(e.target.value); setPage(1); }}
          placeholder="Filter by username…"
          className="border border-slate-700 bg-slate-900/60 rounded-lg px-3 py-1.5 text-sm text-slate-300 placeholder:text-slate-600 focus:outline-none focus:ring-2 focus:ring-blue-500"
        />
      </div>

      {loading ? (
        <div className="flex justify-center py-16"><Spinner size={24} /></div>
      ) : data?.items.length === 0 ? (
        <p className="text-slate-500 text-center py-16">No audit entries match the current filters.</p>
      ) : (
        <>
          <div className="border border-slate-700/60 rounded-xl overflow-hidden" style={{ background: "#161b27" }}>
            <table className="w-full text-sm">
              <thead className="border-b border-slate-700/60" style={{ background: "#0d1117" }}>
                <tr>
                  <th className="text-left px-4 py-3 font-semibold text-slate-500 text-xs uppercase tracking-wide">Time</th>
                  <th className="text-left px-4 py-3 font-semibold text-slate-500 text-xs uppercase tracking-wide">User</th>
                  <th className="text-left px-4 py-3 font-semibold text-slate-500 text-xs uppercase tracking-wide">Action</th>
                  <th className="text-left px-4 py-3 font-semibold text-slate-500 text-xs uppercase tracking-wide">Resource</th>
                  <th className="text-left px-4 py-3 font-semibold text-slate-500 text-xs uppercase tracking-wide">Result</th>
                  <th className="text-left px-4 py-3 font-semibold text-slate-500 text-xs uppercase tracking-wide">IP</th>
                </tr>
              </thead>
              <tbody className="divide-y divide-slate-700/40">
                {data!.items.map((entry) => (
                  <tr key={entry.id} className="hover:bg-slate-800/40 transition-colors">
                    <td className="px-4 py-2.5 text-slate-500 text-xs whitespace-nowrap">{fmtDate(entry.created_at)}</td>
                    <td className="px-4 py-2.5 font-medium text-slate-300">{entry.username ?? "—"}</td>
                    <td className="px-4 py-2.5 text-slate-300">{actionLabels[entry.action] ?? entry.action}</td>
                    <td className="px-4 py-2.5 text-slate-500 text-xs font-mono">
                      {entry.resource_id ? `${entry.resource_type ?? ""} ${entry.resource_id.slice(0, 8)}…` : "—"}
                    </td>
                    <td className="px-4 py-2.5">
                      {entry.success ? (
                        <span className="text-emerald-400 text-xs font-semibold">✓ Success</span>
                      ) : (
                        <span className="text-red-400 text-xs font-semibold" title={entry.detail ?? ""}>✕ Failed</span>
                      )}
                      {entry.detail && !entry.success && (
                        <p className="text-xs text-slate-500 mt-0.5">{entry.detail}</p>
                      )}
                    </td>
                    <td className="px-4 py-2.5 text-slate-500 text-xs font-mono">{entry.ip_address ?? "—"}</td>
                  </tr>
                ))}
              </tbody>
            </table>
          </div>

          {data!.total > 50 && (
            <div className="flex items-center justify-between mt-4 text-sm text-slate-500">
              <span>
                Showing {(page - 1) * 50 + 1}–{Math.min(page * 50, data!.total)} of {data!.total}
              </span>
              <div className="flex gap-2">
                <button
                  onClick={() => setPage((p) => Math.max(1, p - 1))}
                  disabled={page === 1}
                  className="px-3 py-1.5 border border-slate-700 bg-slate-800 hover:bg-slate-700 rounded-lg disabled:opacity-40 transition-colors text-slate-400"
                >
                  ← Prev
                </button>
                <button
                  onClick={() => setPage((p) => p + 1)}
                  disabled={page * 50 >= data!.total}
                  className="px-3 py-1.5 border border-slate-700 bg-slate-800 hover:bg-slate-700 rounded-lg disabled:opacity-40 transition-colors text-slate-400"
                >
                  Next →
                </button>
              </div>
            </div>
          )}
        </>
      )}
    </div>
  );
}
