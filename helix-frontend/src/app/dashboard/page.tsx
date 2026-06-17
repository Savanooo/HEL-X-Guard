"use client";
import { useEffect, useState, useCallback } from "react";
import Link from "next/link";
import { listScans, deleteScan, type Scan, type ScanList } from "@/lib/api";
import RiskBadge from "@/components/RiskBadge";
import StatusBadge from "@/components/StatusBadge";
import Spinner from "@/components/Spinner";

function fmtDate(iso: string) {
  return new Date(iso).toLocaleString("en-GB", {
    day: "2-digit", month: "short", year: "numeric",
    hour: "2-digit", minute: "2-digit",
  });
}

function fmtSize(bytes: number | null) {
  if (bytes == null) return "—";
  if (bytes < 1024) return `${bytes} B`;
  if (bytes < 1_048_576) return `${(bytes / 1024).toFixed(1)} KB`;
  return `${(bytes / 1_048_576).toFixed(1)} MB`;
}

interface Stats { total: number; critical: number; high: number; medium: number; low: number; }

function StatCard({ label, value, color }: { label: string; value: number; color: string }) {
  return (
    <div className={`rounded-xl px-5 py-4 border ${color}`} style={{ background: "#161b27" }}>
      <p className="text-2xl font-bold text-white">{value}</p>
      <p className="text-xs text-slate-500 mt-0.5 font-medium uppercase tracking-wide">{label}</p>
    </div>
  );
}

export default function DashboardPage() {
  const [data, setData] = useState<ScanList | null>(null);
  const [stats, setStats] = useState<Stats | null>(null);
  const [loading, setLoading] = useState(true);
  const [page, setPage] = useState(1);
  const [riskFilter, setRiskFilter] = useState("");
  const [statusFilter, setStatusFilter] = useState("");
  const [deletingId, setDeletingId] = useState<string | null>(null);

  const load = useCallback(() => {
    setLoading(true);
    listScans(page, 20, riskFilter || undefined, statusFilter || undefined)
      .then(setData)
      .catch(console.error)
      .finally(() => setLoading(false));
  }, [page, riskFilter, statusFilter]);

  useEffect(() => { load(); }, [load]);

  // Load summary stats once on mount
  useEffect(() => {
    Promise.all([
      listScans(1, 1),
      listScans(1, 1, "critical"),
      listScans(1, 1, "high"),
      listScans(1, 1, "medium"),
      listScans(1, 1, "low"),
    ]).then(([all, crit, high, med, low]) => {
      setStats({
        total: all.total,
        critical: crit.total,
        high: high.total,
        medium: med.total,
        low: low.total,
      });
    }).catch(() => {});
  }, []);

  async function handleDelete(scan: Scan) {
    if (!confirm(`Delete scan for "${scan.filename}"?`)) return;
    setDeletingId(scan.id);
    try {
      await deleteScan(scan.id);
      load();
    } catch (e) {
      alert(e instanceof Error ? e.message : "Delete failed");
    } finally {
      setDeletingId(null);
    }
  }

  return (
    <div className="space-y-6">
      {/* Header */}
      <div className="flex items-center justify-between mb-6">
        <div>
          <h1 className="text-xl font-bold text-white">Scan History</h1>
          {data && (
            <p className="text-slate-500 text-sm mt-0.5">{data.total} total scans</p>
          )}
        </div>
        <Link
          href="/dashboard/upload"
          className="inline-flex items-center gap-1.5 bg-blue-600 hover:bg-blue-500 text-white text-sm font-semibold px-4 py-2 rounded-lg transition-colors"
        >
          <span className="text-base leading-none">+</span> New Scan
        </Link>
      </div>

      {/* Stats Cards */}
      {stats && (
        <div className="grid grid-cols-2 sm:grid-cols-4 gap-3 mb-6">
          <StatCard label="Total Scans" value={stats.total} color="border-slate-700/60" />
          <StatCard label="Critical + High" value={stats.critical + stats.high} color="border-red-700/50" />
          <StatCard label="Medium" value={stats.medium} color="border-yellow-700/50" />
          <StatCard label="Low / Info" value={stats.low} color="border-green-800/50" />
        </div>
      )}

      {/* Filters */}
      <div className="flex flex-wrap gap-2 mb-4">
        <select
          value={riskFilter}
          onChange={(e) => { setRiskFilter(e.target.value); setPage(1); }}
          className="border border-slate-700 bg-slate-900/60 rounded-lg px-3 py-1.5 text-sm text-slate-300 focus:outline-none focus:ring-2 focus:ring-blue-500"
        >
          <option value="">All Risk Levels</option>
          <option value="critical">Critical</option>
          <option value="high">High</option>
          <option value="medium">Medium</option>
          <option value="low">Low</option>
          <option value="informational">Informational</option>
        </select>
        <select
          value={statusFilter}
          onChange={(e) => { setStatusFilter(e.target.value); setPage(1); }}
          className="border border-slate-700 bg-slate-900/60 rounded-lg px-3 py-1.5 text-sm text-slate-300 focus:outline-none focus:ring-2 focus:ring-blue-500"
        >
          <option value="">All Statuses</option>
          <option value="pending">Pending</option>
          <option value="running">Running</option>
          <option value="completed">Completed</option>
          <option value="failed">Failed</option>
        </select>
        <button
          onClick={load}
          className="border border-slate-700 bg-slate-800 hover:bg-slate-700 text-slate-400 text-sm px-3 py-1.5 rounded-lg transition-colors"
        >
          ↻ Refresh
        </button>
      </div>

      {/* Content */}
      {loading ? (
        <div className="flex justify-center py-20 text-slate-500">
          <Spinner size={28} />
        </div>
      ) : data?.items.length === 0 ? (
        <div className="text-center py-20 text-slate-500">
          <p className="text-4xl mb-3">🛡</p>
          <p className="text-lg font-medium text-slate-400">No scans yet</p>
          <p className="text-sm mt-1">Upload a firmware file to run your first analysis</p>
          <Link
            href="/dashboard/upload"
            className="inline-block mt-4 bg-blue-600 hover:bg-blue-500 text-white text-sm font-semibold px-5 py-2 rounded-lg transition-colors"
          >
            Upload Firmware
          </Link>
        </div>
      ) : (
        <>
          <div className="border border-slate-700/60 rounded-xl overflow-hidden" style={{ background: "#161b27" }}>
            <table className="w-full text-sm">
              <thead className="border-b border-slate-700/60" style={{ background: "#0d1117" }}>
                <tr>
                  <th className="text-left px-5 py-3 font-semibold text-slate-500 text-xs uppercase tracking-wide">File</th>
                  <th className="text-left px-5 py-3 font-semibold text-slate-500 text-xs uppercase tracking-wide">Size</th>
                  <th className="text-left px-5 py-3 font-semibold text-slate-500 text-xs uppercase tracking-wide">Risk</th>
                  <th className="text-left px-5 py-3 font-semibold text-slate-500 text-xs uppercase tracking-wide">Status</th>
                  <th className="text-left px-5 py-3 font-semibold text-slate-500 text-xs uppercase tracking-wide">Date</th>
                  <th className="px-5 py-3"></th>
                </tr>
              </thead>
              <tbody className="divide-y divide-slate-700/40">
                {data!.items.map((scan) => (
                  <tr key={scan.id} className="hover:bg-slate-800/40 transition-colors">
                    <td className="px-5 py-3.5">
                      <Link
                        href={`/dashboard/${scan.id}`}
                        className="font-medium text-blue-400 hover:text-blue-300 block truncate max-w-[240px]"
                      >
                        {scan.filename}
                      </Link>
                      {scan.sha256 && (
                        <p className="text-xs text-slate-600 font-mono mt-0.5">
                          {scan.sha256.slice(0, 16)}…
                        </p>
                      )}
                    </td>
                    <td className="px-5 py-3.5 text-slate-400">{fmtSize(scan.file_size)}</td>
                    <td className="px-5 py-3.5">
                      {scan.risk_level ? (
                        <RiskBadge level={scan.risk_level} score={scan.risk_score} />
                      ) : (
                        <span className="text-slate-600">—</span>
                      )}
                    </td>
                    <td className="px-5 py-3.5">
                      <StatusBadge status={scan.status} />
                    </td>
                    <td className="px-5 py-3.5 text-slate-500 whitespace-nowrap text-xs">
                      {fmtDate(scan.created_at)}
                    </td>
                    <td className="px-5 py-3.5">
                      <div className="flex items-center justify-end gap-3">
                        <Link
                          href={`/dashboard/${scan.id}`}
                          className="text-xs text-blue-400 hover:text-blue-300 font-medium"
                        >
                          View →
                        </Link>
                        <button
                          onClick={() => handleDelete(scan)}
                          disabled={deletingId === scan.id || scan.status === "running"}
                          className="text-xs text-slate-600 hover:text-red-400 disabled:opacity-30 transition-colors"
                          title="Delete scan"
                        >
                          {deletingId === scan.id ? <Spinner size={12} /> : "✕"}
                        </button>
                      </div>
                    </td>
                  </tr>
                ))}
              </tbody>
            </table>
          </div>

          {/* Pagination */}
          {data!.total > 20 && (
            <div className="flex items-center justify-between mt-4 text-sm text-slate-500">
              <span>
                Showing {(page - 1) * 20 + 1}–{Math.min(page * 20, data!.total)} of{" "}
                {data!.total}
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
                  disabled={page * 20 >= data!.total}
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
