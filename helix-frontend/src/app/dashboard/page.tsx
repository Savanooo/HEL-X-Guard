"use client";
import { useEffect, useState, useCallback } from "react";
import Link from "next/link";
import { Shield, RefreshCw, Plus, ChevronLeft, ChevronRight } from "lucide-react";
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

function StatCard({
  label, value, borderColor, valueColor,
}: { label: string; value: number; borderColor: string; valueColor?: string }) {
  return (
    <div
      className={`rounded-xl px-5 py-4 border shadow-card ${borderColor}`}
      style={{ background: "#121826" }}
    >
      <p className={`text-2xl font-bold ${valueColor ?? "text-white"}`}>{value}</p>
      <p className="text-[11px] text-slate-500 mt-1 font-semibold uppercase tracking-[0.08em]">{label}</p>
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

  useEffect(() => {
    Promise.all([
      listScans(1, 1),
      listScans(1, 1, "critical"),
      listScans(1, 1, "high"),
      listScans(1, 1, "medium"),
      listScans(1, 1, "low"),
    ]).then(([all, crit, high, med, low]) => {
      setStats({ total: all.total, critical: crit.total, high: high.total, medium: med.total, low: low.total });
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

  const selectCls = "border border-[#1f2840] bg-[#0b0f1a] rounded-lg px-3 py-1.5 text-sm text-slate-300 focus:outline-none focus:ring-2 focus:ring-brand-500/40 transition-colors";

  return (
    <div className="space-y-6">
      {/* Header */}
      <div className="flex items-center justify-between">
        <div>
          <h1 className="text-[15px] font-semibold text-slate-100">Scan History</h1>
          {data && (
            <p className="text-slate-500 text-xs mt-0.5">{data.total} total scans</p>
          )}
        </div>
        <Link
          href="/dashboard/upload"
          className="inline-flex items-center gap-1.5 bg-brand-600 hover:bg-brand-500 text-white text-sm font-semibold px-4 py-2 rounded-lg transition-colors"
        >
          <Plus size={14} strokeWidth={2.5} />
          New Scan
        </Link>
      </div>

      {/* Stats Cards */}
      {stats && (
        <div className="grid grid-cols-2 sm:grid-cols-4 gap-3">
          <StatCard label="Total Scans"    value={stats.total}                  borderColor="border-[#1f2840]" />
          <StatCard label="Critical / High" value={stats.critical + stats.high} borderColor="border-red-500/30"    valueColor="text-red-400" />
          <StatCard label="Medium"          value={stats.medium}                borderColor="border-amber-500/30"  valueColor="text-amber-400" />
          <StatCard label="Low / Info"      value={stats.low}                   borderColor="border-slate-600/40" />
        </div>
      )}

      {/* Filters */}
      <div className="flex flex-wrap gap-2">
        <select value={riskFilter} onChange={(e) => { setRiskFilter(e.target.value); setPage(1); }} className={selectCls}>
          <option value="">All Risk Levels</option>
          <option value="critical">Critical</option>
          <option value="high">High</option>
          <option value="medium">Medium</option>
          <option value="low">Low</option>
          <option value="informational">Informational</option>
        </select>
        <select value={statusFilter} onChange={(e) => { setStatusFilter(e.target.value); setPage(1); }} className={selectCls}>
          <option value="">All Statuses</option>
          <option value="pending">Pending</option>
          <option value="running">Running</option>
          <option value="completed">Completed</option>
          <option value="failed">Failed</option>
        </select>
        <button
          onClick={load}
          className="inline-flex items-center gap-1.5 border border-[#1f2840] bg-[#121826] hover:bg-[#161d2e] hover:border-[#2d3a54] text-slate-400 text-sm px-3 py-1.5 rounded-lg transition-colors"
        >
          <RefreshCw size={13} />
          Refresh
        </button>
      </div>

      {/* Content */}
      {loading ? (
        <div className="flex justify-center py-20 text-slate-500">
          <Spinner size={28} />
        </div>
      ) : data?.items.length === 0 ? (
        <div className="text-center py-20 text-slate-500">
          <Shield size={40} className="mx-auto mb-3 text-slate-700" strokeWidth={1} />
          <p className="text-[15px] font-semibold text-slate-400">No scans yet</p>
          <p className="text-sm mt-1">Upload a firmware file to run your first analysis</p>
          <Link
            href="/dashboard/upload"
            className="inline-flex items-center gap-1.5 mt-4 bg-brand-600 hover:bg-brand-500 text-white text-sm font-semibold px-5 py-2 rounded-lg transition-colors"
          >
            <Plus size={14} strokeWidth={2.5} />
            Upload Firmware
          </Link>
        </div>
      ) : (
        <>
          <div className="border border-[#1f2840] rounded-xl overflow-hidden shadow-card" style={{ background: "#121826" }}>
            <table className="w-full text-sm">
              <thead className="border-b border-[#1f2840]" style={{ background: "#0b0f1a" }}>
                <tr>
                  <th className="text-left px-5 py-3 font-semibold text-slate-500 text-[10px] uppercase tracking-[0.08em]">File</th>
                  <th className="text-left px-5 py-3 font-semibold text-slate-500 text-[10px] uppercase tracking-[0.08em]">Size</th>
                  <th className="text-left px-5 py-3 font-semibold text-slate-500 text-[10px] uppercase tracking-[0.08em]">Risk</th>
                  <th className="text-left px-5 py-3 font-semibold text-slate-500 text-[10px] uppercase tracking-[0.08em]">Status</th>
                  <th className="text-left px-5 py-3 font-semibold text-slate-500 text-[10px] uppercase tracking-[0.08em]">Date</th>
                  <th className="px-5 py-3" />
                </tr>
              </thead>
              <tbody className="divide-y divide-[#1f2840]">
                {data!.items.map((scan) => (
                  <tr key={scan.id} className="hover:bg-[#161d2e] transition-colors">
                    <td className="px-5 py-3.5">
                      <Link
                        href={`/dashboard/${scan.id}`}
                        className="font-medium text-brand-400 hover:text-brand-300 block truncate max-w-[240px] transition-colors"
                      >
                        {scan.filename}
                      </Link>
                      {scan.sha256 && (
                        <p className="text-[11px] text-slate-600 font-mono mt-0.5 tracking-tight">
                          {scan.sha256.slice(0, 16)}…
                        </p>
                      )}
                    </td>
                    <td className="px-5 py-3.5 text-slate-400 text-[13px]">{fmtSize(scan.file_size)}</td>
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
                    <td className="px-5 py-3.5 text-slate-500 whitespace-nowrap text-[11px] font-mono">
                      {fmtDate(scan.created_at)}
                    </td>
                    <td className="px-5 py-3.5">
                      <div className="flex items-center justify-end gap-3">
                        <Link
                          href={`/dashboard/${scan.id}`}
                          className="text-xs text-brand-400 hover:text-brand-300 font-medium transition-colors"
                        >
                          View →
                        </Link>
                        <button
                          onClick={() => handleDelete(scan)}
                          disabled={deletingId === scan.id || scan.status === "running"}
                          className="text-xs text-slate-600 hover:text-red-400 disabled:opacity-30 transition-colors"
                          title="Delete scan"
                        >
                          {deletingId === scan.id ? <Spinner size={12} /> : "×"}
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
            <div className="flex items-center justify-between text-sm text-slate-500">
              <span className="text-xs">
                {(page - 1) * 20 + 1}–{Math.min(page * 20, data!.total)} of {data!.total}
              </span>
              <div className="flex gap-2">
                <button
                  onClick={() => setPage((p) => Math.max(1, p - 1))}
                  disabled={page === 1}
                  className="inline-flex items-center gap-1 px-3 py-1.5 border border-[#1f2840] bg-[#121826] hover:bg-[#161d2e] rounded-lg disabled:opacity-40 transition-colors text-slate-400 text-xs"
                >
                  <ChevronLeft size={13} /> Prev
                </button>
                <button
                  onClick={() => setPage((p) => p + 1)}
                  disabled={page * 20 >= data!.total}
                  className="inline-flex items-center gap-1 px-3 py-1.5 border border-[#1f2840] bg-[#121826] hover:bg-[#161d2e] rounded-lg disabled:opacity-40 transition-colors text-slate-400 text-xs"
                >
                  Next <ChevronRight size={13} />
                </button>
              </div>
            </div>
          )}
        </>
      )}
    </div>
  );
}
