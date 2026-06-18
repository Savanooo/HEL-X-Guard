"use client";
import React, { useEffect, useState, useCallback } from "react";
import { useRouter, useSearchParams } from "next/navigation";
import Link from "next/link";
import { GitCompare } from "lucide-react";
import {
  listScans, diffScans,
  type Scan, type ScanDiff, type ScanList,
} from "@/lib/api";
import RiskBadge from "@/components/RiskBadge";
import Spinner from "@/components/Spinner";

// ── Helpers ───────────────────────────────────────────────────────────────────

function fmtSize(bytes: number | null) {
  if (bytes == null) return "—";
  if (Math.abs(bytes) < 1024) return `${bytes} B`;
  if (Math.abs(bytes) < 1_048_576) return `${(bytes / 1024).toFixed(1)} KB`;
  return `${(bytes / 1_048_576).toFixed(2)} MB`;
}

function fmtDate(iso: string) {
  return new Date(iso).toLocaleString("en-GB", {
    day: "2-digit", month: "short", year: "numeric", hour: "2-digit", minute: "2-digit",
  });
}

function Delta({ value, unit = "", invert = false }: { value: number; unit?: string; invert?: boolean }) {
  const bad  = invert ? value < 0 : value > 0;
  const good = invert ? value > 0 : value < 0;
  const cls  = value === 0 ? "text-slate-500" : bad ? "text-red-400" : good ? "text-emerald-400" : "text-slate-400";
  return <span className={`font-mono font-semibold ${cls}`}>{value > 0 ? "+" : ""}{value}{unit}</span>;
}

function ScanSelector({
  label, value, onChange, scans, loading, exclude,
}: {
  label: string; value: string; onChange: (v: string) => void;
  scans: Scan[]; loading: boolean; exclude?: string;
}) {
  return (
    <div className="flex-1">
      <p className="text-[10px] font-semibold text-slate-500 uppercase tracking-[0.08em] mb-1.5">{label}</p>
      <select
        value={value}
        onChange={e => onChange(e.target.value)}
        className="w-full border border-[#1f2840] bg-[#0b0f1a] text-slate-200 rounded-lg px-3 py-2.5 text-sm focus:outline-none focus:ring-2 focus:ring-brand-500/40 transition-colors"
        disabled={loading}
      >
        <option value="">— select scan —</option>
        {scans
          .filter(s => s.status === "completed" && s.id !== exclude)
          .map(s => (
            <option key={s.id} value={s.id}>
              {s.filename} · {s.risk_level?.toUpperCase() ?? "?"} · {fmtDate(s.created_at)}
            </option>
          ))}
      </select>
    </div>
  );
}

// ── Category + severity badges ─────────────────────────────────────────────────

const catBg: Record<string, string> = {
  SAFETY_BYPASS: "bg-red-500/15 text-red-300 border-red-500/30",
  CREDENTIAL:    "bg-orange-500/15 text-orange-300 border-orange-500/30",
  PRIVATE_KEY:   "bg-red-500/15 text-red-300 border-red-500/30",
  API_KEY:       "bg-orange-500/15 text-orange-300 border-orange-500/30",
  FLASH_WRITE:   "bg-orange-500/15 text-orange-300 border-orange-500/30",
  SHELL_COMMAND: "bg-amber-500/15 text-amber-300 border-amber-500/30",
  DEBUG_KEYWORD: "bg-amber-500/15 text-amber-300 border-amber-500/30",
  CRYPTO:        "bg-amber-500/15 text-amber-300 border-amber-500/30",
  URL:           "bg-slate-500/15 text-slate-400 border-slate-500/30",
  IP:            "bg-slate-500/15 text-slate-400 border-slate-500/30",
  DOMAIN:        "bg-slate-500/15 text-slate-400 border-slate-500/30",
  VERSION:       "bg-slate-600/15 text-slate-500 border-slate-600/30",
};

function CatBadge({ cat }: { cat: string }) {
  const cls = catBg[cat] ?? "bg-slate-600/15 text-slate-400 border-slate-600/30";
  return (
    <span className={`inline-block rounded border px-2 py-0.5 text-[10px] font-semibold uppercase tracking-wide ${cls}`}>
      {cat.replace(/_/g, " ")}
    </span>
  );
}

function SevBadge({ sev }: { sev?: string }) {
  const s = (sev ?? "low").toLowerCase();
  const cls =
    s === "critical" ? "text-red-300 bg-red-500/10 border-red-500/30" :
    s === "high"     ? "text-orange-300 bg-orange-500/10 border-orange-500/30" :
    s === "medium"   ? "text-amber-300 bg-amber-500/10 border-amber-500/30" :
                       "text-slate-400 bg-slate-500/10 border-slate-600/30";
  return (
    <span className={`inline-block rounded border px-2 py-0.5 text-[10px] font-semibold uppercase ${cls}`}>
      {s}
    </span>
  );
}

// ── Card shell ────────────────────────────────────────────────────────────────

function Card({ children, className = "" }: { children: React.ReactNode; className?: string; }) {
  return (
    <div
      className={`rounded-xl border border-[#1f2840] shadow-card ${className}`}
      style={{ background: "#121826" }}
    >
      {children}
    </div>
  );
}

// ── Page ─────────────────────────────────────────────────────────────────────

export default function DiffPage() {
  const router = useRouter();
  const params = useSearchParams();

  const [scanIdA, setScanIdA] = useState(params.get("a") ?? "");
  const [scanIdB, setScanIdB] = useState(params.get("b") ?? "");
  const [scans, setScans]     = useState<Scan[]>([]);
  const [loadingScans, setLoadingScans] = useState(true);
  const [diff, setDiff]       = useState<ScanDiff | null>(null);
  const [comparing, setComparing] = useState(false);
  const [error, setError]     = useState("");
  const [tab, setTab]         = useState<"strings" | "yara">("strings");
  const [strTab, setStrTab]   = useState<"added" | "removed">("added");

  useEffect(() => {
    (async () => {
      const pages: Scan[] = [];
      let page = 1;
      let total = Infinity;
      while (pages.length < total) {
        const res: ScanList = await listScans(page, 100, undefined, "completed");
        pages.push(...res.items);
        total = res.total;
        if (res.items.length < 100) break;
        page++;
      }
      setScans(pages);
      setLoadingScans(false);
    })().catch(() => setLoadingScans(false));
  }, []);

  useEffect(() => {
    if (params.get("a") && params.get("b")) compare();
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, []);

  const compare = useCallback(async () => {
    if (!scanIdA || !scanIdB) return;
    if (scanIdA === scanIdB) { setError("Select two different scans."); return; }
    setError(""); setDiff(null); setComparing(true);
    try {
      const result = await diffScans(scanIdA, scanIdB);
      setDiff(result);
      router.replace(`/dashboard/diff?a=${scanIdA}&b=${scanIdB}`, { scroll: false });
    } catch (e) {
      setError(e instanceof Error ? e.message : "Comparison failed");
    } finally {
      setComparing(false);
    }
  }, [scanIdA, scanIdB, router]);

  return (
    <div className="space-y-6">
      {/* Header */}
      <div>
        <h1 className="text-[15px] font-semibold text-slate-100">Firmware Compare</h1>
        <p className="text-slate-500 text-sm mt-0.5">
          Compare two completed scans — strings added/removed, new YARA matches, risk delta.
        </p>
      </div>

      {/* Selector card */}
      <Card className="p-5">
        <div className="flex items-end gap-4 flex-wrap">
          <ScanSelector label="Baseline (A)" value={scanIdA} onChange={setScanIdA} scans={scans} loading={loadingScans} exclude={scanIdB} />
          <div className="text-slate-600 text-lg font-bold pb-2.5 flex-shrink-0">vs</div>
          <ScanSelector label="Target (B)" value={scanIdB} onChange={setScanIdB} scans={scans} loading={loadingScans} exclude={scanIdA} />
          <button
            onClick={compare}
            disabled={!scanIdA || !scanIdB || comparing || scanIdA === scanIdB}
            className="flex items-center gap-2 bg-brand-600 hover:bg-brand-500 disabled:opacity-40 text-white font-semibold text-sm px-5 py-2.5 rounded-lg transition-colors flex-shrink-0"
          >
            {comparing ? <Spinner size={14} /> : <GitCompare size={14} strokeWidth={2} />}
            {comparing ? "Comparing…" : "Compare →"}
          </button>
        </div>
        {error && <p className="text-xs text-red-400 mt-3">{error}</p>}
      </Card>

      {/* Results */}
      {diff && (
        <>
          {/* Overview — two scan metas */}
          <div className="grid grid-cols-1 md:grid-cols-2 gap-4">
            {([
              { meta: diff.scan_a, scanLabel: "Baseline A" },
              { meta: diff.scan_b, scanLabel: "Target B" },
            ] as const).map(({ meta, scanLabel }) => (
              <Card key={meta.id} className="p-4">
                <div className="flex items-center justify-between mb-1">
                  <p className="text-[10px] font-semibold text-slate-500 uppercase tracking-[0.08em]">{scanLabel}</p>
                  <RiskBadge level={meta.risk_level ?? "informational"} score={meta.risk_score} />
                </div>
                <Link href={`/dashboard/${meta.id}`} className="font-semibold text-slate-200 hover:text-brand-400 transition-colors block truncate text-[13px]">
                  {meta.filename}
                </Link>
                <div className="grid grid-cols-3 gap-2 mt-3">
                  {([
                    ["Risk",    `${meta.risk_score ?? 0}/100`],
                    ["Entropy", (meta.entropy ?? 0).toFixed(2)],
                    ["Strings", meta.suspicious_count],
                  ] as [string, string | number][]).map(([k, v]) => (
                    <div key={k} className="text-center">
                      <p className="text-[10px] text-slate-600 uppercase tracking-wide">{k}</p>
                      <p className="text-[13px] font-bold text-slate-300 mt-0.5">{v}</p>
                    </div>
                  ))}
                </div>
              </Card>
            ))}
          </div>

          {/* Delta bar */}
          <Card className="px-6 py-4">
            <p className="text-[10px] font-semibold text-slate-500 uppercase tracking-[0.08em] mb-3">Changes (B vs A)</p>
            <div className="flex flex-wrap gap-8">
              {[
                { label: "Risk Score",       node: <Delta value={diff.summary.risk_delta} /> },
                { label: "Entropy",          node: <Delta value={diff.summary.entropy_delta} /> },
                ...(diff.summary.file_size_delta != null ? [{
                  label: "File Size",
                  node: <span className="font-mono font-semibold text-slate-400">{diff.summary.file_size_delta >= 0 ? "+" : ""}{fmtSize(diff.summary.file_size_delta)}</span>,
                }] : []),
                { label: "New Strings",      node: <Delta value={diff.summary.strings_added} /> },
                { label: "Removed Strings",  node: <Delta value={-diff.summary.strings_removed} invert /> },
                { label: "New YARA",         node: <Delta value={diff.summary.yara_new} /> },
                { label: "Resolved YARA",    node: <Delta value={-diff.summary.yara_resolved} invert /> },
              ].map(({ label, node }) => (
                <div key={label} className="text-center">
                  <p className="text-[10px] text-slate-600 uppercase tracking-wide mb-1">{label}</p>
                  {node}
                </div>
              ))}
            </div>
          </Card>

          {/* Findings tabs */}
          <Card>
            <div className="px-5 py-3 border-b border-[#1f2840]">
              <h2 className="font-semibold text-slate-300 text-[13px] tracking-tight">Detailed Changes</h2>
            </div>
            <div className="p-5">
              {/* Tab bar */}
              <div className="flex gap-1 mb-5 border-b border-[#1f2840]">
                {(
                  [
                    ["strings", "Strings", diff.summary.strings_added + diff.summary.strings_removed],
                    ["yara",    "YARA",    diff.summary.yara_new + diff.summary.yara_resolved],
                  ] as [typeof tab, string, number][]
                ).map(([t, label, count]) => (
                  <button
                    key={t}
                    onClick={() => setTab(t)}
                    className={`px-4 py-2 text-sm font-medium border-b-2 transition-colors ${
                      tab === t ? "border-brand-500 text-brand-400" : "border-transparent text-slate-500 hover:text-slate-300"
                    }`}
                  >
                    {label}
                    <span className={`ml-1.5 text-xs px-1.5 py-0.5 rounded font-semibold ${
                      tab === t ? "bg-brand-500/20 text-brand-400" : "bg-slate-800 text-slate-500"
                    }`}>{count}</span>
                  </button>
                ))}
              </div>

              {/* Strings tab */}
              {tab === "strings" && (
                <div>
                  <div className="flex gap-2 mb-4">
                    <button
                      onClick={() => setStrTab("added")}
                      className={`flex items-center gap-1.5 px-3 py-1.5 rounded-lg text-xs font-semibold transition-colors border ${
                        strTab === "added"
                          ? "border-red-500/40 bg-red-500/8 text-red-300"
                          : "border-[#1f2840] bg-[#121826] text-slate-500 hover:text-slate-300"
                      }`}
                    >
                      + {diff.summary.strings_added} Added
                    </button>
                    <button
                      onClick={() => setStrTab("removed")}
                      className={`flex items-center gap-1.5 px-3 py-1.5 rounded-lg text-xs font-semibold transition-colors border ${
                        strTab === "removed"
                          ? "border-emerald-600/40 bg-emerald-500/8 text-emerald-300"
                          : "border-[#1f2840] bg-[#121826] text-slate-500 hover:text-slate-300"
                      }`}
                    >
                      − {diff.summary.strings_removed} Removed
                    </button>
                  </div>

                  {strTab === "added" && (
                    diff.strings_added.length === 0 ? (
                      <p className="text-sm text-slate-500 text-center py-8">No new suspicious strings in B.</p>
                    ) : (
                      <div className="rounded-lg border border-[#1f2840] overflow-hidden">
                        <div className="max-h-[500px] overflow-y-auto divide-y divide-[#1f2840]">
                          {diff.strings_added.map((s, i) => (
                            <div key={i} className="flex items-center gap-3 px-3 py-2 bg-red-500/4 hover:bg-red-500/8 transition-colors">
                              <span className="w-1.5 h-1.5 rounded-full bg-red-500 flex-shrink-0" />
                              <span className="w-32 flex-shrink-0"><CatBadge cat={s.category} /></span>
                              <span className="font-mono text-xs text-slate-300 break-all flex-1">{s.value?.slice(0, 120)}</span>
                              <span className="text-[11px] text-slate-600 font-mono whitespace-nowrap">0x{(s.offset ?? 0).toString(16).padStart(6, "0")}</span>
                            </div>
                          ))}
                        </div>
                      </div>
                    )
                  )}

                  {strTab === "removed" && (
                    diff.strings_removed.length === 0 ? (
                      <p className="text-sm text-slate-500 text-center py-8">No strings removed between A and B.</p>
                    ) : (
                      <div className="rounded-lg border border-[#1f2840] overflow-hidden">
                        <div className="max-h-[500px] overflow-y-auto divide-y divide-[#1f2840]">
                          {diff.strings_removed.map((s, i) => (
                            <div key={i} className="flex items-center gap-3 px-3 py-2 bg-emerald-500/4 hover:bg-emerald-500/8 transition-colors">
                              <span className="w-1.5 h-1.5 rounded-full bg-emerald-500 flex-shrink-0" />
                              <span className="w-32 flex-shrink-0"><CatBadge cat={s.category} /></span>
                              <span className="font-mono text-xs text-slate-300 break-all flex-1">{s.value?.slice(0, 120)}</span>
                              <span className="text-[11px] text-slate-600 font-mono whitespace-nowrap">0x{(s.offset ?? 0).toString(16).padStart(6, "0")}</span>
                            </div>
                          ))}
                        </div>
                      </div>
                    )
                  )}
                </div>
              )}

              {/* YARA tab */}
              {tab === "yara" && (
                <div className="space-y-4">
                  {diff.yara_new.length > 0 && (
                    <div>
                      <p className="text-[10px] font-semibold text-red-400 uppercase tracking-[0.08em] mb-2">
                        + {diff.yara_new.length} New Match{diff.yara_new.length !== 1 ? "es" : ""} (appeared in B)
                      </p>
                      <div className="space-y-1.5">
                        {diff.yara_new.map((m, i) => (
                          <div key={i} className="flex items-center gap-3 px-4 py-2.5 rounded-lg border border-red-500/20 bg-red-500/5">
                            <span className="w-1.5 h-1.5 rounded-full bg-red-500 flex-shrink-0" />
                            <span className="font-medium text-slate-200 text-[13px] flex-1">{m.rule}</span>
                            <SevBadge sev={m.severity} />
                          </div>
                        ))}
                      </div>
                    </div>
                  )}
                  {diff.yara_resolved.length > 0 && (
                    <div>
                      <p className="text-[10px] font-semibold text-emerald-400 uppercase tracking-[0.08em] mb-2">
                        − {diff.yara_resolved.length} Resolved (was in A, gone in B)
                      </p>
                      <div className="space-y-1.5">
                        {diff.yara_resolved.map((m, i) => (
                          <div key={i} className="flex items-center gap-3 px-4 py-2.5 rounded-lg border border-emerald-600/20 bg-emerald-500/5">
                            <span className="w-1.5 h-1.5 rounded-full bg-emerald-500 flex-shrink-0" />
                            <span className="font-medium text-slate-200 text-[13px] flex-1">{m.rule}</span>
                            <SevBadge sev={m.severity} />
                          </div>
                        ))}
                      </div>
                    </div>
                  )}
                  {diff.yara_new.length === 0 && diff.yara_resolved.length === 0 && (
                    <p className="text-sm text-slate-500 text-center py-8">YARA matches identical between A and B.</p>
                  )}
                </div>
              )}
            </div>
          </Card>
        </>
      )}
    </div>
  );
}
