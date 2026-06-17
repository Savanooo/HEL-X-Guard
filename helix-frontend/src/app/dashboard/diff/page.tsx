"use client";
import { useEffect, useState, useCallback } from "react";
import { useRouter, useSearchParams } from "next/navigation";
import Link from "next/link";
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
  const bad = invert ? value < 0 : value > 0;
  const good = invert ? value > 0 : value < 0;
  const cls = value === 0 ? "text-slate-500" : bad ? "text-red-400" : good ? "text-emerald-400" : "text-slate-400";
  const prefix = value > 0 ? "+" : "";
  return <span className={`font-mono font-semibold ${cls}`}>{prefix}{value}{unit}</span>;
}

function ScanSelector({
  label, value, onChange, scans, loading, exclude,
}: {
  label: string;
  value: string;
  onChange: (v: string) => void;
  scans: Scan[];
  loading: boolean;
  exclude?: string;
}) {
  return (
    <div className="flex-1">
      <p className="text-xs font-semibold text-slate-500 uppercase tracking-wide mb-1.5">{label}</p>
      <select
        value={value}
        onChange={e => onChange(e.target.value)}
        className="w-full border border-slate-700 bg-slate-900/60 text-slate-200 rounded-lg px-3 py-2.5 text-sm focus:outline-none focus:ring-2 focus:ring-blue-500"
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

// ── Category badge (same palette as scan detail) ──────────────────────────────
const catColors: Record<string, string> = {
  SAFETY_BYPASS: "bg-red-500",
  CREDENTIAL:    "bg-orange-600",
  PRIVATE_KEY:   "bg-red-600",
  API_KEY:       "bg-orange-500",
  FLASH_WRITE:   "bg-orange-500",
  SHELL_COMMAND: "bg-yellow-500",
  DEBUG_KEYWORD: "bg-yellow-500",
  CRYPTO:        "bg-purple-500",
  URL:           "bg-sky-500",
  IP:            "bg-sky-500",
  DOMAIN:        "bg-sky-500",
  VERSION:       "bg-slate-400",
};

function CatBadge({ cat }: { cat: string }) {
  const bg = catColors[cat] ?? "bg-slate-600";
  const label = cat.replace(/_/g, " ");
  return (
    <span className={`inline-block rounded-full px-2 py-0.5 text-white text-xs font-bold tracking-wide ${bg}`}>
      {label}
    </span>
  );
}

function SevBadge({ sev }: { sev?: string }) {
  const s = (sev ?? "low").toLowerCase();
  const cls =
    s === "critical" ? "bg-red-900/50 text-red-300 border-red-700/60" :
    s === "high"     ? "bg-orange-900/50 text-orange-300 border-orange-700/60" :
    s === "medium"   ? "bg-yellow-900/40 text-yellow-300 border-yellow-700/50" :
                       "bg-slate-800 text-slate-400 border-slate-700";
  return (
    <span className={`inline-block rounded-md px-2 py-0.5 text-xs font-semibold border ${cls}`}>
      {s.toUpperCase()}
    </span>
  );
}

// ── Page ─────────────────────────────────────────────────────────────────────

export default function DiffPage() {
  const router = useRouter();
  const params = useSearchParams();

  const [scanIdA, setScanIdA] = useState(params.get("a") ?? "");
  const [scanIdB, setScanIdB] = useState(params.get("b") ?? "");
  const [scans, setScans] = useState<Scan[]>([]);
  const [loadingScans, setLoadingScans] = useState(true);
  const [diff, setDiff] = useState<ScanDiff | null>(null);
  const [comparing, setComparing] = useState(false);
  const [error, setError] = useState("");
  const [tab, setTab] = useState<"strings" | "yara">("strings");
  const [strTab, setStrTab] = useState<"added" | "removed">("added");

  // Load completed scans for selectors
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

  // Auto-compare if both IDs in URL
  useEffect(() => {
    if (params.get("a") && params.get("b")) compare();
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, []);

  const compare = useCallback(async () => {
    if (!scanIdA || !scanIdB) return;
    if (scanIdA === scanIdB) { setError("Select two different scans."); return; }
    setError("");
    setDiff(null);
    setComparing(true);
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
        <h1 className="text-xl font-bold text-white">Firmware Compare</h1>
        <p className="text-slate-500 text-sm mt-0.5">
          Compare two completed scans — strings added/removed, new YARA matches, risk delta.
        </p>
      </div>

      {/* Selector card */}
      <div className="rounded-xl border border-slate-700/60 p-5" style={{ background: "#161b27" }}>
        <div className="flex items-end gap-4 flex-wrap">
          <ScanSelector
            label="Baseline (A)"
            value={scanIdA}
            onChange={setScanIdA}
            scans={scans}
            loading={loadingScans}
            exclude={scanIdB}
          />
          <div className="text-slate-600 text-xl font-bold pb-2 flex-shrink-0">vs</div>
          <ScanSelector
            label="Target (B)"
            value={scanIdB}
            onChange={setScanIdB}
            scans={scans}
            loading={loadingScans}
            exclude={scanIdA}
          />
          <button
            onClick={compare}
            disabled={!scanIdA || !scanIdB || comparing || scanIdA === scanIdB}
            className="flex items-center gap-2 bg-blue-600 hover:bg-blue-500 disabled:opacity-40 text-white font-semibold text-sm px-5 py-2.5 rounded-lg transition-colors flex-shrink-0"
          >
            {comparing ? <Spinner size={14} /> : (
              <svg width="14" height="14" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2.5" strokeLinecap="round" strokeLinejoin="round"><line x1="18" y1="20" x2="18" y2="10"/><line x1="12" y1="20" x2="12" y2="4"/><line x1="6" y1="20" x2="6" y2="14"/></svg>
            )}
            {comparing ? "Comparing…" : "Compare →"}
          </button>
        </div>
        {error && <p className="text-xs text-red-400 mt-3">{error}</p>}
      </div>

      {/* Results */}
      {diff && (
        <>
          {/* Overview — two scan cards + delta row */}
          <div className="grid grid-cols-1 md:grid-cols-2 gap-4">
            {/* Scan A */}
            <div className="rounded-xl border border-slate-700/60 p-4" style={{ background: "#161b27" }}>
              <div className="flex items-center justify-between mb-1">
                <p className="text-xs font-semibold text-slate-500 uppercase tracking-wide">Baseline A</p>
                <RiskBadge level={diff.scan_a.risk_level ?? "informational"} score={diff.scan_a.risk_score} />
              </div>
              <Link href={`/dashboard/${diff.scan_a.id}`} className="font-semibold text-slate-200 hover:text-blue-400 transition-colors block truncate text-sm">
                {diff.scan_a.filename}
              </Link>
              <div className="grid grid-cols-3 gap-2 mt-3">
                {[
                  ["Risk",    `${diff.scan_a.risk_score ?? 0}/100`],
                  ["Entropy", (diff.scan_a.entropy ?? 0).toFixed(2)],
                  ["Strings", diff.scan_a.suspicious_count],
                ].map(([k, v]) => (
                  <div key={String(k)} className="text-center">
                    <p className="text-xs text-slate-600">{k}</p>
                    <p className="text-sm font-bold text-slate-300">{v}</p>
                  </div>
                ))}
              </div>
            </div>

            {/* Scan B */}
            <div className="rounded-xl border border-slate-700/60 p-4" style={{ background: "#161b27" }}>
              <div className="flex items-center justify-between mb-1">
                <p className="text-xs font-semibold text-slate-500 uppercase tracking-wide">Target B</p>
                <RiskBadge level={diff.scan_b.risk_level ?? "informational"} score={diff.scan_b.risk_score} />
              </div>
              <Link href={`/dashboard/${diff.scan_b.id}`} className="font-semibold text-slate-200 hover:text-blue-400 transition-colors block truncate text-sm">
                {diff.scan_b.filename}
              </Link>
              <div className="grid grid-cols-3 gap-2 mt-3">
                {[
                  ["Risk",    `${diff.scan_b.risk_score ?? 0}/100`],
                  ["Entropy", (diff.scan_b.entropy ?? 0).toFixed(2)],
                  ["Strings", diff.scan_b.suspicious_count],
                ].map(([k, v]) => (
                  <div key={String(k)} className="text-center">
                    <p className="text-xs text-slate-600">{k}</p>
                    <p className="text-sm font-bold text-slate-300">{v}</p>
                  </div>
                ))}
              </div>
            </div>
          </div>

          {/* Delta bar */}
          <div className="rounded-xl border border-slate-700/60 px-6 py-4" style={{ background: "#161b27" }}>
            <p className="text-xs font-semibold text-slate-500 uppercase tracking-wide mb-3">Changes (B vs A)</p>
            <div className="flex flex-wrap gap-8">
              <div className="text-center">
                <p className="text-xs text-slate-600 mb-1">Risk Score</p>
                <Delta value={diff.summary.risk_delta} />
              </div>
              <div className="text-center">
                <p className="text-xs text-slate-600 mb-1">Entropy</p>
                <Delta value={diff.summary.entropy_delta} />
              </div>
              {diff.summary.file_size_delta != null && (
                <div className="text-center">
                  <p className="text-xs text-slate-600 mb-1">File Size</p>
                  <span className="font-mono font-semibold text-slate-400">
                    {diff.summary.file_size_delta >= 0 ? "+" : ""}
                    {fmtSize(diff.summary.file_size_delta)}
                  </span>
                </div>
              )}
              <div className="text-center">
                <p className="text-xs text-slate-600 mb-1">New Strings</p>
                <Delta value={diff.summary.strings_added} />
              </div>
              <div className="text-center">
                <p className="text-xs text-slate-600 mb-1">Removed Strings</p>
                <Delta value={-diff.summary.strings_removed} invert />
              </div>
              <div className="text-center">
                <p className="text-xs text-slate-600 mb-1">New YARA</p>
                <Delta value={diff.summary.yara_new} />
              </div>
              <div className="text-center">
                <p className="text-xs text-slate-600 mb-1">Resolved YARA</p>
                <Delta value={-diff.summary.yara_resolved} invert />
              </div>
            </div>
          </div>

          {/* Findings tabs */}
          <div className="rounded-xl overflow-hidden border border-slate-700/60" style={{ background: "#161b27" }}>
            <div className="px-5 py-3 border-b border-slate-700/50">
              <h2 className="font-semibold text-slate-300 text-sm tracking-tight">Detailed Changes</h2>
            </div>
            <div className="p-5">
              {/* Tab bar */}
              <div className="flex gap-1 mb-5 border-b border-slate-700/50">
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
                      tab === t ? "border-blue-500 text-blue-400" : "border-transparent text-slate-500 hover:text-slate-300"
                    }`}
                  >
                    {label}
                    <span className={`ml-1.5 text-xs px-1.5 py-0.5 rounded-full font-semibold ${
                      tab === t ? "bg-blue-900/50 text-blue-400" : "bg-slate-800 text-slate-500"
                    }`}>{count}</span>
                  </button>
                ))}
              </div>

              {/* Strings tab */}
              {tab === "strings" && (
                <div>
                  {/* Sub-tabs: Added / Removed */}
                  <div className="flex gap-2 mb-4">
                    <button
                      onClick={() => setStrTab("added")}
                      className={`flex items-center gap-1.5 px-3 py-1.5 rounded-lg text-xs font-semibold transition-colors border ${
                        strTab === "added"
                          ? "border-red-700/50 bg-red-900/20 text-red-300"
                          : "border-slate-700/40 bg-slate-800/40 text-slate-500 hover:text-slate-300"
                      }`}
                    >
                      <span className="text-base leading-none">+</span>
                      {diff.summary.strings_added} Added (new risk)
                    </button>
                    <button
                      onClick={() => setStrTab("removed")}
                      className={`flex items-center gap-1.5 px-3 py-1.5 rounded-lg text-xs font-semibold transition-colors border ${
                        strTab === "removed"
                          ? "border-emerald-700/50 bg-emerald-900/20 text-emerald-300"
                          : "border-slate-700/40 bg-slate-800/40 text-slate-500 hover:text-slate-300"
                      }`}
                    >
                      <span className="text-base leading-none">−</span>
                      {diff.summary.strings_removed} Removed (resolved)
                    </button>
                  </div>

                  {strTab === "added" && (
                    diff.strings_added.length === 0 ? (
                      <p className="text-sm text-slate-500 text-center py-8">No new strings — no new suspicious findings in B.</p>
                    ) : (
                      <div className="rounded-lg border border-slate-700/40 overflow-hidden">
                        <div className="max-h-[500px] overflow-y-auto divide-y divide-slate-700/30">
                          {diff.strings_added.map((s, i) => (
                            <div key={i} className="flex items-center gap-3 px-3 py-2 bg-red-950/10 hover:bg-red-950/20 transition-colors">
                              <span className="w-1.5 h-1.5 rounded-full bg-red-500 flex-shrink-0" />
                              <span className="w-32 flex-shrink-0"><CatBadge cat={s.category} /></span>
                              <span className="font-mono text-xs text-slate-300 break-all flex-1">{s.value?.slice(0, 120)}</span>
                              <span className="text-xs text-slate-600 font-mono whitespace-nowrap">0x{(s.offset ?? 0).toString(16).padStart(6, "0")}</span>
                            </div>
                          ))}
                        </div>
                      </div>
                    )
                  )}

                  {strTab === "removed" && (
                    diff.strings_removed.length === 0 ? (
                      <p className="text-sm text-slate-500 text-center py-8">No strings removed — no findings resolved.</p>
                    ) : (
                      <div className="rounded-lg border border-slate-700/40 overflow-hidden">
                        <div className="max-h-[500px] overflow-y-auto divide-y divide-slate-700/30">
                          {diff.strings_removed.map((s, i) => (
                            <div key={i} className="flex items-center gap-3 px-3 py-2 bg-emerald-950/10 hover:bg-emerald-950/20 transition-colors">
                              <span className="w-1.5 h-1.5 rounded-full bg-emerald-500 flex-shrink-0" />
                              <span className="w-32 flex-shrink-0"><CatBadge cat={s.category} /></span>
                              <span className="font-mono text-xs text-slate-300 break-all flex-1">{s.value?.slice(0, 120)}</span>
                              <span className="text-xs text-slate-600 font-mono whitespace-nowrap">0x{(s.offset ?? 0).toString(16).padStart(6, "0")}</span>
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
                      <p className="text-xs font-semibold text-red-400 uppercase tracking-wide mb-2">
                        + {diff.yara_new.length} New Rule Match{diff.yara_new.length !== 1 ? "es" : ""} (appeared in B)
                      </p>
                      <div className="space-y-2">
                        {diff.yara_new.map((m, i) => (
                          <div key={i} className="flex items-center gap-3 px-4 py-2.5 rounded-lg border border-red-800/30 bg-red-950/15">
                            <span className="w-1.5 h-1.5 rounded-full bg-red-500 flex-shrink-0" />
                            <span className="font-semibold text-slate-200 text-sm flex-1">{m.rule}</span>
                            <SevBadge sev={m.severity} />
                          </div>
                        ))}
                      </div>
                    </div>
                  )}
                  {diff.yara_resolved.length > 0 && (
                    <div>
                      <p className="text-xs font-semibold text-emerald-400 uppercase tracking-wide mb-2">
                        − {diff.yara_resolved.length} Resolved Rule{diff.yara_resolved.length !== 1 ? "s" : ""} (was in A, gone in B)
                      </p>
                      <div className="space-y-2">
                        {diff.yara_resolved.map((m, i) => (
                          <div key={i} className="flex items-center gap-3 px-4 py-2.5 rounded-lg border border-emerald-800/30 bg-emerald-950/15">
                            <span className="w-1.5 h-1.5 rounded-full bg-emerald-500 flex-shrink-0" />
                            <span className="font-semibold text-slate-200 text-sm flex-1">{m.rule}</span>
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
          </div>
        </>
      )}
    </div>
  );
}
