"use client";
import { useState } from "react";
import { useRouter } from "next/navigation";
import {
  TrendingUp, TrendingDown, Minus, GitCompare, Search,
} from "lucide-react";
import {
  getFirmwareSeries,
  getFirmwareRegression,
  type FirmwareScanMeta,
  type FirmwareSeries,
  type FirmwareRegression,
} from "@/lib/api";
import Spinner from "@/components/Spinner";

// ── Risk colour helpers ───────────────────────────────────────────────────────

const RISK_RING: Record<string, string> = {
  critical:      "text-red-400",
  high:          "text-orange-400",
  medium:        "text-amber-400",
  low:           "text-green-400",
  informational: "text-slate-400",
};

function riskColor(level: string | null): string {
  return RISK_RING[level ?? ""] ?? "text-slate-400";
}

function RiskDir({ delta }: { delta: number }) {
  if (delta > 0) return <TrendingUp className="inline w-4 h-4 text-red-400" />;
  if (delta < 0) return <TrendingDown className="inline w-4 h-4 text-green-400" />;
  return <Minus className="inline w-4 h-4 text-slate-400" />;
}

// ── Mini score bar ────────────────────────────────────────────────────────────

function ScoreBar({ score, level }: { score: number | null; level: string | null }) {
  const pct = Math.min(score ?? 0, 100);
  const bg =
    level === "critical" ? "bg-red-500" :
    level === "high"     ? "bg-orange-500" :
    level === "medium"   ? "bg-amber-500" :
    level === "low"      ? "bg-green-600" : "bg-slate-600";
  return (
    <div className="w-full bg-slate-700 rounded-full h-1.5 mt-1">
      <div className={`${bg} h-1.5 rounded-full`} style={{ width: `${pct}%` }} />
    </div>
  );
}

// ── Timeline card ─────────────────────────────────────────────────────────────

function TimelineCard({
  scan,
  prev,
  selected,
  onSelect,
}: {
  scan: FirmwareScanMeta;
  prev: FirmwareScanMeta | null;
  selected: boolean;
  onSelect: () => void;
}) {
  const router = useRouter();
  const riskDelta = prev != null && scan.risk_score != null && prev.risk_score != null
    ? scan.risk_score - prev.risk_score : null;

  return (
    <button
      onClick={onSelect}
      className={`w-full text-left p-4 rounded-lg border transition-colors
        ${selected
          ? "border-indigo-500 bg-indigo-500/10"
          : "border-slate-700 bg-slate-800/50 hover:border-slate-600"}`}
    >
      <div className="flex items-start justify-between gap-2">
        <div className="min-w-0">
          <p className="text-sm font-medium text-slate-200 truncate">{scan.filename}</p>
          <p className="text-xs text-slate-500 mt-0.5">
            {scan.created_at ? new Date(scan.created_at).toLocaleString() : "—"}
          </p>
        </div>
        <div className="text-right shrink-0">
          <span className={`text-sm font-semibold ${riskColor(scan.risk_level)}`}>
            {scan.risk_score?.toFixed(1) ?? "—"}
          </span>
          {riskDelta !== null && (
            <span className="ml-1 text-xs text-slate-400">
              <RiskDir delta={riskDelta} />
              {Math.abs(riskDelta).toFixed(1)}
            </span>
          )}
        </div>
      </div>
      <ScoreBar score={scan.risk_score} level={scan.risk_level} />
      <div className="flex gap-4 mt-2 text-xs text-slate-500">
        <span>{scan.yara_count} YARA</span>
        <span>{scan.suspicious_count} strings</span>
        {scan.entropy != null && <span>H={scan.entropy.toFixed(2)}</span>}
      </div>
    </button>
  );
}

// ── Regression diff panel ─────────────────────────────────────────────────────

function RegressionPanel({
  scanA,
  scanB,
  onClose,
}: {
  scanA: FirmwareScanMeta;
  scanB: FirmwareScanMeta;
  onClose: () => void;
}) {
  const [data, setData] = useState<FirmwareRegression | null>(null);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState<string | null>(null);

  useState(() => {
    getFirmwareRegression(scanA.id, scanB.id)
      .then(setData)
      .catch((e: Error) => setError(e.message))
      .finally(() => setLoading(false));
  });

  const dirClass =
    data?.summary.risk_direction === "worse" ? "text-red-400" :
    data?.summary.risk_direction === "better" ? "text-green-400" : "text-slate-400";

  return (
    <div className="border border-slate-700 rounded-xl bg-slate-900 p-5">
      <div className="flex items-center justify-between mb-4">
        <h3 className="text-sm font-semibold text-slate-200 flex items-center gap-2">
          <GitCompare className="w-4 h-4 text-indigo-400" />
          Regression: {scanA.filename} → {scanB.filename}
        </h3>
        <button onClick={onClose} className="text-slate-500 hover:text-slate-300 text-xs">
          close
        </button>
      </div>

      {loading && <Spinner />}
      {error && <p className="text-red-400 text-sm">{error}</p>}

      {data && (
        <>
          {/* Summary row */}
          <div className="grid grid-cols-2 sm:grid-cols-4 gap-3 mb-5">
            {[
              { label: "Risk Δ", value: `${data.risk_delta > 0 ? "+" : ""}${data.risk_delta}`, cls: dirClass },
              { label: "Direction", value: data.summary.risk_direction, cls: dirClass },
              { label: "YARA new", value: String(data.summary.yara_new), cls: data.summary.yara_new > 0 ? "text-red-400" : "text-slate-300" },
              { label: "YARA resolved", value: String(data.summary.yara_resolved), cls: data.summary.yara_resolved > 0 ? "text-green-400" : "text-slate-300" },
            ].map(({ label, value, cls }) => (
              <div key={label} className="bg-slate-800 rounded-lg p-3 text-center">
                <p className="text-xs text-slate-500 mb-1">{label}</p>
                <p className={`text-lg font-semibold ${cls}`}>{value}</p>
              </div>
            ))}
          </div>

          {/* YARA appeared */}
          {data.yara_appeared.length > 0 && (
            <section className="mb-4">
              <h4 className="text-xs font-medium text-red-400 uppercase tracking-wider mb-2">
                YARA Appeared ({data.yara_appeared.length})
              </h4>
              <div className="flex flex-wrap gap-1.5">
                {data.yara_appeared.map(r => (
                  <span key={r} className="px-2 py-0.5 rounded text-xs bg-red-500/10 text-red-300 border border-red-500/30">{r}</span>
                ))}
              </div>
            </section>
          )}

          {/* YARA resolved */}
          {data.yara_resolved.length > 0 && (
            <section className="mb-4">
              <h4 className="text-xs font-medium text-green-400 uppercase tracking-wider mb-2">
                YARA Resolved ({data.yara_resolved.length})
              </h4>
              <div className="flex flex-wrap gap-1.5">
                {data.yara_resolved.map(r => (
                  <span key={r} className="px-2 py-0.5 rounded text-xs bg-green-500/10 text-green-300 border border-green-500/30">{r}</span>
                ))}
              </div>
            </section>
          )}

          {/* String diff tables */}
          {(data.strings_appeared.length > 0 || data.strings_removed.length > 0) && (
            <div className="grid grid-cols-1 sm:grid-cols-2 gap-4">
              {data.strings_appeared.length > 0 && (
                <div>
                  <h4 className="text-xs font-medium text-red-400 uppercase tracking-wider mb-2">
                    Strings Appeared ({data.summary.strings_appeared})
                  </h4>
                  <div className="max-h-48 overflow-y-auto rounded border border-slate-700">
                    <table className="w-full text-xs">
                      <tbody>
                        {data.strings_appeared.map((s, i) => (
                          <tr key={i} className="border-b border-slate-700/50 last:border-0">
                            <td className="px-2 py-1 text-slate-300 font-mono truncate max-w-[12rem]">{s.value}</td>
                            <td className="px-2 py-1 text-slate-500 whitespace-nowrap">{s.category}</td>
                          </tr>
                        ))}
                      </tbody>
                    </table>
                  </div>
                </div>
              )}
              {data.strings_removed.length > 0 && (
                <div>
                  <h4 className="text-xs font-medium text-green-400 uppercase tracking-wider mb-2">
                    Strings Removed ({data.summary.strings_removed})
                  </h4>
                  <div className="max-h-48 overflow-y-auto rounded border border-slate-700">
                    <table className="w-full text-xs">
                      <tbody>
                        {data.strings_removed.map((s, i) => (
                          <tr key={i} className="border-b border-slate-700/50 last:border-0">
                            <td className="px-2 py-1 text-slate-300 font-mono truncate max-w-[12rem]">{s.value}</td>
                            <td className="px-2 py-1 text-slate-500 whitespace-nowrap">{s.category}</td>
                          </tr>
                        ))}
                      </tbody>
                    </table>
                  </div>
                </div>
              )}
            </div>
          )}
        </>
      )}
    </div>
  );
}

// ── Main page ─────────────────────────────────────────────────────────────────

export default function FirmwarePage() {
  const [stem, setStem] = useState("");
  const [deviceLabel, setDeviceLabel] = useState("");
  const [series, setSeries] = useState<FirmwareSeries | null>(null);
  const [loading, setLoading] = useState(false);
  const [error, setError] = useState<string | null>(null);

  // Regression state: indices into series.items
  const [selA, setSelA] = useState<number | null>(null);
  const [selB, setSelB] = useState<number | null>(null);
  const [showDiff, setShowDiff] = useState(false);

  async function handleSearch(e: React.FormEvent) {
    e.preventDefault();
    if (!stem.trim() && !deviceLabel.trim()) return;
    setError(null);
    setLoading(true);
    setSeries(null);
    setSelA(null);
    setSelB(null);
    setShowDiff(false);
    try {
      const res = await getFirmwareSeries({
        stem: stem.trim() || undefined,
        device_label: deviceLabel.trim() || undefined,
      });
      setSeries(res);
    } catch (e: unknown) {
      setError(e instanceof Error ? e.message : "Search failed");
    } finally {
      setLoading(false);
    }
  }

  function handleSelect(idx: number) {
    setShowDiff(false);
    if (selA === null) {
      setSelA(idx);
    } else if (selB === null && idx !== selA) {
      setSelB(idx);
    } else {
      setSelA(idx);
      setSelB(null);
    }
  }

  const items = series?.items ?? [];
  const canCompare = selA !== null && selB !== null;
  const scanA = selA !== null ? items[selA] : null;
  const scanB = selB !== null ? items[selB] : null;

  return (
    <div className="max-w-4xl mx-auto py-8 px-4 space-y-6">
        <div>
          <h1 className="text-xl font-bold text-slate-100">Firmware Version Tracking</h1>
          <p className="text-sm text-slate-500 mt-1">
            Search for a device&apos;s firmware lineage and compare versions.
          </p>
        </div>

        {/* Search form */}
        <form onSubmit={handleSearch} className="flex flex-col sm:flex-row gap-3">
          <input
            className="flex-1 bg-slate-800 border border-slate-700 rounded-lg px-3 py-2 text-sm
                       text-slate-200 placeholder-slate-500 focus:outline-none focus:border-indigo-500"
            placeholder="Filename stem (e.g. camera_fw)"
            value={stem}
            onChange={e => setStem(e.target.value)}
          />
          <input
            className="flex-1 bg-slate-800 border border-slate-700 rounded-lg px-3 py-2 text-sm
                       text-slate-200 placeholder-slate-500 focus:outline-none focus:border-indigo-500"
            placeholder="Device label (optional, exact match)"
            value={deviceLabel}
            onChange={e => setDeviceLabel(e.target.value)}
          />
          <button
            type="submit"
            disabled={loading || (!stem.trim() && !deviceLabel.trim())}
            className="flex items-center gap-2 px-4 py-2 bg-indigo-600 hover:bg-indigo-500
                       disabled:opacity-50 text-white text-sm rounded-lg transition-colors"
          >
            <Search className="w-4 h-4" />
            Search
          </button>
        </form>

        {loading && <div className="flex justify-center py-8"><Spinner /></div>}
        {error && <p className="text-red-400 text-sm">{error}</p>}

        {series && !loading && (
          <>
            <div className="flex items-center justify-between">
              <p className="text-sm text-slate-400">
                {series.count} scan{series.count !== 1 ? "s" : ""} in lineage
              </p>
              {selA !== null && selB === null && (
                <p className="text-xs text-slate-500">Select a second scan to compare</p>
              )}
              {canCompare && (
                <button
                  onClick={() => setShowDiff(true)}
                  className="flex items-center gap-1.5 px-3 py-1.5 bg-indigo-600 hover:bg-indigo-500
                             text-white text-xs rounded-lg transition-colors"
                >
                  <GitCompare className="w-3.5 h-3.5" />
                  Compare selected
                </button>
              )}
            </div>

            {items.length === 0 ? (
              <p className="text-slate-500 text-sm text-center py-8">No completed scans found.</p>
            ) : (
              <div className="space-y-2">
                {items.map((scan, i) => (
                  <div key={scan.id} className="flex items-stretch gap-2">
                    {/* Timeline connector */}
                    <div className="flex flex-col items-center pt-4">
                      <div className={`w-2.5 h-2.5 rounded-full shrink-0
                        ${i === selA || i === selB ? "bg-indigo-400" : "bg-slate-600"}`} />
                      {i < items.length - 1 && (
                        <div className="w-px flex-1 bg-slate-700 mt-1" />
                      )}
                    </div>
                    <div className="flex-1">
                      <TimelineCard
                        scan={scan}
                        prev={i > 0 ? items[i - 1] : null}
                        selected={i === selA || i === selB}
                        onSelect={() => handleSelect(i)}
                      />
                    </div>
                    {(i === selA || i === selB) && (
                      <div className="flex items-center">
                        <span className="text-xs font-bold text-indigo-400 bg-indigo-500/10
                                         border border-indigo-500/30 rounded px-1.5 py-0.5">
                          {i === selA ? "A" : "B"}
                        </span>
                      </div>
                    )}
                  </div>
                ))}
              </div>
            )}

            {showDiff && scanA && scanB && (
              <RegressionPanel
                scanA={scanA}
                scanB={scanB}
                onClose={() => setShowDiff(false)}
              />
            )}
          </>
        )}
    </div>
  );
}
