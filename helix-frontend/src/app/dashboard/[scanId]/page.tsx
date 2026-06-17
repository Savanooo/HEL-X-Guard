"use client";
import { useEffect, useState, useCallback } from "react";
import { useParams, useRouter } from "next/navigation";
import { getScan, triggerExtract, triggerDecompile, downloadReportPdf, type Scan } from "@/lib/api";
import RiskBadge from "@/components/RiskBadge";
import RiskGauge from "@/components/RiskGauge";
import StatusBadge from "@/components/StatusBadge";
import Spinner from "@/components/Spinner";

// ── Helpers ───────────────────────────────────────────────────────────────────

function fmtDate(iso: string | null) {
  if (!iso) return "—";
  return new Date(iso).toLocaleString("en-GB", {
    day: "2-digit", month: "short", year: "numeric",
    hour: "2-digit", minute: "2-digit", second: "2-digit",
  });
}

function fmtSize(bytes: number | null) {
  if (bytes == null) return "—";
  if (bytes < 1024) return `${bytes} B`;
  if (bytes < 1_048_576) return `${(bytes / 1024).toFixed(1)} KB`;
  return `${(bytes / 1_048_576).toFixed(2)} MB`;
}

function Section({ title, children }: { title: string; children: React.ReactNode }) {
  return (
    <div className="bg-white border border-slate-200 rounded-xl overflow-hidden shadow-sm">
      <div className="px-5 py-3.5 border-b border-slate-100 bg-slate-50">
        <h2 className="font-semibold text-slate-700 text-sm">{title}</h2>
      </div>
      <div className="p-5">{children}</div>
    </div>
  );
}

function KV({ label, value, mono }: { label: string; value: React.ReactNode; mono?: boolean }) {
  return (
    <div className="flex gap-4 py-1.5">
      <dt className="w-28 flex-shrink-0 text-xs font-medium text-slate-500 uppercase tracking-wide pt-0.5">
        {label}
      </dt>
      <dd className={`flex-1 text-sm text-slate-800 break-all ${mono ? "font-mono text-xs" : ""}`}>
        {value}
      </dd>
    </div>
  );
}

// ── Page ──────────────────────────────────────────────────────────────────────

export default function ScanDetailPage() {
  const { scanId } = useParams<{ scanId: string }>();
  const router = useRouter();
  const [scan, setScan] = useState<Scan | null>(null);
  const [loading, setLoading] = useState(true);
  const [tab, setTab] = useState<"strings" | "yara" | "binwalk">("strings");
  const [extractError, setExtractError] = useState("");
  const [decompileError, setDecompileError] = useState("");
  const [triggeringExtract, setTriggeringExtract] = useState(false);
  const [triggeringDecompile, setTriggeringDecompile] = useState(false);
  const [showProcessorModal, setShowProcessorModal] = useState(false);
  const [selectedProcessor, setSelectedProcessor] = useState("ARM:LE:32:Cortex");
  const [baseAddress, setBaseAddress] = useState("0x08000000");
  const [downloadingPdf, setDownloadingPdf] = useState(false);
  const [pdfError, setPdfError] = useState("");

  const fetchScan = useCallback(async () => {
    try {
      const s = await getScan(scanId);
      setScan(s);
      setLoading(false);
      return s;
    } catch {
      setLoading(false);
      return null;
    }
  }, [scanId]);

  useEffect(() => {
    fetchScan();
    const interval = setInterval(async () => {
      const s = await fetchScan();
      const mainDone = !s || s.status === "completed" || s.status === "failed";
      const extractDone = !s?.extraction_status || ["completed", "failed"].includes(s.extraction_status);
      const decompileDone = !s?.decompile_status || ["completed", "failed"].includes(s.decompile_status);
      if (mainDone && extractDone && decompileDone) {
        clearInterval(interval);
      }
    }, 2500);
    return () => clearInterval(interval);
  }, [fetchScan]);

  async function handleExtract() {
    setExtractError("");
    setTriggeringExtract(true);
    try {
      const updated = await triggerExtract(scanId);
      setScan(updated);
    } catch (err) {
      setExtractError(err instanceof Error ? err.message : "Failed to trigger extraction");
    } finally {
      setTriggeringExtract(false);
    }
  }

  async function handleDecompile(processor?: string, base_address?: string) {
    setDecompileError("");
    setShowProcessorModal(false);
    setTriggeringDecompile(true);
    try {
      const updated = await triggerDecompile(scanId, processor, base_address);
      setScan(updated);
    } catch (err) {
      setDecompileError(err instanceof Error ? err.message : "Failed to trigger decompilation");
    } finally {
      setTriggeringDecompile(false);
    }
  }

  async function handleDownloadPdf() {
    if (!scan) return;
    setPdfError("");
    setDownloadingPdf(true);
    try {
      const base = scan.filename.replace(/\.[^/.]+$/, "");
      await downloadReportPdf(scanId, `helix-report-${base}.pdf`);
    } catch (err) {
      setPdfError(err instanceof Error ? err.message : "Failed to download PDF");
    } finally {
      setDownloadingPdf(false);
    }
  }

  if (loading) {
    return (
      <div className="flex items-center justify-center h-full text-slate-400">
        <Spinner size={28} />
      </div>
    );
  }

  if (!scan) {
    return (
      <div className="p-8">
        <p className="text-red-600">Scan not found.</p>
        <button onClick={() => router.back()} className="mt-2 text-sm text-blue-600">
          ← Back
        </button>
      </div>
    );
  }

  // eslint-disable-next-line @typescript-eslint/no-explicit-any
  const report = scan.report as Record<string, any> | null;
  const fileInfo   = report?.file    ?? {};
  const entropyInfo = report?.entropy ?? {};
  const riskInfo   = report?.risk    ?? {};
  const stringsInfo = report?.strings ?? {};
  const yaraInfo   = report?.yara    ?? {};
  const binwalkInfo = report?.binwalk ?? {};

  const suspicious: { value: string; category: string; offset: number; encoding: string }[] =
    stringsInfo.suspicious ?? [];
  const yaraMatches: { rule: string; severity?: string; strings?: { identifier: string; data: string }[] }[] =
    yaraInfo.matches ?? [];
  const binwalkFindings: { description: string; offset: number }[] =
    binwalkInfo.findings ?? [];

  return (
    <div className="p-8 max-w-5xl space-y-6">
      {/* Breadcrumb */}
      <div className="flex items-center gap-2 text-sm">
        <button onClick={() => router.push("/dashboard")} className="text-blue-600 hover:underline">
          Scans
        </button>
        <span className="text-slate-400">/</span>
        <span className="text-slate-600 truncate max-w-xs">{scan.filename}</span>
      </div>

      {/* Title row */}
      <div className="flex items-start gap-4 flex-wrap">
        <div className="flex-1 min-w-0">
          <h1 className="text-2xl font-bold text-slate-900 truncate">{scan.filename}</h1>
          <p className="text-slate-500 text-xs mt-1 font-mono">{scan.id}</p>
        </div>
        <div className="flex items-center gap-3">
          {scan.status === "completed" && (
            <button
              onClick={handleDownloadPdf}
              disabled={downloadingPdf}
              className="flex items-center gap-2 bg-white border border-slate-200 hover:bg-slate-50 disabled:opacity-50 text-slate-700 text-sm font-medium px-3.5 py-1.5 rounded-lg transition-colors"
            >
              {downloadingPdf ? <Spinner size={14} /> : "📄"}
              {downloadingPdf ? "Generating…" : "Download PDF"}
            </button>
          )}
          <StatusBadge status={scan.status} />
        </div>
      </div>
      {pdfError && <p className="text-xs text-red-600 -mt-2">{pdfError}</p>}

      {/* Pending / Running banner */}
      {(scan.status === "pending" || scan.status === "running") && (
        <div className="flex items-center gap-3 bg-blue-50 border border-blue-200 rounded-xl px-5 py-4 text-blue-700">
          <Spinner size={18} />
          <div>
            <p className="font-semibold text-sm">
              {scan.status === "pending" ? "Analysis queued…" : "Analysing firmware…"}
            </p>
            <p className="text-xs opacity-70 mt-0.5">Page refreshes automatically every 2.5 s</p>
          </div>
        </div>
      )}

      {/* Failed banner */}
      {scan.status === "failed" && (
        <div className="bg-red-50 border border-red-200 rounded-xl px-5 py-4 text-red-700">
          <p className="font-semibold text-sm">Analysis failed</p>
          {scan.error_message && (
            <p className="text-xs font-mono mt-1 opacity-80">{scan.error_message}</p>
          )}
        </div>
      )}

      {/* Risk + File side by side */}
      {scan.status === "completed" && report && (
        <>
          <div className="grid grid-cols-1 md:grid-cols-2 gap-4">
            {/* Risk card */}
            <Section title="Risk Assessment">
              <div className="flex items-center gap-6">
                <RiskGauge
                  score={scan.risk_score ?? 0}
                  level={scan.risk_level ?? "informational"}
                />
                <div className="flex-1 min-w-0">
                  <RiskBadge
                    level={scan.risk_level ?? "informational"}
                    score={scan.risk_score}
                    large
                  />
                  {riskInfo.reasons?.length > 0 && (
                    <ul className="mt-3 space-y-1">
                      {riskInfo.reasons.map((r: string, i: number) => (
                        <li key={i} className="flex items-start gap-1.5 text-xs text-slate-600">
                          <span className="text-slate-400 mt-0.5">•</span>
                          {r}
                        </li>
                      ))}
                    </ul>
                  )}
                </div>
              </div>
            </Section>

            {/* File metadata */}
            <Section title="File Metadata">
              <dl className="divide-y divide-slate-50">
                <KV label="Name"    value={fileInfo.name} />
                <KV label="Size"    value={fmtSize(fileInfo.size?.bytes)} />
                <KV label="Type"    value={fileInfo.type ?? "—"} />
                <KV label="SHA-256" value={fileInfo.hashes?.sha256} mono />
                <KV label="MD5"     value={fileInfo.hashes?.md5} mono />
                <KV
                  label="Entropy"
                  value={
                    <span>
                      {(entropyInfo.overall ?? 0).toFixed(3)}{" "}
                      <span className="text-slate-400 text-xs">/ 8.00</span>
                      {entropyInfo.interpretation && (
                        <span className="ml-2 text-slate-500 text-xs">
                          — {entropyInfo.interpretation}
                        </span>
                      )}
                    </span>
                  }
                />
                <KV label="Scanned" value={fmtDate(scan.completed_at)} />
              </dl>
            </Section>
          </div>

          {/* Findings tabs */}
          <Section
            title={`Findings  (${suspicious.length} strings · ${yaraMatches.length} YARA · ${binwalkFindings.length} binwalk)`}
          >
            {/* Tab bar */}
            <div className="flex gap-1 mb-4 border-b border-slate-100 pb-3">
              {(
                [
                  ["strings", `Strings (${suspicious.length})`],
                  ["yara",    `YARA (${yaraMatches.length})`],
                  ["binwalk", `Binwalk (${binwalkFindings.length})`],
                ] as [typeof tab, string][]
              ).map(([t, label]) => (
                <button
                  key={t}
                  onClick={() => setTab(t)}
                  className={`px-3 py-1.5 rounded-lg text-sm font-medium transition-colors ${
                    tab === t
                      ? "bg-blue-100 text-blue-700"
                      : "text-slate-500 hover:text-slate-700 hover:bg-slate-100"
                  }`}
                >
                  {label}
                </button>
              ))}
            </div>

            {/* Strings tab */}
            {tab === "strings" && (
              suspicious.length === 0 ? (
                <p className="text-slate-400 text-sm">No suspicious strings found.</p>
              ) : (
                <div className="space-y-1 max-h-96 overflow-y-auto">
                  {suspicious.slice(0, 100).map((s, i) => (
                    <div
                      key={i}
                      className="flex items-start gap-3 py-1.5 border-b border-slate-50 last:border-0"
                    >
                      <span className="w-28 flex-shrink-0">
                        <CategoryBadge cat={s.category} />
                      </span>
                      <span className="font-mono text-xs text-slate-700 break-all flex-1">
                        {s.value.length > 120 ? s.value.slice(0, 120) + "…" : s.value}
                      </span>
                      <span className="text-xs text-slate-400 whitespace-nowrap">
                        0x{s.offset.toString(16).padStart(6, "0")}
                      </span>
                    </div>
                  ))}
                  {suspicious.length > 100 && (
                    <p className="text-xs text-slate-400 pt-2 text-center">
                      … and {suspicious.length - 100} more findings
                    </p>
                  )}
                </div>
              )
            )}

            {/* YARA tab */}
            {tab === "yara" && (
              yaraMatches.length === 0 ? (
                <p className="text-slate-400 text-sm">No YARA matches.</p>
              ) : (
                <div className="space-y-3">
                  {yaraMatches.map((m, i) => (
                    <div key={i} className="border border-slate-200 rounded-lg p-3">
                      <div className="flex items-center gap-2 mb-1">
                        <span className="font-mono text-sm font-semibold text-slate-800">{m.rule}</span>
                        {m.severity && <CategoryBadge cat={m.severity.toUpperCase()} />}
                      </div>
                      {m.strings && m.strings.length > 0 && (
                        <ul className="mt-1 space-y-0.5">
                          {m.strings.slice(0, 5).map((s, j) => (
                            <li key={j} className="text-xs font-mono text-slate-500">
                              {s.identifier}: {s.data}
                            </li>
                          ))}
                        </ul>
                      )}
                    </div>
                  ))}
                </div>
              )
            )}

            {/* Binwalk tab */}
            {tab === "binwalk" && (
              binwalkInfo.error ? (
                <p className="text-sm text-slate-500">
                  Binwalk unavailable: {binwalkInfo.error}
                </p>
              ) : binwalkFindings.length === 0 ? (
                <p className="text-slate-400 text-sm">No binwalk findings.</p>
              ) : (
                <div className="space-y-1">
                  {binwalkFindings.map((f, i) => (
                    <div
                      key={i}
                      className="flex items-start gap-4 py-1.5 border-b border-slate-50 last:border-0 text-sm"
                    >
                      <span className="font-mono text-xs text-slate-400 w-20 flex-shrink-0">
                        0x{(f.offset ?? 0).toString(16).padStart(6, "0")}
                      </span>
                      <span className="text-slate-700">{f.description}</span>
                    </div>
                  ))}
                </div>
              )
            )}
          </Section>

          {/* Deep analysis: extract / decompile */}
          <Section title="Deep Analysis">
            <div className="grid grid-cols-1 md:grid-cols-2 gap-4">
              {/* Extraction */}
              <div className="border border-slate-200 rounded-lg p-4">
                <div className="flex items-center justify-between mb-2">
                  <p className="font-semibold text-sm text-slate-800">Binwalk Extraction</p>
                  <JobStatusPill status={scan.extraction_status} />
                </div>
                <p className="text-xs text-slate-500 mb-3">
                  Extracts embedded filesystems/files for inspection. Extracted files are listed only — never executed.
                </p>
                <button
                  onClick={handleExtract}
                  disabled={triggeringExtract || scan.extraction_status === "pending" || scan.extraction_status === "running"}
                  className="flex items-center gap-2 bg-slate-800 hover:bg-slate-700 disabled:opacity-40 text-white text-xs font-semibold px-3 py-1.5 rounded-lg transition-colors"
                >
                  {triggeringExtract && <Spinner size={12} />}
                  {scan.extraction_status ? "Re-run Extraction" : "Run Extraction"}
                </button>
                {extractError && <p className="text-xs text-red-600 mt-2">{extractError}</p>}
                {scan.extraction_error && (
                  <p className="text-xs text-slate-500 mt-2">⚠ {scan.extraction_error}</p>
                )}
                {scan.extraction?.extracted && scan.extraction.extracted.length > 0 && (
                  <ul className="mt-3 space-y-0.5 max-h-32 overflow-y-auto">
                    {scan.extraction.extracted.slice(0, 20).map((f: string, i: number) => (
                      <li key={i} className="text-xs font-mono text-slate-600 truncate">{f}</li>
                    ))}
                  </ul>
                )}
              </div>

              {/* Decompile */}
              <div className="border border-slate-200 rounded-lg p-4">
                <div className="flex items-center justify-between mb-2">
                  <p className="font-semibold text-sm text-slate-800">Ghidra Decompile</p>
                  <JobStatusPill status={scan.decompile_status} />
                </div>
                <p className="text-xs text-slate-500 mb-3">
                  Optional, heavy. Statically disassembles the binary — never executes it. Requires Ghidra configured on the server.
                </p>
                <button
                  onClick={() => setShowProcessorModal(true)}
                  disabled={triggeringDecompile || scan.decompile_status === "pending" || scan.decompile_status === "running"}
                  className="flex items-center gap-2 bg-slate-800 hover:bg-slate-700 disabled:opacity-40 text-white text-xs font-semibold px-3 py-1.5 rounded-lg transition-colors"
                >
                  {triggeringDecompile && <Spinner size={12} />}
                  {scan.decompile_status ? "Re-run Decompile" : "Run Decompile"}
                </button>
                {decompileError && <p className="text-xs text-red-600 mt-2">{decompileError}</p>}
                {scan.decompile_error && (
                  <p className="text-xs text-slate-500 mt-2">⚠ {scan.decompile_error}</p>
                )}
                {scan.decompile?.functions && scan.decompile.functions.length > 0 && (
                  <p className="text-xs text-slate-600 mt-3">
                    {scan.decompile.functions.length} function(s) decompiled
                  </p>
                )}
              </div>
            </div>
          </Section>
        </>
      )}
      {/* Processor selection modal */}
      {showProcessorModal && (
        <div className="fixed inset-0 z-50 flex items-center justify-center bg-black/40">
          <div className="bg-white rounded-2xl shadow-2xl p-6 w-full max-w-md mx-4">
            <h3 className="text-base font-semibold text-slate-900 mb-1">Ghidra Decompile Settings</h3>
            <p className="text-xs text-slate-500 mb-4">
              For ELF/PE binaries, leave processor as Auto. For raw firmware (STM32, MIPS, etc.) select the CPU architecture.
            </p>

            <label className="block text-xs font-medium text-slate-700 mb-1">Processor Architecture</label>
            <select
              value={selectedProcessor}
              onChange={e => setSelectedProcessor(e.target.value)}
              className="w-full border border-slate-200 rounded-lg px-3 py-2 text-sm text-slate-800 mb-4 focus:outline-none focus:ring-2 focus:ring-blue-500"
            >
              <option value="">Auto (ELF / PE only)</option>
              <option value="ARM:LE:32:Cortex">ARM Cortex-M LE 32-bit — STM32, NXP, etc.</option>
              <option value="ARM:LE:32:v8">ARM v8 LE 32-bit</option>
              <option value="ARM:BE:32:v8">ARM v8 BE 32-bit</option>
              <option value="MIPS:LE:32:default">MIPS 32-bit Little-Endian</option>
              <option value="MIPS:BE:32:default">MIPS 32-bit Big-Endian</option>
              <option value="x86:LE:32:default">x86 32-bit</option>
              <option value="x86:LE:64:default">x86-64</option>
            </select>

            <label className="block text-xs font-medium text-slate-700 mb-1">
              Base Load Address <span className="text-slate-400 font-normal">(for raw binaries)</span>
            </label>
            <input
              type="text"
              value={baseAddress}
              onChange={e => setBaseAddress(e.target.value)}
              placeholder="e.g. 0x08000000"
              className="w-full border border-slate-200 rounded-lg px-3 py-2 text-sm font-mono text-slate-800 mb-5 focus:outline-none focus:ring-2 focus:ring-blue-500"
            />

            <div className="flex gap-2 justify-end">
              <button
                onClick={() => setShowProcessorModal(false)}
                className="px-4 py-2 text-sm text-slate-600 hover:bg-slate-100 rounded-lg transition-colors"
              >
                Cancel
              </button>
              <button
                onClick={() => handleDecompile(selectedProcessor || undefined, baseAddress || undefined)}
                className="px-4 py-2 text-sm font-semibold bg-slate-800 hover:bg-slate-700 text-white rounded-lg transition-colors"
              >
                Run Decompile
              </button>
            </div>
          </div>
        </div>
      )}
    </div>
  );
}

// ── Job status pill (extraction / decompile) ──────────────────────────────────

function JobStatusPill({ status }: { status?: string | null }) {
  if (!status) {
    return <span className="text-xs text-slate-400">Not run</span>;
  }
  const styles: Record<string, string> = {
    pending:   "bg-slate-100 text-slate-600",
    running:   "bg-blue-100 text-blue-700",
    completed: "bg-emerald-100 text-emerald-700",
    failed:    "bg-red-100 text-red-700",
  };
  return (
    <span className={`inline-flex items-center gap-1 rounded px-2 py-0.5 text-xs font-medium ${styles[status] ?? "bg-slate-100 text-slate-600"}`}>
      {status === "running" && <Spinner size={10} />}
      {status.charAt(0).toUpperCase() + status.slice(1)}
    </span>
  );
}

// ── Category badge ────────────────────────────────────────────────────────────

const catStyles: Record<string, string> = {
  PRIVATE_KEY:    "bg-red-100 text-red-700",
  CERTIFICATE:    "bg-red-100 text-red-700",
  API_KEY:        "bg-orange-100 text-orange-700",
  CREDENTIAL:     "bg-orange-100 text-orange-700",
  SHELL_COMMAND:  "bg-yellow-100 text-yellow-700",
  DEBUG_KEYWORD:  "bg-yellow-100 text-yellow-700",
  URL:            "bg-sky-100 text-sky-700",
  IP:             "bg-sky-100 text-sky-700",
  DOMAIN:         "bg-sky-100 text-sky-700",
  NETWORK_SERVICE:"bg-sky-100 text-sky-700",
  CRITICAL:       "bg-red-100 text-red-700",
  HIGH:           "bg-orange-100 text-orange-700",
  MEDIUM:         "bg-yellow-100 text-yellow-700",
  LOW:            "bg-green-100 text-green-700",
};

function CategoryBadge({ cat }: { cat: string }) {
  const cls = catStyles[cat] ?? "bg-slate-100 text-slate-600";
  return (
    <span className={`inline-block rounded px-1.5 py-0.5 text-xs font-semibold ${cls}`}>
      {cat}
    </span>
  );
}
