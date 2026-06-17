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

// Strip Python bytes notation b'...' and escape sequences for display
function cleanYaraData(raw: string): string {
  let s = raw.trim();
  if (s.startsWith("b'") && s.endsWith("'")) s = s.slice(2, -1);
  else if (s.startsWith('b"') && s.endsWith('"')) s = s.slice(2, -1);
  // Replace non-printable escape sequences with hex
  s = s.replace(/\\x([0-9a-fA-F]{2})/g, (_, h) => {
    const b = parseInt(h, 16);
    return b >= 32 && b < 127 ? String.fromCharCode(b) : `\\x${h}`;
  });
  return s;
}

// Deduplicate YARA match strings (same identifier + same data)
function dedupeStrings(arr: { identifier: string; data: string }[]) {
  const seen = new Set<string>();
  return arr.filter(s => {
    const key = `${s.identifier}::${s.data}`;
    if (seen.has(key)) return false;
    seen.add(key);
    return true;
  });
}

function Section({ title, children, accent }: { title: string; children: React.ReactNode; accent?: string }) {
  return (
    <div className={`bg-white border rounded-xl overflow-hidden shadow-sm ${accent ? `border-l-4 ${accent} border-slate-200` : "border-slate-200"}`}>
      <div className="px-5 py-3 border-b border-slate-100 bg-slate-50/60">
        <h2 className="font-semibold text-slate-700 text-sm tracking-tight">{title}</h2>
      </div>
      <div className="p-5">{children}</div>
    </div>
  );
}

function KV({ label, value, mono }: { label: string; value: React.ReactNode; mono?: boolean }) {
  return (
    <div className="flex gap-4 py-2 border-b border-slate-50 last:border-0">
      <dt className="w-24 flex-shrink-0 text-xs font-semibold text-slate-400 uppercase tracking-wider pt-0.5">
        {label}
      </dt>
      <dd className={`flex-1 text-sm text-slate-800 break-all ${mono ? "font-mono text-xs text-slate-600" : ""}`}>
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
      <div>
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
    <div className="space-y-6">
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
            <div className={`bg-white rounded-xl shadow-sm overflow-hidden border-2 ${
              scan.risk_level === "critical" ? "border-red-500" :
              scan.risk_level === "high"     ? "border-orange-400" :
              scan.risk_level === "medium"   ? "border-yellow-400" :
              scan.risk_level === "low"      ? "border-green-400" :
                                               "border-slate-200"
            }`}>
              <div className={`px-5 py-3 border-b ${
                scan.risk_level === "critical" ? "bg-red-50 border-red-100" :
                scan.risk_level === "high"     ? "bg-orange-50 border-orange-100" :
                scan.risk_level === "medium"   ? "bg-yellow-50 border-yellow-100" :
                                                 "bg-slate-50 border-slate-100"
              }`}>
                <h2 className="font-semibold text-slate-700 text-sm tracking-tight">Risk Assessment</h2>
              </div>
              <div className="p-5">
                <div className="flex flex-col items-center mb-4">
                  <RiskGauge score={scan.risk_score ?? 0} level={scan.risk_level ?? "informational"} />
                  <div className="mt-2 text-center">
                    <RiskBadge level={scan.risk_level ?? "informational"} score={scan.risk_score} large />
                    <p className="text-xs text-slate-400 mt-1">
                      {yaraMatches.length} YARA · {suspicious.length} strings
                    </p>
                  </div>
                </div>
                {riskInfo.reasons?.length > 0 && (
                  <ul className="space-y-1.5 border-t border-slate-100 pt-3">
                    {riskInfo.reasons.map((r: string, i: number) => (
                      <li key={i} className="flex items-start gap-2 text-xs text-slate-600">
                        <span className={`mt-0.5 text-base leading-none ${
                          r.toLowerCase().includes("critical") || r.toLowerCase().includes("safety") || r.toLowerCase().includes("unsigned") ? "text-red-500" :
                          r.toLowerCase().includes("high") || r.toLowerCase().includes("flash") || r.toLowerCase().includes("hidden") ? "text-orange-500" :
                          r.toLowerCase().includes("medium") || r.toLowerCase().includes("debug") ? "text-yellow-500" :
                          "text-slate-400"
                        }`}>›</span>
                        {r}
                      </li>
                    ))}
                  </ul>
                )}
              </div>
            </div>

            {/* File metadata */}
            <Section title="File Metadata">
              <dl>
                <KV label="Name"    value={<span className="font-medium text-slate-700 truncate block max-w-xs">{fileInfo.name}</span>} />
                <KV label="Size"    value={fmtSize(fileInfo.size?.bytes)} />
                <KV label="Type"    value={fileInfo.type ?? "—"} />
                <KV label="SHA-256" value={fileInfo.hashes?.sha256} mono />
                <KV label="MD5"     value={fileInfo.hashes?.md5} mono />
                <KV
                  label="Entropy"
                  value={
                    <span className="flex items-center gap-2">
                      <span className="font-semibold">{(entropyInfo.overall ?? 0).toFixed(3)}</span>
                      <span className="text-slate-400">/ 8.00</span>
                      {entropyInfo.interpretation && (
                        <span className="text-slate-400 text-xs">— {entropyInfo.interpretation}</span>
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
            title={`Findings — ${suspicious.length} strings · ${yaraMatches.length} YARA · ${binwalkFindings.length} binwalk`}
          >
            {/* Tab bar */}
            <div className="flex gap-1 mb-5 border-b border-slate-100 pb-0">
              {(
                [
                  ["strings", "Strings", suspicious.length],
                  ["yara",    "YARA",    yaraMatches.length],
                  ["binwalk", "Binwalk", binwalkFindings.length],
                ] as [typeof tab, string, number][]
              ).map(([t, label, count]) => (
                <button
                  key={t}
                  onClick={() => setTab(t)}
                  className={`px-4 py-2 text-sm font-medium border-b-2 transition-colors ${
                    tab === t
                      ? "border-blue-600 text-blue-700"
                      : "border-transparent text-slate-500 hover:text-slate-700"
                  }`}
                >
                  {label}
                  <span className={`ml-1.5 text-xs px-1.5 py-0.5 rounded-full font-semibold ${
                    tab === t ? "bg-blue-100 text-blue-700" : "bg-slate-100 text-slate-500"
                  }`}>{count}</span>
                </button>
              ))}
            </div>

            {/* Strings tab */}
            {tab === "strings" && (
              suspicious.length === 0 ? (
                <div className="text-center py-8 text-slate-400">
                  <p className="text-2xl mb-2">✓</p>
                  <p className="text-sm">No suspicious strings found.</p>
                </div>
              ) : (
                <div className="rounded-lg border border-slate-100 overflow-hidden">
                  <div className="max-h-[480px] overflow-y-auto divide-y divide-slate-50">
                    {suspicious.map((s, i) => (
                      <div key={i} className="flex items-center gap-3 px-3 py-2 hover:bg-slate-50 transition-colors">
                        <span className="w-32 flex-shrink-0">
                          <CategoryBadge cat={s.category} />
                        </span>
                        <span className="font-mono text-xs text-slate-700 break-all flex-1 leading-relaxed">
                          {s.value.length > 140 ? s.value.slice(0, 140) + "…" : s.value}
                        </span>
                        <span className="text-xs text-slate-300 font-mono whitespace-nowrap">
                          0x{s.offset.toString(16).padStart(6, "0")}
                        </span>
                      </div>
                    ))}
                  </div>
                </div>
              )
            )}

            {/* YARA tab */}
            {tab === "yara" && (
              yaraMatches.length === 0 ? (
                <div className="text-center py-8 text-slate-400">
                  <p className="text-2xl mb-2">✓</p>
                  <p className="text-sm">No YARA rule matches detected.</p>
                </div>
              ) : (
                <div className="space-y-3">
                  {yaraMatches.map((m, i) => {
                    const sev = (m.severity ?? "low").toLowerCase();
                    const borderCls =
                      sev === "critical" ? "border-l-red-500 bg-red-50/30" :
                      sev === "high"     ? "border-l-orange-400 bg-orange-50/30" :
                      sev === "medium"   ? "border-l-yellow-400 bg-yellow-50/20" :
                                           "border-l-slate-300 bg-slate-50/30";
                    const deduped = m.strings ? dedupeStrings(m.strings) : [];
                    // Only show printable string matches, skip binary-only hits
                    const printable = deduped.filter(s => {
                      const cleaned = cleanYaraData(s.data);
                      return !cleaned.startsWith("\\x") && cleaned.length > 0;
                    });
                    return (
                      <div key={i} className={`border border-l-4 border-slate-200 rounded-lg p-4 ${borderCls}`}>
                        <div className="flex items-center justify-between gap-3 mb-2">
                          <span className="font-semibold text-slate-900 text-sm">{m.rule}</span>
                          {m.severity && <CategoryBadge cat={m.severity.toUpperCase()} />}
                        </div>
                        {printable.length > 0 && (
                          <div className="flex flex-wrap gap-2 mt-1">
                            {printable.map((s, j) => (
                              <code key={j} className="inline-flex items-center gap-1 text-xs bg-white border border-slate-200 rounded px-2 py-0.5 text-slate-700 font-mono shadow-sm">
                                <span className="text-slate-400">{s.identifier}:</span>
                                <span className="text-slate-800 font-semibold">{cleanYaraData(s.data)}</span>
                              </code>
                            ))}
                          </div>
                        )}
                      </div>
                    );
                  })}
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
                {scan.extraction_status === "completed" && scan.extraction && (
                  <ExtractionResults extraction={scan.extraction} />
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
                  <DecompileFunctions functions={scan.decompile.functions} />
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

// ── Extraction results ────────────────────────────────────────────────────────

interface ExtractedFile {
  path: string;
  name: string;
  size: number | null;
  sha256: string | null;
}

function ExtractionResults({ extraction }: { extraction: Record<string, unknown> }) {
  const findings = (extraction.findings as { offset: number; hex_offset: string; description: string }[]) ?? [];
  const rawExtracted = (extraction.extracted as (string | ExtractedFile)[]) ?? [];
  const files: ExtractedFile[] = rawExtracted.map(f =>
    typeof f === "string" ? { path: f, name: f.split("/").pop() ?? f, size: null, sha256: null } : f
  );

  return (
    <div className="mt-3 space-y-3">
      {/* Binwalk signatures */}
      {findings.length > 0 ? (
        <div>
          <p className="text-xs font-medium text-slate-600 mb-1">{findings.length} signature(s) detected</p>
          <div className="max-h-36 overflow-y-auto space-y-0.5 bg-slate-50 rounded-lg px-2 py-1.5">
            {findings.map((f, i) => (
              <div key={i} className="flex gap-2 text-xs">
                <span className="font-mono text-slate-400 w-20 flex-shrink-0">{f.hex_offset}</span>
                <span className="text-slate-600 truncate">{f.description}</span>
              </div>
            ))}
          </div>
        </div>
      ) : (
        <p className="text-xs text-slate-400">No embedded signatures detected by binwalk.</p>
      )}

      {/* Extracted files with hashes */}
      {files.length > 0 ? (
        <div>
          <p className="text-xs font-medium text-slate-600 mb-1">{files.length} file(s) extracted</p>
          <div className="max-h-48 overflow-y-auto space-y-1">
            {files.map((f, i) => (
              <div key={i} className="border border-slate-100 rounded-lg p-2 text-xs">
                <p className="font-mono text-slate-800 font-medium truncate">{f.name}</p>
                <div className="flex flex-wrap gap-x-4 gap-y-0.5 mt-0.5 text-slate-400">
                  {f.size != null && <span>{fmtSize(f.size)}</span>}
                  {f.sha256 && (
                    <span className="font-mono">
                      SHA256: {f.sha256.slice(0, 16)}&hellip;
                    </span>
                  )}
                </div>
                {f.sha256 && (
                  <p className="font-mono text-slate-300 text-xs mt-0.5 break-all">{f.sha256}</p>
                )}
              </div>
            ))}
          </div>
        </div>
      ) : (
        <p className="text-xs text-slate-400">
          No files extracted — raw ARM firmware with no embedded filesystems or compressed sections.
        </p>
      )}
    </div>
  );
}

// ── Decompile function list ───────────────────────────────────────────────────

function DecompileFunctions({ functions }: { functions: { name: string; address: string; code: string }[] }) {
  const [open, setOpen] = useState<number | null>(null);
  const [search, setSearch] = useState("");
  const [searchCode, setSearchCode] = useState(false);
  const q = search.toLowerCase();
  const filtered = q
    ? functions.filter(f =>
        f.name.toLowerCase().includes(q) ||
        (searchCode && f.code.toLowerCase().includes(q))
      )
    : functions;
  return (
    <div className="mt-3">
      <p className="text-xs text-slate-600 mb-2 font-medium">{functions.length} function(s) decompiled</p>
      <div className="flex gap-2 items-center mb-2">
        <input
          type="text"
          placeholder="Filter functions…"
          value={search}
          onChange={e => { setSearch(e.target.value); setOpen(null); }}
          className="flex-1 border border-slate-200 rounded-lg px-2.5 py-1.5 text-xs focus:outline-none focus:ring-1 focus:ring-blue-400"
        />
        <label className="flex items-center gap-1 text-xs text-slate-500 whitespace-nowrap cursor-pointer select-none">
          <input
            type="checkbox"
            checked={searchCode}
            onChange={e => setSearchCode(e.target.checked)}
            className="accent-blue-500"
          />
          search code
        </label>
      </div>
      {search && (
        <p className="text-xs text-slate-400 mb-1">
          {filtered.length} match{filtered.length !== 1 ? "es" : ""}{searchCode ? " (name + code)" : " (name)"}
        </p>
      )}
      <div className="max-h-96 overflow-y-auto space-y-1">
        {filtered.map((fn, i) => (
          <div key={i} className="border border-slate-100 rounded-lg overflow-hidden">
            <button
              onClick={() => setOpen(open === i ? null : i)}
              className="w-full flex items-center justify-between px-3 py-1.5 text-left hover:bg-slate-50 transition-colors"
            >
              <span className="font-mono text-xs text-slate-800 truncate">{fn.name}</span>
              <span className="text-xs text-slate-400 ml-2 flex-shrink-0">{fn.address}</span>
            </button>
            {open === i && (
              <pre className="bg-slate-950 text-green-400 text-xs p-3 overflow-x-auto max-h-48 leading-relaxed whitespace-pre-wrap break-all">
                {fn.code}
              </pre>
            )}
          </div>
        ))}
        {filtered.length === 0 && search && (
          <p className="text-xs text-slate-400 text-center py-4">
            No functions match &ldquo;{search}&rdquo;
            {!searchCode && " — try enabling \"search code\""}
          </p>
        )}
      </div>
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

const catStyles: Record<string, { bg: string; label: string }> = {
  PRIVATE_KEY:    { bg: "bg-red-600 text-white",         label: "PRIVATE KEY" },
  CERTIFICATE:    { bg: "bg-red-500 text-white",         label: "CERTIFICATE" },
  API_KEY:        { bg: "bg-orange-500 text-white",      label: "API KEY" },
  CREDENTIAL:     { bg: "bg-orange-600 text-white",      label: "CREDENTIAL" },
  SAFETY_BYPASS:  { bg: "bg-red-500 text-white",         label: "SAFETY BYPASS" },
  FLASH_WRITE:    { bg: "bg-orange-500 text-white",      label: "FLASH WRITE" },
  SHELL_COMMAND:  { bg: "bg-yellow-500 text-white",      label: "SHELL CMD" },
  DEBUG_KEYWORD:  { bg: "bg-yellow-500 text-white",      label: "DEBUG" },
  CRYPTO:         { bg: "bg-purple-500 text-white",      label: "CRYPTO" },
  URL:            { bg: "bg-sky-500 text-white",         label: "URL" },
  IP:             { bg: "bg-sky-500 text-white",         label: "IP" },
  DOMAIN:         { bg: "bg-sky-500 text-white",         label: "DOMAIN" },
  NETWORK_SERVICE:{ bg: "bg-sky-500 text-white",         label: "NETWORK" },
  VERSION:        { bg: "bg-slate-400 text-white",       label: "VERSION" },
  CRITICAL:       { bg: "bg-red-600 text-white",         label: "CRITICAL" },
  HIGH:           { bg: "bg-orange-500 text-white",      label: "HIGH" },
  MEDIUM:         { bg: "bg-yellow-500 text-white",      label: "MEDIUM" },
  LOW:            { bg: "bg-green-500 text-white",       label: "LOW" },
};

function CategoryBadge({ cat }: { cat: string }) {
  const style = catStyles[cat];
  const cls   = style?.bg ?? "bg-slate-200 text-slate-600";
  const label = style?.label ?? cat;
  return (
    <span className={`inline-block rounded-full px-2 py-0.5 text-xs font-bold tracking-wide ${cls}`}>
      {label}
    </span>
  );
}
