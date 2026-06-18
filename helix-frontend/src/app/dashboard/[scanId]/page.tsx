"use client";
import React, { useEffect, useState, useCallback } from "react";
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

function Section({ title, children }: { title: string; children: React.ReactNode }) {
  return (
    <div className="rounded-xl overflow-hidden border border-slate-700/60" style={{ background: "#161b27" }}>
      <div className="px-5 py-3 border-b border-slate-700/50">
        <h2 className="font-semibold text-slate-300 text-sm tracking-tight">{title}</h2>
      </div>
      <div className="p-5">{children}</div>
    </div>
  );
}

function KV({ label, value, mono }: { label: string; value: React.ReactNode; mono?: boolean }) {
  return (
    <div className="flex gap-4 py-2.5 border-b border-slate-700/40 last:border-0">
      <dt className="w-24 flex-shrink-0 text-xs font-semibold text-slate-500 uppercase tracking-wider pt-0.5">
        {label}
      </dt>
      <dd className={`flex-1 text-sm text-slate-200 break-all ${mono ? "font-mono text-xs text-slate-400" : ""}`}>
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
  const [tab, setTab] = useState<"strings" | "yara" | "binwalk" | "tree">("strings");
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
      <div className="flex items-center gap-2 text-xs">
        <button onClick={() => router.push("/dashboard")} className="text-blue-400 hover:text-blue-300 transition-colors">
          Scans
        </button>
        <span className="text-slate-600">/</span>
        <span className="text-slate-400 truncate max-w-xs">{scan.filename}</span>
      </div>

      {/* Title row */}
      <div className="flex items-center gap-4 flex-wrap">
        <div className="flex-1 min-w-0">
          <h1 className="text-xl font-bold text-white truncate">{scan.filename}</h1>
          <p className="text-slate-600 text-xs mt-0.5 font-mono">{scan.id}</p>
        </div>
        <div className="flex items-center gap-3">
          {scan.status === "completed" && (
            <>
              <a
                href={`/dashboard/diff?a=${scanId}`}
                className="flex items-center gap-2 bg-slate-800 border border-slate-700 hover:bg-slate-700 text-slate-300 text-xs font-medium px-3.5 py-2 rounded-lg transition-colors"
              >
                <svg width="13" height="13" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2" strokeLinecap="round" strokeLinejoin="round"><line x1="18" y1="20" x2="18" y2="10"/><line x1="12" y1="20" x2="12" y2="4"/><line x1="6" y1="20" x2="6" y2="14"/></svg>
                Compare
              </a>
              <button
                onClick={handleDownloadPdf}
                disabled={downloadingPdf}
                className="flex items-center gap-2 bg-slate-800 border border-slate-700 hover:bg-slate-700 disabled:opacity-50 text-slate-300 text-xs font-medium px-3.5 py-2 rounded-lg transition-colors"
              >
                {downloadingPdf ? <Spinner size={13} /> : (
                  <svg width="13" height="13" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2" strokeLinecap="round" strokeLinejoin="round"><path d="M14 2H6a2 2 0 0 0-2 2v16a2 2 0 0 0 2 2h12a2 2 0 0 0 2-2V8z"/><polyline points="14 2 14 8 20 8"/><line x1="16" y1="13" x2="8" y2="13"/><line x1="16" y1="17" x2="8" y2="17"/><polyline points="10 9 9 9 8 9"/></svg>
                )}
                {downloadingPdf ? "Generating…" : "PDF"}
              </button>
            </>
          )}
          <StatusBadge status={scan.status} />
        </div>
      </div>
      {pdfError && <p className="text-xs text-red-400 -mt-2">{pdfError}</p>}

      {/* Pending / Running banner */}
      {(scan.status === "pending" || scan.status === "running") && (
        <div className="flex items-center gap-3 bg-blue-950/40 border border-blue-800/40 rounded-xl px-5 py-4 text-blue-300">
          <Spinner size={18} />
          <div>
            <p className="font-semibold text-sm">
              {scan.status === "pending" ? "Analysis queued…" : "Analysing firmware…"}
            </p>
            <p className="text-xs opacity-60 mt-0.5">Page refreshes automatically every 2.5 s</p>
          </div>
        </div>
      )}

      {/* Failed banner */}
      {scan.status === "failed" && (
        <div className="bg-red-950/40 border border-red-800/40 rounded-xl px-5 py-4 text-red-300">
          <p className="font-semibold text-sm">Analysis failed</p>
          {scan.error_message && (
            <p className="text-xs font-mono mt-1 opacity-70">{scan.error_message}</p>
          )}
        </div>
      )}

      {/* Risk + File side by side */}
      {scan.status === "completed" && report && (
        <>
          <div className="grid grid-cols-1 md:grid-cols-2 gap-4">
            {/* Risk card */}
            <div className={`rounded-xl overflow-hidden border-2 ${
              scan.risk_level === "critical" ? "border-red-500" :
              scan.risk_level === "high"     ? "border-orange-400" :
              scan.risk_level === "medium"   ? "border-yellow-400" :
              scan.risk_level === "low"      ? "border-green-500" :
                                               "border-slate-700"
            }`} style={{ background: "#161b27" }}>
              <div className="px-5 py-3 border-b border-slate-700/50">
                <h2 className="font-semibold text-slate-300 text-sm tracking-tight">Risk Assessment</h2>
              </div>
              <div className="p-5">
                <div className="flex flex-col items-center mb-4">
                  <RiskGauge score={scan.risk_score ?? 0} level={scan.risk_level ?? "informational"} />
                  <div className="mt-2 text-center">
                    <RiskBadge level={scan.risk_level ?? "informational"} score={scan.risk_score} large />
                    <p className="text-xs text-slate-500 mt-1">
                      {yaraMatches.length} YARA · {suspicious.length} strings
                    </p>
                  </div>
                </div>
                {riskInfo.reasons?.length > 0 && (
                  <ul className="space-y-1.5 border-t border-slate-700/40 pt-3">
                    {riskInfo.reasons.map((r: string, i: number) => (
                      <li key={i} className="flex items-start gap-2 text-xs text-slate-300">
                        <span className={`mt-0.5 text-base leading-none ${
                          r.toLowerCase().includes("critical") || r.toLowerCase().includes("safety") || r.toLowerCase().includes("unsigned") ? "text-red-400" :
                          r.toLowerCase().includes("high") || r.toLowerCase().includes("flash") || r.toLowerCase().includes("hidden") ? "text-orange-400" :
                          r.toLowerCase().includes("medium") || r.toLowerCase().includes("debug") ? "text-yellow-400" :
                          "text-slate-500"
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
                <KV label="Name"    value={<span className="font-medium text-slate-200 truncate block max-w-xs">{fileInfo.name}</span>} />
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
            <div className="flex gap-1 mb-5 border-b border-slate-700/50 pb-0">
              {(
                [
                  ["strings", "Strings", suspicious.length],
                  ["yara",    "YARA",    yaraMatches.length],
                  ["binwalk", "Binwalk", binwalkFindings.length],
                  ["tree",    "Pipeline Tree", null],
                ] as [typeof tab, string, number | null][]
              ).map(([t, label, count]) => (
                <button
                  key={t}
                  onClick={() => setTab(t)}
                  className={`px-4 py-2 text-sm font-medium border-b-2 transition-colors ${
                    tab === t
                      ? "border-blue-500 text-blue-400"
                      : "border-transparent text-slate-500 hover:text-slate-300"
                  }`}
                >
                  {label}
                  {count !== null && (
                    <span className={`ml-1.5 text-xs px-1.5 py-0.5 rounded-full font-semibold ${
                      tab === t ? "bg-blue-900/50 text-blue-400" : "bg-slate-800 text-slate-500"
                    }`}>{count}</span>
                  )}
                </button>
              ))}
            </div>

            {/* Strings tab */}
            {tab === "strings" && (
              suspicious.length === 0 ? (
                <div className="text-center py-8 text-slate-500">
                  <p className="text-sm">No suspicious strings found.</p>
                </div>
              ) : (
                <div className="rounded-lg border border-slate-700/40 overflow-hidden">
                  <div className="max-h-[480px] overflow-y-auto divide-y divide-slate-700/30">
                    {suspicious.map((s, i) => (
                      <div key={i} className="flex items-center gap-3 px-3 py-2 hover:bg-slate-800/40 transition-colors">
                        <span className="w-32 flex-shrink-0">
                          <CategoryBadge cat={s.category} />
                        </span>
                        <span className="font-mono text-xs text-slate-300 break-all flex-1 leading-relaxed">
                          {s.value.length > 140 ? s.value.slice(0, 140) + "…" : s.value}
                        </span>
                        <span className="text-xs text-slate-600 font-mono whitespace-nowrap">
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
                <div className="text-center py-8 text-slate-500">
                  <p className="text-sm">No YARA rule matches detected.</p>
                </div>
              ) : (
                <div className="space-y-3">
                  {yaraMatches.map((m, i) => {
                    const sev = (m.severity ?? "low").toLowerCase();
                    const borderCls =
                      sev === "critical" ? "border-l-red-500 bg-red-950/20" :
                      sev === "high"     ? "border-l-orange-400 bg-orange-950/20" :
                      sev === "medium"   ? "border-l-yellow-400 bg-yellow-950/20" :
                                           "border-l-slate-600 bg-slate-800/20";
                    const deduped = m.strings ? dedupeStrings(m.strings) : [];
                    // Only show printable string matches, skip binary-only hits
                    const printable = deduped.filter(s => {
                      const cleaned = cleanYaraData(s.data);
                      return !cleaned.startsWith("\\x") && cleaned.length > 0;
                    });
                    return (
                      <div key={i} className={`border border-l-4 border-slate-700/40 rounded-lg p-4 ${borderCls}`}>
                        <div className="flex items-center justify-between gap-3 mb-2">
                          <span className="font-semibold text-slate-200 text-sm">{m.rule}</span>
                          {m.severity && <CategoryBadge cat={m.severity.toUpperCase()} />}
                        </div>
                        {printable.length > 0 && (
                          <div className="flex flex-wrap gap-2 mt-1">
                            {printable.map((s, j) => (
                              <code key={j} className="inline-flex items-center gap-1 text-xs bg-slate-900/60 border border-slate-700 rounded px-2 py-0.5 font-mono">
                                <span className="text-slate-500">{s.identifier}:</span>
                                <span className="text-slate-200 font-semibold">{cleanYaraData(s.data)}</span>
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
                <p className="text-slate-500 text-sm">No binwalk findings.</p>
              ) : (
                <div className="space-y-1">
                  {binwalkFindings.map((f, i) => (
                    <div
                      key={i}
                      className="flex items-start gap-4 py-1.5 border-b border-slate-700/30 last:border-0 text-sm"
                    >
                      <span className="font-mono text-xs text-slate-500 w-20 flex-shrink-0">
                        0x{(f.offset ?? 0).toString(16).padStart(6, "0")}
                      </span>
                      <span className="text-slate-300">{f.description}</span>
                    </div>
                  ))}
                </div>
              )
            )}
            {/* Pipeline Tree tab */}
            {tab === "tree" && (
              <PipelineTree
                filename={scan.filename}
                report={report}
                riskScore={scan.risk_score ?? 0}
                riskLevel={scan.risk_level ?? "informational"}
              />
            )}
          </Section>

          {/* Deep analysis: extract / decompile */}
          <Section title="Deep Analysis">
            {/* Action bar — horizontal rows */}
            <div className="space-y-2 mb-5">
              {/* Binwalk row */}
              <div className="flex items-center gap-4 px-4 py-3 rounded-lg border border-slate-700/40" style={{ background: "rgba(13,17,23,0.5)" }}>
                <div className="flex-1 min-w-0">
                  <div className="flex items-center gap-2.5 flex-wrap">
                    <p className="text-sm font-semibold text-slate-200">Binwalk Extraction</p>
                    <JobStatusPill status={scan.extraction_status} />
                  </div>
                  <p className="text-xs text-slate-600 mt-0.5">Extracts embedded filesystems — listed only, never executed.</p>
                  {extractError && <p className="text-xs text-red-400 mt-1">{extractError}</p>}
                  {scan.extraction_error && <p className="text-xs text-slate-500 mt-1">⚠ {scan.extraction_error}</p>}
                </div>
                <button
                  onClick={handleExtract}
                  disabled={triggeringExtract || scan.extraction_status === "pending" || scan.extraction_status === "running"}
                  className="flex items-center gap-2 bg-blue-600 hover:bg-blue-500 disabled:opacity-40 text-white text-xs font-semibold px-3.5 py-2 rounded-lg transition-colors flex-shrink-0"
                >
                  {triggeringExtract && <Spinner size={12} />}
                  {scan.extraction_status ? "Re-run" : "Run Extraction"}
                </button>
              </div>

              {/* Ghidra row */}
              <div className="flex items-center gap-4 px-4 py-3 rounded-lg border border-slate-700/40" style={{ background: "rgba(13,17,23,0.5)" }}>
                <div className="flex-1 min-w-0">
                  <div className="flex items-center gap-2.5 flex-wrap">
                    <p className="text-sm font-semibold text-slate-200">Ghidra Decompile</p>
                    <JobStatusPill status={scan.decompile_status} />
                  </div>
                  <p className="text-xs text-slate-600 mt-0.5">Static disassembly — never executes. Requires Ghidra on server.</p>
                  {decompileError && <p className="text-xs text-red-400 mt-1">{decompileError}</p>}
                  {scan.decompile_error && <p className="text-xs text-slate-500 mt-1">⚠ {scan.decompile_error}</p>}
                </div>
                <button
                  onClick={() => setShowProcessorModal(true)}
                  disabled={triggeringDecompile || scan.decompile_status === "pending" || scan.decompile_status === "running"}
                  className="flex items-center gap-2 bg-blue-600 hover:bg-blue-500 disabled:opacity-40 text-white text-xs font-semibold px-3.5 py-2 rounded-lg transition-colors flex-shrink-0"
                >
                  {triggeringDecompile && <Spinner size={12} />}
                  {scan.decompile_status ? "Re-run" : "Run Decompile"}
                </button>
              </div>
            </div>

            {/* Extraction results — full width */}
            {scan.extraction_status === "completed" && scan.extraction && (
              <div className="mb-4">
                <p className="text-xs font-semibold text-slate-400 uppercase tracking-wide mb-2">Extraction Results</p>
                <ExtractionResults extraction={scan.extraction} />
              </div>
            )}

            {/* Decompile tree — full width */}
            {scan.decompile?.functions && scan.decompile.functions.length > 0 && (
              <div>
                <p className="text-xs font-semibold text-slate-400 uppercase tracking-wide mb-2">Decompiled Functions</p>
                <DecompileFunctions functions={scan.decompile.functions} />
              </div>
            )}
          </Section>
        </>
      )}
      {/* Processor selection modal */}
      {showProcessorModal && (
        <div className="fixed inset-0 z-50 flex items-center justify-center bg-black/60">
          <div className="rounded-2xl shadow-2xl p-6 w-full max-w-md mx-4 border border-slate-700" style={{ background: "#161b27" }}>
            <h3 className="text-base font-semibold text-slate-200 mb-1">Ghidra Decompile Settings</h3>
            <p className="text-xs text-slate-500 mb-4">
              For ELF/PE binaries, leave processor as Auto. For raw firmware (STM32, MIPS, etc.) select the CPU architecture.
            </p>

            <label className="block text-xs font-medium text-slate-400 mb-1">Processor Architecture</label>
            <select
              value={selectedProcessor}
              onChange={e => setSelectedProcessor(e.target.value)}
              className="w-full border border-slate-700 bg-slate-900/60 rounded-lg px-3 py-2 text-sm text-slate-200 mb-4 focus:outline-none focus:ring-2 focus:ring-blue-500"
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

            <label className="block text-xs font-medium text-slate-400 mb-1">
              Base Load Address <span className="text-slate-600 font-normal">(for raw binaries)</span>
            </label>
            <input
              type="text"
              value={baseAddress}
              onChange={e => setBaseAddress(e.target.value)}
              placeholder="e.g. 0x08000000"
              className="w-full border border-slate-700 bg-slate-900/60 rounded-lg px-3 py-2 text-sm font-mono text-slate-200 mb-5 focus:outline-none focus:ring-2 focus:ring-blue-500 placeholder:text-slate-600"
            />

            <div className="flex gap-2 justify-end">
              <button
                onClick={() => setShowProcessorModal(false)}
                className="px-4 py-2 text-sm text-slate-400 hover:bg-slate-800 rounded-lg transition-colors"
              >
                Cancel
              </button>
              <button
                onClick={() => handleDecompile(selectedProcessor || undefined, baseAddress || undefined)}
                className="px-4 py-2 text-sm font-semibold bg-blue-600 hover:bg-blue-500 text-white rounded-lg transition-colors"
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
          <p className="text-xs font-medium text-slate-400 mb-1">{findings.length} signature(s) detected</p>
          <div className="max-h-36 overflow-y-auto space-y-0.5 bg-slate-900/60 rounded-lg px-2 py-1.5">
            {findings.map((f, i) => (
              <div key={i} className="flex gap-2 text-xs">
                <span className="font-mono text-slate-500 w-20 flex-shrink-0">{f.hex_offset}</span>
                <span className="text-slate-400 truncate">{f.description}</span>
              </div>
            ))}
          </div>
        </div>
      ) : (
        <p className="text-xs text-slate-500">No embedded signatures detected by binwalk.</p>
      )}

      {/* Extracted files with hashes */}
      {files.length > 0 ? (
        <div>
          <p className="text-xs font-medium text-slate-400 mb-1">{files.length} file(s) extracted</p>
          <div className="max-h-48 overflow-y-auto space-y-1">
            {files.map((f, i) => (
              <div key={i} className="border border-slate-700/40 rounded-lg p-2 text-xs">
                <p className="font-mono text-slate-200 font-medium truncate">{f.name}</p>
                <div className="flex flex-wrap gap-x-4 gap-y-0.5 mt-0.5 text-slate-500">
                  {f.size != null && <span>{fmtSize(f.size)}</span>}
                  {f.sha256 && (
                    <span className="font-mono">
                      SHA256: {f.sha256.slice(0, 16)}&hellip;
                    </span>
                  )}
                </div>
                {f.sha256 && (
                  <p className="font-mono text-slate-600 text-xs mt-0.5 break-all">{f.sha256}</p>
                )}
              </div>
            ))}
          </div>
        </div>
      ) : (
        <p className="text-xs text-slate-500">
          No files extracted — raw ARM firmware with no embedded filesystems or compressed sections.
        </p>
      )}
    </div>
  );
}

// ── Decompile function tree ───────────────────────────────────────────────────

type FnEntry = { name: string; address: string; code: string };

function groupByBlock(fns: FnEntry[], blockSize = 0x1000) {
  const map = new Map<number, FnEntry[]>();
  for (const fn of fns) {
    const addr = parseInt(fn.address, 16) || 0;
    const blockStart = Math.floor(addr / blockSize) * blockSize;
    if (!map.has(blockStart)) map.set(blockStart, []);
    map.get(blockStart)!.push(fn);
  }
  return Array.from(map.entries())
    .sort(([a], [b]) => a - b)
    .map(([start, items]) => ({
      key:   `0x${start.toString(16).padStart(8, "0")}`,
      range: `0x${start.toString(16).padStart(8, "0")} – 0x${(start + blockSize - 1).toString(16).padStart(8, "0")}`,
      items,
    }));
}

function DecompileFunctions({ functions }: { functions: FnEntry[] }) {
  const [openGroups, setOpenGroups] = useState<Set<string>>(() => new Set());
  const [openFn, setOpenFn]         = useState<string | null>(null);
  const [search, setSearch]         = useState("");
  const [searchCode, setSearchCode] = useState(false);

  const q        = search.toLowerCase();
  const filtered = q
    ? functions.filter(f =>
        f.name.toLowerCase().includes(q) ||
        f.address.toLowerCase().includes(q) ||
        (searchCode && f.code.toLowerCase().includes(q))
      )
    : functions;
  const groups = groupByBlock(filtered);
  const maxFn  = Math.max(1, ...groups.map(g => g.items.length));

  // Address range bounds
  const allAddrs = functions.map(f => parseInt(f.address, 16) || 0);
  const minAddr  = allAddrs.length ? Math.min(...allAddrs) : 0;
  const maxAddr  = allAddrs.length ? Math.max(...allAddrs) : 0;

  function toggleGroup(key: string) {
    setOpenGroups(prev => {
      const next = new Set(prev);
      next.has(key) ? next.delete(key) : next.add(key);
      return next;
    });
  }

  function densityColor(count: number) {
    const pct = count / maxFn;
    if (pct > 0.75) return { bar: "bg-red-500",    text: "text-red-400" };
    if (pct > 0.45) return { bar: "bg-amber-500",   text: "text-amber-400" };
    if (pct > 0.20) return { bar: "bg-blue-500",    text: "text-blue-400" };
    return              { bar: "bg-slate-600",    text: "text-slate-500" };
  }

  const allOpen = openGroups.size === groups.length && groups.length > 0;

  return (
    <div className="space-y-3">
      {/* Top bar */}
      <div className="flex items-center gap-3 flex-wrap">
        <div className="relative flex-1 min-w-[180px]">
          <svg className="absolute left-2.5 top-1/2 -translate-y-1/2 text-slate-600 pointer-events-none" width="11" height="11" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2.5" strokeLinecap="round" strokeLinejoin="round"><circle cx="11" cy="11" r="8"/><line x1="21" y1="21" x2="16.65" y2="16.65"/></svg>
          <input
            type="text"
            placeholder={`Search ${functions.length} functions…`}
            value={search}
            onChange={e => { setSearch(e.target.value); setOpenFn(null); }}
            className="w-full border border-slate-700/60 bg-[#0d1117] text-slate-200 rounded-lg pl-7 pr-3 py-1.5 text-xs focus:outline-none focus:ring-1 focus:ring-blue-500/60 placeholder:text-slate-600"
          />
        </div>
        <label className="flex items-center gap-1.5 text-xs text-slate-600 cursor-pointer select-none whitespace-nowrap">
          <input type="checkbox" checked={searchCode} onChange={e => setSearchCode(e.target.checked)} className="accent-blue-500 w-3 h-3" />
          incl. code
        </label>
        <button
          onClick={() => setOpenGroups(allOpen ? new Set() : new Set(groups.map(g => g.key)))}
          className="text-xs text-slate-500 hover:text-slate-300 transition-colors whitespace-nowrap px-2 py-1 rounded border border-slate-700/40 hover:border-slate-600"
        >
          {allOpen ? "Collapse all" : "Expand all"}
        </button>
      </div>

      {/* Stats strip */}
      <div className="flex items-center gap-4 px-3 py-1.5 rounded-lg bg-slate-900/40 border border-slate-800/40 text-xs font-mono">
        <span className="text-slate-400"><span className="text-white font-semibold">{search ? filtered.length : functions.length}</span> fn</span>
        <span className="text-slate-700">·</span>
        <span className="text-slate-400"><span className="text-white font-semibold">{groups.length}</span> blocks</span>
        <span className="text-slate-700">·</span>
        <span className="text-slate-500">
          {`0x${minAddr.toString(16).padStart(8, "0")}`}
          <span className="text-slate-700 mx-1">→</span>
          {`0x${maxAddr.toString(16).padStart(8, "0")}`}
        </span>
        {search && <span className="text-slate-600 ml-auto">&ldquo;{search}&rdquo; · {filtered.length} match{filtered.length !== 1 ? "es" : ""}</span>}
      </div>

      {/* Memory block table */}
      <div className="rounded-xl border border-slate-700/40 overflow-hidden" style={{ background: "#0d1117" }}>
        {/* Column headers */}
        <div className="grid grid-cols-[1.5rem_9rem_1fr_4.5rem] gap-0 px-4 py-2 border-b border-slate-800/60 bg-slate-900/30">
          <span />
          <span className="text-[10px] font-bold uppercase tracking-widest text-slate-600">Address</span>
          <span className="text-[10px] font-bold uppercase tracking-widest text-slate-600 pl-3">Density</span>
          <span className="text-[10px] font-bold uppercase tracking-widest text-slate-600 text-right">Fn</span>
        </div>

        {groups.length === 0 ? (
          <p className="text-xs text-slate-600 text-center py-10">No functions match &ldquo;{search}&rdquo;</p>
        ) : (
          <div className="divide-y divide-slate-800/40">
            {groups.map(({ key, items }) => {
              const isOpen = openGroups.has(key);
              const { bar: barColor, text: textColor } = densityColor(items.length);
              const barPct = Math.max(4, Math.round((items.length / maxFn) * 100));

              return (
                <div key={key}>
                  {/* Block row */}
                  <button
                    onClick={() => toggleGroup(key)}
                    className="w-full grid grid-cols-[1.5rem_9rem_1fr_4.5rem] gap-0 px-4 py-2.5 items-center text-left hover:bg-slate-800/20 transition-colors group"
                  >
                    {/* Expand chevron */}
                    <svg
                      className={`w-3 h-3 text-slate-600 group-hover:text-slate-400 transition-all flex-shrink-0 ${isOpen ? "rotate-90" : ""}`}
                      viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2.5" strokeLinecap="round" strokeLinejoin="round"
                    >
                      <polyline points="9 18 15 12 9 6"/>
                    </svg>

                    {/* Start address */}
                    <span className="font-mono text-xs text-slate-300 tracking-tight">{key}</span>

                    {/* Density bar */}
                    <div className="flex items-center gap-2 pl-3">
                      <div className="flex-1 h-1.5 bg-slate-800 rounded-full overflow-hidden max-w-[160px]">
                        <div
                          className={`h-full rounded-full transition-all ${barColor}`}
                          style={{ width: `${barPct}%` }}
                        />
                      </div>
                    </div>

                    {/* Count */}
                    <span className={`text-right text-xs font-mono font-semibold ${textColor}`}>
                      {items.length}
                    </span>
                  </button>

                  {/* Expanded: function list */}
                  {isOpen && (
                    <div className="border-t border-slate-800/40 bg-[#080d14]">
                      {/* Function rows — 2 columns on wider screens */}
                      <div className="divide-y divide-slate-800/30">
                        {items.map((fn, idx) => {
                          const fnKey = `${key}:${idx}`;
                          const isFnOpen = openFn === fnKey;
                          return (
                            <div key={fnKey}>
                              <button
                                onClick={() => setOpenFn(isFnOpen ? null : fnKey)}
                                className="w-full flex items-center gap-3 pl-10 pr-4 py-1.5 text-left hover:bg-slate-800/20 transition-colors group"
                              >
                                {/* tiny fn chevron */}
                                <svg
                                  className={`w-2.5 h-2.5 flex-shrink-0 transition-all ${isFnOpen ? "rotate-90 text-blue-400" : "text-slate-700 group-hover:text-slate-500"}`}
                                  viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2.5" strokeLinecap="round" strokeLinejoin="round"
                                >
                                  <polyline points="9 18 15 12 9 6"/>
                                </svg>
                                {/* address */}
                                <span className="font-mono text-[11px] text-slate-600 flex-shrink-0 w-24">{fn.address}</span>
                                {/* name */}
                                <span className="font-mono text-[11px] text-slate-300 truncate flex-1">
                                  {fn.name}
                                </span>
                                {/* line count hint */}
                                {fn.code && (
                                  <span className="text-[10px] text-slate-700 flex-shrink-0 font-mono">
                                    {fn.code.split("\n").length}L
                                  </span>
                                )}
                              </button>
                              {isFnOpen && (
                                <pre className="text-[11px] leading-relaxed font-mono text-emerald-300/90 bg-[#060b10] pl-16 pr-4 py-3 overflow-x-auto max-h-80 whitespace-pre-wrap break-all border-t border-slate-800/40">
                                  {fn.code || "(no pseudocode)"}
                                </pre>
                              )}
                            </div>
                          );
                        })}
                      </div>
                    </div>
                  )}
                </div>
              );
            })}
          </div>
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
    pending:   "bg-slate-800 text-slate-400",
    running:   "bg-blue-900/50 text-blue-300",
    completed: "bg-emerald-900/50 text-emerald-400",
    failed:    "bg-red-900/50 text-red-400",
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

// ── Pipeline Tree ─────────────────────────────────────────────────────────────

type PhaseAccent = "normal" | "ok" | "warn" | "danger";

function PhaseSection({
  num, icon, title, summary, accent = "normal", defaultOpen = false, children,
}: {
  num: string;
  icon: React.ReactNode;
  title: string;
  summary: React.ReactNode;
  accent?: PhaseAccent;
  defaultOpen?: boolean;
  children?: React.ReactNode;
}) {
  const [open, setOpen] = useState(defaultOpen);

  const borderCls =
    accent === "danger" ? "border-l-red-500/70" :
    accent === "warn"   ? "border-l-amber-500/60" :
    accent === "ok"     ? "border-l-emerald-500/50" :
                          "border-l-slate-700/40";

  const numCls =
    accent === "danger" ? "bg-red-500/10 text-red-400 ring-red-500/20" :
    accent === "warn"   ? "bg-amber-500/10 text-amber-400 ring-amber-500/20" :
    accent === "ok"     ? "bg-emerald-500/10 text-emerald-400 ring-emerald-500/20" :
                          "bg-slate-800/60 text-slate-500 ring-slate-700/30";

  const iconCls =
    accent === "danger" ? "text-red-400" :
    accent === "warn"   ? "text-amber-400" :
    accent === "ok"     ? "text-emerald-400" :
                          "text-slate-500";

  return (
    <div className={`border-l-2 ${borderCls} rounded-r-xl overflow-hidden`} style={{ background: "#161b27" }}>
      <button
        onClick={() => setOpen(o => !o)}
        className="w-full flex items-center gap-3 px-4 py-3 text-left hover:bg-slate-800/20 transition-colors group"
      >
        {/* Phase number */}
        <span className={`text-[10px] font-bold font-mono rounded-md px-1.5 py-0.5 ring-1 flex-shrink-0 ${numCls}`}>
          {num}
        </span>
        {/* Icon */}
        <span className={`flex-shrink-0 ${iconCls}`}>{icon}</span>
        {/* Title */}
        <span className="text-sm font-semibold text-slate-200 flex-1 text-left">{title}</span>
        {/* Summary */}
        <span className="text-xs text-slate-500 font-mono mr-2 hidden sm:block">{summary}</span>
        {/* Chevron */}
        {children && (
          <svg
            className={`w-3.5 h-3.5 text-slate-600 group-hover:text-slate-400 transition-all flex-shrink-0 ${open ? "rotate-90" : ""}`}
            viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2.5" strokeLinecap="round" strokeLinejoin="round"
          >
            <polyline points="9 18 15 12 9 6"/>
          </svg>
        )}
      </button>

      {open && children && (
        <div className="px-4 pb-3 border-t border-slate-800/40">
          {children}
        </div>
      )}
    </div>
  );
}

// SVG icon set for pipeline phases
const PhaseIcons = {
  hash: (
    <svg width="14" height="14" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="1.75" strokeLinecap="round" strokeLinejoin="round">
      <line x1="4" y1="9" x2="20" y2="9"/><line x1="4" y1="15" x2="20" y2="15"/>
      <line x1="10" y1="3" x2="8" y2="21"/><line x1="16" y1="3" x2="14" y2="21"/>
    </svg>
  ),
  entropy: (
    <svg width="14" height="14" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="1.75" strokeLinecap="round" strokeLinejoin="round">
      <polyline points="22 12 18 12 15 21 9 3 6 12 2 12"/>
    </svg>
  ),
  strings: (
    <svg width="14" height="14" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="1.75" strokeLinecap="round" strokeLinejoin="round">
      <circle cx="11" cy="11" r="8"/><line x1="21" y1="21" x2="16.65" y2="16.65"/>
    </svg>
  ),
  yara: (
    <svg width="14" height="14" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="1.75" strokeLinecap="round" strokeLinejoin="round">
      <circle cx="12" cy="12" r="10"/><circle cx="12" cy="12" r="4"/><line x1="21.17" y1="8" x2="12" y2="8"/><line x1="3.95" y1="6.06" x2="8.54" y2="14"/><line x1="10.88" y1="21.94" x2="15.46" y2="14"/>
    </svg>
  ),
  binwalk: (
    <svg width="14" height="14" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="1.75" strokeLinecap="round" strokeLinejoin="round">
      <rect x="2" y="3" width="20" height="14" rx="2"/><line x1="8" y1="21" x2="16" y2="21"/><line x1="12" y1="17" x2="12" y2="21"/>
    </svg>
  ),
  risk: (
    <svg width="14" height="14" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="1.75" strokeLinecap="round" strokeLinejoin="round">
      <path d="M12 22s8-4 8-10V5l-8-3-8 3v7c0 6 8 10 8 10z"/>
    </svg>
  ),
};

function PipelineTree({
  filename, report, riskScore, riskLevel,
}: {
  filename: string;
  // eslint-disable-next-line @typescript-eslint/no-explicit-any
  report: Record<string, any> | null;
  riskScore: number;
  riskLevel: string;
}) {
  if (!report) return <p className="text-slate-500 text-sm text-center py-8">No report data.</p>;

  const hashes   = report.file?.hashes ?? {};
  const entropy  = report.entropy ?? {};
  const stringsR = report.strings ?? {};
  const yaraR    = report.yara ?? {};
  const binwalkR = report.binwalk ?? {};
  const riskR    = report.risk ?? {};

  // Group suspicious strings by category
  const byCategory: Record<string, { value: string; offset: number }[]> = {};
  for (const s of (stringsR.suspicious ?? [])) {
    if (!byCategory[s.category]) byCategory[s.category] = [];
    byCategory[s.category].push(s);
  }
  const catOrder = ["SAFETY_BYPASS", "PRIVATE_KEY", "CERTIFICATE", "API_KEY", "CREDENTIAL",
    "FLASH_WRITE", "SHELL_COMMAND", "DEBUG_KEYWORD", "CRYPTO", "URL", "IP", "DOMAIN",
    "NETWORK_SERVICE", "VERSION"];

  const riskLevelColor =
    riskLevel === "critical" ? "text-red-400" :
    riskLevel === "high"     ? "text-orange-400" :
    riskLevel === "medium"   ? "text-yellow-400" :
    riskLevel === "low"      ? "text-green-400"  : "text-slate-400";

  const entropyAccent: PhaseAccent = entropy.overall > 7.5 ? "danger" : entropy.overall > 6 ? "warn" : "normal";
  const strAccent: PhaseAccent     = (stringsR.suspicious_count ?? 0) > 5 ? "danger"
    : (stringsR.suspicious_count ?? 0) > 0 ? "warn" : "ok";
  const yaraAccent: PhaseAccent    = (yaraR.matches ?? []).some((m: {severity?: string}) => m.severity === "critical") ? "danger"
    : (yaraR.matches ?? []).length > 0 ? "warn" : "ok";
  const riskAccent: PhaseAccent    = riskLevel === "critical" ? "danger" : riskLevel === "high" ? "warn"
    : riskLevel === "medium" ? "warn" : riskLevel === "low" ? "ok" : "normal";

  return (
    <div className="space-y-1.5">
      {/* File header */}
      <div className="flex items-center justify-between px-4 py-3 rounded-xl border border-slate-700/40" style={{ background: "#161b27" }}>
        <div className="flex items-center gap-3 min-w-0">
          <svg className="text-slate-500 flex-shrink-0" width="15" height="15" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="1.75" strokeLinecap="round" strokeLinejoin="round">
            <path d="M14 2H6a2 2 0 0 0-2 2v16a2 2 0 0 0 2 2h12a2 2 0 0 0 2-2V8z"/><polyline points="14 2 14 8 20 8"/>
          </svg>
          <span className="font-mono text-sm font-semibold text-white truncate">{filename}</span>
        </div>
        <div className="flex items-center gap-2 flex-shrink-0 ml-4">
          <span className={`font-mono text-xs font-bold ${riskLevelColor}`}>{Math.round(riskScore)}/100</span>
          <span className={`text-[10px] font-bold uppercase tracking-widest px-2 py-0.5 rounded-md ${
            riskLevel === "critical" ? "bg-red-900/50 text-red-300" :
            riskLevel === "high"     ? "bg-orange-900/50 text-orange-300" :
            riskLevel === "medium"   ? "bg-yellow-900/40 text-yellow-300" :
            riskLevel === "low"      ? "bg-green-900/40 text-green-300" :
                                       "bg-slate-800 text-slate-400"
          }`}>{riskLevel}</span>
        </div>
      </div>

      {/* Phase 01 — File Identity */}
      <PhaseSection
        num="01" icon={PhaseIcons.hash} title="File Identity"
        summary={hashes.sha256 ? `${hashes.sha256.slice(0, 16)}…` : "—"}
        accent="normal" defaultOpen
      >
        <div className="mt-2 space-y-1.5">
          {[
            ["SHA-256", hashes.sha256],
            ["SHA-1",   hashes.sha1],
            ["MD5",     hashes.md5],
          ].map(([label, val]) => (
            <div key={label} className="flex items-center gap-3">
              <span className="text-[10px] font-bold text-slate-600 uppercase tracking-widest w-14 flex-shrink-0">{label}</span>
              <span className="font-mono text-[11px] text-slate-400 break-all">{val ?? "—"}</span>
            </div>
          ))}
        </div>
      </PhaseSection>

      {/* Phase 02 — Entropy */}
      <PhaseSection
        num="02" icon={PhaseIcons.entropy} title="Entropy Analysis"
        summary={`${(entropy.overall ?? 0).toFixed(3)} / 8.000`}
        accent={entropyAccent} defaultOpen={entropyAccent !== "normal"}
      >
        <div className="mt-2 space-y-2">
          <div className="flex items-center gap-3">
            <div className="flex-1 h-2 bg-slate-800 rounded-full overflow-hidden">
              <div
                className={`h-full rounded-full ${entropy.overall > 7.5 ? "bg-red-500" : entropy.overall > 6 ? "bg-amber-500" : "bg-blue-500"}`}
                style={{ width: `${Math.min(100, ((entropy.overall ?? 0) / 8) * 100).toFixed(1)}%` }}
              />
            </div>
            <span className="font-mono text-xs text-slate-400 w-16 text-right">{(entropy.overall ?? 0).toFixed(3)}</span>
          </div>
          <p className="text-xs text-slate-500">{entropy.interpretation ?? "—"}</p>
          {entropy.blocks?.length > 0 && (
            <p className="text-[11px] text-slate-600 font-mono">{entropy.blocks.length} blocks analyzed · 1 KB each</p>
          )}
        </div>
      </PhaseSection>

      {/* Phase 03 — String Extraction */}
      <PhaseSection
        num="03" icon={PhaseIcons.strings} title="String Extraction"
        summary={`${stringsR.total ?? 0} total · ${stringsR.suspicious_count ?? 0} suspicious`}
        accent={strAccent} defaultOpen={(stringsR.suspicious_count ?? 0) > 0}
      >
        <div className="mt-2 space-y-2">
          {(stringsR.suspicious_count ?? 0) === 0 ? (
            <p className="text-xs text-emerald-500">No suspicious strings found.</p>
          ) : catOrder.map(cat => {
            const items = byCategory[cat];
            if (!items?.length) return null;
            const catLabel = catStyles[cat]?.label ?? cat;
            const isCritCat = ["SAFETY_BYPASS", "PRIVATE_KEY", "CERTIFICATE"].includes(cat);
            const isWarnCat = ["FLASH_WRITE", "API_KEY", "CREDENTIAL", "SHELL_COMMAND", "DEBUG_KEYWORD"].includes(cat);
            const headerCls = isCritCat ? "text-red-400" : isWarnCat ? "text-amber-400" : "text-slate-400";
            return (
              <div key={cat}>
                <div className="flex items-center gap-2 mb-1">
                  <span className={`text-[10px] font-bold uppercase tracking-widest ${headerCls}`}>{catLabel}</span>
                  <span className="text-[10px] text-slate-600">({items.length})</span>
                </div>
                <div className="space-y-0.5 pl-2 border-l border-slate-800">
                  {items.slice(0, 6).map((s, i) => (
                    <div key={i} className="flex items-center gap-2">
                      <span className="font-mono text-[11px] text-slate-400 truncate flex-1">{s.value}</span>
                      <span className="font-mono text-[10px] text-slate-700 flex-shrink-0">
                        0x{s.offset.toString(16).padStart(6, "0")}
                      </span>
                    </div>
                  ))}
                  {items.length > 6 && (
                    <span className="text-[10px] text-slate-600 pl-0.5">+{items.length - 6} more</span>
                  )}
                </div>
              </div>
            );
          })}
        </div>
      </PhaseSection>

      {/* Phase 04 — YARA */}
      <PhaseSection
        num="04" icon={PhaseIcons.yara} title="YARA Matching"
        summary={`${(yaraR.matches ?? []).length} match${(yaraR.matches ?? []).length !== 1 ? "es" : ""}`}
        accent={yaraAccent} defaultOpen={(yaraR.matches ?? []).length > 0}
      >
        <div className="mt-2 space-y-1.5">
          {(yaraR.matches ?? []).length === 0 ? (
            <p className="text-xs text-emerald-500">No YARA rule matches.</p>
          ) : (yaraR.matches ?? []).map((m: { rule: string; severity?: string }, i: number) => {
            const sev = (m.severity ?? "low").toLowerCase();
            const sevCls =
              sev === "critical" ? "bg-red-900/50 text-red-300 border-red-700/40" :
              sev === "high"     ? "bg-orange-900/50 text-orange-300 border-orange-700/40" :
              sev === "medium"   ? "bg-yellow-900/40 text-yellow-300 border-yellow-700/40" :
                                   "bg-slate-800 text-slate-400 border-slate-700/40";
            return (
              <div key={i} className="flex items-center justify-between gap-3">
                <span className="font-mono text-xs text-slate-300">{m.rule}</span>
                <span className={`text-[10px] font-bold uppercase tracking-wider px-2 py-0.5 rounded border flex-shrink-0 ${sevCls}`}>
                  {sev}
                </span>
              </div>
            );
          })}
          {yaraR.error && <p className="text-[11px] text-slate-600 font-mono">{yaraR.error}</p>}
        </div>
      </PhaseSection>

      {/* Phase 05 — Binwalk */}
      <PhaseSection
        num="05" icon={PhaseIcons.binwalk} title="Binwalk Signatures"
        summary={`${(binwalkR.findings ?? []).length} signature${(binwalkR.findings ?? []).length !== 1 ? "s" : ""}`}
        accent={(binwalkR.findings ?? []).length > 0 ? "warn" : "normal"}
        defaultOpen={(binwalkR.findings ?? []).length > 0}
      >
        <div className="mt-2 space-y-1">
          {(binwalkR.findings ?? []).length === 0 ? (
            <p className="text-xs text-slate-500">No embedded signatures — bare-metal MCU firmware (expected).</p>
          ) : (binwalkR.findings ?? []).map((f: { description: string; offset: number }, i: number) => (
            <div key={i} className="flex items-center gap-3">
              <span className="font-mono text-[10px] text-slate-700 flex-shrink-0 w-20">
                0x{f.offset.toString(16).padStart(6, "0")}
              </span>
              <span className="text-xs text-slate-400">{f.description}</span>
            </div>
          ))}
          {binwalkR.error && <p className="text-[11px] text-slate-600">{binwalkR.error}</p>}
        </div>
      </PhaseSection>

      {/* Phase 06 — Risk Score */}
      <PhaseSection
        num="06" icon={PhaseIcons.risk} title="Risk Assessment"
        summary={`${Math.round(riskScore)} / 100`}
        accent={riskAccent} defaultOpen
      >
        <div className="mt-2 space-y-2">
          <div className="flex items-center gap-3">
            <div className="flex-1 h-2 bg-slate-800 rounded-full overflow-hidden">
              <div
                className={`h-full rounded-full ${
                  riskLevel === "critical" ? "bg-red-500" :
                  riskLevel === "high"     ? "bg-orange-500" :
                  riskLevel === "medium"   ? "bg-yellow-500" :
                  riskLevel === "low"      ? "bg-green-500" : "bg-slate-600"
                }`}
                style={{ width: `${Math.min(100, Math.round(riskScore))}%` }}
              />
            </div>
            <span className={`font-mono text-sm font-bold w-16 text-right ${riskLevelColor}`}>
              {Math.round(riskScore)}/100
            </span>
          </div>
          {(riskR.reasons ?? []).length > 0 && (
            <ul className="space-y-1 pl-1">
              {(riskR.reasons ?? []).map((r: string, i: number) => (
                <li key={i} className="text-xs text-slate-500 flex items-start gap-2">
                  <span className="text-slate-700 mt-0.5 flex-shrink-0">—</span>
                  {r}
                </li>
              ))}
            </ul>
          )}
        </div>
      </PhaseSection>
    </div>
  );
}
