"use client";
import React, { useEffect, useState, useCallback } from "react";
import { useParams, useRouter } from "next/navigation";
import { getScan, triggerExtract, triggerDecompile, triggerCve, triggerDisasm, downloadReportPdf, getFunctionDisasm, type Scan, type FnInsn } from "@/lib/api";
import RiskBadge from "@/components/RiskBadge";
import RiskGauge from "@/components/RiskGauge";
import StatusBadge from "@/components/StatusBadge";
import Spinner from "@/components/Spinner";
import PipelineTree, { type PipelineData, type Severity as PipelineSev } from "@/components/PipelineTree";

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
    <div
      className="rounded-xl overflow-hidden border border-[#1f2840] shadow-card"
      style={{ background: "#121826" }}
    >
      <div className="px-5 py-3 border-b border-[#1f2840]">
        <h2 className="font-semibold text-slate-300 text-[13px] tracking-tight">{title}</h2>
      </div>
      <div className="p-5">{children}</div>
    </div>
  );
}

function KV({ label, value, mono }: { label: string; value: React.ReactNode; mono?: boolean }) {
  return (
    <div className="flex gap-4 py-2.5 border-b border-[#1f2840] last:border-0">
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
  const [tab, setTab] = useState<"strings" | "yara" | "binwalk" | "tree" | "arch" | "sbom" | "crypto" | "compliance" | "peripherals">("strings");
  const [extractError, setExtractError] = useState("");
  const [decompileError, setDecompileError] = useState("");
  const [triggeringExtract, setTriggeringExtract] = useState(false);
  const [triggeringDecompile, setTriggeringDecompile] = useState(false);
  const [showProcessorModal, setShowProcessorModal] = useState(false);
  const [selectedProcessor, setSelectedProcessor] = useState("ARM:LE:32:Cortex");
  const [baseAddress, setBaseAddress] = useState("0x08000000");
  const [downloadingPdf, setDownloadingPdf] = useState(false);
  const [pdfError, setPdfError] = useState("");
  const [triggeringCve, setTriggeringCve] = useState(false);
  const [cveError, setCveError] = useState("");
  const [triggeringDisasm, setTriggeringDisasm] = useState(false);
  const [disasmError, setDisasmError] = useState("");

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
      const extractDone = !s?.extraction_status || ["completed", "failed"].includes(s.extraction_status as string);
      const decompileDone = !s?.decompile_status || ["completed", "failed"].includes(s.decompile_status as string);
      const cveDone = !s?.cve_status || ["completed", "failed"].includes(s.cve_status as string);
      const disasmDone = !s?.disasm_status || ["completed", "failed"].includes(s.disasm_status as string);
      if (mainDone && extractDone && decompileDone && cveDone && disasmDone) {
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

  async function handleTriggerCve() {
    setCveError("");
    setTriggeringCve(true);
    try {
      const updated = await triggerCve(scanId);
      setScan(updated);
    } catch (err) {
      setCveError(err instanceof Error ? err.message : "Failed to trigger CVE match");
    } finally {
      setTriggeringCve(false);
    }
  }

  async function handleTriggerDisasm() {
    setDisasmError("");
    setTriggeringDisasm(true);
    try {
      const updated = await triggerDisasm(scanId);
      setScan(updated);
    } catch (err) {
      setDisasmError(err instanceof Error ? err.message : "Failed to trigger disassembly");
    } finally {
      setTriggeringDisasm(false);
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
  const binwalkInfo    = report?.binwalk    ?? {};
  const archInfo       = report?.arch       ?? {};
  const checksecInfo   = report?.checksec   ?? {};
  const cryptoInfo     = report?.crypto     ?? {};
  const compInfo       = report?.components ?? {};
  const complianceData = report?.compliance ?? { mappings: [], summary: { cwe: [], eu_cra: [], iec_62443: [], fda: [] } };
  const cveResult      = scan.cve           ?? {};
  const disasmResult   = scan.disasm        ?? {};
  const peripheralInfo = report?.peripherals ?? { available: false, peripherals: [], flags: [], flag_names: [] };
  const cryptoKeysInfo = report?.crypto_keys ?? { available: false, keys: [], count: 0, has_private: false };

  const suspicious: { value: string; category: string; offset: number; encoding: string }[] =
    stringsInfo.suspicious ?? [];
  const yaraMatches: { rule: string; severity?: string; strings?: { identifier: string; data: string }[] }[] =
    yaraInfo.matches ?? [];
  const binwalkFindings: { description: string; offset: number }[] =
    binwalkInfo.findings ?? [];

  // String → function cross-references (populated after Ghidra decompile)
  type XrefFn = { name: string; address: string };
  const xrefList: { value: string; category: string; functions: XrefFn[] }[] =
    (scan.decompile as { xrefs?: { available: boolean; xrefs: { value: string; category: string; functions: XrefFn[] }[] } } | null)
      ?.xrefs?.xrefs ?? [];
  const xrefByValue = new Map<string, XrefFn[]>(
    xrefList.map(x => [x.value, x.functions])
  );

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
                className="flex items-center gap-2 bg-[#121826] border border-[#1f2840] hover:bg-[#161d2e] hover:border-[#2d3a54] text-slate-300 text-xs font-medium px-3.5 py-2 rounded-lg transition-colors"
              >
                <svg width="13" height="13" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2" strokeLinecap="round" strokeLinejoin="round"><line x1="18" y1="20" x2="18" y2="10"/><line x1="12" y1="20" x2="12" y2="4"/><line x1="6" y1="20" x2="6" y2="14"/></svg>
                Compare
              </a>
              <button
                onClick={handleDownloadPdf}
                disabled={downloadingPdf}
                className="flex items-center gap-2 bg-[#121826] border border-[#1f2840] hover:bg-[#161d2e] hover:border-[#2d3a54] disabled:opacity-50 text-slate-300 text-xs font-medium px-3.5 py-2 rounded-lg transition-colors"
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
        <div className="flex items-center gap-3 bg-amber-500/8 border border-amber-500/25 rounded-xl px-5 py-4 text-amber-300">
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
            <div className={`rounded-xl overflow-hidden border shadow-card ${
              scan.risk_level === "critical" ? "border-red-500/40" :
              scan.risk_level === "high"     ? "border-orange-500/40" :
              scan.risk_level === "medium"   ? "border-amber-500/40" :
              scan.risk_level === "low"      ? "border-emerald-500/40" :
                                               "border-[#1f2840]"
            }`} style={{ background: "#121826" }}>
              <div className="px-5 py-3 border-b border-[#1f2840]">
                <h2 className="font-semibold text-slate-300 text-[13px] tracking-tight">Risk Assessment</h2>
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
                          r.toLowerCase().includes("medium") || r.toLowerCase().includes("debug") ? "text-amber-400" :
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
            <div className="flex flex-wrap gap-1 mb-5 border-b border-[#1f2840] pb-0">
              {(
                [
                  ["strings",    "Strings",      suspicious.length],
                  ["yara",       "YARA",          yaraMatches.length],
                  ["binwalk",    "Binwalk",       binwalkFindings.length],
                  ["arch",       "Arch",          archInfo.is_bare_metal ? 1 : null],
                  ["sbom",       "SBOM",          compInfo.count ?? null],
                  ["crypto",     "Crypto",        cryptoInfo.count ?? null],
                  ["compliance",  "Compliance",    (complianceData.mappings as unknown[])?.length ?? null],
                  ["peripherals","Peripherals",   (peripheralInfo.peripherals as unknown[])?.length || null],
                  ["tree",       "Pipeline Tree", null],
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
                    <span className={`ml-1.5 text-xs px-1.5 py-0.5 rounded font-semibold ${
                      tab === t ? "bg-brand-500/15 text-brand-400" : "bg-[#1f2840] text-slate-500"
                    }`}>{count}</span>
                  )}
                </button>
              ))}
            </div>

            <TabErrorBoundary tabKey={tab}>
            {/* Strings tab */}
            {tab === "strings" && (
              suspicious.length === 0 ? (
                <div className="text-center py-8 text-slate-500">
                  <p className="text-sm">No suspicious strings found.</p>
                </div>
              ) : (
                <div className="rounded-lg border border-[#1f2840] overflow-hidden">
                  <div className="max-h-[480px] overflow-y-auto divide-y divide-[#1f2840]">
                    {suspicious.map((s, i) => {
                      const fns = xrefByValue.get(s.value);
                      return (
                        <div key={i} className="flex items-center gap-3 px-3 py-2 hover:bg-[#161d2e] transition-colors">
                          <span className="w-32 flex-shrink-0">
                            <CategoryBadge cat={s.category} />
                          </span>
                          <span className="font-mono text-xs text-slate-300 break-all flex-1 leading-relaxed">
                            {s.value.length > 140 ? s.value.slice(0, 140) + "…" : s.value}
                          </span>
                          {fns && fns.length > 0 && (
                            <span className="flex-shrink-0">
                              <XrefBadge fns={fns} />
                            </span>
                          )}
                          <span className="text-xs text-slate-600 font-mono whitespace-nowrap">
                            0x{s.offset.toString(16).padStart(6, "0")}
                          </span>
                        </div>
                      );
                    })}
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
                      sev === "critical" ? "border-l-[#ef4444] bg-red-500/5" :
                      sev === "high"     ? "border-l-[#f97316] bg-orange-500/5" :
                      sev === "medium"   ? "border-l-[#f59e0b] bg-amber-500/5" :
                                           "border-l-[#1f2840]";
                    const deduped = m.strings ? dedupeStrings(m.strings) : [];
                    // Only show printable string matches, skip binary-only hits
                    const printable = deduped.filter(s => {
                      const cleaned = cleanYaraData(s.data);
                      return !cleaned.startsWith("\\x") && cleaned.length > 0;
                    });
                    return (
                      <div key={i} className={`border border-l-[3px] border-[#1f2840] rounded-lg p-4 ${borderCls}`}>
                        <div className="flex items-center justify-between gap-3 mb-2">
                          <span className="font-semibold text-slate-200 text-sm">{m.rule}</span>
                          {m.severity && <CategoryBadge cat={m.severity.toUpperCase()} />}
                        </div>
                        {printable.length > 0 && (
                          <div className="flex flex-wrap gap-2 mt-1">
                            {printable.map((s, j) => (
                              <code key={j} className="inline-flex items-center gap-1 text-xs bg-[#0b0f1a] border border-[#2d3a54] rounded px-2 py-0.5 font-mono">
                                <span className="text-slate-600">{s.identifier}</span>
                                <span className="text-emerald-300/90 font-medium">{cleanYaraData(s.data)}</span>
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
                      className="flex items-start gap-4 py-1.5 border-b border-[#1f2840] last:border-0 text-sm"
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
            {/* Arch tab */}
            {tab === "arch" && (
              <ArchPanel arch={archInfo} checksec={checksecInfo} />
            )}

            {/* SBOM tab */}
            {tab === "sbom" && (
              <div className="space-y-4">
                {/* Component list */}
                {compInfo.count === 0 || !compInfo.components?.length ? (
                  <p className="text-sm text-slate-500 text-center py-8">No SBOM components detected.</p>
                ) : (
                  <div className="space-y-2">
                    {(compInfo.components as { component: string; version: string | null; evidence_offset: number; evidence: string }[]).map((c, i) => {
                      const cves = ((cveResult as { matches?: { component: string; cve_id: string; cvss: number; severity: string; summary: string }[] }).matches ?? []).filter(m => m.component === c.component);
                      const maxSev = cves.reduce((acc: string, m) => {
                        const order = ["critical","high","medium","low","informational"];
                        return order.indexOf(m.severity) < order.indexOf(acc) ? m.severity : acc;
                      }, "informational");
                      const hasCve = cves.length > 0;
                      return (
                        <div key={i} className={`rounded-lg border px-4 py-3 ${hasCve ? "border-orange-500/30 bg-orange-500/5" : "border-[#1f2840]"}`} style={hasCve ? {} : { background: "#0b0f1a" }}>
                          <div className="flex items-center gap-3 flex-wrap">
                            <span className="font-semibold text-slate-200 text-sm">{c.component}</span>
                            {c.version && (
                              <span className="font-mono text-xs text-slate-400 bg-[#1f2840] px-2 py-0.5 rounded">{c.version}</span>
                            )}
                            {hasCve && (
                              <span className={`text-xs font-semibold px-2 py-0.5 rounded border ${
                                maxSev === "critical" ? "bg-red-500/15 text-red-300 border-red-500/30" :
                                maxSev === "high"     ? "bg-orange-500/15 text-orange-300 border-orange-500/30" :
                                                        "bg-amber-500/15 text-amber-300 border-amber-500/30"
                              }`}>
                                {cves.length} CVE{cves.length !== 1 ? "s" : ""}
                              </span>
                            )}
                            <span className="ml-auto text-xs text-slate-600 font-mono">0x{c.evidence_offset.toString(16).padStart(6, "0")}</span>
                          </div>
                          <p className="text-[10px] font-mono text-slate-600 mt-1 truncate">{c.evidence}</p>
                          {hasCve && (
                            <div className="mt-2 space-y-1">
                              {cves.map((cv, j) => (
                                <div key={j} className="flex items-center gap-2 text-xs text-slate-400">
                                  <span className="font-mono font-semibold text-slate-300">{cv.cve_id}</span>
                                  <span className="text-slate-600">CVSS {cv.cvss}</span>
                                  <span className="text-slate-500 truncate">{cv.summary}</span>
                                </div>
                              ))}
                            </div>
                          )}
                        </div>
                      );
                    })}
                  </div>
                )}

                {/* CVE summary if no components but CVEs exist */}
                {scan.cve_status === "completed" && !compInfo.count && (cveResult as { count?: number }).count === 0 && (
                  <p className="text-xs text-slate-500 text-center">No CVE matches found.</p>
                )}
              </div>
            )}

            {/* Crypto tab */}
            {tab === "crypto" && (
              <div className="space-y-4">
                {/* Crypto constants */}
                <div>
                  <p className="text-[10px] font-bold uppercase tracking-widest text-slate-600 mb-2">Algorithm Constants</p>
                  {cryptoInfo.count === 0 || !cryptoInfo.matches?.length ? (
                    <p className="text-sm text-slate-500 text-center py-4">No cryptographic constants detected.</p>
                  ) : (
                    <div className="rounded-lg border border-[#1f2840] overflow-hidden">
                      <div className="grid grid-cols-[8rem_5rem_1fr] px-3 py-2 border-b border-[#1f2840] text-[10px] font-bold uppercase tracking-widest text-slate-600" style={{ background: "#121826" }}>
                        <span>Algorithm</span>
                        <span>Confidence</span>
                        <span>Offset</span>
                      </div>
                      <div className="max-h-64 overflow-y-auto divide-y divide-[#1f2840]">
                        {(cryptoInfo.matches as { algo: string; offset: number; confidence: string }[]).map((m, i) => (
                          <div key={i} className="grid grid-cols-[8rem_5rem_1fr] px-3 py-2 hover:bg-[#161d2e] transition-colors text-xs">
                            <span className="font-mono font-semibold text-blue-300">{m.algo}</span>
                            <span className={`font-semibold ${
                              m.confidence === "high"   ? "text-red-400" :
                              m.confidence === "medium" ? "text-amber-400" : "text-slate-500"
                            }`}>{m.confidence}</span>
                            <span className="font-mono text-slate-500">0x{(typeof m.offset === "number" ? m.offset : 0).toString(16).padStart(6, "0")}</span>
                          </div>
                        ))}
                      </div>
                    </div>
                  )}
                </div>

                {/* Key material */}
                <div>
                  <p className="text-[10px] font-bold uppercase tracking-widest text-slate-600 mb-2">
                    Key Material
                    {cryptoKeysInfo.has_private && (
                      <span className="ml-2 px-1.5 py-0.5 rounded bg-red-900/40 text-red-400 text-[9px] font-bold">PRIVATE KEY</span>
                    )}
                  </p>
                  {!cryptoKeysInfo.available || !Array.isArray(cryptoKeysInfo.keys) || cryptoKeysInfo.keys.length === 0 ? (
                    <p className="text-sm text-slate-500 text-center py-4">No key material candidates detected.</p>
                  ) : (
                    <div className="rounded-lg border border-[#1f2840] overflow-hidden">
                      <div className="grid grid-cols-[6rem_5rem_4rem_1fr] px-3 py-2 border-b border-[#1f2840] text-[10px] font-bold uppercase tracking-widest text-slate-600" style={{ background: "#121826" }}>
                        <span>Type</span>
                        <span>Offset</span>
                        <span>Size</span>
                        <span>Label</span>
                      </div>
                      <div className="max-h-64 overflow-y-auto divide-y divide-[#1f2840]">
                        {(cryptoKeysInfo.keys as { type: string; offset: number; size: number; entropy: number | null; label: string; context: string }[]).map((k, i) => (
                          <div key={i} className="grid grid-cols-[6rem_5rem_4rem_1fr] px-3 py-2 hover:bg-[#161d2e] transition-colors text-xs">
                            <span className={`font-semibold ${
                              k.type === "pem_private_key"  ? "text-red-400" :
                              k.type === "weak_key"         ? "text-orange-400" :
                              k.type === "high_entropy_blob"? "text-yellow-400" :
                              k.type === "iv_candidate"     ? "text-purple-400" :
                                                              "text-slate-400"
                            }`}>{k.type.replace(/_/g, " ")}</span>
                            <span className="font-mono text-slate-400">0x{(typeof k.offset === "number" ? k.offset : 0).toString(16).padStart(5, "0")}</span>
                            <span className="text-slate-400">{k.size}B</span>
                            <span className="text-slate-300 truncate" title={k.label}>{k.label}</span>
                          </div>
                        ))}
                      </div>
                    </div>
                  )}
                </div>
              </div>
            )}

            {/* Peripherals tab */}
            {tab === "peripherals" && (
              <div className="space-y-4">
                {!peripheralInfo.available ? (
                  <p className="text-sm text-slate-500 text-center py-8">
                    Peripheral map not available — only generated for bare-metal Cortex-M firmware.
                  </p>
                ) : (
                  <>
                    {/* Security flags */}
                    {Array.isArray(peripheralInfo.flags) && peripheralInfo.flags.length > 0 && (
                      <div className="rounded-lg border border-[#1f2840] overflow-hidden">
                        <div className="px-4 py-2 border-b border-[#1f2840] text-[10px] font-bold uppercase tracking-widest text-slate-600" style={{ background: "#121826" }}>
                          Security Flags
                        </div>
                        <div className="divide-y divide-[#1f2840]">
                          {(peripheralInfo.flags as { flag: string; severity: string; description: string; risk_score: number }[]).map((f, i) => (
                            <div key={i} className="flex items-start gap-3 px-4 py-3">
                              <span className={`mt-0.5 text-xs font-bold uppercase px-1.5 py-0.5 rounded flex-shrink-0 ${
                                f.severity === "critical" ? "bg-red-900/40 text-red-400" :
                                f.severity === "high"     ? "bg-orange-900/40 text-orange-400" :
                                                            "bg-amber-900/30 text-amber-400"
                              }`}>{f.severity}</span>
                              <div className="min-w-0">
                                <p className="text-xs font-semibold text-slate-200 font-mono">{f.flag}</p>
                                <p className="text-xs text-slate-500 mt-0.5">{f.description}</p>
                              </div>
                              <span className="ml-auto text-xs text-slate-500 flex-shrink-0">+{f.risk_score} risk</span>
                            </div>
                          ))}
                        </div>
                      </div>
                    )}

                    {/* Peripheral accesses */}
                    {Array.isArray(peripheralInfo.peripherals) && peripheralInfo.peripherals.length > 0 ? (
                      <div className="rounded-lg border border-[#1f2840] overflow-hidden">
                        <div className="grid grid-cols-[10rem_6rem_4rem_1fr] px-3 py-2 border-b border-[#1f2840] text-[10px] font-bold uppercase tracking-widest text-slate-600" style={{ background: "#121826" }}>
                          <span>Peripheral</span>
                          <span>Base</span>
                          <span>Accesses</span>
                          <span>Category</span>
                        </div>
                        <div className="max-h-96 overflow-y-auto divide-y divide-[#1f2840]">
                          {(peripheralInfo.peripherals as { name: string; base: string; access_count: number; category: string; families: string }[]).map((p, i) => (
                            <div key={i} className="grid grid-cols-[10rem_6rem_4rem_1fr] px-3 py-2 hover:bg-[#161d2e] transition-colors text-xs">
                              <span className="font-mono font-semibold text-blue-300">{p.name}</span>
                              <span className="font-mono text-slate-400">{p.base}</span>
                              <span className="text-slate-300 font-semibold">{p.access_count}</span>
                              <span className={`font-medium ${
                                p.category === "debug"    ? "text-amber-400" :
                                p.category === "flash"    ? "text-orange-400" :
                                p.category === "watchdog" ? "text-yellow-400" :
                                p.category === "security" ? "text-red-400" :
                                p.category === "crypto"   ? "text-purple-400" :
                                                            "text-slate-500"
                              }`}>{p.category}</span>
                            </div>
                          ))}
                        </div>
                      </div>
                    ) : (
                      <p className="text-sm text-slate-500 text-center py-4">No peripheral accesses detected.</p>
                    )}
                  </>
                )}
              </div>
            )}

            {/* Compliance tab */}
            {tab === "compliance" && (
              <CompliancePanel data={complianceData} />
            )}

            {/* Pipeline Tree tab */}
            {tab === "tree" && report && (
              <PipelineTree
                data={buildPipelineData(
                  scan.filename,
                  report,
                  scan.risk_score ?? 0,
                  scan.risk_level ?? "informational",
                )}
              />
            )}
            {tab === "tree" && !report && (
              <p className="text-slate-500 text-sm text-center py-8">No report data available.</p>
            )}
            </TabErrorBoundary>
          </Section>

          {/* Deep analysis: extract / decompile */}
          <Section title="Deep Analysis">
            {/* Action bar — horizontal rows */}
            <div className="space-y-2 mb-5">
              {/* Binwalk row */}
              <div className="flex items-center gap-4 px-4 py-3 rounded-lg border border-slate-700/40" style={{ background: "#0b0f1a" }}>
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
              <div className="flex items-center gap-4 px-4 py-3 rounded-lg border border-slate-700/40" style={{ background: "#0b0f1a" }}>
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

              {/* CVE Match row */}
              <div className="flex items-center gap-4 px-4 py-3 rounded-lg border border-slate-700/40" style={{ background: "#0b0f1a" }}>
                <div className="flex-1 min-w-0">
                  <div className="flex items-center gap-2.5 flex-wrap">
                    <p className="text-sm font-semibold text-slate-200">CVE Match</p>
                    <JobStatusPill status={scan.cve_status} />
                  </div>
                  <p className="text-xs text-slate-600 mt-0.5">Cross-references detected SBOM components against offline CVE database.</p>
                  {cveError && <p className="text-xs text-red-400 mt-1">{cveError}</p>}
                  {scan.cve_error && <p className="text-xs text-slate-500 mt-1">⚠ {scan.cve_error}</p>}
                </div>
                <button
                  onClick={handleTriggerCve}
                  disabled={triggeringCve || scan.cve_status === "pending" || scan.cve_status === "running"}
                  className="flex items-center gap-2 bg-blue-600 hover:bg-blue-500 disabled:opacity-40 text-white text-xs font-semibold px-3.5 py-2 rounded-lg transition-colors flex-shrink-0"
                >
                  {triggeringCve && <Spinner size={12} />}
                  {scan.cve_status ? "Re-run" : "Run CVE Match"}
                </button>
              </div>

              {/* Disasm Stats row */}
              <div className="flex items-center gap-4 px-4 py-3 rounded-lg border border-slate-700/40" style={{ background: "#0b0f1a" }}>
                <div className="flex-1 min-w-0">
                  <div className="flex items-center gap-2.5 flex-wrap">
                    <p className="text-sm font-semibold text-slate-200">Disasm Stats</p>
                    <JobStatusPill status={scan.disasm_status} />
                    {scan.disasm_status === "completed" && (disasmResult as { total_instructions?: number }).total_instructions != null && (
                      <span className="text-xs text-slate-500">
                        {((disasmResult as { total_instructions: number }).total_instructions).toLocaleString()} insns
                        {" · "}
                        {(disasmResult as { function_prologues?: number }).function_prologues ?? 0} prologues
                      </span>
                    )}
                  </div>
                  <p className="text-xs text-slate-600 mt-0.5">Capstone instruction histogram and function prologue count — Thumb/ARM/x86.</p>
                  {disasmError && <p className="text-xs text-red-400 mt-1">{disasmError}</p>}
                  {scan.disasm_error && <p className="text-xs text-slate-500 mt-1">⚠ {scan.disasm_error}</p>}
                </div>
                <button
                  onClick={handleTriggerDisasm}
                  disabled={triggeringDisasm || scan.disasm_status === "pending" || scan.disasm_status === "running"}
                  className="flex items-center gap-2 bg-blue-600 hover:bg-blue-500 disabled:opacity-40 text-white text-xs font-semibold px-3.5 py-2 rounded-lg transition-colors flex-shrink-0"
                >
                  {triggeringDisasm && <Spinner size={12} />}
                  {scan.disasm_status ? "Re-run" : "Run Disasm"}
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
                <DecompileFunctions functions={scan.decompile.functions} scanId={scanId} />
              </div>
            )}

            {/* Disasm results — full width */}
            {scan.disasm_status === "completed" && scan.disasm && (
              <div>
                <p className="text-xs font-semibold text-slate-400 uppercase tracking-wide mb-2">Disasm Stats</p>
                <DisasmResults disasm={scan.disasm} />
              </div>
            )}
          </Section>
        </>
      )}
      {/* Processor selection modal */}
      {showProcessorModal && (
        <div className="fixed inset-0 z-50 flex items-center justify-center bg-black/60">
          <div className="rounded-2xl shadow-2xl p-6 w-full max-w-md mx-4 border border-[#2d3a54]" style={{ background: "#161d2e" }}>
            <h3 className="text-base font-semibold text-slate-200 mb-1">Ghidra Decompile Settings</h3>
            <p className="text-xs text-slate-500 mb-4">
              For ELF/PE binaries, leave processor as Auto. For raw firmware (STM32, MIPS, etc.) select the CPU architecture.
            </p>

            <label className="block text-xs font-medium text-slate-400 mb-1">Processor Architecture</label>
            <select
              value={selectedProcessor}
              onChange={e => setSelectedProcessor(e.target.value)}
              className="w-full border border-[#1f2840] bg-[#0b0f1a] rounded-lg px-3 py-2 text-sm text-slate-200 mb-4 focus:outline-none focus:ring-2 focus:ring-brand-500/40"
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
              className="w-full border border-[#1f2840] bg-[#0b0f1a] rounded-lg px-3 py-2 text-sm font-mono text-slate-200 mb-5 focus:outline-none focus:ring-2 focus:ring-brand-500/40 placeholder:text-slate-600"
            />

            <div className="flex gap-2 justify-end">
              <button
                onClick={() => setShowProcessorModal(false)}
                className="px-4 py-2 text-sm text-slate-400 hover:bg-[#1f2840] rounded-lg transition-colors"
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
          <div className="max-h-36 overflow-y-auto space-y-0.5 bg-[#0b0f1a] rounded-lg px-2 py-1.5">
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
              <div key={i} className="border border-[#1f2840] rounded-lg p-2 text-xs">
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

function CopyButton({ text }: { text: string }) {
  const [copied, setCopied] = useState(false);
  function handleCopy() {
    navigator.clipboard.writeText(text).then(() => {
      setCopied(true);
      setTimeout(() => setCopied(false), 1500);
    }).catch(() => {});
  }
  return (
    <button
      onClick={handleCopy}
      className="text-[10px] font-mono text-slate-600 hover:text-slate-300 transition-colors px-1.5 py-0.5 rounded border border-transparent hover:border-[#2d3a54]"
    >
      {copied ? "✓ copied" : "copy"}
    </button>
  );
}

function DecompileFunctions({ functions, scanId }: { functions: FnEntry[]; scanId: string }) {
  const [openGroups, setOpenGroups] = useState<Set<string>>(() => new Set());
  const [openFn, setOpenFn]         = useState<string | null>(null);
  const [search, setSearch]         = useState("");
  const [searchCode, setSearchCode] = useState(false);
  const [asmCache, setAsmCache]     = useState<Map<string, FnInsn[] | "error">>(new Map());
  const [asmLoading, setAsmLoading] = useState<Set<string>>(new Set());

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

  async function fetchFnAsm(fnAddr: string) {
    setAsmLoading(prev => { const n = new Set(prev); n.add(fnAddr); return n; });
    try {
      const insns = await getFunctionDisasm(scanId, fnAddr);
      setAsmCache(prev => { const m = new Map(prev); m.set(fnAddr, insns); return m; });
    } catch {
      setAsmCache(prev => { const m = new Map(prev); m.set(fnAddr, "error" as const); return m; });
    } finally {
      setAsmLoading(prev => { const n = new Set(prev); n.delete(fnAddr); return n; });
    }
  }

  function handleFnClick(fnKey: string, fnAddr: string) {
    if (openFn === fnKey) { setOpenFn(null); return; }
    setOpenFn(fnKey);
    if (!asmCache.has(fnAddr) && !asmLoading.has(fnAddr)) void fetchFnAsm(fnAddr);
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
            className="w-full border border-[#1f2840] bg-[#0b0f1a] text-slate-200 rounded-lg pl-7 pr-3 py-1.5 text-xs focus:outline-none focus:ring-1 focus:ring-brand-500/40 placeholder:text-slate-600"
          />
        </div>
        <label className="flex items-center gap-1.5 text-xs text-slate-600 cursor-pointer select-none whitespace-nowrap">
          <input type="checkbox" checked={searchCode} onChange={e => setSearchCode(e.target.checked)} className="accent-blue-500 w-3 h-3" />
          incl. code
        </label>
        <button
          onClick={() => setOpenGroups(allOpen ? new Set() : new Set(groups.map(g => g.key)))}
          className="text-xs text-slate-500 hover:text-slate-300 transition-colors whitespace-nowrap px-2 py-1 rounded border border-[#1f2840] hover:border-[#2d3a54]"
        >
          {allOpen ? "Collapse all" : "Expand all"}
        </button>
      </div>

      {/* Stats strip */}
      <div className="flex items-center gap-4 px-3 py-1.5 rounded-lg bg-[#0b0f1a] border border-[#1f2840] text-xs font-mono">
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
      <div className="rounded-xl border border-[#1f2840] overflow-hidden" style={{ background: "#0b0f1a" }}>
        {/* Column headers */}
        <div className="grid grid-cols-[1.5rem_9rem_1fr_4.5rem] gap-0 px-4 py-2 border-b border-[#1f2840]" style={{ background: "#121826" }}>
          <span />
          <span className="text-[10px] font-bold uppercase tracking-widest text-slate-600">Address</span>
          <span className="text-[10px] font-bold uppercase tracking-widest text-slate-600 pl-3">Density</span>
          <span className="text-[10px] font-bold uppercase tracking-widest text-slate-600 text-right">Fn</span>
        </div>

        {groups.length === 0 ? (
          <p className="text-xs text-slate-600 text-center py-10">No functions match &ldquo;{search}&rdquo;</p>
        ) : (
          <div className="divide-y divide-[#1f2840]">
            {groups.map(({ key, items }) => {
              const isOpen = openGroups.has(key);
              const { bar: barColor, text: textColor } = densityColor(items.length);
              const barPct = Math.max(4, Math.round((items.length / maxFn) * 100));

              return (
                <div key={key}>
                  {/* Block row */}
                  <button
                    onClick={() => toggleGroup(key)}
                    className="w-full grid grid-cols-[1.5rem_9rem_1fr_4.5rem] gap-0 px-4 py-2.5 items-center text-left hover:bg-[#161d2e]/60 transition-colors group"
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
                      <div className="flex-1 h-1.5 bg-[#1f2840] rounded-full overflow-hidden max-w-[160px]">
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
                    <div className="border-t border-[#1f2840] bg-[#080c14]">
                      <div className="divide-y divide-[#1a2234]">
                        {items.map((fn, idx) => {
                          const fnKey    = `${key}:${idx}`;
                          const isFnOpen = openFn === fnKey;
                          const cached   = asmCache.get(fn.address);
                          const asmErr   = cached === "error";
                          const asmInsns = asmErr ? null : (cached ?? null);
                          const loading  = asmLoading.has(fn.address);
                          const asmText  = asmInsns
                            ? asmInsns.map(i =>
                                `${i.addr}  ${i.bytes.padEnd(12, " ")}  ${i.mnemonic.padEnd(8, " ")} ${i.op_str}`
                              ).join("\n")
                            : "";

                          return (
                            <div key={fnKey}>
                              <button
                                onClick={() => handleFnClick(fnKey, fn.address)}
                                className="w-full flex items-center gap-3 pl-10 pr-4 py-1.5 text-left hover:bg-[#161d2e]/60 transition-colors group"
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

                              {/* Two-column drill-down: Capstone ASM | Ghidra Pseudo-C */}
                              {isFnOpen && (
                                <TabErrorBoundary tabKey={fnKey}>
                                  <div className="border-t border-[#1f2840] grid grid-cols-2 divide-x divide-[#1f2840]" style={{ background: "#060b10" }}>

                                    {/* LEFT — Capstone Assembly */}
                                    <div className="flex flex-col min-w-0">
                                      <div className="flex items-center justify-between px-3 py-1.5 border-b border-[#1f2840]" style={{ background: "#080c14" }}>
                                        <span className="text-[10px] font-bold uppercase tracking-widest text-slate-600">Assembly · Capstone · Thumb-2</span>
                                        <CopyButton text={asmText} />
                                      </div>
                                      <div className="overflow-y-auto overflow-x-auto" style={{ maxHeight: 320 }}>
                                        {loading ? (
                                          <div className="flex items-center justify-center py-6">
                                            <Spinner size={16} />
                                          </div>
                                        ) : asmErr ? (
                                          <p className="text-xs text-red-400 font-mono px-3 py-3">Failed to load disassembly.</p>
                                        ) : !asmInsns ? (
                                          <p className="text-[11px] text-slate-600 font-mono px-3 py-3">Fetching…</p>
                                        ) : asmInsns.length === 0 ? (
                                          <p className="text-[11px] text-slate-500 font-mono px-3 py-3">No instructions decoded at this address.</p>
                                        ) : (
                                          <table className="w-full text-[11px] font-mono border-collapse">
                                            <tbody>
                                              {asmInsns.map((insn, i) => (
                                                <tr key={i} className="hover:bg-[#161d2e] transition-colors">
                                                  <td className="text-slate-600 pl-3 pr-2 py-0.5 whitespace-nowrap select-all w-[7rem]">{insn.addr}</td>
                                                  <td className="text-slate-700 pr-2 py-0.5 whitespace-nowrap w-[5rem]">{insn.bytes}</td>
                                                  <td className="text-blue-300 font-semibold pr-2 py-0.5 whitespace-nowrap w-[4rem]">{insn.mnemonic}</td>
                                                  <td className="text-slate-300 pr-3 py-0.5">{insn.op_str}</td>
                                                </tr>
                                              ))}
                                            </tbody>
                                          </table>
                                        )}
                                      </div>
                                    </div>

                                    {/* RIGHT — Ghidra Pseudo-C */}
                                    <div className="flex flex-col min-w-0">
                                      <div className="flex items-center justify-between px-3 py-1.5 border-b border-[#1f2840]" style={{ background: "#080c14" }}>
                                        <span className="text-[10px] font-bold uppercase tracking-widest text-slate-600">Pseudo-C · Ghidra · reconstructed</span>
                                        <CopyButton text={fn.code || ""} />
                                      </div>
                                      <pre
                                        className="text-[11px] leading-relaxed font-mono text-emerald-300/90 px-3 py-2 overflow-y-auto overflow-x-auto whitespace-pre"
                                        style={{ maxHeight: 320 }}
                                      >
                                        {fn.code || "(no decompiled output for this function)"}
                                      </pre>
                                    </div>

                                  </div>
                                </TabErrorBoundary>
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
    pending:   "bg-slate-500/10 text-slate-400 border border-slate-600/30",
    running:   "bg-amber-500/10 text-amber-400 border border-amber-500/30",
    completed: "bg-emerald-500/10 text-emerald-400 border border-emerald-600/30",
    failed:    "bg-red-500/10 text-red-400 border border-red-500/30",
  };
  return (
    <span className={`inline-flex items-center gap-1 rounded border px-2 py-0.5 text-xs font-medium ${styles[status] ?? "bg-slate-500/10 text-slate-400 border-slate-600/30"}`}>
      {status === "running" && <Spinner size={10} />}
      {status.charAt(0).toUpperCase() + status.slice(1)}
    </span>
  );
}

// ── Category badge ────────────────────────────────────────────────────────────

const catStyles: Record<string, { bg: string; label: string }> = {
  PRIVATE_KEY:     { bg: "bg-red-500/15 text-red-300 border border-red-500/30",      label: "PRIVATE KEY" },
  CERTIFICATE:     { bg: "bg-red-500/15 text-red-300 border border-red-500/30",      label: "CERTIFICATE" },
  SAFETY_BYPASS:   { bg: "bg-red-500/15 text-red-300 border border-red-500/30",      label: "SAFETY BYPASS" },
  API_KEY:         { bg: "bg-orange-500/15 text-orange-300 border border-orange-500/30", label: "API KEY" },
  CREDENTIAL:      { bg: "bg-orange-500/15 text-orange-300 border border-orange-500/30", label: "CREDENTIAL" },
  FLASH_WRITE:     { bg: "bg-orange-500/15 text-orange-300 border border-orange-500/30", label: "FLASH WRITE" },
  SHELL_COMMAND:   { bg: "bg-amber-500/15 text-amber-300 border border-amber-500/30",  label: "SHELL CMD" },
  DEBUG_KEYWORD:   { bg: "bg-amber-500/15 text-amber-300 border border-amber-500/30",  label: "DEBUG" },
  CRYPTO:          { bg: "bg-amber-500/15 text-amber-300 border border-amber-500/30",  label: "CRYPTO" },
  URL:             { bg: "bg-slate-500/15 text-slate-400 border border-slate-500/30",  label: "URL" },
  IP:              { bg: "bg-slate-500/15 text-slate-400 border border-slate-500/30",  label: "IP" },
  DOMAIN:          { bg: "bg-slate-500/15 text-slate-400 border border-slate-500/30",  label: "DOMAIN" },
  NETWORK_SERVICE:   { bg: "bg-slate-500/15 text-slate-400 border border-slate-500/30",  label: "NETWORK" },
  WIFI_CREDENTIAL:   { bg: "bg-orange-500/15 text-orange-300 border border-orange-500/30", label: "WIFI CRED" },
  MQTT_BROKER:       { bg: "bg-amber-500/15 text-amber-300 border border-amber-500/30",  label: "MQTT" },
  AT_COMMAND:        { bg: "bg-amber-500/15 text-amber-300 border border-amber-500/30",  label: "AT CMD" },
  BOOTLOADER:        { bg: "bg-orange-500/15 text-orange-300 border border-orange-500/30", label: "BOOTLOADER" },
  FILE_PATH:         { bg: "bg-slate-500/15 text-slate-400 border border-slate-500/30",  label: "FILE PATH" },
  VERSION:           { bg: "bg-slate-600/15 text-slate-500 border border-slate-600/30",  label: "VERSION" },
  CRITICAL:        { bg: "bg-red-500/15 text-red-300 border border-red-500/30",        label: "CRITICAL" },
  HIGH:            { bg: "bg-orange-500/15 text-orange-300 border border-orange-500/30", label: "HIGH" },
  MEDIUM:          { bg: "bg-amber-500/15 text-amber-300 border border-amber-500/30",  label: "MEDIUM" },
  LOW:             { bg: "bg-slate-500/15 text-slate-400 border border-slate-500/30",  label: "LOW" },
};

function CategoryBadge({ cat }: { cat: string }) {
  const style = catStyles[cat];
  const cls   = style?.bg ?? "bg-slate-600/15 text-slate-400 border border-slate-600/30";
  const label = style?.label ?? cat;
  return (
    <span className={`inline-block rounded px-2 py-0.5 text-[10px] font-semibold uppercase tracking-wide ${cls}`}>
      {label}
    </span>
  );
}

// ── Disasm results panel ──────────────────────────────────────────────────────

function DisasmResults({ disasm }: { disasm: Record<string, unknown> }) {
  if (!disasm || disasm.available === false) {
    return (
      <p className="text-xs text-slate-500 font-mono">
        {String(disasm?.error ?? "No disassembly data available.")}
      </p>
    );
  }

  const total     = (disasm.total_instructions  as number | undefined) ?? 0;
  const prologues = (disasm.function_prologues   as number | undefined) ?? 0;
  const branches  = (disasm.branch_instructions  as number | undefined) ?? 0;
  const memory    = (disasm.memory_instructions  as number | undefined) ?? 0;
  const codeBytes = (disasm.code_bytes           as number | undefined) ?? 0;
  const mode      = (disasm.load_address         as string | undefined) ?? "—";

  const susp = (disasm.suspicious as Record<string, number> | undefined) ?? {};
  const suspEntries = Object.entries(susp).filter(([, v]) => v > 0);

  const tops = Array.isArray(disasm.top_mnemonics)
    ? (disasm.top_mnemonics as { mnemonic: string; count: number }[])
    : [];
  const maxCount = tops.length > 0 ? tops[0].count : 1;

  return (
    <div className="space-y-4">
      {/* Stats grid */}
      <div className="grid grid-cols-2 sm:grid-cols-4 gap-2">
        {[
          ["Total Instructions",         total.toLocaleString()],
          ["Prologue Candidates ≈",      prologues.toLocaleString()],
          ["Branch Instructions",        branches.toLocaleString()],
          ["Memory Instructions",        memory.toLocaleString()],
        ].map(([label, val]) => (
          <div key={label} className="rounded-lg px-3 py-2.5 border border-[#1f2840]" style={{ background: "#0b0f1a" }}>
            <p className="text-[10px] font-bold uppercase tracking-widest text-slate-600 mb-0.5">{label}</p>
            <p className="text-base font-semibold text-slate-200 font-mono">{val}</p>
          </div>
        ))}
      </div>

      {/* Meta row */}
      <div className="flex flex-wrap gap-4 text-xs text-slate-500 font-mono px-1">
        <span>mode: <span className="text-slate-300">thumb</span></span>
        <span>base: <span className="text-slate-300">{mode}</span></span>
        <span>file: <span className="text-slate-300">{(codeBytes / 1024).toFixed(0)} KB</span></span>
      </div>

      {/* Suspicious instructions */}
      {suspEntries.length > 0 && (
        <div className="flex flex-wrap gap-2">
          {suspEntries.map(([mn, count]) => (
            <span key={mn} className="inline-flex items-center gap-1.5 rounded border border-orange-500/30 bg-orange-500/10 px-2.5 py-1 text-xs font-mono">
              <span className="font-semibold text-orange-300">{mn}</span>
              <span className="text-orange-400/70">{count}×</span>
            </span>
          ))}
        </div>
      )}

      {/* Top mnemonics bar chart */}
      {tops.length > 0 && (
        <div>
          <p className="text-[10px] font-bold uppercase tracking-widest text-slate-600 mb-2">Top Mnemonics</p>
          <div className="space-y-1">
            {tops.map(({ mnemonic, count }) => {
              const pct = Math.max(2, Math.round((count / maxCount) * 100));
              return (
                <div key={mnemonic} className="flex items-center gap-2 text-xs font-mono">
                  <span className="w-12 text-right text-slate-400 flex-shrink-0">{mnemonic}</span>
                  <div className="flex-1 h-1.5 bg-[#1f2840] rounded-full overflow-hidden max-w-[200px]">
                    <div className="h-full rounded-full bg-blue-500/70" style={{ width: `${pct}%` }} />
                  </div>
                  <span className="text-slate-500 w-16 flex-shrink-0">{count.toLocaleString()}</span>
                </div>
              );
            })}
          </div>
        </div>
      )}

      {typeof disasm.error === "string" && disasm.error && (
        <p className="text-[11px] text-slate-500 font-mono">error: {disasm.error}</p>
      )}
    </div>
  );
}


// ── String → function xref badge ─────────────────────────────────────────────

function XrefBadge({ fns }: { fns: { name: string; address: string }[] }) {
  const [open, setOpen] = useState(false);
  return (
    <span className="relative">
      <button
        onClick={() => setOpen(v => !v)}
        className="inline-flex items-center gap-1 text-[10px] font-semibold px-1.5 py-0.5 rounded border border-blue-500/30 bg-blue-500/10 text-blue-300 hover:bg-blue-500/20 transition-colors"
        title={`Referenced in ${fns.length} decompiled function${fns.length !== 1 ? "s" : ""}`}
      >
        <svg width="9" height="9" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2.5" strokeLinecap="round" strokeLinejoin="round">
          <polyline points="9 18 15 12 9 6"/>
        </svg>
        {fns.length} fn
      </button>
      {open && (
        <span
          className="absolute right-0 top-6 z-50 min-w-[14rem] rounded-lg border border-[#2d3a54] shadow-xl py-1"
          style={{ background: "#0b0f1a" }}
        >
          <span className="block text-[9px] font-bold uppercase tracking-widest text-slate-600 px-3 py-1">
            Referenced in:
          </span>
          {fns.map((fn, i) => (
            <span key={i} className="flex items-center gap-2 px-3 py-1 hover:bg-[#161d2e]">
              <span className="font-mono text-[10px] text-slate-500 flex-shrink-0">{fn.address}</span>
              <span className="font-mono text-[11px] text-slate-200 truncate">{fn.name}</span>
            </span>
          ))}
        </span>
      )}
    </span>
  );
}


// ── Tab error boundary ────────────────────────────────────────────────────────
// Catches render errors inside a tab so only that tab shows a fallback,
// not the entire page. Resets automatically when the active tab changes.

interface TebProps { tabKey: string; children: React.ReactNode }
interface TebState { hasError: boolean; message: string | null; prevTabKey: string }

class TabErrorBoundary extends React.Component<TebProps, TebState> {
  constructor(props: TebProps) {
    super(props);
    this.state = { hasError: false, message: null, prevTabKey: props.tabKey };
  }

  static getDerivedStateFromProps(props: TebProps, state: TebState): Partial<TebState> | null {
    if (props.tabKey !== state.prevTabKey) {
      return { hasError: false, message: null, prevTabKey: props.tabKey };
    }
    return null;
  }

  static getDerivedStateFromError(err: Error): Partial<TebState> {
    return { hasError: true, message: err.message };
  }

  render() {
    if (this.state.hasError) {
      return (
        <div className="rounded-lg border border-red-500/30 bg-red-500/5 px-4 py-3 space-y-1">
          <p className="text-xs font-semibold text-red-400">Render error in this tab</p>
          {this.state.message && (
            <p className="text-[11px] font-mono text-red-400/70 break-all">{this.state.message}</p>
          )}
        </div>
      );
    }
    return this.props.children;
  }
}


// ── Arch panel ────────────────────────────────────────────────────────────────
// Renders the Arch tab. Uses its own state for the collapsible vector table.
// All address fields from the backend are already hex strings — printed as-is.

// eslint-disable-next-line @typescript-eslint/no-explicit-any
function ArchPanel({ arch, checksec }: { arch: Record<string, any>; checksec: Record<string, any> }) {
  const [vtOpen, setVtOpen] = useState(false);

  if (!arch || Object.keys(arch).length === 0) {
    return <p className="text-sm text-slate-500 text-center py-8">No architecture data available.</p>;
  }

  if (arch.error && !arch.arch) {
    return <p className="text-xs text-slate-500 py-4">Arch detect error: {String(arch.error)}</p>;
  }

  // All address fields are pre-formatted hex strings from the backend.
  const kvRows: [string, string][] = [
    ["Architecture",  String(arch.arch     ?? "—")],
    ["Endianness",    String(arch.endianness ?? "—")],
    ["Load Address",  String(arch.inferred_load_address ?? "—")],
    ["Initial SP",    String(arch.initial_sp   ?? "—")],
    ["Reset Handler", String(arch.reset_handler ?? "—")],
  ];
  const boolRows: [string, boolean | undefined][] = [
    ["Bare Metal", arch.is_bare_metal as boolean | undefined],
    ["Thumb Mode", arch.thumb_mode    as boolean | undefined],
    ["SP in RAM",  arch.sp_in_ram     as boolean | undefined],
  ];

  const vectorTable: { index: number; raw: string; addr: string; thumb: boolean }[] =
    Array.isArray(arch.vector_table) ? arch.vector_table : [];
  const resetDisasm: string[] =
    Array.isArray(arch.reset_disasm) ? arch.reset_disasm : [];

  return (
    <div className="space-y-4">
      {/* KV summary grid */}
      <div className="grid grid-cols-2 sm:grid-cols-3 gap-2">
        {kvRows.map(([label, val]) => (
          <div key={label} className="rounded-lg px-3 py-2.5 border border-[#1f2840]" style={{ background: "#0b0f1a" }}>
            <p className="text-[10px] font-bold uppercase tracking-widest text-slate-600 mb-0.5">{label}</p>
            <p className="text-[13px] font-semibold text-slate-200 font-mono break-all">{val}</p>
          </div>
        ))}
        {boolRows.map(([label, val]) => {
          const known = val != null;
          const yes   = val === true;
          return (
            <div
              key={label}
              className={`rounded-lg px-3 py-2.5 border ${
                !known ? "border-[#1f2840]" : yes ? "border-emerald-500/20 bg-emerald-500/5" : "border-slate-600/20"
              }`}
              style={!known || !yes ? { background: "#0b0f1a" } : {}}
            >
              <p className="text-[10px] font-bold uppercase tracking-widest text-slate-600 mb-0.5">{label}</p>
              <p className={`text-[13px] font-semibold font-mono ${known ? (yes ? "text-emerald-400" : "text-slate-400") : "text-slate-600"}`}>
                {!known ? "—" : yes ? "Yes" : "No"}
              </p>
            </div>
          );
        })}
      </div>

      {/* ELF security mitigations */}
      {checksec?.is_elf && (
        <div>
          <p className="text-xs font-semibold text-slate-400 uppercase tracking-wide mb-2">ELF Security Mitigations</p>
          <div className="grid grid-cols-2 sm:grid-cols-3 gap-2">
            {(
              [
                ["NX",      checksec.nx,      true   ],
                ["PIE",     checksec.pie,     true   ],
                ["Canary",  checksec.canary,  true   ],
                ["Fortify", checksec.fortify, true   ],
                ["RELRO",   checksec.relro,   "full" ],
              ] as [string, unknown, unknown][]
            ).map(([label, val, good]) => {
              const ok = val === good;
              return (
                <div key={label} className={`flex items-center gap-2 rounded-lg px-3 py-2 border ${ok ? "border-emerald-500/20 bg-emerald-500/5" : "border-red-500/20 bg-red-500/5"}`}>
                  <span className={`text-sm leading-none ${ok ? "text-emerald-400" : "text-red-400"}`}>{ok ? "+" : "−"}</span>
                  <span className="text-xs font-mono font-semibold text-slate-300">{label}</span>
                  {typeof val === "string" && (
                    <span className="ml-auto text-[10px] text-slate-500">{val}</span>
                  )}
                </div>
              );
            })}
          </div>
        </div>
      )}

      {/* Collapsible vector table */}
      {vectorTable.length > 0 && (
        <div>
          <button
            onClick={() => setVtOpen(o => !o)}
            className="flex items-center gap-2 text-xs font-semibold text-slate-400 uppercase tracking-wide mb-2 hover:text-slate-200 transition-colors"
          >
            <svg
              className={`w-3 h-3 transition-transform ${vtOpen ? "rotate-90" : ""}`}
              viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2.5"
              strokeLinecap="round" strokeLinejoin="round"
            >
              <polyline points="9 18 15 12 9 6" />
            </svg>
            Interrupt Vectors ({vectorTable.length})
          </button>
          {vtOpen && (
            <div className="rounded-lg border border-[#1f2840] overflow-hidden" style={{ background: "#0b0f1a" }}>
              <div className="grid grid-cols-[2.5rem_4rem_10rem_1fr] px-3 py-1.5 border-b border-[#1f2840] text-[10px] font-bold uppercase tracking-widest text-slate-600" style={{ background: "#121826" }}>
                <span>#</span>
                <span>Raw</span>
                <span>Address</span>
                <span>Thumb</span>
              </div>
              <div className="max-h-56 overflow-y-auto divide-y divide-[#1f2840]">
                {vectorTable.map((vt, i) => (
                  <div key={i} className="grid grid-cols-[2.5rem_4rem_10rem_1fr] px-3 py-1 text-xs font-mono">
                    <span className="text-slate-600">{vt.index}</span>
                    <span className="text-slate-500">{String(vt.raw ?? "—")}</span>
                    <span className="text-slate-300">{String(vt.addr ?? "—")}</span>
                    <span className={vt.thumb ? "text-blue-400" : "text-slate-600"}>{vt.thumb ? "T" : "—"}</span>
                  </div>
                ))}
              </div>
            </div>
          )}
        </div>
      )}

      {/* Reset disasm — already formatted strings */}
      {resetDisasm.length > 0 && (
        <div>
          <p className="text-xs font-semibold text-slate-400 uppercase tracking-wide mb-2">
            Reset Handler ({resetDisasm.length} instructions)
          </p>
          <pre className="text-[11px] font-mono text-emerald-300/90 bg-[#060b10] rounded-lg p-3 overflow-x-auto max-h-52 border border-[#1f2840] whitespace-pre">
            {resetDisasm.map(line => String(line)).join("\n")}
          </pre>
        </div>
      )}

      {arch.error && (
        <p className="text-[11px] text-slate-500 font-mono">arch_detect error: {String(arch.error)}</p>
      )}
    </div>
  );
}


// ── Pipeline Tree adapter ─────────────────────────────────────────────────────
// Converts the raw scan report JSON into the PipelineData shape the component expects.

const CAT_LABELS: Record<string, string> = {
  SAFETY_BYPASS: "Safety Bypass", PRIVATE_KEY: "Private Key", CERTIFICATE: "Certificate",
  API_KEY: "API Key", CREDENTIAL: "Credential", FLASH_WRITE: "Flash Write",
  SHELL_COMMAND: "Shell Command", DEBUG_KEYWORD: "Debug Keyword", CRYPTO: "Crypto",
  URL: "URL", IP: "IP Address", DOMAIN: "Domain", NETWORK_SERVICE: "Network Service",
  VERSION: "Version String", WIFI_CREDENTIAL: "WiFi Credential", MQTT_BROKER: "MQTT Broker",
  AT_COMMAND: "AT Command", BOOTLOADER: "Bootloader", FILE_PATH: "File Path",
};
const CAT_SEV: Record<string, PipelineSev> = {
  SAFETY_BYPASS: "critical", PRIVATE_KEY: "critical", CERTIFICATE: "critical",
  API_KEY: "high", CREDENTIAL: "high", FLASH_WRITE: "high", WIFI_CREDENTIAL: "high",
  BOOTLOADER: "high", SHELL_COMMAND: "medium", DEBUG_KEYWORD: "medium", CRYPTO: "medium",
  MQTT_BROKER: "medium", AT_COMMAND: "medium",
  URL: "low", IP: "low", DOMAIN: "low", NETWORK_SERVICE: "low", FILE_PATH: "low", VERSION: "info",
};

function normSev(s?: string | null): PipelineSev {
  const l = (s ?? "").toLowerCase();
  if (l === "critical") return "critical";
  if (l === "high")     return "high";
  if (l === "medium")   return "medium";
  if (l === "low")      return "low";
  if (l === "informational" || l === "info") return "info";
  return "none";
}

// eslint-disable-next-line @typescript-eslint/no-explicit-any
function buildPipelineData(filename: string, report: Record<string, any>, riskScore: number, riskLevel: string): PipelineData {
  const hashes   = report.file?.hashes ?? {};
  const entropy  = report.entropy ?? {};
  const strR     = report.strings ?? {};
  const yaraR    = report.yara ?? {};
  const binwalkR = report.binwalk ?? {};
  const riskR    = report.risk ?? {};

  // Group suspicious strings by category
  const byCat: Record<string, { value: string; offset: number }[]> = {};
  for (const s of (strR.suspicious ?? [])) {
    if (!byCat[s.category]) byCat[s.category] = [];
    byCat[s.category].push(s);
  }
  const catOrder = ["SAFETY_BYPASS","PRIVATE_KEY","CERTIFICATE","API_KEY","CREDENTIAL",
    "WIFI_CREDENTIAL","FLASH_WRITE","BOOTLOADER","SHELL_COMMAND","DEBUG_KEYWORD","CRYPTO",
    "MQTT_BROKER","AT_COMMAND","URL","IP","DOMAIN","NETWORK_SERVICE","FILE_PATH","VERSION"];

  const fileSev = normSev(riskLevel);
  const entropySev: PipelineSev = (entropy.overall ?? 0) > 7.5 ? "critical"
    : (entropy.overall ?? 0) > 6 ? "medium" : "none";
  const strSuspCount = strR.suspicious_count ?? 0;
  const strSev: PipelineSev = strSuspCount > 10 ? "critical" : strSuspCount > 3 ? "high"
    : strSuspCount > 0 ? "medium" : "none";
  const yaraMatches: { rule: string; severity?: string }[] = yaraR.matches ?? [];
  const yaraSev: PipelineSev = yaraMatches.some(m => m.severity === "critical") ? "critical"
    : yaraMatches.some(m => m.severity === "high") ? "high"
    : yaraMatches.length > 0 ? "medium" : "none";
  const binCount = (binwalkR.findings ?? []).length;

  return {
    file: { name: filename, sha256: hashes.sha256, score: Math.round(riskScore), severity: fileSev },
    stages: [
      {
        id: "file-identity", index: "01", title: "File Identity",
        summary: hashes.sha256 ? `${hashes.sha256.slice(0, 14)}…` : "—", severity: "none",
        children: [
          { id: "sha256", label: "SHA-256", value: hashes.sha256 ?? "—" },
          { id: "sha1",   label: "SHA-1",   value: hashes.sha1  ?? "—" },
          { id: "md5",    label: "MD5",     value: hashes.md5   ?? "—" },
        ],
      },
      {
        id: "entropy", index: "02", title: "Entropy Analysis",
        summary: `${(entropy.overall ?? 0).toFixed(3)} / 8.000`, severity: entropySev,
        children: [
          { id: "ent-val",    label: "Overall",        value: (entropy.overall ?? 0).toFixed(4), severity: entropySev },
          { id: "ent-interp", label: "Interpretation", value: entropy.interpretation ?? "—" },
          { id: "ent-blocks", label: "Blocks analyzed", value: String(entropy.blocks?.length ?? 0) },
        ],
      },
      {
        id: "strings", index: "03", title: "String Extraction",
        summary: `${strR.total ?? 0} total · ${strSuspCount} suspicious`, severity: strSev,
        children: catOrder
          .filter(cat => byCat[cat]?.length)
          .map(cat => ({
            id: `cat-${cat}`,
            label: CAT_LABELS[cat] ?? cat,
            severity: CAT_SEV[cat] ?? "low",
            count: byCat[cat].length,
            children: byCat[cat].slice(0, 10).map((s, i) => ({
              id: `str-${cat}-${i}`,
              label: "value",
              value: s.value.length > 80 ? s.value.slice(0, 80) + "…" : s.value,
              offset: `0x${s.offset.toString(16).padStart(6, "0")}`,
              severity: CAT_SEV[cat] ?? "low",
            })),
          })),
      },
      {
        id: "yara", index: "04", title: "YARA Matching",
        summary: `${yaraMatches.length} match${yaraMatches.length !== 1 ? "es" : ""}`, severity: yaraSev,
        children: yaraMatches.length === 0
          ? [{ id: "yara-none", label: "No rule matches", severity: "none" as PipelineSev }]
          : yaraMatches.map((m, i) => ({ id: `yara-${i}`, label: m.rule, severity: normSev(m.severity) })),
      },
      {
        id: "binwalk", index: "05", title: "Binwalk Signatures",
        summary: `${binCount} signature${binCount !== 1 ? "s" : ""}`,
        severity: binCount > 0 ? "medium" : "none",
        children: binCount === 0
          ? [{ id: "bin-none", label: "No embedded signatures — bare-metal MCU (expected)", severity: "none" as PipelineSev }]
          // eslint-disable-next-line @typescript-eslint/no-explicit-any
          : (binwalkR.findings ?? []).map((f: any, i: number) => ({
              id: `bin-${i}`, label: f.description,
              offset: `0x${f.offset.toString(16).padStart(6, "0")}`, severity: "medium" as PipelineSev,
            })),
      },
      {
        id: "risk", index: "06", title: "Risk Assessment",
        summary: `${Math.round(riskScore)} / 100`, severity: fileSev,
        children: (riskR.reasons ?? []).map((r: string, i: number) => ({
          id: `risk-${i}`, label: r, severity: fileSev,
        })),
      },
    ],
  };
}

// (old inline PhaseSection / PhaseIcons / PipelineTree removed — see src/components/PipelineTree.tsx)


// ── Compliance panel ──────────────────────────────────────────────────────────

interface ComplianceMapping {
  finding:   string;
  source:    string;
  cwe:       string[];
  eu_cra:    string[];
  iec_62443: string[];
  fda:       string[];
}
interface ComplianceSummary {
  cwe:       string[];
  eu_cra:    string[];
  iec_62443: string[];
  fda:       string[];
}
interface ComplianceData {
  mappings:  ComplianceMapping[];
  summary:   ComplianceSummary;
  error?:    string | null;
}

const STD_META: { key: keyof ComplianceSummary; label: string; color: string }[] = [
  { key: "cwe",       label: "CWE",          color: "text-red-400 bg-red-500/10 border-red-500/25" },
  { key: "eu_cra",    label: "EU CRA",        color: "text-blue-400 bg-blue-500/10 border-blue-500/25" },
  { key: "iec_62443", label: "IEC 62443-4-2", color: "text-purple-400 bg-purple-500/10 border-purple-500/25" },
  { key: "fda",       label: "FDA",           color: "text-emerald-400 bg-emerald-500/10 border-emerald-500/25" },
];

function StdChip({ label, color }: { label: string; color: string }) {
  return (
    <span className={`inline-block rounded border px-2 py-0.5 text-[10px] font-mono font-semibold whitespace-nowrap ${color}`}>
      {label}
    </span>
  );
}

function CompliancePanel({ data }: { data: unknown }) {
  const d = data as ComplianceData | null | undefined;
  const mappings: ComplianceMapping[] = d?.mappings ?? [];
  const summary:  ComplianceSummary  = d?.summary  ?? { cwe: [], eu_cra: [], iec_62443: [], fda: [] };

  if (!d || mappings.length === 0) {
    return (
      <div className="text-center py-12 text-slate-500">
        <p className="text-sm">No compliance mappings found.</p>
        <p className="text-xs mt-1 text-slate-600">Run a scan with findings to generate compliance data.</p>
      </div>
    );
  }

  return (
    <div className="space-y-5">
      {/* Summary chips */}
      <div className="grid grid-cols-1 sm:grid-cols-2 lg:grid-cols-4 gap-3">
        {STD_META.map(({ key, label, color }) => (
          <div key={key} className="rounded-xl border border-[#1f2840] p-3" style={{ background: "#0b0f1a" }}>
            <p className="text-[10px] font-bold uppercase tracking-widest text-slate-600 mb-2">{label}</p>
            <div className="flex flex-wrap gap-1">
              {(summary[key] ?? []).length === 0 ? (
                <span className="text-xs text-slate-700">None</span>
              ) : (
                (summary[key] ?? []).map((ref: string) => (
                  <StdChip key={ref} label={ref} color={color} />
                ))
              )}
            </div>
          </div>
        ))}
      </div>

      {/* Mapping table */}
      <div className="rounded-lg border border-[#1f2840] overflow-hidden">
        <div className="grid grid-cols-[1fr_auto_auto_auto_auto] gap-x-3 px-3 py-2 border-b border-[#1f2840] text-[10px] font-bold uppercase tracking-widest text-slate-600" style={{ background: "#121826" }}>
          <span>Finding</span>
          <span>CWE</span>
          <span>EU CRA</span>
          <span>IEC 62443</span>
          <span>FDA</span>
        </div>
        <div className="divide-y divide-[#1a2234] max-h-[520px] overflow-y-auto">
          {mappings.map((m, i) => (
            <div key={i} className="grid grid-cols-[1fr_auto_auto_auto_auto] gap-x-3 items-start px-3 py-2.5 hover:bg-[#161d2e] transition-colors">
              <div className="min-w-0">
                <p className="text-xs text-slate-200 leading-snug">{m.finding}</p>
                <p className="text-[10px] font-mono text-slate-700 mt-0.5 truncate">{m.source}</p>
              </div>
              <div className="flex flex-wrap gap-1 justify-end max-w-[9rem]">
                {(m.cwe ?? []).map((ref: string) => <StdChip key={ref} label={ref} color={STD_META[0].color} />)}
              </div>
              <div className="flex flex-wrap gap-1 justify-end max-w-[9rem]">
                {(m.eu_cra ?? []).map((ref: string) => <StdChip key={ref} label={ref} color={STD_META[1].color} />)}
              </div>
              <div className="flex flex-wrap gap-1 justify-end max-w-[6rem]">
                {(m.iec_62443 ?? []).map((ref: string) => <StdChip key={ref} label={ref} color={STD_META[2].color} />)}
              </div>
              <div className="flex flex-wrap gap-1 justify-end max-w-[9rem]">
                {(m.fda ?? []).map((ref: string) => <StdChip key={ref} label={ref} color={STD_META[3].color} />)}
              </div>
            </div>
          ))}
        </div>
      </div>

      {d?.error && (
        <p className="text-xs text-red-400 font-mono">compliance error: {d.error}</p>
      )}
    </div>
  );
}
