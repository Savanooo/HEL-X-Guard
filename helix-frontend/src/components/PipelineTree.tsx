"use client";
import React, { useState, useCallback } from "react";
import {
  Hash, Activity, Search, Target, Cpu, Shield,
  ChevronRight, ChevronsUpDown, SlidersHorizontal, FileText,
} from "lucide-react";

// ── Types ─────────────────────────────────────────────────────────────────────

export type Severity = "critical" | "high" | "medium" | "low" | "info" | "none";

export interface TreeChild {
  id: string;
  label: string;
  severity?: Severity;
  value?: string;    // monospace value (hash, string content)
  offset?: string;   // hex offset, e.g. "0x1b04da"
  count?: number;
  children?: TreeChild[];
}

export interface PipelineStage {
  id: string;
  index: string;    // "01" – "06"
  title: string;
  summary: string;
  severity: Severity;
  children?: TreeChild[];
}

export interface PipelineFile {
  name: string;
  sha256?: string;
  score: number;
  severity: Severity;
}

export interface PipelineData {
  file: PipelineFile;
  stages: PipelineStage[];
}

// ── Severity palette ──────────────────────────────────────────────────────────

interface SevStyle {
  badge: string;
  leftBorder: string;
  numPill: string;
  dot: string;
  text: string;
  childBorder: string;
  trunk: string;
  branch: string;
  glow?: string;
}

const S: Record<Severity, SevStyle> = {
  critical: {
    badge:       "bg-red-500/15 text-red-400 border border-red-500/30",
    leftBorder:  "border-l-red-500",
    numPill:     "bg-red-500/15 text-red-400 ring-1 ring-red-500/30",
    dot:         "bg-red-500",
    text:        "text-red-400",
    childBorder: "border-red-500/25",
    trunk:       "rgba(239,68,68,0.28)",
    branch:      "rgba(239,68,68,0.55)",
    glow:        "rgba(239,68,68,0.22)",
  },
  high: {
    badge:       "bg-orange-500/15 text-orange-400 border border-orange-500/30",
    leftBorder:  "border-l-orange-500",
    numPill:     "bg-orange-500/15 text-orange-400 ring-1 ring-orange-500/30",
    dot:         "bg-orange-500",
    text:        "text-orange-400",
    childBorder: "border-orange-500/20",
    trunk:       "rgba(249,115,22,0.22)",
    branch:      "rgba(249,115,22,0.45)",
  },
  medium: {
    badge:       "bg-amber-500/15 text-amber-300 border border-amber-500/30",
    leftBorder:  "border-l-amber-500",
    numPill:     "bg-amber-500/15 text-amber-300 ring-1 ring-amber-500/30",
    dot:         "bg-amber-400",
    text:        "text-amber-400",
    childBorder: "border-amber-500/18",
    trunk:       "rgba(245,158,11,0.18)",
    branch:      "rgba(245,158,11,0.38)",
  },
  low: {
    badge:       "bg-blue-500/15 text-blue-400 border border-blue-500/30",
    leftBorder:  "border-l-blue-500",
    numPill:     "bg-blue-500/15 text-blue-400 ring-1 ring-blue-500/30",
    dot:         "bg-blue-400",
    text:        "text-blue-400",
    childBorder: "border-blue-500/18",
    trunk:       "rgba(59,130,246,0.18)",
    branch:      "rgba(59,130,246,0.32)",
  },
  info: {
    badge:       "bg-slate-700/50 text-slate-400 border border-slate-600/30",
    leftBorder:  "border-l-slate-500",
    numPill:     "bg-slate-800 text-slate-500 ring-1 ring-slate-700/30",
    dot:         "bg-slate-500",
    text:        "text-slate-400",
    childBorder: "border-slate-700/30",
    trunk:       "rgba(100,116,139,0.18)",
    branch:      "rgba(100,116,139,0.30)",
  },
  none: {
    badge:       "bg-slate-800/50 text-slate-500 border border-slate-700/30",
    leftBorder:  "border-l-slate-700",
    numPill:     "bg-slate-800/60 text-slate-600 ring-1 ring-slate-700/20",
    dot:         "bg-slate-600",
    text:        "text-slate-500",
    childBorder: "border-slate-800/50",
    trunk:       "rgba(51,65,85,0.22)",
    branch:      "rgba(51,65,85,0.32)",
  },
};

const SEV_ORDER: Severity[] = ["critical", "high", "medium", "low", "info", "none"];
const STAGE_ICONS: Record<string, React.ReactElement> = {
  "01": <Hash size={12} />,
  "02": <Activity size={12} />,
  "03": <Search size={12} />,
  "04": <Target size={12} />,
  "05": <Cpu size={12} />,
  "06": <Shield size={12} />,
};

// ── Connector: L-shaped trunk+branch for the root→stage level ─────────────────

// Layout constants for level-1 connectors
const TX = 11;   // trunk x-position (px from left)
const BW = 17;   // branch width (px)
const CY = 22;   // center-y of the stage header (px from top of row)

function L1Connector({
  isLast, trunkColor, branchColor, glowColor,
}: {
  isLast: boolean;
  trunkColor: string;
  branchColor: string;
  glowColor?: string;
}) {
  const shadow = glowColor ? `0 0 6px ${glowColor}` : undefined;
  return (
    <>
      {/* Incoming trunk: top of row → row center */}
      <div className="absolute pointer-events-none w-px"
        style={{ left: TX, top: 0, height: CY, background: trunkColor, boxShadow: shadow }} />
      {/* Outgoing trunk: row center → bottom (only for non-last) */}
      {!isLast && (
        <div className="absolute pointer-events-none w-px"
          style={{ left: TX, top: CY, bottom: 0, background: trunkColor }} />
      )}
      {/* Horizontal branch */}
      <div className="absolute pointer-events-none h-px"
        style={{ left: TX, top: CY, width: BW, background: branchColor, boxShadow: shadow }} />
    </>
  );
}

// ── Severity badge pill ───────────────────────────────────────────────────────

function SevBadge({ sev }: { sev: Severity }) {
  if (sev === "none") return null;
  return (
    <span className={`inline-flex items-center px-1.5 py-[1px] rounded text-[9px] font-bold uppercase tracking-wider flex-shrink-0 ${S[sev].badge}`}>
      {sev}
    </span>
  );
}

// ── Leaf children (string findings, YARA rules, etc.) ─────────────────────────

function ChildGroup({ node, filterSev }: { node: TreeChild; filterSev: Severity | null }) {
  const [open, setOpen] = useState(false);
  const sev = node.severity ?? "none";
  const cfg = S[sev];
  const hasChildren = node.children && node.children.length > 0;
  const dimmed = filterSev !== null && SEV_ORDER.indexOf(sev) > SEV_ORDER.indexOf(filterSev);

  return (
    <div className={`transition-opacity duration-150 ${dimmed ? "opacity-20" : "opacity-100"}`}>
      <button
        onClick={() => hasChildren && setOpen(o => !o)}
        disabled={!hasChildren}
        className={`w-full flex items-center gap-2 px-2 py-1.5 rounded-lg text-left transition-all duration-150 group min-w-0
          ${hasChildren ? "cursor-pointer hover:bg-slate-800/20" : "cursor-default"}`}
      >
        <span className={`w-1.5 h-1.5 rounded-full flex-shrink-0 ${cfg.dot}`} />

        {/* Label / key-value layout */}
        {node.value !== undefined && !hasChildren ? (
          <>
            <span className="text-[10px] font-semibold text-slate-600 uppercase tracking-wide w-14 flex-shrink-0">{node.label}</span>
            <span className="font-mono text-[11px] text-slate-300 truncate flex-1">{node.value}</span>
          </>
        ) : (
          <>
            <span className={`text-[11px] font-medium flex-1 min-w-0 truncate ${sev !== "none" ? cfg.text : "text-slate-400"}`}>
              {node.label}
            </span>
            {node.count !== undefined && (
              <span className="text-[10px] text-slate-600 flex-shrink-0 font-mono">({node.count})</span>
            )}
          </>
        )}

        {node.offset && (
          <span className="font-mono text-[10px] text-slate-700 flex-shrink-0">{node.offset}</span>
        )}

        {hasChildren && sev !== "none" && <SevBadge sev={sev} />}

        {hasChildren && (
          <ChevronRight size={10}
            className={`text-slate-600 group-hover:text-slate-400 flex-shrink-0 transition-transform duration-200 ${open ? "rotate-90" : ""}`}
          />
        )}
      </button>

      {/* Nested grandchildren (e.g. category → individual strings) */}
      {hasChildren && open && (
        <div className={`ml-4 pl-2.5 border-l border-dashed ${S[sev].childBorder} space-y-0.5 pb-1`}>
          {node.children!.map(child => (
            <ChildGroup key={child.id} node={child} filterSev={filterSev} />
          ))}
        </div>
      )}
    </div>
  );
}

// ── Stage node ────────────────────────────────────────────────────────────────

function StageNode({
  stage, isLast, isOpen, onToggle, filterSev,
}: {
  stage: PipelineStage;
  isLast: boolean;
  isOpen: boolean;
  onToggle: () => void;
  filterSev: Severity | null;
}) {
  const cfg = S[stage.severity];
  const isCritical = stage.severity === "critical";
  const neutral    = S.none.trunk;

  return (
    <div className="relative">
      <L1Connector
        isLast={isLast}
        trunkColor={neutral}
        branchColor={cfg.branch}
        glowColor={isCritical ? cfg.glow : undefined}
      />

      {/* Content area, offset past the L1 connector */}
      <div style={{ marginLeft: TX + BW + 1 }}>
        {/* Stage header card */}
        <button
          onClick={onToggle}
          className={`w-full flex items-center gap-2.5 px-3 py-2.5 rounded-xl border border-l-[3px] text-left
            transition-all duration-150 group hover:brightness-110
            ${cfg.leftBorder} border-slate-700/35`}
          style={{
            background: "#131824",
            boxShadow: isCritical
              ? `0 0 0 1px rgba(239,68,68,0.07), 0 4px 24px ${cfg.glow}`
              : undefined,
          }}
        >
          {/* Phase number pill */}
          <span className={`text-[10px] font-bold font-mono px-1.5 py-[2px] rounded-md flex-shrink-0 ${cfg.numPill}`}>
            {stage.index}
          </span>

          {/* Phase icon */}
          <span className={`${cfg.text} flex-shrink-0`}>
            {STAGE_ICONS[stage.index] ?? <FileText size={12} />}
          </span>

          {/* Title */}
          <span className="text-[13px] font-semibold text-slate-200 flex-1 text-left tracking-tight">
            {stage.title}
          </span>

          {/* Summary (hidden on small screens) */}
          <span className="font-mono text-[10px] text-slate-600 hidden sm:block mr-2 flex-shrink-0">
            {stage.summary}
          </span>

          {/* Severity badge */}
          <SevBadge sev={stage.severity} />

          {/* Expand chevron */}
          <ChevronRight
            size={13}
            className={`text-slate-600 group-hover:text-slate-400 transition-transform duration-200 flex-shrink-0 ml-1
              ${isOpen ? "rotate-90" : ""}`}
          />
        </button>

        {/* Expanded children */}
        {isOpen && stage.children && stage.children.length > 0 && (
          <div
            className={`mt-1 ml-1 pl-3 border-l-2 border-dashed pb-1 ${cfg.childBorder}`}
          >
            {stage.children.map(child => (
              <ChildGroup key={child.id} node={child} filterSev={filterSev} />
            ))}
          </div>
        )}
      </div>
    </div>
  );
}

// ── Root node (file card) ─────────────────────────────────────────────────────

function RootNode({ file }: { file: PipelineFile }) {
  const cfg = S[file.severity];
  return (
    <div
      className={`flex items-center justify-between px-4 py-3 rounded-xl border border-l-[3px] ${cfg.leftBorder} border-slate-700/40`}
      style={{
        background: "#131824",
        boxShadow: file.severity === "critical"
          ? `0 4px 28px rgba(239,68,68,0.12), 0 0 0 1px rgba(239,68,68,0.06)`
          : undefined,
      }}
    >
      <div className="flex items-center gap-3 min-w-0">
        <FileText size={14} className="text-slate-500 flex-shrink-0" />
        <span className="font-mono text-sm font-bold text-white truncate">{file.name}</span>
        {file.sha256 && (
          <span className="font-mono text-[10px] text-slate-700 hidden lg:block truncate max-w-[200px]">
            {file.sha256.slice(0, 20)}…
          </span>
        )}
      </div>
      <div className="flex items-center gap-2.5 flex-shrink-0 ml-4">
        <span className={`font-mono text-[13px] font-bold ${cfg.text}`}>{file.score}/100</span>
        <SevBadge sev={file.severity} />
      </div>
    </div>
  );
}

// ── Filter chips ──────────────────────────────────────────────────────────────

const CHIPS: { sev: Severity; label: string }[] = [
  { sev: "critical", label: "Critical" },
  { sev: "high",     label: "High"     },
  { sev: "medium",   label: "Medium"   },
  { sev: "low",      label: "Low"      },
];

// ── Main component ────────────────────────────────────────────────────────────

export default function PipelineTree({ data }: { data: PipelineData }) {
  const [openStages, setOpenStages] = useState<Set<string>>(() =>
    new Set(
      data.stages
        .filter(s => s.severity !== "none" && (s.children?.length ?? 0) > 0)
        .map(s => s.id)
    )
  );
  const [filterSev, setFilterSev] = useState<Severity | null>(null);

  const allOpen = openStages.size === data.stages.length;

  const toggleStage = useCallback((id: string) => {
    setOpenStages(prev => {
      const next = new Set(prev);
      next.has(id) ? next.delete(id) : next.add(id);
      return next;
    });
  }, []);

  const toggleAll = useCallback(() => {
    setOpenStages(allOpen ? new Set() : new Set(data.stages.map(s => s.id)));
  }, [allOpen, data.stages]);

  const rootTrunk = S.none.trunk;

  return (
    <div className="space-y-2 select-none">

      {/* Controls */}
      <div className="flex items-center justify-between gap-3 flex-wrap">
        <div className="flex items-center gap-1.5 flex-wrap">
          <SlidersHorizontal size={11} className="text-slate-600" />
          {CHIPS.map(({ sev, label }) => {
            const active = filterSev === sev;
            return (
              <button
                key={sev}
                onClick={() => setFilterSev(active ? null : sev)}
                className={`text-[10px] font-bold uppercase tracking-wider px-2 py-[2px] rounded border transition-all duration-150 ${
                  active
                    ? S[sev].badge
                    : "bg-transparent text-slate-600 border-slate-700/30 hover:text-slate-400 hover:border-slate-600/40"
                }`}
              >
                {label}
              </button>
            );
          })}
          {filterSev && (
            <button onClick={() => setFilterSev(null)}
              className="text-[10px] text-slate-600 hover:text-slate-400 transition-colors underline ml-0.5">
              clear
            </button>
          )}
        </div>
        <button
          onClick={toggleAll}
          className="flex items-center gap-1.5 text-[11px] text-slate-500 hover:text-slate-300 transition-colors
            px-2 py-1 rounded-md border border-slate-700/30 hover:border-slate-600/50"
        >
          <ChevronsUpDown size={11} />
          {allOpen ? "Collapse all" : "Expand all"}
        </button>
      </div>

      {/* Root file card */}
      <RootNode file={data.file} />

      {/* Root → first stage connector (short vertical line) */}
      <div className="relative h-3">
        <div className="absolute w-px h-full" style={{ left: TX, background: rootTrunk }} />
      </div>

      {/* Stage tree */}
      <div className="relative">
        {data.stages.map((stage, idx) => (
          <StageNode
            key={stage.id}
            stage={stage}
            isLast={idx === data.stages.length - 1}
            isOpen={openStages.has(stage.id)}
            onToggle={() => toggleStage(stage.id)}
            filterSev={filterSev}
          />
        ))}
      </div>
    </div>
  );
}
