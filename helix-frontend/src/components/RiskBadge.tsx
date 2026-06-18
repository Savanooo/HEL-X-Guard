import type { RiskLevel } from "@/lib/api";

const CHIP: Record<string, string> = {
  critical:      "text-red-400     border-red-500/30     bg-red-500/10",
  high:          "text-orange-400  border-orange-500/30  bg-orange-500/10",
  medium:        "text-amber-400   border-amber-500/30   bg-amber-500/10",
  low:           "text-emerald-400 border-emerald-600/30 bg-emerald-500/10",
  informational: "text-slate-400   border-slate-600/40   bg-slate-500/10",
};

const DOT: Record<string, string> = {
  critical:      "bg-red-500",
  high:          "bg-orange-500",
  medium:        "bg-amber-500",
  low:           "bg-emerald-500",
  informational: "bg-slate-500",
};

const LABELS: Record<string, string> = {
  critical:      "CRITICAL",
  high:          "HIGH",
  medium:        "MEDIUM",
  low:           "LOW",
  informational: "INFO",
};

interface Props { level: RiskLevel | string; score?: number | null; large?: boolean; }

export default function RiskBadge({ level, score, large }: Props) {
  const chipCls = CHIP[level] ?? "text-slate-400 border-slate-600/40 bg-slate-500/10";
  const dotCls  = DOT[level]  ?? "bg-slate-500";
  const label   = LABELS[level] ?? level.toUpperCase();

  return (
    <span className={`inline-flex items-center gap-1.5 rounded-md border font-semibold ${
      large ? "px-3 py-1 text-sm" : "px-2 py-0.5 text-xs"
    } ${chipCls}`}>
      <span className={`w-1.5 h-1.5 rounded-full flex-shrink-0 ${dotCls}`} />
      {label}
      {score != null && (
        <span className="opacity-60 font-normal">{Math.round(score)}</span>
      )}
    </span>
  );
}
