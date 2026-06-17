import type { RiskLevel } from "@/lib/api";

const styles: Record<string, string> = {
  critical:      "bg-red-900/50 text-red-300 border border-red-700/60",
  high:          "bg-orange-900/50 text-orange-300 border border-orange-700/60",
  medium:        "bg-yellow-900/40 text-yellow-300 border border-yellow-700/50",
  low:           "bg-green-900/40 text-green-300 border border-green-800/50",
  informational: "bg-sky-900/40 text-sky-300 border border-sky-800/50",
};

const labels: Record<string, string> = {
  critical:      "CRITICAL",
  high:          "HIGH",
  medium:        "MEDIUM",
  low:           "LOW",
  informational: "INFO",
};

interface Props {
  level: RiskLevel | string;
  score?: number | null;
  large?: boolean;
}

export default function RiskBadge({ level, score, large }: Props) {
  const cls = styles[level] ?? "bg-slate-800 text-slate-400 border border-slate-700";
  const label = labels[level] ?? level.toUpperCase();

  return (
    <span
      className={`inline-flex items-center gap-1.5 rounded-md font-semibold ${
        large ? "px-3 py-1 text-sm" : "px-2 py-0.5 text-xs"
      } ${cls}`}
    >
      {label}
      {score != null && (
        <span className="opacity-70 font-normal">{Math.round(score)}/100</span>
      )}
    </span>
  );
}
