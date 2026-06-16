import type { RiskLevel } from "@/lib/api";

const styles: Record<string, string> = {
  critical:      "bg-red-100 text-red-700 border border-red-200",
  high:          "bg-orange-100 text-orange-700 border border-orange-200",
  medium:        "bg-yellow-100 text-yellow-700 border border-yellow-200",
  low:           "bg-green-100 text-green-700 border border-green-200",
  informational: "bg-sky-100 text-sky-700 border border-sky-200",
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
  const cls = styles[level] ?? "bg-slate-100 text-slate-600 border border-slate-200";
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
