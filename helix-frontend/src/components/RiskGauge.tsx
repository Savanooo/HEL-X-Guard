"use client";

const COLOR: Record<string, string> = {
  critical:      "#ef4444",
  high:          "#f97316",
  medium:        "#f59e0b",
  low:           "#22c55e",
  informational: "#64748b",
};

interface Props { score: number; level: string; }

export default function RiskGauge({ score, level }: Props) {
  const color = COLOR[level] ?? "#64748b";
  const R     = 58;
  const total = Math.PI * R;
  const filled = (Math.max(0, Math.min(100, score)) / 100) * total;

  return (
    <div className="flex flex-col items-center">
      <svg width="150" height="88" viewBox="0 0 150 88" aria-hidden>
        {/* Track — dark blue-tinted */}
        <path
          d={`M 17 75 A ${R} ${R} 0 0 1 133 75`}
          fill="none"
          stroke="#1f2840"
          strokeWidth="14"
          strokeLinecap="round"
        />
        {/* Fill — severity color */}
        <path
          d={`M 17 75 A ${R} ${R} 0 0 1 133 75`}
          fill="none"
          stroke={color}
          strokeWidth="14"
          strokeLinecap="round"
          strokeDasharray={`${filled} ${total}`}
          style={{ transition: "stroke-dasharray 0.6s ease" }}
        />
        {/* Score */}
        <text x="75" y="72" textAnchor="middle" fontSize="28" fontWeight="700" fill={color}>
          {Math.round(score)}
        </text>
        <text x="75" y="86" textAnchor="middle" fontSize="11" fill="#64748b">
          / 100
        </text>
      </svg>
    </div>
  );
}
