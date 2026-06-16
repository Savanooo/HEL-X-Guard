"use client";

const COLOR: Record<string, string> = {
  critical:      "#dc2626",
  high:          "#f97316",
  medium:        "#eab308",
  low:           "#22c55e",
  informational: "#38bdf8",
};

interface Props {
  score: number;
  level: string;
}

export default function RiskGauge({ score, level }: Props) {
  const color = COLOR[level] ?? "#94a3b8";
  const R = 58;
  // Half-circle arc length
  const total = Math.PI * R;
  const filled = (Math.max(0, Math.min(100, score)) / 100) * total;

  return (
    <div className="flex flex-col items-center gap-1">
      <svg width="150" height="88" viewBox="0 0 150 88" aria-hidden>
        {/* Track */}
        <path
          d={`M 17 75 A ${R} ${R} 0 0 1 133 75`}
          fill="none"
          stroke="#e2e8f0"
          strokeWidth="14"
          strokeLinecap="round"
        />
        {/* Fill */}
        <path
          d={`M 17 75 A ${R} ${R} 0 0 1 133 75`}
          fill="none"
          stroke={color}
          strokeWidth="14"
          strokeLinecap="round"
          strokeDasharray={`${filled} ${total}`}
          style={{ transition: "stroke-dasharray 0.6s ease" }}
        />
        {/* Score text */}
        <text
          x="75"
          y="72"
          textAnchor="middle"
          fontSize="28"
          fontWeight="700"
          fill={color}
        >
          {Math.round(score)}
        </text>
        <text
          x="75"
          y="86"
          textAnchor="middle"
          fontSize="11"
          fill="#94a3b8"
        >
          / 100
        </text>
      </svg>
    </div>
  );
}
