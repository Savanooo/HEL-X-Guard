import type { Config } from "tailwindcss";

const config: Config = {
  content: [
    "./src/pages/**/*.{js,ts,jsx,tsx,mdx}",
    "./src/components/**/*.{js,ts,jsx,tsx,mdx}",
    "./src/app/**/*.{js,ts,jsx,tsx,mdx}",
  ],
  theme: {
    extend: {
      fontFamily: {
        sans: ["Inter", "system-ui", "sans-serif"],
        mono: ["JetBrains Mono", "Menlo", "monospace"],
      },
      colors: {
        brand: {
          300: "#93c5fd",
          400: "#60a5fa",
          500: "#3b82f6",
          600: "#2563eb",
        },
        hx: {
          bg:          "#0b0f1a",
          surface:     "#121826",
          raised:      "#161d2e",
          border:      "#1f2840",
          "border-hi": "#2d3a54",
        },
        sev: {
          critical: "#ef4444",
          high:     "#f97316",
          medium:   "#f59e0b",
          low:      "#64748b",
        },
        ink: {
          1: "#e2e8f0",
          2: "#94a3b8",
          3: "#64748b",
        },
      },
      boxShadow: {
        card: "inset 0 1px 0 rgba(255,255,255,0.04), 0 1px 3px rgba(0,0,0,0.3)",
        "card-hover": "inset 0 1px 0 rgba(255,255,255,0.06), 0 2px 8px rgba(0,0,0,0.4)",
        brand: "0 0 0 3px rgba(59,130,246,0.15)",
      },
    },
  },
  plugins: [],
};
export default config;
