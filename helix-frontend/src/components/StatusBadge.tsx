import Spinner from "./Spinner";
import type { ScanStatus } from "@/lib/api";

const CHIP: Record<string, string> = {
  pending:   "text-slate-400   bg-slate-500/10  border-slate-600/30",
  running:   "text-amber-400   bg-amber-500/10  border-amber-500/30",
  completed: "text-emerald-400 bg-emerald-500/10 border-emerald-600/30",
  failed:    "text-red-400     bg-red-500/10    border-red-500/30",
};

const DOT: Record<string, string> = {
  pending:   "bg-slate-500",
  running:   "bg-amber-400 animate-pulse",
  completed: "bg-emerald-500",
  failed:    "bg-red-500",
};

export default function StatusBadge({ status }: { status: ScanStatus | string }) {
  const chipCls = CHIP[status] ?? "text-slate-400 bg-slate-500/10 border-slate-600/30";
  const dotCls  = DOT[status]  ?? "bg-slate-500";

  return (
    <span className={`inline-flex items-center gap-1.5 rounded-md border px-2 py-0.5 text-xs font-medium ${chipCls}`}>
      {status === "running"
        ? <Spinner size={10} />
        : <span className={`w-1.5 h-1.5 rounded-full flex-shrink-0 ${dotCls}`} />}
      {status.charAt(0).toUpperCase() + status.slice(1)}
    </span>
  );
}
