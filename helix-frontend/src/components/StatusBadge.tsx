import Spinner from "./Spinner";
import type { ScanStatus } from "@/lib/api";

const styles: Record<string, string> = {
  pending:   "bg-slate-800 text-slate-400",
  running:   "bg-blue-900/50 text-blue-300",
  completed: "bg-emerald-900/50 text-emerald-400",
  failed:    "bg-red-900/50 text-red-400",
};

export default function StatusBadge({ status }: { status: ScanStatus | string }) {
  const cls = styles[status] ?? "bg-slate-800 text-slate-400";
  return (
    <span
      className={`inline-flex items-center gap-1.5 rounded-md px-2 py-0.5 text-xs font-medium ${cls}`}
    >
      {status === "running" && <Spinner size={10} />}
      {status.charAt(0).toUpperCase() + status.slice(1)}
    </span>
  );
}
