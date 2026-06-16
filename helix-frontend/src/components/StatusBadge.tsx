import Spinner from "./Spinner";
import type { ScanStatus } from "@/lib/api";

const styles: Record<string, string> = {
  pending:   "bg-slate-100 text-slate-600",
  running:   "bg-blue-100 text-blue-700",
  completed: "bg-emerald-100 text-emerald-700",
  failed:    "bg-red-100 text-red-700",
};

export default function StatusBadge({ status }: { status: ScanStatus | string }) {
  const cls = styles[status] ?? "bg-slate-100 text-slate-600";
  return (
    <span
      className={`inline-flex items-center gap-1.5 rounded-md px-2 py-0.5 text-xs font-medium ${cls}`}
    >
      {status === "running" && <Spinner size={10} />}
      {status.charAt(0).toUpperCase() + status.slice(1)}
    </span>
  );
}
