"use client";
import { useState, useRef, type DragEvent } from "react";
import { useRouter } from "next/navigation";
import { UploadCloud, FileCode2, Lock, Search, Zap, BarChart3 } from "lucide-react";
import { createScan } from "@/lib/api";
import Spinner from "@/components/Spinner";

const ALLOWED_EXTS = [".bin", ".fw", ".img", ".hex", ".rom", ".elf", ".axf", ".srec"];

const INFO_ITEMS = [
  { Icon: Lock,      text: "Never executed — static analysis only" },
  { Icon: Search,    text: "Extracts strings, entropy, YARA, binwalk" },
  { Icon: Zap,       text: "Results ready in seconds" },
  { Icon: BarChart3, text: "Risk score 0–100 with findings breakdown" },
];

export default function UploadPage() {
  const router = useRouter();
  const [dragging, setDragging] = useState(false);
  const [file, setFile] = useState<File | null>(null);
  const [uploading, setUploading] = useState(false);
  const [error, setError] = useState("");
  const inputRef = useRef<HTMLInputElement>(null);

  function handleFiles(files: FileList | null) {
    if (!files || files.length === 0) return;
    const f = files[0];
    const ext = f.name.slice(f.name.lastIndexOf(".")).toLowerCase();
    if (ALLOWED_EXTS.length && !ALLOWED_EXTS.includes(ext)) {
      setError(`Extension "${ext}" not supported. Allowed: ${ALLOWED_EXTS.join(", ")}`);
      return;
    }
    setError("");
    setFile(f);
  }

  function onDrop(e: DragEvent<HTMLDivElement>) {
    e.preventDefault();
    setDragging(false);
    handleFiles(e.dataTransfer.files);
  }

  async function handleSubmit() {
    if (!file) return;
    setUploading(true);
    setError("");
    try {
      const scan = await createScan(file);
      router.push(`/dashboard/${scan.id}`);
    } catch (err) {
      setError(err instanceof Error ? err.message : "Upload failed");
      setUploading(false);
    }
  }

  function fmtSize(bytes: number) {
    if (bytes < 1024) return `${bytes} B`;
    if (bytes < 1_048_576) return `${(bytes / 1024).toFixed(1)} KB`;
    return `${(bytes / 1_048_576).toFixed(1)} MB`;
  }

  return (
    <div className="max-w-xl mx-auto">
      <h1 className="text-[15px] font-semibold text-slate-100 mb-0.5">New Scan</h1>
      <p className="text-slate-500 text-sm mb-8">Upload a firmware binary for static security analysis.</p>

      {/* Drop zone */}
      <div
        onDragOver={(e) => { e.preventDefault(); setDragging(true); }}
        onDragLeave={() => setDragging(false)}
        onDrop={onDrop}
        onClick={() => inputRef.current?.click()}
        className={`relative cursor-pointer border-2 border-dashed rounded-2xl p-12 text-center transition-all ${
          dragging
            ? "border-brand-500 bg-brand-500/5"
            : file
            ? "border-emerald-500 bg-emerald-500/5"
            : "border-[#2d3a54] hover:border-[#3d4f6e]"
        }`}
      >
        <input
          ref={inputRef}
          type="file"
          className="hidden"
          accept={ALLOWED_EXTS.join(",")}
          onChange={(e) => handleFiles(e.target.files)}
        />

        {file ? (
          <div className="space-y-2">
            <FileCode2 className="mx-auto text-emerald-400" size={40} strokeWidth={1.25} />
            <p className="font-semibold text-slate-200 text-[15px]">{file.name}</p>
            <p className="text-slate-400 text-sm">{fmtSize(file.size)}</p>
            <button
              onClick={(e) => { e.stopPropagation(); setFile(null); }}
              className="text-xs text-slate-500 hover:text-red-400 transition-colors mt-1"
            >
              Remove
            </button>
          </div>
        ) : (
          <div className="space-y-3">
            <UploadCloud className="mx-auto text-slate-600" size={48} strokeWidth={1} />
            <div>
              <p className="font-semibold text-slate-300 text-[15px]">Drop firmware file here</p>
              <p className="text-slate-500 text-sm mt-0.5">or click to browse</p>
            </div>
            <p className="text-xs text-slate-600">
              Supported: {ALLOWED_EXTS.join("  ")} · Max 500 MB
            </p>
          </div>
        )}
      </div>

      {/* Error */}
      {error && (
        <div className="mt-4 bg-red-500/10 border border-red-500/30 text-red-300 rounded-xl px-4 py-3 text-sm">
          {error}
        </div>
      )}

      {/* Info boxes */}
      <div className="mt-6 grid grid-cols-2 gap-3">
        {INFO_ITEMS.map(({ Icon, text }) => (
          <div
            key={text}
            className="flex items-start gap-2.5 border border-[#1f2840] rounded-xl px-3 py-2.5 text-xs text-slate-500"
            style={{ background: "#121826" }}
          >
            <Icon size={13} className="text-slate-600 flex-shrink-0 mt-0.5" strokeWidth={1.5} />
            <span>{text}</span>
          </div>
        ))}
      </div>

      {/* Submit */}
      <button
        onClick={handleSubmit}
        disabled={!file || uploading}
        className="mt-6 w-full flex items-center justify-center gap-2 bg-brand-600 hover:bg-brand-500 disabled:opacity-50 disabled:cursor-not-allowed text-white font-semibold text-sm py-3 rounded-xl transition-colors"
      >
        {uploading ? (
          <>
            <Spinner size={16} />
            Uploading &amp; starting scan…
          </>
        ) : (
          "Start Analysis →"
        )}
      </button>
    </div>
  );
}
