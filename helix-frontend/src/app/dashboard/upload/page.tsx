"use client";
import { useState, useRef, type DragEvent } from "react";
import { useRouter } from "next/navigation";
import { createScan } from "@/lib/api";
import Spinner from "@/components/Spinner";

const ALLOWED_EXTS = [".bin", ".fw", ".img", ".hex", ".rom", ".elf", ".axf", ".srec"];

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
    <div className="p-8 max-w-2xl">
      {/* Header */}
      <h1 className="text-2xl font-bold text-slate-900 mb-1">New Scan</h1>
      <p className="text-slate-500 text-sm mb-8">
        Upload a firmware binary for static security analysis.
      </p>

      {/* Drop zone */}
      <div
        onDragOver={(e) => { e.preventDefault(); setDragging(true); }}
        onDragLeave={() => setDragging(false)}
        onDrop={onDrop}
        onClick={() => inputRef.current?.click()}
        className={`relative cursor-pointer border-2 border-dashed rounded-2xl p-12 text-center transition-all ${
          dragging
            ? "border-blue-500 bg-blue-50"
            : file
            ? "border-emerald-400 bg-emerald-50"
            : "border-slate-300 bg-white hover:border-slate-400 hover:bg-slate-50"
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
            <div className="text-4xl">📦</div>
            <p className="font-semibold text-slate-900">{file.name}</p>
            <p className="text-slate-500 text-sm">{fmtSize(file.size)}</p>
            <button
              onClick={(e) => { e.stopPropagation(); setFile(null); }}
              className="text-xs text-slate-400 hover:text-red-500 transition-colors"
            >
              Remove
            </button>
          </div>
        ) : (
          <div className="space-y-3">
            <div className="text-5xl opacity-30">📂</div>
            <div>
              <p className="font-semibold text-slate-700">
                Drop firmware file here
              </p>
              <p className="text-slate-500 text-sm mt-0.5">
                or click to browse
              </p>
            </div>
            <p className="text-xs text-slate-400">
              Supported: {ALLOWED_EXTS.join("  ")} · Max 500 MB
            </p>
          </div>
        )}
      </div>

      {/* Error */}
      {error && (
        <div className="mt-4 bg-red-50 border border-red-200 text-red-700 rounded-xl px-4 py-3 text-sm">
          {error}
        </div>
      )}

      {/* Info boxes */}
      <div className="mt-6 grid grid-cols-2 gap-3 text-xs text-slate-500">
        {[
          { icon: "🔒", text: "File is never executed — static analysis only" },
          { icon: "🔍", text: "Extracts strings, entropy, YARA, binwalk findings" },
          { icon: "⚡", text: "Results ready in seconds (may take longer for large files)" },
          { icon: "📊", text: "Risk score 0–100 with detailed findings breakdown" },
        ].map(({ icon, text }) => (
          <div key={text} className="flex items-start gap-2 bg-slate-100 rounded-xl px-3 py-2.5">
            <span>{icon}</span>
            <span>{text}</span>
          </div>
        ))}
      </div>

      {/* Submit */}
      <button
        onClick={handleSubmit}
        disabled={!file || uploading}
        className="mt-6 w-full flex items-center justify-center gap-2 bg-blue-600 hover:bg-blue-700 disabled:opacity-50 disabled:cursor-not-allowed text-white font-semibold text-sm py-3 rounded-xl transition-colors"
      >
        {uploading ? (
          <>
            <Spinner size={16} />
            Uploading & starting scan…
          </>
        ) : (
          "Start Analysis →"
        )}
      </button>
    </div>
  );
}
