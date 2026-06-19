"use client";
import { useEffect, useState, type FormEvent } from "react";
import { Plus, Check, X, Shield, Trash2, ToggleLeft, ToggleRight } from "lucide-react";
import {
  listYaraRules,
  createYaraRule,
  updateYaraRule,
  deleteYaraRule,
  validateYaraRule,
  type YaraRule,
} from "@/lib/api";
import Spinner from "@/components/Spinner";

const SEV_CHIP: Record<string, string> = {
  critical: "bg-red-500/10 text-red-300 border border-red-500/30",
  high:     "bg-orange-500/10 text-orange-300 border border-orange-500/30",
  medium:   "bg-amber-500/10 text-amber-300 border border-amber-500/30",
  low:      "bg-slate-500/10 text-slate-400 border border-slate-600/30",
};

const BLANK_RULE = `rule MyRule
{
    meta:
        description = "Describe what this rule detects"
        severity    = "medium"
    strings:
        $s = "suspicious_string"
    condition:
        $s
}`;

function fmtDate(iso: string) {
  return new Date(iso).toLocaleString("en-GB", {
    day: "2-digit", month: "short", year: "numeric",
    hour: "2-digit", minute: "2-digit",
  });
}

const inputCls  = "w-full rounded-lg border border-[#1f2840] bg-[#0b0f1a] text-slate-200 px-3 py-2 text-sm placeholder:text-slate-600 focus:outline-none focus:ring-2 focus:ring-brand-500/40 transition-colors";
const labelCls  = "block text-[10px] font-semibold text-slate-500 uppercase tracking-[0.08em] mb-1";

export default function RulesPage() {
  const [rules, setRules]           = useState<YaraRule[] | null>(null);
  const [showForm, setShowForm]     = useState(false);
  const [editingId, setEditingId]   = useState<string | null>(null);

  // Form fields
  const [name, setName]             = useState("");
  const [description, setDesc]      = useState("");
  const [severity, setSeverity]     = useState("medium");
  const [content, setContent]       = useState(BLANK_RULE);
  const [enabled, setEnabled]       = useState(true);

  // Validation state
  const [validating, setValidating] = useState(false);
  const [validResult, setValidResult] = useState<{ ok: boolean; error: string | null } | null>(null);

  const [submitting, setSubmitting] = useState(false);
  const [error, setError]           = useState("");
  const [deletingId, setDeletingId] = useState<string | null>(null);

  function load() {
    listYaraRules().then(setRules).catch(console.error);
  }

  useEffect(() => { load(); }, []);

  function openCreate() {
    setEditingId(null);
    setName(""); setDesc(""); setSeverity("medium");
    setContent(BLANK_RULE); setEnabled(true);
    setValidResult(null); setError("");
    setShowForm(true);
  }

  function openEdit(rule: YaraRule) {
    setEditingId(rule.id);
    setName(rule.name); setDesc(rule.description);
    setSeverity(rule.severity); setContent(rule.content);
    setEnabled(rule.enabled); setValidResult(null); setError("");
    setShowForm(true);
  }

  function cancel() {
    setShowForm(false); setEditingId(null); setValidResult(null); setError("");
  }

  async function handleValidate() {
    setValidating(true);
    setValidResult(null);
    try {
      const res = await validateYaraRule(content);
      setValidResult(res);
    } catch (err) {
      setValidResult({ ok: false, error: err instanceof Error ? err.message : "Validation failed" });
    } finally {
      setValidating(false);
    }
  }

  async function handleSubmit(e: FormEvent) {
    e.preventDefault();
    setError("");
    setSubmitting(true);
    try {
      if (editingId) {
        await updateYaraRule(editingId, { name, description, severity, content, enabled });
      } else {
        await createYaraRule({ name, description, severity, content, enabled });
      }
      cancel();
      load();
    } catch (err) {
      setError(err instanceof Error ? err.message : "Save failed");
    } finally {
      setSubmitting(false);
    }
  }

  async function handleToggleEnabled(rule: YaraRule) {
    try {
      await updateYaraRule(rule.id, { enabled: !rule.enabled });
      load();
    } catch {}
  }

  async function handleDelete(rule: YaraRule) {
    if (!confirm(`Delete rule "${rule.name}"? This cannot be undone.`)) return;
    setDeletingId(rule.id);
    try {
      await deleteYaraRule(rule.id);
      load();
    } catch (err) {
      alert(err instanceof Error ? err.message : "Delete failed");
    } finally {
      setDeletingId(null);
    }
  }

  return (
    <div>
      <div className="flex items-center justify-between mb-6">
        <div>
          <h1 className="text-[15px] font-semibold text-slate-100">YARA Rules</h1>
          <p className="text-slate-500 text-sm mt-0.5">
            Manage custom YARA rules — active rules are merged with built-in rules on each scan
          </p>
        </div>
        <button
          onClick={showForm ? cancel : openCreate}
          className="inline-flex items-center gap-1.5 bg-brand-600 hover:bg-brand-500 text-white text-sm font-semibold px-4 py-2 rounded-lg transition-colors"
        >
          {showForm ? "Cancel" : <><Plus size={14} strokeWidth={2.5} /> New Rule</>}
        </button>
      </div>

      {/* ── Editor form ── */}
      {showForm && (
        <form
          onSubmit={handleSubmit}
          className="border border-[#1f2840] rounded-xl p-5 mb-6 space-y-4 shadow-card"
          style={{ background: "#121826" }}
        >
          <h2 className="text-sm font-semibold text-slate-200">
            {editingId ? "Edit Rule" : "New YARA Rule"}
          </h2>

          <div className="grid grid-cols-2 gap-4">
            <div>
              <label className={labelCls}>Rule Name</label>
              <input value={name} onChange={e => setName(e.target.value)} required
                placeholder="e.g. DetectHardcodedPassword" className={inputCls} />
            </div>
            <div>
              <label className={labelCls}>Severity</label>
              <select value={severity} onChange={e => setSeverity(e.target.value)} className={inputCls}>
                <option value="critical">Critical</option>
                <option value="high">High</option>
                <option value="medium">Medium</option>
                <option value="low">Low</option>
              </select>
            </div>
          </div>

          <div>
            <label className={labelCls}>Description</label>
            <input value={description} onChange={e => setDesc(e.target.value)}
              placeholder="What does this rule detect?" className={inputCls} />
          </div>

          <div>
            <div className="flex items-center justify-between mb-1">
              <label className={labelCls + " mb-0"}>YARA Source</label>
              <button
                type="button"
                onClick={handleValidate}
                disabled={validating || !content.trim()}
                className="inline-flex items-center gap-1 text-[11px] font-semibold px-2.5 py-1 rounded-md border border-[#2d3a54] text-slate-400 hover:text-slate-200 hover:border-brand-500/50 transition-colors disabled:opacity-40"
              >
                {validating ? <Spinner size={10} /> : <Shield size={11} />}
                Validate
              </button>
            </div>
            <textarea
              value={content}
              onChange={e => { setContent(e.target.value); setValidResult(null); }}
              rows={12}
              className={inputCls + " font-mono text-xs resize-y"}
              spellCheck={false}
            />
            {validResult && (
              <div className={`mt-1.5 flex items-start gap-2 text-xs px-3 py-2 rounded-lg border ${
                validResult.ok
                  ? "bg-emerald-500/5 border-emerald-500/20 text-emerald-400"
                  : "bg-red-500/5 border-red-500/20 text-red-400"
              }`}>
                {validResult.ok
                  ? <Check size={13} className="mt-0.5 flex-shrink-0" />
                  : <X size={13} className="mt-0.5 flex-shrink-0" />}
                <span className="font-mono whitespace-pre-wrap break-all">
                  {validResult.ok ? "Rule compiles successfully" : validResult.error}
                </span>
              </div>
            )}
          </div>

          <div className="flex items-center gap-2">
            <input type="checkbox" id="enabled-cb" checked={enabled}
              onChange={e => setEnabled(e.target.checked)} className="accent-brand-500" />
            <label htmlFor="enabled-cb" className="text-sm text-slate-400 cursor-pointer">
              Enable rule immediately
            </label>
          </div>

          {error && (
            <p className="text-xs text-red-400 bg-red-500/5 border border-red-500/20 rounded-lg px-3 py-2">
              {error}
            </p>
          )}

          <div className="flex gap-2 pt-1">
            <button
              type="submit"
              disabled={submitting}
              className="inline-flex items-center gap-1.5 bg-brand-600 hover:bg-brand-500 text-white text-sm font-semibold px-4 py-2 rounded-lg transition-colors disabled:opacity-50"
            >
              {submitting ? <Spinner size={14} /> : null}
              {editingId ? "Save Changes" : "Create Rule"}
            </button>
            <button type="button" onClick={cancel}
              className="text-sm text-slate-500 hover:text-slate-300 transition-colors px-3 py-2">
              Cancel
            </button>
          </div>
        </form>
      )}

      {/* ── Rule list ── */}
      {rules === null ? (
        <div className="flex items-center justify-center py-16"><Spinner /></div>
      ) : rules.length === 0 ? (
        <div className="text-center py-16 border border-dashed border-[#1f2840] rounded-xl">
          <Shield size={32} className="mx-auto mb-3 text-slate-700" />
          <p className="text-slate-500 text-sm">No custom YARA rules yet.</p>
          <p className="text-slate-600 text-xs mt-1">Built-in rules from firmware_rules.yar are always active.</p>
        </div>
      ) : (
        <div className="space-y-2">
          {rules.map(rule => (
            <div
              key={rule.id}
              className={`border rounded-xl p-4 transition-colors ${
                rule.enabled
                  ? "border-[#1f2840] bg-[#0b0f1a]/60"
                  : "border-[#151a26] bg-[#080c14]/40 opacity-60"
              }`}
            >
              <div className="flex items-start gap-3">
                {/* Name + badges */}
                <div className="flex-1 min-w-0">
                  <div className="flex items-center gap-2 flex-wrap">
                    <span className="font-mono text-[13px] font-semibold text-slate-100 truncate">
                      {rule.name}
                    </span>
                    <span className={`text-[10px] font-semibold px-2 py-0.5 rounded-full ${SEV_CHIP[rule.severity] ?? SEV_CHIP.low}`}>
                      {rule.severity}
                    </span>
                    {!rule.enabled && (
                      <span className="text-[10px] text-slate-600 font-semibold px-2 py-0.5 rounded-full border border-[#2d3a54]">
                        disabled
                      </span>
                    )}
                  </div>
                  {rule.description && (
                    <p className="text-slate-500 text-xs mt-1">{rule.description}</p>
                  )}
                  <p className="text-[10px] text-slate-700 mt-1.5 font-mono">
                    by {rule.created_by} · {fmtDate(rule.updated_at)}
                  </p>
                </div>

                {/* Actions */}
                <div className="flex items-center gap-1 flex-shrink-0">
                  <button
                    onClick={() => handleToggleEnabled(rule)}
                    title={rule.enabled ? "Disable" : "Enable"}
                    className="p-1.5 rounded-lg text-slate-500 hover:text-brand-400 hover:bg-brand-500/10 transition-colors"
                  >
                    {rule.enabled
                      ? <ToggleRight size={16} className="text-emerald-400" />
                      : <ToggleLeft size={16} />}
                  </button>
                  <button
                    onClick={() => openEdit(rule)}
                    className="text-[11px] font-semibold px-2.5 py-1.5 rounded-lg border border-[#1f2840] text-slate-400 hover:text-slate-200 hover:border-[#2d3a54] transition-colors"
                  >
                    Edit
                  </button>
                  <button
                    onClick={() => handleDelete(rule)}
                    disabled={deletingId === rule.id}
                    className="p-1.5 rounded-lg text-slate-600 hover:text-red-400 hover:bg-red-500/10 transition-colors disabled:opacity-40"
                    title="Delete"
                  >
                    {deletingId === rule.id ? <Spinner size={14} /> : <Trash2 size={14} />}
                  </button>
                </div>
              </div>

              {/* Collapsed YARA preview */}
              <details className="mt-3">
                <summary className="text-[10px] text-slate-700 cursor-pointer hover:text-slate-500 select-none">
                  Show source
                </summary>
                <pre className="mt-2 text-[11px] font-mono text-slate-400 bg-[#060b10] rounded-lg p-3 overflow-x-auto whitespace-pre max-h-48 overflow-y-auto">
                  {rule.content}
                </pre>
              </details>
            </div>
          ))}
        </div>
      )}
    </div>
  );
}
