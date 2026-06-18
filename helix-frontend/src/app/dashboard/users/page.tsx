"use client";
import { useEffect, useState, type FormEvent } from "react";
import { Plus } from "lucide-react";
import { listUsers, createUser, type User } from "@/lib/api";
import Spinner from "@/components/Spinner";

const roleChip: Record<string, string> = {
  admin:   "bg-red-500/10 text-red-300 border border-red-500/30",
  analyst: "bg-brand-500/10 text-brand-400 border border-brand-500/30",
  viewer:  "bg-slate-500/10 text-slate-400 border border-slate-600/30",
};

function fmtDate(iso: string) {
  return new Date(iso).toLocaleString("en-GB", {
    day: "2-digit", month: "short", year: "numeric",
    hour: "2-digit", minute: "2-digit",
  });
}

export default function UsersPage() {
  const [users, setUsers] = useState<User[] | null>(null);
  const [showForm, setShowForm] = useState(false);
  const [username, setUsername] = useState("");
  const [email, setEmail] = useState("");
  const [password, setPassword] = useState("");
  const [role, setRole] = useState("viewer");
  const [error, setError] = useState("");
  const [submitting, setSubmitting] = useState(false);

  function load() {
    listUsers().then(setUsers).catch(console.error);
  }

  useEffect(() => { load(); }, []);

  async function handleSubmit(e: FormEvent) {
    e.preventDefault();
    setError("");
    setSubmitting(true);
    try {
      await createUser({ username, email, password, role });
      setUsername(""); setEmail(""); setPassword(""); setRole("viewer");
      setShowForm(false);
      load();
    } catch (err) {
      setError(err instanceof Error ? err.message : "Failed to create user");
    } finally {
      setSubmitting(false);
    }
  }

  const inputCls = "w-full rounded-lg border border-[#1f2840] bg-[#0b0f1a] text-slate-200 px-3 py-2 text-sm placeholder:text-slate-600 focus:outline-none focus:ring-2 focus:ring-brand-500/40 transition-colors";
  const labelCls = "block text-[10px] font-semibold text-slate-500 uppercase tracking-[0.08em] mb-1";

  return (
    <div>
      <div className="flex items-center justify-between mb-6">
        <div>
          <h1 className="text-[15px] font-semibold text-slate-100">Users</h1>
          <p className="text-slate-500 text-sm mt-0.5">Manage accounts and roles</p>
        </div>
        <button
          onClick={() => setShowForm((v) => !v)}
          className="inline-flex items-center gap-1.5 bg-brand-600 hover:bg-brand-500 text-white text-sm font-semibold px-4 py-2 rounded-lg transition-colors"
        >
          {showForm ? "Cancel" : <><Plus size={14} strokeWidth={2.5} /> New User</>}
        </button>
      </div>

      {showForm && (
        <form
          onSubmit={handleSubmit}
          className="border border-[#1f2840] rounded-xl p-5 mb-6 space-y-4 shadow-card"
          style={{ background: "#121826" }}
        >
          <div className="grid grid-cols-2 gap-4">
            <div>
              <label className={labelCls}>Username</label>
              <input value={username} onChange={(e) => setUsername(e.target.value)} required className={inputCls} />
            </div>
            <div>
              <label className={labelCls}>Email</label>
              <input type="email" value={email} onChange={(e) => setEmail(e.target.value)} required className={inputCls} />
            </div>
            <div>
              <label className={labelCls}>Password</label>
              <input
                type="password" value={password} onChange={(e) => setPassword(e.target.value)}
                required minLength={8} placeholder="8+ chars, letter + digit" className={inputCls}
              />
            </div>
            <div>
              <label className={labelCls}>Role</label>
              <select value={role} onChange={(e) => setRole(e.target.value)} className={inputCls}>
                <option value="viewer">Viewer</option>
                <option value="analyst">Analyst</option>
                <option value="admin">Admin</option>
              </select>
            </div>
          </div>
          {error && (
            <div className="bg-red-500/10 border border-red-500/30 text-red-300 rounded-lg px-3 py-2 text-sm">
              {error}
            </div>
          )}
          <button
            type="submit"
            disabled={submitting}
            className="bg-brand-600 hover:bg-brand-500 disabled:opacity-50 text-white text-sm font-semibold px-4 py-2 rounded-lg transition-colors"
          >
            {submitting ? "Creating…" : "Create User"}
          </button>
        </form>
      )}

      {!users ? (
        <div className="flex justify-center py-16"><Spinner size={24} /></div>
      ) : (
        <div className="border border-[#1f2840] rounded-xl overflow-hidden shadow-card" style={{ background: "#121826" }}>
          <table className="w-full text-sm">
            <thead className="border-b border-[#1f2840]" style={{ background: "#0b0f1a" }}>
              <tr>
                {["Username", "Email", "Role", "Status", "Created"].map(h => (
                  <th key={h} className="text-left px-5 py-3 font-semibold text-slate-500 text-[10px] uppercase tracking-[0.08em]">{h}</th>
                ))}
              </tr>
            </thead>
            <tbody className="divide-y divide-[#1f2840]">
              {users.map((u) => (
                <tr key={u.id} className="hover:bg-[#161d2e] transition-colors">
                  <td className="px-5 py-3 font-medium text-slate-200">{u.username}</td>
                  <td className="px-5 py-3 text-slate-400 text-[13px]">{u.email}</td>
                  <td className="px-5 py-3">
                    <span className={`inline-block rounded px-2 py-0.5 text-[10px] font-semibold capitalize ${roleChip[u.role] ?? "bg-slate-500/10 text-slate-400 border border-slate-600/30"}`}>
                      {u.role}
                    </span>
                  </td>
                  <td className="px-5 py-3">
                    {u.is_active
                      ? <span className="text-emerald-400 text-xs font-medium">Active</span>
                      : <span className="text-red-400 text-xs font-medium">Disabled</span>}
                  </td>
                  <td className="px-5 py-3 text-slate-500 text-[11px] font-mono">{fmtDate(u.created_at)}</td>
                </tr>
              ))}
            </tbody>
          </table>
        </div>
      )}
    </div>
  );
}
