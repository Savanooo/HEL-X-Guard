"use client";
import { useEffect, useState, type FormEvent } from "react";
import { listUsers, createUser, type User } from "@/lib/api";
import Spinner from "@/components/Spinner";

const roleStyles: Record<string, string> = {
  admin:   "bg-red-900/50 text-red-300",
  analyst: "bg-blue-900/50 text-blue-300",
  viewer:  "bg-slate-800 text-slate-400",
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

  const inputCls = "w-full rounded-lg border border-slate-700 bg-slate-900/60 text-slate-200 px-3 py-2 text-sm placeholder:text-slate-600 focus:outline-none focus:ring-2 focus:ring-blue-500";
  const labelCls = "block text-xs font-medium text-slate-500 uppercase tracking-wide mb-1";

  return (
    <div className="">
      <div className="flex items-center justify-between mb-6">
        <div>
          <h1 className="text-xl font-bold text-white">Users</h1>
          <p className="text-slate-500 text-sm mt-0.5">Manage accounts and roles</p>
        </div>
        <button
          onClick={() => setShowForm((v) => !v)}
          className="bg-blue-600 hover:bg-blue-500 text-white text-sm font-semibold px-4 py-2 rounded-lg transition-colors"
        >
          {showForm ? "Cancel" : "+ New User"}
        </button>
      </div>

      {showForm && (
        <form
          onSubmit={handleSubmit}
          className="border border-slate-700/60 rounded-xl p-5 mb-6 space-y-4"
          style={{ background: "#161b27" }}
        >
          <div className="grid grid-cols-2 gap-4">
            <div>
              <label className={labelCls}>Username</label>
              <input
                value={username}
                onChange={(e) => setUsername(e.target.value)}
                required
                className={inputCls}
              />
            </div>
            <div>
              <label className={labelCls}>Email</label>
              <input
                type="email"
                value={email}
                onChange={(e) => setEmail(e.target.value)}
                required
                className={inputCls}
              />
            </div>
            <div>
              <label className={labelCls}>Password</label>
              <input
                type="password"
                value={password}
                onChange={(e) => setPassword(e.target.value)}
                required
                minLength={8}
                placeholder="8+ chars, letter + digit"
                className={inputCls}
              />
            </div>
            <div>
              <label className={labelCls}>Role</label>
              <select
                value={role}
                onChange={(e) => setRole(e.target.value)}
                className={inputCls}
              >
                <option value="viewer">Viewer</option>
                <option value="analyst">Analyst</option>
                <option value="admin">Admin</option>
              </select>
            </div>
          </div>

          {error && (
            <div className="bg-red-950/40 border border-red-800/40 text-red-300 rounded-lg px-3 py-2 text-sm">
              {error}
            </div>
          )}

          <button
            type="submit"
            disabled={submitting}
            className="bg-blue-600 hover:bg-blue-500 disabled:opacity-50 text-white text-sm font-semibold px-4 py-2 rounded-lg transition-colors"
          >
            {submitting ? "Creating…" : "Create User"}
          </button>
        </form>
      )}

      {!users ? (
        <div className="flex justify-center py-16"><Spinner size={24} /></div>
      ) : (
        <div className="border border-slate-700/60 rounded-xl overflow-hidden" style={{ background: "#161b27" }}>
          <table className="w-full text-sm">
            <thead className="border-b border-slate-700/60" style={{ background: "#0d1117" }}>
              <tr>
                <th className="text-left px-5 py-3 font-semibold text-slate-500 text-xs uppercase tracking-wide">Username</th>
                <th className="text-left px-5 py-3 font-semibold text-slate-500 text-xs uppercase tracking-wide">Email</th>
                <th className="text-left px-5 py-3 font-semibold text-slate-500 text-xs uppercase tracking-wide">Role</th>
                <th className="text-left px-5 py-3 font-semibold text-slate-500 text-xs uppercase tracking-wide">Status</th>
                <th className="text-left px-5 py-3 font-semibold text-slate-500 text-xs uppercase tracking-wide">Created</th>
              </tr>
            </thead>
            <tbody className="divide-y divide-slate-700/40">
              {users.map((u) => (
                <tr key={u.id} className="hover:bg-slate-800/40 transition-colors">
                  <td className="px-5 py-3 font-medium text-slate-200">{u.username}</td>
                  <td className="px-5 py-3 text-slate-400">{u.email}</td>
                  <td className="px-5 py-3">
                    <span className={`inline-block rounded px-2 py-0.5 text-xs font-semibold capitalize ${roleStyles[u.role] ?? "bg-slate-800 text-slate-400"}`}>
                      {u.role}
                    </span>
                  </td>
                  <td className="px-5 py-3">
                    {u.is_active ? (
                      <span className="text-emerald-400 text-xs font-medium">Active</span>
                    ) : (
                      <span className="text-red-400 text-xs font-medium">Disabled</span>
                    )}
                  </td>
                  <td className="px-5 py-3 text-slate-500 text-xs">{fmtDate(u.created_at)}</td>
                </tr>
              ))}
            </tbody>
          </table>
        </div>
      )}
    </div>
  );
}
