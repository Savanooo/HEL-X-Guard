"use client";
import { useEffect, useState } from "react";
import { useRouter, usePathname } from "next/navigation";
import Link from "next/link";
import { clearToken, getMe, getToken, type User } from "@/lib/api";
import Spinner from "@/components/Spinner";

// ── SVG Icons ────────────────────────────────────────────────────────────────

function IconScans() {
  return (
    <svg width="16" height="16" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2" strokeLinecap="round" strokeLinejoin="round">
      <rect x="3" y="3" width="18" height="18" rx="2"/>
      <path d="M3 9h18M9 21V9"/>
    </svg>
  );
}

function IconUpload() {
  return (
    <svg width="16" height="16" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2" strokeLinecap="round" strokeLinejoin="round">
      <path d="M21 15v4a2 2 0 0 1-2 2H5a2 2 0 0 1-2-2v-4"/>
      <polyline points="17 8 12 3 7 8"/>
      <line x1="12" y1="3" x2="12" y2="15"/>
    </svg>
  );
}

function IconUsers() {
  return (
    <svg width="16" height="16" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2" strokeLinecap="round" strokeLinejoin="round">
      <path d="M17 21v-2a4 4 0 0 0-4-4H5a4 4 0 0 0-4 4v2"/>
      <circle cx="9" cy="7" r="4"/>
      <path d="M23 21v-2a4 4 0 0 0-3-3.87M16 3.13a4 4 0 0 1 0 7.75"/>
    </svg>
  );
}

function IconShield() {
  return (
    <svg width="16" height="16" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2" strokeLinecap="round" strokeLinejoin="round">
      <path d="M12 22s8-4 8-10V5l-8-3-8 3v7c0 6 8 10 8 10z"/>
    </svg>
  );
}

function IconLogout() {
  return (
    <svg width="14" height="14" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2" strokeLinecap="round" strokeLinejoin="round">
      <path d="M9 21H5a2 2 0 0 1-2-2V5a2 2 0 0 1 2-2h4"/>
      <polyline points="16 17 21 12 16 7"/>
      <line x1="21" y1="12" x2="9" y2="12"/>
    </svg>
  );
}

// ── Layout ───────────────────────────────────────────────────────────────────

const PAGE_TITLES: Record<string, string> = {
  "/dashboard":        "Scan History",
  "/dashboard/upload": "New Scan",
  "/dashboard/users":  "User Management",
  "/dashboard/audit":  "Audit Log",
};

export default function DashboardLayout({ children }: { children: React.ReactNode }) {
  const router   = useRouter();
  const pathname = usePathname();
  const [user, setUser] = useState<User | null>(null);

  useEffect(() => {
    if (!getToken()) { router.replace("/login"); return; }
    getMe().then(setUser).catch(() => { clearToken(); router.replace("/login"); });
  }, [router]);

  if (!user) {
    return (
      <div className="flex h-screen items-center justify-center bg-slate-950">
        <Spinner size={32} />
      </div>
    );
  }

  function signOut() { clearToken(); router.push("/login"); }

  const navLinks = [
    { href: "/dashboard",        label: "Scans",     Icon: IconScans  },
    { href: "/dashboard/upload", label: "New Scan",  Icon: IconUpload },
    ...(user.role === "admin" ? [
      { href: "/dashboard/users", label: "Users",     Icon: IconUsers  },
      { href: "/dashboard/audit", label: "Audit Log", Icon: IconShield },
    ] : []),
  ];

  const pageTitle = PAGE_TITLES[pathname] ?? "Scan Detail";

  return (
    <div className="flex h-screen overflow-hidden bg-slate-100">
      {/* ── Sidebar ─────────────────────────────────────── */}
      <aside className="w-52 flex-shrink-0 bg-slate-950 flex flex-col">
        {/* Logo */}
        <div className="px-5 pt-6 pb-5 border-b border-slate-800">
          <div className="flex items-center gap-2 mb-0.5">
            <div className="w-7 h-7 rounded-lg bg-blue-600 flex items-center justify-center flex-shrink-0">
              <svg width="14" height="14" viewBox="0 0 24 24" fill="none" stroke="white" strokeWidth="2.5" strokeLinecap="round" strokeLinejoin="round">
                <path d="M12 22s8-4 8-10V5l-8-3-8 3v7c0 6 8 10 8 10z"/>
              </svg>
            </div>
            <div>
              <p className="text-white font-bold text-sm tracking-wide leading-tight">HELİX-Guard</p>
              <p className="text-slate-500 text-xs">Firmware Security</p>
            </div>
          </div>
        </div>

        {/* Nav */}
        <nav className="flex-1 px-3 py-4 space-y-0.5">
          {navLinks.map(({ href, label, Icon }) => {
            const active = pathname === href || (href !== "/dashboard" && pathname.startsWith(href));
            return (
              <Link
                key={href}
                href={href}
                className={`flex items-center gap-3 px-3 py-2.5 rounded-lg text-sm font-medium transition-all ${
                  active
                    ? "bg-blue-600 text-white shadow-sm"
                    : "text-slate-400 hover:text-slate-200 hover:bg-slate-800/60"
                }`}
              >
                <Icon />
                {label}
              </Link>
            );
          })}
        </nav>

        {/* User card */}
        <div className="m-3 rounded-xl bg-slate-900 border border-slate-800 p-3">
          <div className="flex items-center gap-2.5 mb-2.5">
            <div className="w-8 h-8 rounded-full bg-blue-600 flex items-center justify-center text-white text-sm font-bold flex-shrink-0">
              {user.username[0].toUpperCase()}
            </div>
            <div className="min-w-0">
              <p className="text-white text-sm font-semibold truncate">{user.username}</p>
              <p className="text-slate-500 text-xs capitalize">{user.role}</p>
            </div>
          </div>
          <button
            onClick={signOut}
            className="w-full flex items-center gap-1.5 text-xs text-slate-500 hover:text-red-400 transition-colors px-1 py-0.5"
          >
            <IconLogout />
            Sign out
          </button>
        </div>
      </aside>

      {/* ── Main area ───────────────────────────────────── */}
      <div className="flex-1 flex flex-col overflow-hidden">
        {/* Top header */}
        <header className="bg-white border-b border-slate-200 px-8 py-4 flex items-center justify-between flex-shrink-0">
          <h1 className="text-base font-semibold text-slate-800">{pageTitle}</h1>
          <div className="flex items-center gap-2 text-xs text-slate-400">
            <div className="w-2 h-2 rounded-full bg-emerald-500 animate-pulse" />
            System online
          </div>
        </header>

        {/* Scrollable content — centered with max width */}
        <main className="flex-1 overflow-auto">
          <div className="max-w-5xl mx-auto px-8 py-8">
            {children}
          </div>
        </main>
      </div>
    </div>
  );
}
