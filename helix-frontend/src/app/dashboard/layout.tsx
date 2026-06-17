"use client";
import { useEffect, useState } from "react";
import { useRouter, usePathname } from "next/navigation";
import Link from "next/link";
import { clearToken, getMe, getToken, type User } from "@/lib/api";
import Spinner from "@/components/Spinner";

function IconScans() {
  return <svg width="16" height="16" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="1.75" strokeLinecap="round" strokeLinejoin="round"><rect x="3" y="3" width="18" height="18" rx="2"/><path d="M3 9h18M9 21V9"/></svg>;
}
function IconUpload() {
  return <svg width="16" height="16" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="1.75" strokeLinecap="round" strokeLinejoin="round"><path d="M21 15v4a2 2 0 0 1-2 2H5a2 2 0 0 1-2-2v-4"/><polyline points="17 8 12 3 7 8"/><line x1="12" y1="3" x2="12" y2="15"/></svg>;
}
function IconUsers() {
  return <svg width="16" height="16" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="1.75" strokeLinecap="round" strokeLinejoin="round"><path d="M17 21v-2a4 4 0 0 0-4-4H5a4 4 0 0 0-4 4v2"/><circle cx="9" cy="7" r="4"/><path d="M23 21v-2a4 4 0 0 0-3-3.87M16 3.13a4 4 0 0 1 0 7.75"/></svg>;
}
function IconShield() {
  return <svg width="16" height="16" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="1.75" strokeLinecap="round" strokeLinejoin="round"><path d="M12 22s8-4 8-10V5l-8-3-8 3v7c0 6 8 10 8 10z"/></svg>;
}

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

  const mainLinks = [
    { href: "/dashboard",        label: "Scans",    Icon: IconScans  },
    { href: "/dashboard/upload", label: "New Scan", Icon: IconUpload },
  ];
  const adminLinks = user.role === "admin" ? [
    { href: "/dashboard/users", label: "Users",     Icon: IconUsers  },
    { href: "/dashboard/audit", label: "Audit Log", Icon: IconShield },
  ] : [];

  const pageTitle = PAGE_TITLES[pathname] ?? (pathname.startsWith("/dashboard/") ? "Scan Detail" : "");

  return (
    <div className="flex h-screen overflow-hidden" style={{ background: "#0d1117" }}>
      {/* Sidebar */}
      <aside className="w-60 flex-shrink-0 flex flex-col border-r border-slate-800/60" style={{ background: "#0d1117" }}>
        {/* Logo */}
        <div className="px-5 py-5 border-b border-slate-800/60">
          <div className="flex items-center gap-3">
            <div className="w-9 h-9 rounded-xl bg-blue-600 flex items-center justify-center flex-shrink-0 shadow-lg shadow-blue-900/50">
              <svg width="17" height="17" viewBox="0 0 24 24" fill="none" stroke="white" strokeWidth="2.2" strokeLinecap="round" strokeLinejoin="round">
                <path d="M12 22s8-4 8-10V5l-8-3-8 3v7c0 6 8 10 8 10z"/>
              </svg>
            </div>
            <div>
              <p className="text-white font-bold text-[15px] tracking-wide leading-tight">HELİX-Guard</p>
              <p className="text-slate-500 text-[11px] leading-tight mt-0.5">Your Eyes Beyond</p>
            </div>
          </div>
        </div>

        {/* Nav */}
        <div className="flex-1 pt-5 pb-2 overflow-y-auto">
          {/* Analysis section */}
          <div className="flex items-center gap-2 px-5 mb-1">
            <div className="w-1.5 h-1.5 rounded-full bg-blue-500" />
            <p className="text-slate-600 text-[10px] font-bold uppercase tracking-[0.12em]">Analysis</p>
          </div>
          <nav>
            {mainLinks.map(({ href, label, Icon }) => {
              const active = href === "/dashboard" ? pathname === href : pathname.startsWith(href);
              return (
                <Link key={href} href={href}
                  className={`flex items-center gap-3 pl-5 pr-4 py-2.5 text-[13px] font-medium transition-all border-l-2 ${
                    active
                      ? "border-blue-500 bg-blue-500/10 text-white"
                      : "border-transparent text-slate-400 hover:text-slate-200 hover:bg-slate-800/30"
                  }`}
                >
                  <span className={active ? "text-blue-400" : "text-slate-500"}>
                    <Icon />
                  </span>
                  {label}
                </Link>
              );
            })}
          </nav>

          {/* Administration section (admin only) */}
          {adminLinks.length > 0 && (
            <>
              <div className="flex items-center gap-2 px-5 mt-5 mb-1">
                <div className="w-1.5 h-1.5 rounded-full bg-slate-600" />
                <p className="text-slate-600 text-[10px] font-bold uppercase tracking-[0.12em]">Administration</p>
              </div>
              <nav>
                {adminLinks.map(({ href, label, Icon }) => {
                  const active = pathname.startsWith(href);
                  return (
                    <Link key={href} href={href}
                      className={`flex items-center gap-3 pl-5 pr-4 py-2.5 text-[13px] font-medium transition-all border-l-2 ${
                        active
                          ? "border-blue-500 bg-blue-500/10 text-white"
                          : "border-transparent text-slate-400 hover:text-slate-200 hover:bg-slate-800/30"
                      }`}
                    >
                      <span className={active ? "text-blue-400" : "text-slate-500"}>
                        <Icon />
                      </span>
                      {label}
                    </Link>
                  );
                })}
              </nav>
            </>
          )}
        </div>

        {/* User card */}
        <div className="border-t border-slate-800/60 px-4 py-3.5">
          <div className="flex items-center gap-3">
            <div className="w-8 h-8 rounded-full bg-blue-600 flex items-center justify-center text-white text-xs font-bold flex-shrink-0">
              {user.username[0].toUpperCase()}
            </div>
            <div className="min-w-0 flex-1">
              <p className="text-slate-200 text-xs font-semibold truncate">{user.username}</p>
              <p className="text-slate-500 text-[11px] capitalize">{user.role}</p>
            </div>
            <button
              onClick={signOut}
              title="Sign out"
              className="text-slate-600 hover:text-red-400 transition-colors flex-shrink-0"
            >
              <svg width="14" height="14" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2" strokeLinecap="round" strokeLinejoin="round">
                <path d="M9 21H5a2 2 0 0 1-2-2V5a2 2 0 0 1 2-2h4"/>
                <polyline points="16 17 21 12 16 7"/>
                <line x1="21" y1="12" x2="9" y2="12"/>
              </svg>
            </button>
          </div>
        </div>
      </aside>

      {/* Main */}
      <div className="flex-1 flex flex-col overflow-hidden">
        {/* Top bar */}
        <header className="border-b border-slate-800 px-8 py-3.5 flex items-center justify-between flex-shrink-0" style={{ background: "#0d1117" }}>
          <h1 className="text-sm font-semibold text-slate-300">{pageTitle}</h1>
          <div className="flex items-center gap-2 text-xs text-slate-600">
            <div className="w-1.5 h-1.5 rounded-full bg-emerald-500" />
            Online
          </div>
        </header>

        {/* Content — full width with padding */}
        <main className="flex-1 overflow-auto px-8 py-7" style={{ background: "#0f1520" }}>
          {children}
        </main>
      </div>
    </div>
  );
}
