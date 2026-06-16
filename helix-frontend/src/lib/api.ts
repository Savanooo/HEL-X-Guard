const API_URL = process.env.NEXT_PUBLIC_API_URL ?? "http://127.0.0.1:8000";

// ── Token helpers ─────────────────────────────────────────────────────────────

export function getToken(): string | null {
  if (typeof window === "undefined") return null;
  return localStorage.getItem("helix_token");
}

export function setToken(token: string): void {
  localStorage.setItem("helix_token", token);
}

export function clearToken(): void {
  localStorage.removeItem("helix_token");
}

// ── Fetch wrapper ─────────────────────────────────────────────────────────────

async function req<T>(path: string, init: RequestInit = {}): Promise<T> {
  const token = getToken();
  const passedHeaders = (init.headers as Record<string, string>) ?? {};
  const headers: Record<string, string> = { ...passedHeaders };

  if (token) headers["Authorization"] = `Bearer ${token}`;
  // Don't set Content-Type for FormData (browser sets it with boundary)
  if (!("Content-Type" in headers) && !(init.body instanceof FormData)) {
    headers["Content-Type"] = "application/json";
  }

  const res = await fetch(`${API_URL}${path}`, { ...init, headers });

  if (res.status === 401) {
    clearToken();
    if (typeof window !== "undefined") window.location.href = "/login";
    throw new Error("Unauthorized");
  }

  if (res.status === 204) return undefined as T;

  if (!res.ok) {
    const body = await res.json().catch(() => null);
    throw new Error(body?.detail ?? `${res.status} ${res.statusText}`);
  }

  return res.json() as Promise<T>;
}

// ── Types ─────────────────────────────────────────────────────────────────────

export interface User {
  id: string;
  username: string;
  email: string;
  role: string;
  is_active: boolean;
  created_at: string;
}

export type ScanStatus = "pending" | "running" | "completed" | "failed";
export type RiskLevel = "informational" | "low" | "medium" | "high" | "critical";
export type JobStatus = "pending" | "running" | "completed" | "failed" | null;

export interface Scan {
  id: string;
  filename: string;
  file_size: number | null;
  sha256: string | null;
  status: ScanStatus;
  risk_score: number | null;
  risk_level: RiskLevel | null;
  extraction_status?: JobStatus;
  decompile_status?: JobStatus;
  created_at: string;
  completed_at: string | null;
  error_message?: string | null;
  // eslint-disable-next-line @typescript-eslint/no-explicit-any
  report?: Record<string, any> | null;
  // eslint-disable-next-line @typescript-eslint/no-explicit-any
  extraction?: Record<string, any> | null;
  extraction_error?: string | null;
  // eslint-disable-next-line @typescript-eslint/no-explicit-any
  decompile?: Record<string, any> | null;
  decompile_error?: string | null;
}

export interface ScanList {
  items: Scan[];
  total: number;
  page: number;
  page_size: number;
}

export interface AuditLogEntry {
  id: string;
  user_id: string | null;
  username: string | null;
  action: string;
  resource_type: string | null;
  resource_id: string | null;
  success: boolean;
  detail: string | null;
  ip_address: string | null;
  created_at: string;
}

export interface AuditLogList {
  items: AuditLogEntry[];
  total: number;
  page: number;
  page_size: number;
}

// ── Auth ──────────────────────────────────────────────────────────────────────

export const login = (username: string, password: string) =>
  req<{ access_token: string }>("/api/v1/auth/login", {
    method: "POST",
    body: new URLSearchParams({ username, password }),
    headers: { "Content-Type": "application/x-www-form-urlencoded" },
  });

export const getMe = () => req<User>("/api/v1/auth/me");

export const listUsers = () => req<User[]>("/api/v1/auth/users");

export const createUser = (body: {
  username: string;
  email: string;
  password: string;
  role: string;
}) => req<User>("/api/v1/auth/users", { method: "POST", body: JSON.stringify(body) });

// ── Scans ─────────────────────────────────────────────────────────────────────

export const createScan = (file: File) => {
  const form = new FormData();
  form.append("file", file);
  return req<Scan>("/api/v1/scans", { method: "POST", body: form });
};

export const listScans = (
  page = 1,
  pageSize = 20,
  riskLevel?: string,
  status?: string,
) => {
  const q = new URLSearchParams({
    page: String(page),
    page_size: String(pageSize),
  });
  if (riskLevel) q.set("risk_level", riskLevel);
  if (status) q.set("status", status);
  return req<ScanList>(`/api/v1/scans?${q}`);
};

export const getScan = (id: string) => req<Scan>(`/api/v1/scans/${id}`);
export const deleteScan = (id: string) =>
  req<void>(`/api/v1/scans/${id}`, { method: "DELETE" });

export const triggerExtract = (id: string) =>
  req<Scan>(`/api/v1/scans/${id}/extract`, { method: "POST" });

export const triggerDecompile = (id: string) =>
  req<Scan>(`/api/v1/scans/${id}/decompile`, { method: "POST" });

/** Downloads the PDF report. Uses fetch (not a plain <a href>) because the
 * endpoint requires a Bearer token, which anchor tags can't send. */
export async function downloadReportPdf(id: string, suggestedName: string): Promise<void> {
  const token = getToken();
  const res = await fetch(`${API_URL}/api/v1/scans/${id}/report.pdf`, {
    headers: token ? { Authorization: `Bearer ${token}` } : {},
  });
  if (!res.ok) {
    const body = await res.json().catch(() => null);
    throw new Error(body?.detail ?? `${res.status} ${res.statusText}`);
  }
  const blob = await res.blob();
  const url = URL.createObjectURL(blob);
  const a = document.createElement("a");
  a.href = url;
  a.download = suggestedName;
  document.body.appendChild(a);
  a.click();
  a.remove();
  URL.revokeObjectURL(url);
}

// ── Audit ─────────────────────────────────────────────────────────────────────

export const listAuditLog = (
  page = 1,
  pageSize = 50,
  action?: string,
  username?: string,
) => {
  const q = new URLSearchParams({ page: String(page), page_size: String(pageSize) });
  if (action) q.set("action", action);
  if (username) q.set("username", username);
  return req<AuditLogList>(`/api/v1/audit?${q}`);
};
