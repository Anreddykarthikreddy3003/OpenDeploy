// Minimal same-origin API client. Cookie sessions are HttpOnly; mutating
// requests carry the CSRF token returned by the session endpoints.

export class ApiError extends Error {
  status: number;
  code: string;
  body: any;
  constructor(status: number, code: string, message: string, body: any) {
    super(message);
    this.status = status;
    this.code = code;
    this.body = body;
  }
}

let csrfToken = "";
export function setCsrf(token: string | undefined) {
  csrfToken = token ?? "";
}

type Listener = (err: ApiError) => void;
const listeners = new Set<Listener>();
/** Subscribe to auth-relevant errors (401/403 session, MFA, re-auth). */
export function onAuthError(fn: Listener): () => void {
  listeners.add(fn);
  return () => listeners.delete(fn);
}

// Re-authentication is resolved by the UI (a dialog) and the request retried.
let reauthHandler: (() => Promise<boolean>) | null = null;
export function setReauthHandler(fn: (() => Promise<boolean>) | null) {
  reauthHandler = fn;
}

export async function api<T = any>(method: string, path: string, body?: unknown, opts: { raw?: boolean; retry?: boolean } = {}): Promise<T> {
  const headers: Record<string, string> = { Accept: "application/json" };
  let payload: BodyInit | undefined;
  if (body instanceof FormData || body instanceof Blob) {
    payload = body as BodyInit;
  } else if (body !== undefined) {
    headers["Content-Type"] = "application/json";
    payload = JSON.stringify(body);
  }
  if (method !== "GET" && csrfToken) headers["X-CSRF-Token"] = csrfToken;
  const res = await fetch(path, { method, headers, body: payload, credentials: "same-origin", cache: "no-store" });
  const text = await res.text();
  let data: any = null;
  if (text) {
    try {
      data = JSON.parse(text);
    } catch {
      data = text;
    }
  }
  if (!res.ok) {
    const err = new ApiError(res.status, data?.code ?? "error", data?.message ?? `Request failed (${res.status})`, data);
    if (err.code === "reauth_required" && reauthHandler && opts.retry !== false) {
      if (await reauthHandler()) return api<T>(method, path, body, { ...opts, retry: false });
    }
    if (["unauthorized", "mfa_required", "mfa_enrollment_required"].includes(err.code) || res.status === 401) {
      listeners.forEach((l) => l(err));
    }
    throw err;
  }
  return data as T;
}

/** POSTs and returns the binary response (file downloads), with the same
 * CSRF, re-authentication and session handling as api(). */
export async function download(path: string, retry = true): Promise<{ blob: Blob; filename: string }> {
  const headers: Record<string, string> = {};
  if (csrfToken) headers["X-CSRF-Token"] = csrfToken;
  const res = await fetch(path, { method: "POST", headers, credentials: "same-origin", cache: "no-store" });
  if (!res.ok) {
    let data: any = null;
    try {
      data = await res.json();
    } catch {
      /* not JSON */
    }
    const err = new ApiError(res.status, data?.code ?? "error", data?.message ?? `Request failed (${res.status})`, data);
    if (err.code === "reauth_required" && reauthHandler && retry) {
      if (await reauthHandler()) return download(path, false);
    }
    if (["unauthorized", "mfa_required", "mfa_enrollment_required"].includes(err.code) || res.status === 401) {
      listeners.forEach((l) => l(err));
    }
    throw err;
  }
  const cd = res.headers.get("Content-Disposition") ?? "";
  const m = /filename="([^"]+)"/.exec(cd);
  return { blob: await res.blob(), filename: m?.[1] ?? "download" };
}

export const get = <T = any>(p: string) => api<T>("GET", p);
export const post = <T = any>(p: string, b?: unknown) => api<T>("POST", p, b ?? {});
export const put = <T = any>(p: string, b?: unknown) => api<T>("PUT", p, b ?? {});
export const patch = <T = any>(p: string, b?: unknown) => api<T>("PATCH", p, b ?? {});
export const del = <T = any>(p: string, b?: unknown) => api<T>("DELETE", p, b);

export function errorMessage(e: unknown): string {
  if (e instanceof ApiError) return e.message;
  if (e instanceof Error) return e.message;
  return String(e);
}
