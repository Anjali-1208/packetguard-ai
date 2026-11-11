let accessToken = null;
let onAuthLost = () => {};
export const setToken = (t) => { accessToken = t; };
export const getToken = () => accessToken;
export const setAuthLostHandler = (fn) => { onAuthLost = fn; };

async function raw(path, opts = {}) {
  const headers = { ...(opts.body ? { "Content-Type": "application/json" } : {}), ...(accessToken ? { Authorization: `Bearer ${accessToken}` } : {}) };
  return fetch(`/api${path}`, { credentials: "same-origin", ...opts, headers, body: opts.body ? JSON.stringify(opts.body) : undefined });
}

export async function refreshSession() {
  const r = await fetch("/api/auth/refresh", { method: "POST", credentials: "same-origin", headers: { "Content-Type": "application/json" }, body: "{}" });
  if (!r.ok) return null;
  const d = await r.json(); accessToken = d.accessToken; return d;
}

export async function api(path, opts = {}) {
  let r = await raw(path, opts);
  if (r.status === 401 && !path.startsWith("/auth/")) {
    const d = await refreshSession();
    if (d) r = await raw(path, opts); else { onAuthLost(); throw new Error("Session expired"); }
  }
  if (!r.ok) {
    let msg = `Request failed (${r.status})`; let code;
    try { const j = await r.json(); msg = j.error?.message || msg; code = j.error?.code; } catch {}
    const e = new Error(msg); e.status = r.status; e.code = code; throw e;
  }
  const ct = r.headers.get("content-type") || "";
  return ct.includes("json") ? r.json() : r.blob();
}
