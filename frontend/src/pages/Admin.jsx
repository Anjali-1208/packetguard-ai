import React, { useEffect, useState } from "react";
import { NavLink, Route, Routes, Navigate } from "react-router-dom";
import { api } from "../api.js";
import { Empty, Err, timeAgo } from "../components/ui.jsx";

const Tabs = () => (
  <nav className="tabs">{[["users", "Users"], ["config", "Detection thresholds"], ["audit", "Audit log"], ["health", "Pipeline & model"]].map(([p, l]) => <NavLink key={p} to={`/admin/${p}`} className={({ isActive }) => (isActive ? "on" : "")}>{l}</NavLink>)}</nav>
);

function Users() {
  const [users, setUsers] = useState(null); const [err, setErr] = useState(""); const [f, setF] = useState({ name: "", email: "", password: "", role: "analyst" });
  const load = () => api("/admin/users").then((d) => setUsers(d.users)).catch((e) => setErr(e.message)); useEffect(() => { load(); }, []);
  const create = async (e) => { e.preventDefault(); setErr(""); try { await api("/admin/users", { method: "POST", body: f }); setF({ name: "", email: "", password: "", role: "analyst" }); load(); } catch (x) { setErr(x.message); } };
  const patch = (u, body) => api(`/admin/users/${u.id}`, { method: "PATCH", body }).then(load).catch((e) => setErr(e.message));
  return (<>
    <Err msg={err} />
    <form className="card inline-form" onSubmit={create}><h3>Create account</h3>
      <input placeholder="Name" value={f.name} onChange={(e) => setF({ ...f, name: e.target.value })} required />
      <input placeholder="Email" type="email" value={f.email} onChange={(e) => setF({ ...f, email: e.target.value })} required />
      <input placeholder="Password" type="password" value={f.password} onChange={(e) => setF({ ...f, password: e.target.value })} required />
      <select value={f.role} onChange={(e) => setF({ ...f, role: e.target.value })}><option value="analyst">Analyst</option><option value="admin">Administrator</option></select>
      <button className="primary">Create</button></form>
    <div className="card tbl-wrap">{!users ? <Empty>Loading…</Empty> : <table><thead><tr><th>Name</th><th>Email</th><th>Role</th><th>Status</th><th>Last login</th><th /></tr></thead>
      <tbody>{users.map((u) => <tr key={u.id}><td>{u.name}</td><td className="mono">{u.email}</td><td>{u.role}</td><td><span className={`st ${u.status === "active" ? "st-resolved" : "st-blocked"}`}>{u.status}</span></td>
        <td>{u.lastLogin ? timeAgo(u.lastLogin) : "never"}</td>
        <td><button className="ghost" onClick={() => patch(u, { status: u.status === "active" ? "suspended" : "active" })}>{u.status === "active" ? "Suspend" : "Reactivate"}</button></td></tr>)}</tbody></table>}</div></>);
}

function Config() {
  const [t, setT] = useState(null); const [msg, setMsg] = useState(""); const [err, setErr] = useState("");
  useEffect(() => { api("/admin/config").then((d) => setT(d.thresholds)).catch((e) => setErr(e.message)); }, []);
  if (!t) return err ? <Err msg={err} /> : <Empty>Loading…</Empty>;
  const save = async (e) => { e.preventDefault(); setErr(""); setMsg(""); try { await api("/admin/config", { method: "PATCH", body: { critical: +t.critical, high: +t.high, anomaly_high: +t.anomaly_high } }); setMsg("Saved. The ML service picks this up within ~15 seconds."); } catch (x) { setErr(x.message); } };
  const field = (k, l, step, hint) => <label>{l}<input type="number" step={step} value={t[k]} onChange={(e) => setT({ ...t, [k]: e.target.value })} /><small>{hint}</small></label>;
  return (<form className="card cfg" onSubmit={save}><h3>Severity thresholds</h3>
    {field("critical", "Critical — supervised confidence ≥", 0.01, "Known attack at or above this confidence is CRITICAL (and triggers Slack/email).")}
    {field("high", "High — supervised confidence ≥", 0.01, "Known attack at or above this (but below critical) is HIGH; lower is MEDIUM.")}
    {field("anomaly_high", "Anomaly-only — score ≤", 0.01, "For flows only the anomaly model flags: ≤ 1.5× this is HIGH, ≤ this is MEDIUM, otherwise LOW.")}
    <Err msg={err} />{msg && <p className="ok">{msg}</p>}<button className="primary">Save thresholds</button></form>);
}

function Audit() {
  const [d, setD] = useState(null); const [action, setAction] = useState(""); const [err, setErr] = useState("");
  const load = () => api(`/admin/audit-logs?limit=100${action ? `&action=${encodeURIComponent(action)}` : ""}`).then(setD).catch((e) => setErr(e.message)); useEffect(() => { load(); }, [action]); // eslint-disable-line
  const actions = ["", "LOGIN", "LOGIN_FAILED", "ACCOUNT_LOCKOUT", "LOGOUT", "ML_VERDICT", "ALERT_ACKNOWLEDGED", "ALERT_RESOLVED", "ALERT_FALSE_POSITIVE", "BLOCK_APPROVED", "BLOCKRULE_UPDATED", "USER_CREATED", "USER_UPDATED", "CONFIG_UPDATED"];
  return (<><Err msg={err} /><div className="card filters"><label>Action<select value={action} onChange={(e) => setAction(e.target.value)}>{actions.map((a) => <option key={a} value={a}>{a || "All"}</option>)}</select></label>
    <button className="ghost" onClick={load}>Refresh</button><small>Append-only: the API exposes no edit or delete for audit records.</small></div>
    <div className="card tbl-wrap">{!d ? <Empty>Loading…</Empty> : <table><thead><tr><th>Time</th><th>Actor</th><th>Action</th><th>Target</th><th>Details</th></tr></thead>
      <tbody>{d.logs.map((l) => <tr key={l.id}><td>{new Date(l.timestamp).toLocaleString()}</td><td className="mono">{l.actor}</td><td>{l.action}</td><td className="mono">{l.target}</td><td className="mono dim">{l.details}</td></tr>)}</tbody></table>}</div></>);
}

const dot = (s) => <span className={`dot dot-${s}`} />;
function Health() {
  const [h, setH] = useState(null); const [m, setM] = useState(null); const [err, setErr] = useState("");
  useEffect(() => { const l = () => api("/admin/health").then(setH).catch((e) => setErr(e.message)); l(); const t = setInterval(l, 8000);
    api("/stats/model-performance").then(setM).catch(() => setM(false)); return () => clearInterval(t); }, []);
  return (<><Err msg={err} />
    <div className="cards">{h && Object.entries(h.components).map(([k, v]) => <div key={k} className="card stat"><span className="k">{k}</span><span className="v sm">{dot(v.status)} {v.status}</span>
      {k === "inference" && v.processed != null && <small>{v.processed} scored · {v.avgScoringMs} ms avg · {v.failures} failures</small>}
      {k === "capture" && v.published != null && <small>{v.published} flows published · mode {v.mode}</small>}</div>)}
      {h && <div className="card stat"><span className="k">Users / active block rules</span><span className="v sm">{h.users} / {h.activeBlockRules}</span></div>}</div>
    <div className="card"><h3>Model evaluation</h3>{m === null ? <Empty>Loading…</Empty> : m === false ? <Empty>Model metrics unavailable (ML service starting?).</Empty> : (<>
      <p className="sub">Version <b className="mono">{m.model_version}</b> · trained on <b>{m.dataset}</b> ({m.train_rows.toLocaleString()} train / {m.test_rows.toLocaleString()} test)</p>
      {m.dataset === "synthetic" && <p className="notice">These scores come from the built-in synthetic data, which is easy to separate. Train on real CIC-IDS2017 (see README) for realistic numbers.</p>}
      <div className="cards">{[["Accuracy", m.accuracy], ["Macro precision", m.macro_precision], ["Macro recall", m.macro_recall], ["Macro F1", m.macro_f1], ["Anomaly benign FPR", m.anomaly_benign_false_positive_rate], ["Generalization F1", m.generalization_macro_f1], ["Novel traffic flagged", m.novel_flagged_by_anomaly_model]].filter(([, v]) => v != null).map(([k, v]) => <div key={k} className="card stat"><span className="k">{k}</span><span className="v sm">{(v * 100).toFixed(2)}%</span></div>)}</div>
      <h4>Confusion matrix (rows = actual, columns = predicted)</h4><div className="tbl-wrap"><table className="cm"><thead><tr><th />{m.classes.map((c) => <th key={c}>{c}</th>)}</tr></thead>
        <tbody>{m.confusion_matrix.map((row, i) => { const max = Math.max(...row); return <tr key={i}><th>{m.classes[i]}</th>{row.map((v, j) => <td key={j} style={{ background: v ? `rgba(79,209,232,${0.12 + 0.6 * (v / max) * (i === j ? 1 : 0.4)})` : "transparent", color: i !== j && v ? "#ff9f8a" : undefined }}>{v}</td>)}</tr>; })}</tbody></table></div></>)}</div></>);
}

export default function Admin() {
  return (<div className="page"><header className="page-h"><div><h1>Administration</h1><p className="sub">Users, detection configuration, audit trail and system health</p></div></header><Tabs />
    <Routes><Route index element={<Navigate to="users" replace />} /><Route path="users" element={<Users />} /><Route path="config" element={<Config />} /><Route path="audit" element={<Audit />} /><Route path="health" element={<Health />} /></Routes></div>);
}
