import React, { useCallback, useEffect, useRef, useState } from "react";
import { Link, useSearchParams } from "react-router-dom";
import { api } from "../api.js";
import { useAuth } from "../auth.jsx";
import { Empty, Err, Notice, Sev, STATUS_LABEL, Status, timeAgo } from "../components/ui.jsx";

export default function Alerts() {
  const { socket } = useAuth();
  const [sp, setSp] = useSearchParams();
  const [data, setData] = useState(null); const [err, setErr] = useState(""); const [page, setPage] = useState(1);
  const q = { severity: sp.get("severity") || "", status: sp.get("status") || "", srcIp: sp.get("srcIp") || "", from: sp.get("from") || "", to: sp.get("to") || "", sort: sp.get("sort") || "severity" };
  const qs = useCallback(() => { const p = new URLSearchParams(); Object.entries(q).forEach(([k, v]) => v && p.set(k, k === "to" ? v + "T23:59:59" : v)); return p; }, [sp]); // eslint-disable-line

  const load = useCallback(() => { const p = qs(); p.set("page", page); p.set("limit", 25);
    api(`/alerts?${p}`).then((d) => { setData(d); setErr(""); }).catch((e) => setErr(e.message)); }, [qs, page]);
  useEffect(() => { load(); }, [load]);

  const timer = useRef();
  useEffect(() => {
    if (!socket) return;
    const refresh = () => { clearTimeout(timer.current); timer.current = setTimeout(load, 600); };
    socket.on("new-alert", refresh); socket.on("alert-updated", refresh);
    return () => { socket.off("new-alert", refresh); socket.off("alert-updated", refresh); };
  }, [socket, load]);

  const set = (k) => (e) => { const n = new URLSearchParams(sp); e.target.value ? n.set(k, e.target.value) : n.delete(k); setSp(n); setPage(1); };
  const exportCsv = async () => {
    const blob = await api(`/alerts/export?${qs()}`); const a = document.createElement("a");
    a.href = URL.createObjectURL(blob); a.download = "alerts.csv"; a.click(); URL.revokeObjectURL(a.href);
  };
  const pages = data ? Math.max(1, Math.ceil(data.total / data.limit)) : 1;

  return (
    <div className="page">
      <header className="page-h"><div><h1>Live alerts</h1><p className="sub">{data ? `${data.total.toLocaleString()} matching` : "Loading…"} · updates in real time</p></div><Notice /></header>
      <div className="card filters">
        <label>Severity<select value={q.severity} onChange={set("severity")}><option value="">All</option>{["critical", "high", "medium", "low"].map((s) => <option key={s}>{s}</option>)}</select></label>
        <label>Status<select value={q.status} onChange={set("status")}><option value="">All</option>{Object.entries(STATUS_LABEL).map(([k, v]) => <option key={k} value={k}>{v}</option>)}</select></label>
        <label>Source IP<input value={q.srcIp} onChange={set("srcIp")} placeholder="203.0.113.55" /></label>
        <label>From<input type="date" value={q.from} onChange={set("from")} /></label>
        <label>To<input type="date" value={q.to} onChange={set("to")} /></label>
        <label>Sort<select value={q.sort} onChange={set("sort")}><option value="severity">Severity, then newest</option><option value="recent">Newest first</option></select></label>
        <button className="ghost" onClick={exportCsv}>Export CSV</button>
      </div>
      <Err msg={err} />
      <div className="card tbl-wrap">
        {!data ? <Empty>Loading…</Empty> : data.alerts.length === 0 ? <Empty>No alerts match these filters.</Empty> : (
          <table><thead><tr><th>Severity</th><th>Detection</th><th>Confidence</th><th>Source → Destination</th><th>Status</th><th>When</th></tr></thead>
            <tbody>{data.alerts.map((a) => (
              <tr key={a.id}><td><Sev s={a.severity} /></td>
                <td><Link to={`/alerts/${a.id}`}>{a.supervisedLabel === "Benign" ? "Anomalous traffic" : a.supervisedLabel}</Link>{a.anomalyFlag && <span className="tag">anomaly</span>}</td>
                <td className="mono">{(a.supervisedConfidence * 100).toFixed(0)}%</td>
                <td className="mono">{a.srcIp} → {a.dstIp}{a.dstPort ? `:${a.dstPort}` : ""}</td><td><Status s={a.status} /></td><td>{timeAgo(a.createdAt)}</td></tr>))}</tbody></table>)}
      </div>
      <div className="pager"><button className="ghost" disabled={page <= 1} onClick={() => setPage(page - 1)}>← Prev</button><span>Page {page} / {pages}</span>
        <button className="ghost" disabled={page >= pages} onClick={() => setPage(page + 1)}>Next →</button></div>
    </div>
  );
}
