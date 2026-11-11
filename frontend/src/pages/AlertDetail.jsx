import React, { useCallback, useEffect, useState } from "react";
import { Link, useParams } from "react-router-dom";
import { api } from "../api.js";
import { useAuth } from "../auth.jsx";
import { ContribChart, Empty, Err, Notice, Sev, Status, fmt, label, timeAgo } from "../components/ui.jsx";

export default function AlertDetail() {
  const { id } = useParams(); const { socket } = useAuth();
  const [d, setD] = useState(null); const [err, setErr] = useState(""); const [reason, setReason] = useState(""); const [busy, setBusy] = useState(false);
  const [intel, setIntel] = useState(null);

  const load = useCallback(() => api(`/alerts/${id}`).then((r) => { setD(r); setIntel(r.threatIntel); }).catch((e) => setErr(e.message)), [id]);
  useEffect(() => { load(); }, [load]);
  useEffect(() => {
    if (!socket) return; const f = (u) => u.id === id && load();
    socket.on("alert-updated", f); return () => socket.off("alert-updated", f);
  }, [socket, id, load]);

  const act = async (fn) => { setBusy(true); setErr(""); try { await fn(); await load(); } catch (e) { setErr(e.message); } finally { setBusy(false); } };
  const setStatus = (status) => act(() => api(`/alerts/${id}/status`, { method: "PATCH", body: { status, reason: reason || undefined } }));
  const block = () => act(() => api(`/alerts/${id}/block`, { method: "POST", body: { reason: reason || `Blocked after reviewing ${d.alert.supervisedLabel} alert` } }));
  const getIntel = () => api(`/threatintel/${d.alert.srcIp}`).then(setIntel).catch((e) => setErr(e.message));

  if (!d) return <div className="page">{err ? <Err msg={err} /> : <Empty>Loading…</Empty>}</div>;
  const a = d.alert; const st = a.status; const open = st === "new" || st === "acknowledged";
  const top = a.shapTopFeatures?.[0];
  const headline = a.supervisedLabel === "Benign" ? "Traffic statistically unlike the benign baseline (anomaly model)" : `${a.supervisedLabel} detected by the supervised model`;

  return (
    <div className="page">
      <Link to="/alerts" className="back">← Live alerts</Link>
      <header className="page-h"><div><h1><Sev s={a.severity} /> {headline}</h1>
        <p className="sub mono">{a.srcIp}{a.srcPort ? `:${a.srcPort}` : ""} → {a.dstIp}{a.dstPort ? `:${a.dstPort}` : ""} · {a.protocol} · {timeAgo(a.createdAt)} · model {a.modelVersion}</p></div><Status s={st} /></header>
      <Notice /><Err msg={err} />
      <section className="grid2">
        <div className="card">
          <h3>Why was this flagged?</h3>
          <div className="meters">
            <div><span>Supervised confidence</span><b>{(a.supervisedConfidence * 100).toFixed(1)}%</b><div className="meter"><i style={{ width: `${a.supervisedConfidence * 100}%` }} /></div></div>
            <div><span>Anomaly score {a.anomalyFlag ? "(outlier)" : ""}</span><b className="mono">{a.anomalyScore.toFixed(3)}</b><small>Lower = more unusual. Below 0 is an outlier.</small></div>
          </div>
          {a.supervisedLabel !== "Benign" && (<><h4>Top SHAP features</h4>
            {top && <p className="sub">{label(top.feature)} contributed most, {top.contribution >= 0 ? "pushing the verdict toward" : "pulling the verdict away from"} <b>{a.supervisedLabel}</b>.</p>}
            <ContribChart data={a.shapTopFeatures} /></>)}
          {a.anomalyFlag && (<><h4>How far from normal (std. deviations vs benign)</h4><ContribChart data={a.anomalyTopFeatures} /></>)}
        </div>
        <div className="card">
          <h3>Analyst response</h3>
          <label>Reason / note<textarea rows={3} value={reason} onChange={(e) => setReason(e.target.value)} placeholder="Optional for status changes, recommended for blocks" /></label>
          <div className="actions">
            <button className="primary" disabled={busy || st !== "new"} onClick={() => setStatus("acknowledged")}>Acknowledge</button>
            <button disabled={busy || st !== "acknowledged"} onClick={() => setStatus("resolved")}>Resolve</button>
            <button disabled={busy || !open} onClick={() => setStatus("false_positive")}>False positive</button>
            <button className="danger" disabled={busy || st !== "acknowledged"} onClick={block}>Approve IP block</button>
          </div>
          {st === "new" && <small>Acknowledge first — a block can only be approved on an acknowledged alert.</small>}
          {st === "blocked" && <p className="ok">Simulated block rule #{a.blockRuleId} is active for {a.srcIp}. Nothing is enforced on the network — this is a recorded decision.</p>}
          {a.statusReason && <p className="sub">Note: {a.statusReason}</p>}
          <h3>Threat intelligence</h3>
          {intel?.available ? (<dl className="kv"><dt>Reputation</dt><dd><b className={intel.abuseScore >= 75 ? "hot" : ""}>{intel.abuseScore}/100</b></dd><dt>Country</dt><dd>{intel.country}</dd>
            <dt>Last reported</dt><dd>{intel.lastReportedAt ? new Date(intel.lastReportedAt).toLocaleString() : "–"}</dd><dt>Source</dt><dd>{intel.source}{intel.cached ? " (cached)" : ""}</dd></dl>)
            : intel?.available === false ? <p className="sub">Provider unavailable — alert shown without enrichment.</p> : <button className="ghost" onClick={getIntel}>Look up {a.srcIp}</button>}
        </div>
      </section>
      <section className="grid2">
        <div className="card"><h3>Raw flow features</h3>
          <table className="kvt"><tbody>{Object.entries(a.features || {}).map(([k, v]) => <tr key={k}><td>{label(k)}</td><td className="mono">{fmt(v)}</td></tr>)}</tbody></table>
          <small>Header-derived metadata only — packet payloads are never captured or stored.</small></div>
        <div className="card"><h3>Related alerts · same source IP</h3>
          {d.related.length === 0 ? <Empty>No other alerts from {a.srcIp}.</Empty> : <ul className="feed">{d.related.map((r) => (
            <li key={r.id}><Link to={`/alerts/${r.id}`} className="feed-row"><Sev s={r.severity} /><span className="lbl">{r.supervisedLabel}</span><Status s={r.status} /><time>{timeAgo(r.createdAt)}</time></Link></li>))}</ul>}</div>
      </section>
    </div>
  );
}
