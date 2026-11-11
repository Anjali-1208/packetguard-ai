import React, { useCallback, useEffect, useState } from "react";
import { Link } from "react-router-dom";
import { Area, AreaChart, CartesianGrid, ResponsiveContainer, Tooltip, XAxis, YAxis } from "recharts";
import { api } from "../api.js";
import { useAuth } from "../auth.jsx";
import { Empty, Err, Notice, SEV_ORDER, Sev, STATUS_LABEL, Status, timeAgo } from "../components/ui.jsx";

export default function Dashboard() {
  const { socket } = useAuth();
  const [stats, setStats] = useState(null); const [feed, setFeed] = useState(null); const [err, setErr] = useState("");

  const loadStats = useCallback(() => api("/stats/summary?minutes=30").then(setStats).catch((e) => setErr(e.message)), []);
  const loadFeed = useCallback(() => api("/alerts?sort=recent&limit=12").then((d) => setFeed(d.alerts)).catch((e) => setErr(e.message)), []);
  useEffect(() => { loadStats(); loadFeed(); const t = setInterval(loadStats, 15000); return () => clearInterval(t); }, [loadStats, loadFeed]);

  useEffect(() => {
    if (!socket) return;
    const onNew = (a) => setFeed((f) => [a, ...(f || [])].slice(0, 12));
    const onUpd = ({ id, status }) => setFeed((f) => (f || []).map((a) => (a.id === id ? { ...a, status } : a)));
    const onStats = (s) => setStats((p) => (p ? { ...p, ...s } : p));
    socket.on("new-alert", onNew); socket.on("alert-updated", onUpd); socket.on("stats-updated", onStats);
    return () => { socket.off("new-alert", onNew); socket.off("alert-updated", onUpd); socket.off("stats-updated", onStats); };
  }, [socket]);

  return (
    <div className="page">
      <header className="page-h"><div><h1>Operations overview</h1><p className="sub">Live view of the detection pipeline</p></div><Notice /></header>
      <Err msg={err} />
      <section className="cards">
        {SEV_ORDER.map((s) => (
          <Link key={s} to={`/alerts?severity=${s}`} className={`card stat sev-edge-${s}`}>
            <span className="k">{s}</span><span className="v">{stats ? stats.bySeverity[s] : "–"}</span></Link>))}
        <div className="card stat"><span className="k">Flows analysed</span><span className="v">{stats ? stats.totalFlows.toLocaleString() : "–"}</span><small>{stats ? `${stats.flowsLastHour.toLocaleString()} in the last hour` : ""}</small></div>
      </section>
      <section className="grid2">
        <div className="card">
          <h3>Alerts per minute · last 30 min</h3>
          {stats ? <div style={{ height: 230 }}><ResponsiveContainer>
            <AreaChart data={stats.timeline.map((p) => ({ ...p, label: new Date(p.t).toLocaleTimeString([], { hour: "2-digit", minute: "2-digit" }) }))} margin={{ left: -18, right: 8, top: 8 }}>
              <defs><linearGradient id="g" x1="0" y1="0" x2="0" y2="1"><stop offset="0%" stopColor="#4fd1e8" stopOpacity={0.5} /><stop offset="100%" stopColor="#4fd1e8" stopOpacity={0} /></linearGradient></defs>
              <CartesianGrid stroke="#1b2735" vertical={false} /><XAxis dataKey="label" stroke="#6b7a8c" fontSize={11} interval={4} /><YAxis allowDecimals={false} stroke="#6b7a8c" fontSize={11} />
              <Tooltip contentStyle={{ background: "#0f161e", border: "1px solid #223040", color: "#dbe4ee" }} />
              <Area type="monotone" dataKey="alerts" stroke="#4fd1e8" fill="url(#g)" strokeWidth={2} />
            </AreaChart></ResponsiveContainer></div> : <Empty>Loading…</Empty>}
        </div>
        <div className="card">
          <h3>Alert status</h3>
          {stats ? <ul className="bars">{Object.entries(stats.byStatus).map(([k, n]) => (
            <li key={k}><span>{STATUS_LABEL[k]}</span><div><i style={{ width: `${stats.totalAlerts ? (n / stats.totalAlerts) * 100 : 0}%` }} className={`b-${k}`} /></div><b>{n}</b></li>))}</ul> : <Empty>Loading…</Empty>}
          {stats?.falsePositiveRate != null && <p className="sub">False-positive rate among reviewed alerts: <b>{(stats.falsePositiveRate * 100).toFixed(1)}%</b></p>}
        </div>
      </section>
      <section className="card">
        <div className="row-h"><h3>Live alert feed</h3><Link to="/alerts" className="more">All alerts →</Link></div>
        {!feed ? <Empty>Loading…</Empty> : feed.length === 0 ? <Empty>No alerts yet. Once the sniffer publishes flows, detections appear here instantly.</Empty> : (
          <ul className="feed">{feed.map((a) => (
            <li key={a.id}><Link to={`/alerts/${a.id}`} className="feed-row">
              <Sev s={a.severity} /><span className="lbl">{a.supervisedLabel}{a.supervisedLabel === "Benign" && <em> · anomaly</em>}</span>
              <span className="ip">{a.srcIp} → {a.dstIp}{a.dstPort ? `:${a.dstPort}` : ""}</span><Status s={a.status} /><time>{timeAgo(a.createdAt)}</time></Link></li>))}</ul>)}
      </section>
    </div>
  );
}
