import React, { useEffect, useState } from "react";
import { api } from "../api.js";
import { useAuth } from "../auth.jsx";
import { Empty, Err, timeAgo } from "../components/ui.jsx";

export default function BlockRules() {
  const { user } = useAuth(); const [rules, setRules] = useState(null); const [err, setErr] = useState("");
  const load = () => api("/blockrules").then((d) => setRules(d.rules)).catch((e) => setErr(e.message));
  useEffect(() => { load(); }, []);
  const toggle = (r) => api(`/blockrules/${r.id}`, { method: "PATCH", body: { active: !r.active } }).then(load).catch((e) => setErr(e.message));
  return (
    <div className="page">
      <header className="page-h"><div><h1>Block rules</h1><p className="sub">Simulated IPS decisions approved by analysts. Nothing here touches live traffic.</p></div></header>
      <Err msg={err} />
      <div className="card tbl-wrap">{!rules ? <Empty>Loading…</Empty> : rules.length === 0 ? <Empty>No block rules yet. Approve one from an acknowledged alert.</Empty> : (
        <table><thead><tr><th>IP</th><th>Reason</th><th>Approved by</th><th>When</th><th>State</th>{user.role === "admin" && <th />}</tr></thead>
          <tbody>{rules.map((r) => <tr key={r.id}><td className="mono">{r.ip}</td><td>{r.reason}</td><td>{r.createdBy?.name}</td><td>{timeAgo(r.createdAt)}</td>
            <td><span className={`st ${r.active ? "st-blocked" : "st-resolved"}`}>{r.active ? "Active" : "Inactive"}</span></td>
            {user.role === "admin" && <td><button className="ghost" onClick={() => toggle(r)}>{r.active ? "Deactivate" : "Activate"}</button></td>}</tr>)}</tbody></table>)}</div>
    </div>
  );
}
