import React, { useEffect, useState } from "react";
import { Link } from "react-router-dom";
import { api } from "../api.js";
import { useAuth } from "../auth.jsx";
import { Empty, Err, timeAgo } from "../components/ui.jsx";
import { useOutletContext } from "react-router-dom";

export default function Notifications() {
  const { socket } = useAuth(); const { setUnread } = useOutletContext();
  const [items, setItems] = useState(null); const [err, setErr] = useState("");
  const load = () => api("/notifications").then((d) => { setItems(d.notifications); setUnread(d.unread); }).catch((e) => setErr(e.message));
  useEffect(() => { load(); }, []); // eslint-disable-line
  useEffect(() => { if (!socket) return; socket.on("notification", load); return () => socket.off("notification", load); }, [socket]); // eslint-disable-line
  const readAll = () => api("/notifications/read-all", { method: "POST", body: {} }).then(load);
  const read = (n) => api(`/notifications/${n.id}/read`, { method: "PATCH", body: {} }).then(load);
  return (
    <div className="page">
      <header className="page-h"><div><h1>Notifications</h1><p className="sub">Critical alerts also go to Slack / email when configured.</p></div><button className="ghost" onClick={readAll}>Mark all read</button></header>
      <Err msg={err} />
      <div className="card">{!items ? <Empty>Loading…</Empty> : items.length === 0 ? <Empty>Nothing yet.</Empty> : (
        <ul className="feed">{items.map((n) => <li key={n.id} className={n.readFlag ? "read" : ""}><div className="feed-row" onClick={() => read(n)}>
          <span className="sev sev-critical">critical</span><span className="lbl">{n.message}</span><Link to={`/alerts/${n.alertId}`}>Open</Link><time>{timeAgo(n.createdAt)}</time></div></li>)}</ul>)}</div>
    </div>
  );
}
