import React, { useEffect, useState } from "react";
import { NavLink, Outlet } from "react-router-dom";
import { useAuth } from "../auth.jsx";
import { api } from "../api.js";

export default function Layout() {
  const { user, logout, socket, connected } = useAuth();
  const [unread, setUnread] = useState(0);
  const [toast, setToast] = useState(null);

  useEffect(() => { api("/notifications").then((d) => setUnread(d.unread)).catch(() => {}); }, []);
  useEffect(() => {
    if (!socket) return;
    const onN = (n) => { setUnread((u) => u + 1); setToast(n); setTimeout(() => setToast(null), 6000); };
    socket.on("notification", onN); return () => socket.off("notification", onN);
  }, [socket]);

  const nav = [["/", "Dashboard"], ["/alerts", "Live Alerts"], ["/blockrules", "Block Rules"], ["/notifications", `Notifications${unread ? ` (${unread})` : ""}`]];
  if (user.role === "admin") nav.push(["/admin", "Administration"]);

  return (
    <div className="shell">
      <aside className="rail">
        <div className="brand"><span className="glyph">◈</span><div><b>PacketGuard</b><small>AI · threat console</small></div></div>
        <nav>{nav.map(([to, label]) => <NavLink key={to} to={to} end={to === "/"} className={({ isActive }) => (isActive ? "on" : "")}>{label}</NavLink>)}</nav>
        <div className="who">
          <div className={`link ${connected ? "up" : "down"}`}><i />{connected ? "live stream connected" : "reconnecting…"}</div>
          <div className="me">{user.name}<small>{user.role}</small></div>
          <button className="ghost" onClick={() => logout()}>Sign out</button>
        </div>
      </aside>
      <main><Outlet context={{ setUnread }} /></main>
      {toast && <div className="toast" role="alert"><b>Critical</b> {toast.message}</div>}
    </div>
  );
}
