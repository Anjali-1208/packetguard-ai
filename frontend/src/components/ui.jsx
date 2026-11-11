import React from "react";
import { Bar, BarChart, Cell, ResponsiveContainer, Tooltip, XAxis, YAxis } from "recharts";

export const FEATURE_LABELS = {
  flow_duration: "Flow duration", total_fwd_packets: "Forward packets", total_bwd_packets: "Backward packets",
  total_fwd_bytes: "Forward bytes", total_bwd_bytes: "Backward bytes", fwd_packet_length_mean: "Avg fwd packet size",
  bwd_packet_length_mean: "Avg bwd packet size", flow_bytes_per_sec: "Bytes / second", flow_packets_per_sec: "Packets / second",
  syn_flag_count: "SYN flags", fin_flag_count: "FIN flags", protocol: "Protocol",
};
export const label = (f) => FEATURE_LABELS[f] || f;
export const SEV_ORDER = ["critical", "high", "medium", "low"];
export const STATUS_LABEL = { new: "New", acknowledged: "Acknowledged", blocked: "Blocked", resolved: "Resolved", false_positive: "False positive" };

// severity is always colour + text, never colour alone
export const Sev = ({ s }) => <span className={`sev sev-${s}`}>{s}</span>;
export const Status = ({ s }) => <span className={`st st-${s}`}>{STATUS_LABEL[s] || s}</span>;
export const Notice = () => <p className="notice">AI severity and verdict are <b>recommendations</b>. The final block decision belongs to the analyst.</p>;
export const Empty = ({ children }) => <div className="empty">{children}</div>;
export const Err = ({ msg }) => (msg ? <div className="err" role="alert">{msg}</div> : null);

export function timeAgo(iso) {
  const s = Math.max(0, (Date.now() - new Date(iso).getTime()) / 1000);
  if (s < 60) return `${Math.floor(s)}s ago`; if (s < 3600) return `${Math.floor(s / 60)}m ago`;
  if (s < 86400) return `${Math.floor(s / 3600)}h ago`; return new Date(iso).toLocaleDateString();
}
export const fmt = (v) => (typeof v === "number" ? (Math.abs(v) >= 1000 ? Math.round(v).toLocaleString() : +v.toFixed(2)) : v);

/** Horizontal SHAP / deviation bars. Positive = pushed toward the predicted class (red); negative = pushed away (teal). */
export function ContribChart({ data }) {
  const rows = (data || []).map((d) => ({ name: label(d.feature), v: d.contribution }));
  if (!rows.length) return <Empty>No explanation stored for this alert.</Empty>;
  return (
    <div style={{ height: 40 + rows.length * 44 }}>
      <ResponsiveContainer>
        <BarChart data={rows} layout="vertical" margin={{ left: 10, right: 24, top: 4, bottom: 4 }}>
          <XAxis type="number" stroke="#6b7a8c" fontSize={11} /><YAxis type="category" dataKey="name" width={130} stroke="#b7c3d0" fontSize={12} />
          <Tooltip cursor={{ fill: "rgba(255,255,255,.04)" }} contentStyle={{ background: "#0f161e", border: "1px solid #223040", color: "#dbe4ee" }} formatter={(v) => v.toFixed(3)} />
          <Bar dataKey="v" radius={3}>{rows.map((r, i) => <Cell key={i} fill={r.v >= 0 ? "#ff6b5e" : "#3dd6b5"} />)}</Bar>
        </BarChart>
      </ResponsiveContainer>
    </div>
  );
}
