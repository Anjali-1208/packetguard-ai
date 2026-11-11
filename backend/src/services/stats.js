import { Alert, Flow } from "../models/index.js";

let cache = { at: 0, minutes: 0, data: null };
export async function summary(minutes = 30) {
  if (cache.data && cache.minutes === minutes && Date.now() - cache.at < 3000) return cache.data;
  const since = new Date(Date.now() - minutes * 60000);
  const hourAgo = new Date(Date.now() - 3600000);
  const [sev, st, tl, totalFlows, flowsLastHour] = await Promise.all([
    Alert.aggregate([{ $group: { _id: "$severity", n: { $sum: 1 } } }]),
    Alert.aggregate([{ $group: { _id: "$status", n: { $sum: 1 } } }]),
    Alert.aggregate([{ $match: { createdAt: { $gte: since } } },
      { $group: { _id: { $dateTrunc: { date: "$createdAt", unit: "minute" } }, n: { $sum: 1 } } }]),
    Flow.estimatedDocumentCount(), Flow.countDocuments({ timestamp: { $gte: hourAgo } }),
  ]);
  const bySeverity = { critical: 0, high: 0, medium: 0, low: 0 }; sev.forEach((x) => (bySeverity[x._id] = x.n));
  const byStatus = { new: 0, acknowledged: 0, blocked: 0, resolved: 0, false_positive: 0 }; st.forEach((x) => (byStatus[x._id] = x.n));
  const map = new Map(tl.map((x) => [new Date(x._id).getTime(), x.n]));
  const end = Math.floor(Date.now() / 60000) * 60000; const timeline = [];
  for (let t = end - (minutes - 1) * 60000; t <= end; t += 60000) timeline.push({ t: new Date(t).toISOString(), alerts: map.get(t) || 0 });
  const total = Object.values(byStatus).reduce((a, b) => a + b, 0); const reviewed = total - byStatus.new;
  const data = { bySeverity, byStatus, totalAlerts: total, totalFlows, flowsLastHour, timeline,
    falsePositiveRate: reviewed ? byStatus.false_positive / reviewed : null };
  cache = { at: Date.now(), minutes, data };
  return data;
}
