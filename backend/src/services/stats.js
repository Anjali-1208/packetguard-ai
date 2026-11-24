
import { Alert, Flow } from "../models/index.js";

// Store recently calculated statistics to reduce repeated database queries.
let cache = { at: 0, minutes: 0, data: null };

export async function summary(minutes = 30) {
  // Reuse cached results when the requested time period matches
  // and the cached data is less than 3 seconds old.
  if (cache.data && cache.minutes === minutes && Date.now() - cache.at < 3000) return cache.data;

  // Calculate the time boundaries for the selected period and last hour.
  const since = new Date(Date.now() - minutes * 60000);
  const hourAgo = new Date(Date.now() - 3600000);

  // Run independent database queries in parallel for better efficiency.
  const [sev, st, tl, totalFlows, flowsLastHour] = await Promise.all([
    Alert.aggregate([{ $group: { _id: "$severity", n: { $sum: 1 } } }]),
    Alert.aggregate([{ $group: { _id: "$status", n: { $sum: 1 } } }]),
    Alert.aggregate([{ $match: { createdAt: { $gte: since } } },
      { $group: { _id: { $dateTrunc: { date: "$createdAt", unit: "minute" } }, n: { $sum: 1 } } }]),
    Flow.estimatedDocumentCount(), Flow.countDocuments({ timestamp: { $gte: hourAgo } }),
  ]);

  // Organize alert counts by severity and status.
  const bySeverity = { critical: 0, high: 0, medium: 0, low: 0 }; sev.forEach((x) => (bySeverity[x._id] = x.n));
  const byStatus = { new: 0, acknowledged: 0, blocked: 0, resolved: 0, false_positive: 0 }; st.forEach((x) => (byStatus[x._id] = x.n));

  // Convert the alert timeline results into a lookup map by minute.
  const map = new Map(tl.map((x) => [new Date(x._id).getTime(), x.n]));

  // Generate a continuous minute-by-minute timeline, including minutes with no alerts.
  const end = Math.floor(Date.now() / 60000) * 60000; const timeline = [];
  for (let t = end - (minutes - 1) * 60000; t <= end; t += 60000) timeline.push({ t: new Date(t).toISOString(), alerts: map.get(t) || 0 });

  // Calculate total alerts, reviewed alerts, and the false-positive rate.
  const total = Object.values(byStatus).reduce((a, b) => a + b, 0); const reviewed = total - byStatus.new;
  const data = { bySeverity, byStatus, totalAlerts: total, totalFlows, flowsLastHour, timeline,
    falsePositiveRate: reviewed ? byStatus.false_positive / reviewed : null };

  // Update the cache with the latest calculated statistics.
  cache = { at: Date.now(), minutes, data };
  return data;
}
