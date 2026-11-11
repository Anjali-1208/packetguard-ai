import { Alert } from "../models/index.js";
import { ser } from "./helpers.js";
import { audit } from "./audit.js";
import { createNotifications, sendExternal } from "./notify.js";
import { emitStatsDebounced } from "../socket.js";

async function onNewAlert(raw, io) {
  const a = ser(raw);
  io.emit("new-alert", a);                      // live push to every connected dashboard
  emitStatsDebounced();
  await audit("ml-service", "ML_VERDICT", `alert:${a.id}`, { flowId: a.flowId, label: a.supervisedLabel,
    confidence: a.supervisedConfidence, anomalyScore: a.anomalyScore, severity: a.severity, modelVersion: a.modelVersion });
  if (a.severity === "critical") {              // async, off the main path
    createNotifications(a, io).catch((e) => console.warn("[watcher] notifications:", e.message));
    sendExternal(a).catch((e) => console.warn("[watcher] external:", e.message));
  }
}

/** MongoDB change stream (needs a replica set). Falls back to polling if streams are unavailable. */
export function startWatcher(io) {
  let lastId = null;
  const startChangeStream = () => {
    const cs = Alert.watch([{ $match: { operationType: "insert" } }]);
    console.log("[watcher] change stream open");
    cs.on("change", (c) => { lastId = c.fullDocument._id; onNewAlert(c.fullDocument, io).catch((e) => console.error("[watcher]", e.message)); });
    cs.on("error", (e) => { console.warn("[watcher] change stream error, falling back to polling:", e.message); try { cs.close(); } catch {} poll(); });
  };
  const poll = async () => {
    console.log("[watcher] polling mode");
    if (!lastId) { const l = await Alert.findOne().sort({ _id: -1 }).lean(); lastId = l?._id || null; }
    setInterval(async () => {
      try {
        const fresh = await Alert.find(lastId ? { _id: { $gt: lastId } } : {}).sort({ _id: 1 }).limit(100).lean();
        for (const a of fresh) { lastId = a._id; await onNewAlert(a, io); }
      } catch (e) { console.warn("[watcher] poll error:", e.message); }
    }, 2000);
  };
  try { startChangeStream(); } catch (e) { console.warn("[watcher] change streams unavailable:", e.message); poll(); }
}
