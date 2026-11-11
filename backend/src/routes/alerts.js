import { Router } from "express";
import { z } from "zod";
import { Alert, Flow, ThreatIntel } from "../models/index.js";
import { prisma } from "../prisma.js";
import { authenticate, requireRole } from "../middleware/auth.js";
import { ApiError, asyncHandler, ser } from "../services/helpers.js";
import { canTransition } from "../services/transitions.js";
import { audit } from "../services/audit.js";
import { emitStatsDebounced } from "../socket.js";

const r = Router();
r.use(authenticate);

const listQuery = z.object({
  severity: z.enum(["low", "medium", "high", "critical"]).optional(),
  status: z.enum(["new", "acknowledged", "blocked", "resolved", "false_positive"]).optional(),
  srcIp: z.string().trim().max(45).optional(),
  from: z.coerce.date().optional(), to: z.coerce.date().optional(),
  sort: z.enum(["severity", "recent"]).default("severity"),
  page: z.coerce.number().int().min(1).default(1),
  limit: z.coerce.number().int().min(1).max(200).default(50),
});

function buildFilter(q) {
  const f = {};
  if (q.severity) f.severity = q.severity;
  if (q.status) f.status = q.status;
  if (q.srcIp) f.srcIp = q.srcIp; // exact match on a validated string: no operator injection possible
  if (q.from || q.to) f.createdAt = { ...(q.from && { $gte: q.from }), ...(q.to && { $lte: q.to }) };
  return f;
}
// ranking: severity (critical->low), then recency, ties by confidence (SDD 7.5.3)
const sortFor = (s) => (s === "recent" ? { createdAt: -1 } : { severityRank: -1, createdAt: -1, supervisedConfidence: -1 });
const NOTE = "Severity and verdict are recommendations. The final block decision belongs to the analyst.";

r.get("/", asyncHandler(async (req, res) => {
  const q = listQuery.parse(req.query); const f = buildFilter(q);
  const [alerts, total] = await Promise.all([
    Alert.find(f, { features: 0 }).sort(sortFor(q.sort)).skip((q.page - 1) * q.limit).limit(q.limit).lean(),
    Alert.countDocuments(f),
  ]);
  res.json({ alerts: alerts.map(ser), total, page: q.page, limit: q.limit, note: NOTE });
}));

r.get("/export", asyncHandler(async (req, res) => {
  const q = listQuery.parse(req.query);
  const rows = await Alert.find(buildFilter(q), { features: 0 }).sort(sortFor(q.sort)).limit(5000).lean();
  const esc = (v) => `"${String(v ?? "").replace(/"/g, '""')}"`;
  const head = ["id", "createdAt", "severity", "status", "verdict", "supervisedLabel", "supervisedConfidence", "anomalyScore", "srcIp", "dstIp", "dstPort"];
  const csv = [head.join(","), ...rows.map((a) => head.map((h) => esc(h === "id" ? a._id : a[h])).join(","))].join("\n");
  res.setHeader("Content-Type", "text/csv"); res.setHeader("Content-Disposition", "attachment; filename=alerts.csv"); res.send(csv);
}));

r.get("/:id", asyncHandler(async (req, res) => {
  const a = await Alert.findById(req.params.id).lean();
  if (!a) throw new ApiError(404, "NOT_FOUND", "Alert not found.");
  const [flow, intel, related] = await Promise.all([
    a.flowId ? Flow.findById(a.flowId).lean() : null,
    ThreatIntel.findOne({ ip: a.srcIp }).lean(),
    Alert.find({ srcIp: a.srcIp, _id: { $ne: a._id } }, { features: 0 }).sort({ createdAt: -1 }).limit(5).lean(),
  ]);
  res.json({ alert: ser(a), flow: ser(flow), threatIntel: intel ? ser(intel) : null, related: related.map(ser), note: NOTE });
}));

const statusBody = z.object({ status: z.enum(["acknowledged", "resolved", "false_positive"]), reason: z.string().trim().max(500).optional() });
r.patch("/:id/status", asyncHandler(async (req, res) => {
  const { status, reason } = statusBody.parse(req.body);
  const a = await Alert.findById(req.params.id);
  if (!a) throw new ApiError(404, "NOT_FOUND", "Alert not found.");
  if (!canTransition(a.status, status))
    throw new ApiError(409, "INVALID_STATUS_TRANSITION", `Cannot move an alert from '${a.status}' to '${status}'.`);
  const upd = { status, statusReason: reason, statusUpdatedBy: req.user.id, ...(status === "acknowledged" && { assignedToUserId: req.user.id }) };
  // compare-and-set so two analysts acting simultaneously cannot both win
  const doc = await Alert.findOneAndUpdate({ _id: a._id, status: a.status }, upd, { new: true }).lean();
  if (!doc) throw new ApiError(409, "CONFLICT", "Another analyst just changed this alert. Refresh and retry.");
  await audit(`user:${req.user.id}`, `ALERT_${status.toUpperCase()}`, `alert:${a._id}`, { from: a.status, reason });
  req.app.get("io").emit("alert-updated", { id: String(doc._id), status: doc.status });
  emitStatsDebounced(); res.json({ alert: ser(doc) });
}));

const blockBody = z.object({ reason: z.string().trim().min(3, "please give a reason").max(500) });
r.post("/:id/block", requireRole("analyst", "admin"), asyncHandler(async (req, res) => {
  const { reason } = blockBody.parse(req.body);
  const a = await Alert.findById(req.params.id);
  if (!a) throw new ApiError(404, "NOT_FOUND", "Alert not found.");
  if (!canTransition(a.status, "blocked"))
    throw new ApiError(409, "INVALID_STATUS_TRANSITION", a.status === "new" ? "Acknowledge the alert before approving a block." : `Cannot block an alert that is '${a.status}'.`);
  // the ONLY place a BlockRule is ever created: an explicit, authenticated analyst action (FR-RESP-05)
  let rule = await prisma.blockRule.findFirst({ where: { ip: a.srcIp, active: true } });
  if (!rule) rule = await prisma.blockRule.create({ data: { ip: a.srcIp, reason, alertId: String(a._id), createdById: req.user.id } });
  const doc = await Alert.findOneAndUpdate({ _id: a._id, status: a.status }, { status: "blocked", statusReason: reason, statusUpdatedBy: req.user.id, blockRuleId: rule.id }, { new: true }).lean();
  if (!doc) throw new ApiError(409, "CONFLICT", "Another analyst just changed this alert. Refresh and retry.");
  await audit(`user:${req.user.id}`, "BLOCK_APPROVED", `alert:${a._id}`, { ip: a.srcIp, blockRuleId: rule.id, reason });
  const io = req.app.get("io"); io.emit("alert-updated", { id: String(doc._id), status: "blocked" }); emitStatsDebounced();
  res.status(201).json({ blockRuleId: rule.id, ip: rule.ip, active: rule.active });
}));

export default r;
