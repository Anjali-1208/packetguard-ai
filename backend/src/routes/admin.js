import { Router } from "express";
import bcrypt from "bcryptjs";
import { z } from "zod";
import { prisma } from "../prisma.js";
import { Config } from "../models/index.js";
import mongoose from "mongoose";
import { authenticate, requireRole } from "../middleware/auth.js";
import { ApiError, asyncHandler } from "../services/helpers.js";
import { audit } from "../services/audit.js";
import { passwordSchema } from "./auth.js";
import { config } from "../config.js";

const r = Router();
r.use(authenticate, requireRole("admin"));
const safe = ({ passwordHash, ...u }) => ({ ...u, role: u.role.toLowerCase() });

r.get("/users", asyncHandler(async (_req, res) => {
  res.json({ users: (await prisma.user.findMany({ orderBy: { id: "asc" } })).map(safe) });
}));

r.post("/users", asyncHandler(async (req, res) => {
  const b = z.object({ name: z.string().trim().min(2).max(80), email: z.string().trim().toLowerCase().email(),
    password: passwordSchema, role: z.enum(["analyst", "admin"]).default("analyst") }).parse(req.body);
  if (await prisma.user.findUnique({ where: { email: b.email } })) throw new ApiError(409, "EMAIL_EXISTS", "An account with this email already exists.");
  const u = await prisma.user.create({ data: { name: b.name, email: b.email, role: b.role.toUpperCase(), passwordHash: await bcrypt.hash(b.password, 12) } });
  await audit(`user:${req.user.id}`, "USER_CREATED", `user:${u.id}`, { role: b.role });
  res.status(201).json({ user: safe(u) });
}));

r.patch("/users/:id", asyncHandler(async (req, res) => {
  const id = Number(req.params.id);
  const b = z.object({ status: z.enum(["active", "suspended"]).optional(), role: z.enum(["analyst", "admin"]).optional() }).parse(req.body);
  if (id === req.user.id) throw new ApiError(409, "SELF_MODIFY", "You cannot change your own role or status.");
  if (!(await prisma.user.findUnique({ where: { id } }))) throw new ApiError(404, "NOT_FOUND", "User not found.");
  const u = await prisma.user.update({ where: { id }, data: { ...(b.status && { status: b.status }), ...(b.role && { role: b.role.toUpperCase() }) } });
  if (b.status === "suspended") await prisma.refreshToken.updateMany({ where: { userId: id }, data: { revoked: true } });
  await audit(`user:${req.user.id}`, "USER_UPDATED", `user:${id}`, b);
  res.json({ user: safe(u) });
}));

const DEFAULTS = { critical: 0.9, high: 0.7, anomaly_high: -0.1 };
r.get("/config", asyncHandler(async (_req, res) => {
  const doc = await Config.findById("severity").lean();
  res.json({ thresholds: { ...DEFAULTS, ...(doc || {}), _id: undefined } });
}));
r.patch("/config", asyncHandler(async (req, res) => {
  const b = z.object({ critical: z.number().min(0.5).max(1), high: z.number().min(0.1).max(1), anomaly_high: z.number().min(-1).max(0) })
    .refine((v) => v.high < v.critical, { message: "high must be lower than critical" }).parse(req.body);
  await Config.updateOne({ _id: "severity" }, { $set: b }, { upsert: true });
  await audit(`user:${req.user.id}`, "CONFIG_UPDATED", "severity-thresholds", b);
  res.json({ thresholds: b });
}));

r.get("/audit-logs", asyncHandler(async (req, res) => {
  const q = z.object({ actor: z.string().max(100).optional(), action: z.string().max(60).optional(),
    from: z.coerce.date().optional(), to: z.coerce.date().optional(),
    page: z.coerce.number().int().min(1).default(1), limit: z.coerce.number().int().min(1).max(200).default(50) }).parse(req.query);
  const where = { ...(q.actor && { actor: { contains: q.actor } }), ...(q.action && { action: q.action }),
    ...((q.from || q.to) && { timestamp: { ...(q.from && { gte: q.from }), ...(q.to && { lte: q.to }) } }) };
  const [logs, total] = await Promise.all([
    prisma.auditLog.findMany({ where, orderBy: { timestamp: "desc" }, skip: (q.page - 1) * q.limit, take: q.limit }),
    prisma.auditLog.count({ where }),
  ]);
  res.json({ logs, total, page: q.page });
}));

async function ping(url) {
  try { const x = await fetch(url, { signal: AbortSignal.timeout(2500) }); return x.ok ? await x.json() : null; } catch { return null; }
}
r.get("/health", asyncHandler(async (_req, res) => {
  const [ml, sniffer, users, rules] = await Promise.all([
    ping(`${config.mlUrl}/health`), ping(`${config.snifferUrl}/health`), prisma.user.count(), prisma.blockRule.count({ where: { active: true } }),
  ]);
  const recent = (iso) => iso && Date.now() - new Date(iso).getTime() < 120000;
  res.json({
    components: {
      backend: { status: "ok" },
      database: { status: mongoose.connection.readyState === 1 ? "ok" : "down" },
      capture: { status: sniffer ? (recent(sniffer.lastFlow) ? "ok" : "idle") : "down", ...(sniffer || {}) },
      streaming: { status: ml?.status === "ok" ? "ok" : (sniffer ? "degraded" : "down") },
      inference: { status: ml ? (ml.status === "ok" ? "ok" : "starting") : "down", ...(ml || {}) },
    },
    users, activeBlockRules: rules,
  });
}));

export default r;
