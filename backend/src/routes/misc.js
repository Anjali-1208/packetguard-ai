import { Router } from "express";
import { z } from "zod";
import { prisma } from "../prisma.js";
import { Notification } from "../models/index.js";
import { authenticate, requireRole } from "../middleware/auth.js";
import { ApiError, asyncHandler, ser } from "../services/helpers.js";
import { audit } from "../services/audit.js";
import { summary } from "../services/stats.js";
import { lookup } from "../services/threatintel.js";
import { config } from "../config.js";

export const blockrules = Router();
blockrules.use(authenticate);
blockrules.get("/", asyncHandler(async (_req, res) => {
  const rules = await prisma.blockRule.findMany({ orderBy: { createdAt: "desc" }, include: { createdBy: { select: { id: true, name: true, email: true } } } });
  res.json({ rules });
}));
blockrules.patch("/:id", requireRole("admin"), asyncHandler(async (req, res) => {
  const b = z.object({ active: z.boolean().optional(), reason: z.string().trim().min(3).max(500).optional() }).parse(req.body);
  const id = Number(req.params.id);
  if (!Number.isInteger(id)) throw new ApiError(400, "INVALID_ID", "Invalid id.");
  const exists = await prisma.blockRule.findUnique({ where: { id } });
  if (!exists) throw new ApiError(404, "NOT_FOUND", "Block rule not found.");
  const rule = await prisma.blockRule.update({ where: { id }, data: b });
  await audit(`user:${req.user.id}`, "BLOCKRULE_UPDATED", `blockrule:${id}`, b);
  res.json({ rule });
}));

export const stats = Router();
stats.use(authenticate);
stats.get("/summary", asyncHandler(async (req, res) => {
  const minutes = Math.min(Math.max(Number(req.query.minutes) || 30, 5), 240);
  res.json(await summary(minutes));
}));
stats.get("/model-performance", asyncHandler(async (_req, res) => {
  try {
    const r = await fetch(`${config.mlUrl}/model/metrics`, { signal: AbortSignal.timeout(4000) });
    if (!r.ok) throw new Error("ml status " + r.status);
    res.json(await r.json());
  } catch { throw new ApiError(502, "ML_UNAVAILABLE", "Model metrics are temporarily unavailable."); }
}));

export const threatintel = Router();
threatintel.use(authenticate);
threatintel.get("/:ip", asyncHandler(async (req, res) => {
  const ip = z.string().trim().max(45).regex(/^[0-9a-fA-F:.]+$/, "not a valid IP").parse(req.params.ip);
  res.json(await lookup(ip, { force: req.query.refresh === "1" }));
}));

export const notifications = Router();
notifications.use(authenticate);
notifications.get("/", asyncHandler(async (req, res) => {
  const items = await Notification.find({ userId: req.user.id }).sort({ createdAt: -1 }).limit(50).lean();
  res.json({ notifications: items.map(ser), unread: items.filter((n) => !n.readFlag).length });
}));
notifications.post("/read-all", asyncHandler(async (req, res) => {
  await Notification.updateMany({ userId: req.user.id, readFlag: false }, { readFlag: true }); res.json({ ok: true });
}));
notifications.patch("/:id/read", asyncHandler(async (req, res) => {
  await Notification.updateOne({ _id: req.params.id, userId: req.user.id }, { readFlag: true }); res.json({ ok: true });
}));
