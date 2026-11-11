import nodemailer from "nodemailer";
import { config } from "../config.js";
import { Notification } from "../models/index.js";
import { prisma } from "../prisma.js";

let mailer = null;
if (config.smtp.host) mailer = nodemailer.createTransport({ host: config.smtp.host, port: config.smtp.port, auth: config.smtp.user ? { user: config.smtp.user, pass: config.smtp.pass } : undefined });

/** Fire-and-forget external delivery. Failures are logged and never retried forever (SRS API-07). */
export async function sendExternal(alert) {
  const text = `CRITICAL alert: ${alert.supervisedLabel} from ${alert.srcIp} -> ${alert.dstIp} (confidence ${(alert.supervisedConfidence * 100).toFixed(0)}%). Review in PacketGuard.`;
  const jobs = [];
  if (config.slackWebhook) jobs.push(fetch(config.slackWebhook, { method: "POST", headers: { "Content-Type": "application/json" }, body: JSON.stringify({ text }), signal: AbortSignal.timeout(5000) }));
  if (mailer && config.smtp.to) jobs.push(mailer.sendMail({ from: config.smtp.from, to: config.smtp.to, subject: `[PacketGuard] Critical: ${alert.supervisedLabel} from ${alert.srcIp}`, text }));
  if (!jobs.length) return console.log("[notify] (no Slack/SMTP configured) would send:", text);
  const res = await Promise.allSettled(jobs);
  res.filter((r) => r.status === "rejected").forEach((r) => console.warn("[notify] delivery failed:", r.reason?.message));
}

/** In-app notification per active user; unique index makes this idempotent per alert+type+user. */
export async function createNotifications(alert, io) {
  const users = await prisma.user.findMany({ where: { status: "active" }, select: { id: true } });
  for (const u of users) {
    try {
      const n = await Notification.create({ userId: u.id, alertId: String(alert.id), type: "critical-alert",
        message: `Critical ${alert.supervisedLabel} alert from ${alert.srcIp}` });
      io.to(`user:${u.id}`).emit("notification", { id: String(n._id), alertId: n.alertId, type: n.type, message: n.message, createdAt: n.createdAt, readFlag: false });
    } catch (e) { if (e.code !== 11000) console.warn("[notify] create failed:", e.message); }
  }
}
