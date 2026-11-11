import bcrypt from "bcryptjs";
import { prisma } from "../prisma.js";
import { Config, Flow, Notification } from "../models/index.js";
import { config } from "../config.js";

export async function seed() {
  if (config.seedDemoUsers && (await prisma.user.count()) === 0) {
    const mk = (name, email, pw, role) => bcrypt.hash(pw, 12).then((passwordHash) => prisma.user.create({ data: { name, email, passwordHash, role } }));
    await mk("Demo Admin", "admin@packetguard.local", "Admin123", "ADMIN");
    await mk("Demo Analyst", "analyst@packetguard.local", "Analyst123", "ANALYST");
    console.log("[seed] created demo users: admin@packetguard.local / Admin123, analyst@packetguard.local / Analyst123");
  }
  await Config.updateOne({ _id: "severity" }, { $setOnInsert: { critical: 0.9, high: 0.7, anomaly_high: -0.1 } }, { upsert: true });
}

/** Scheduled retention job (SRS 3.4.6): raw flows 90 days, notifications 90 days. Alerts/audit kept >= 1 year. */
export function startRetentionJob() {
  const run = async () => {
    const cutoff = new Date(Date.now() - 90 * 24 * 3600 * 1000);
    try {
      const f = await Flow.deleteMany({ timestamp: { $lt: cutoff } });
      const n = await Notification.deleteMany({ createdAt: { $lt: cutoff } });
      if (f.deletedCount || n.deletedCount) console.log(`[retention] purged ${f.deletedCount} flows, ${n.deletedCount} notifications`);
    } catch (e) { console.warn("[retention]", e.message); }
  };
  setInterval(run, 24 * 3600 * 1000); setTimeout(run, 60000);
}
