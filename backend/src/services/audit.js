import { prisma } from "../prisma.js";
/** Audit writes never block or fail the primary operation (SDD 3.4.5). */
export async function audit(actor, action, target = "", details = {}) {
  try {
    await prisma.auditLog.create({ data: { actor: String(actor), action, target: String(target), details: JSON.stringify(details) } });
  } catch (e) { console.error("[audit] write failed:", e.message); }
}
