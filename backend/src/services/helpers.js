import crypto from "crypto";
export class ApiError extends Error {
  constructor(status, code, message) { super(message); this.status = status; this.code = code; }
}
export const asyncHandler = (fn) => (req, res, next) => Promise.resolve(fn(req, res, next)).catch(next);
export const hash = (s) => crypto.createHash("sha256").update(String(s)).digest("hex");
export const hashIp = (ip) => hash(ip || "").slice(0, 12);

/** Mongo doc (lean or hydrated) -> API object with string id. */
export function ser(doc) {
  if (!doc) return doc;
  const o = typeof doc.toObject === "function" ? doc.toObject() : { ...doc };
  o.id = String(o._id); delete o._id; delete o.__v;
  if (o.flowId) o.flowId = String(o.flowId);
  return o;
}
