import jwt from "jsonwebtoken";
import { config } from "../config.js";
import { ApiError } from "../services/helpers.js";

export function signAccess(user) {
  return jwt.sign(
    { userId: user.id, role: String(user.role).toLowerCase() },
    config.jwtSecret,
    { expiresIn: config.accessTtl }
  );
}
export function verifyToken(token) { return jwt.verify(token, config.jwtSecret); }

export function authenticate(req, _res, next) {
  const h = req.headers.authorization || "";
  if (!h.startsWith("Bearer ")) return next(new ApiError(401, "UNAUTHENTICATED", "Authentication required."));
  try {
    const p = verifyToken(h.slice(7));
    req.user = { id: p.userId, role: String(p.role).toLowerCase() };
    next();
  } catch {
    next(new ApiError(401, "INVALID_TOKEN", "Session expired or invalid. Please sign in again."));
  }
}

// role is always read from the verified JWT, never from the client
export const requireRole = (...roles) => (req, _res, next) =>
  roles.includes(req.user?.role) ? next() : next(new ApiError(403, "FORBIDDEN", "You do not have permission to do this."));