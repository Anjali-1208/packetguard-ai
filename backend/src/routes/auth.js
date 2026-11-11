import { Router } from "express";
import bcrypt from "bcryptjs";
import crypto from "crypto";
import { z } from "zod";
import rateLimit from "express-rate-limit";
import { prisma } from "../prisma.js";
import { config } from "../config.js";
import { signAccess, authenticate } from "../middleware/auth.js";
import { ApiError, asyncHandler, hash, hashIp } from "../services/helpers.js";
import { audit } from "../services/audit.js";

export const passwordSchema = z.string().min(8, "at least 8 characters")
  .regex(/[A-Z]/, "needs an uppercase letter").regex(/[a-z]/, "needs a lowercase letter").regex(/[0-9]/, "needs a number");
const registerSchema = z.object({ name: z.string().trim().min(2).max(80), email: z.string().trim().toLowerCase().email(), password: passwordSchema });
const loginSchema = z.object({ email: z.string().trim().toLowerCase().email(), password: z.string().min(1) });

const r = Router();
r.use(rateLimit({ windowMs: 15 * 60 * 1000, limit: config.authRateLimit, standardHeaders: true, legacyHeaders: false,
  handler: (_q, res) => res.status(429).json({ error: { code: "RATE_LIMITED", message: "Too many attempts. Try again later." } }) }));

const cookieOpts = { httpOnly: true, sameSite: "strict", secure: config.cookieSecure, path: "/api/auth", maxAge: config.refreshTtlMs };
const pub = (u) => ({ id: u.id, name: u.name, email: u.email, role: u.role.toLowerCase() });

async function issue(res, user) {
  const refresh = crypto.randomBytes(48).toString("hex");
  await prisma.refreshToken.create({ data: { tokenHash: hash(refresh), userId: user.id, expiresAt: new Date(Date.now() + config.refreshTtlMs) } });
  res.cookie("pg_refresh", refresh, cookieOpts);
  return { accessToken: signAccess(user), refreshToken: refresh, expiresIn: 900, user: pub(user) };
}

r.post("/register", asyncHandler(async (req, res) => {
  if (!config.allowSelfRegister) throw new ApiError(403, "REGISTRATION_DISABLED", "Self-registration is disabled. Ask an administrator.");
  const b = registerSchema.parse(req.body);
  if (await prisma.user.findUnique({ where: { email: b.email } })) throw new ApiError(409, "EMAIL_EXISTS", "An account with this email already exists.");
  const user = await prisma.user.create({ data: { name: b.name, email: b.email, passwordHash: await bcrypt.hash(b.password, 12), role: "ANALYST" } });
  await audit(user.email, "REGISTER", `user:${user.id}`);
  res.status(201).json(await issue(res, user));
}));

r.post("/login", asyncHandler(async (req, res) => {
  const { email, password } = loginSchema.parse(req.body);
  const user = await prisma.user.findUnique({ where: { email } });
  const ipH = hashIp(req.ip);
  const bad = new ApiError(401, "INVALID_CREDENTIALS", "Incorrect email or password.");
  if (!user) { await bcrypt.compare(password, "$2a$12$invalidinvalidinvalidinvalidinvalidinvalidinvalidinvali"); await audit(email, "LOGIN_FAILED", "unknown-user", { ip: ipH }); throw bad; }
  if (user.lockedUntil && user.lockedUntil > new Date()) throw new ApiError(403, "ACCOUNT_LOCKED", "Account temporarily locked after repeated failed logins. Try again in 15 minutes.");
  if (user.status !== "active") throw new ApiError(403, "ACCOUNT_SUSPENDED", "This account has been suspended.");
  if (!(await bcrypt.compare(password, user.passwordHash))) {
    const attempts = user.failedAttempts + 1; const lock = attempts >= 5;
    await prisma.user.update({ where: { id: user.id }, data: { failedAttempts: lock ? 0 : attempts, lockedUntil: lock ? new Date(Date.now() + 15 * 60000) : null } });
    await audit(email, lock ? "ACCOUNT_LOCKOUT" : "LOGIN_FAILED", `user:${user.id}`, { ip: ipH, attempts });
    throw bad;
  }
  await prisma.user.update({ where: { id: user.id }, data: { failedAttempts: 0, lockedUntil: null, lastLogin: new Date() } });
  await audit(email, "LOGIN", `user:${user.id}`, { ip: ipH });
  res.json(await issue(res, user));
}));

r.post("/refresh", asyncHandler(async (req, res) => {
  const token = req.cookies?.pg_refresh || req.body?.refreshToken;
  if (!token) throw new ApiError(401, "UNAUTHENTICATED", "No session.");
  const row = await prisma.refreshToken.findUnique({ where: { tokenHash: hash(token) }, include: { user: true } });
  if (!row || row.revoked || row.expiresAt < new Date() || row.user.status !== "active") throw new ApiError(401, "INVALID_TOKEN", "Session expired. Please sign in again.");
  await prisma.refreshToken.update({ where: { id: row.id }, data: { revoked: true } }); // rotate
  res.json(await issue(res, row.user));
}));

r.post("/logout", asyncHandler(async (req, res) => {
  const token = req.cookies?.pg_refresh || req.body?.refreshToken;
  if (token) {
    const row = await prisma.refreshToken.findUnique({ where: { tokenHash: hash(token) }, include: { user: true } });
    if (row) { await prisma.refreshToken.update({ where: { id: row.id }, data: { revoked: true } }); await audit(row.user.email, "LOGOUT", `user:${row.userId}`); }
  }
  res.clearCookie("pg_refresh", { path: "/api/auth" });
  res.json({ ok: true });
}));

r.get("/me", authenticate, asyncHandler(async (req, res) => {
  const u = await prisma.user.findUnique({ where: { id: req.user.id } });
  if (!u) throw new ApiError(401, "UNAUTHENTICATED", "Account not found.");
  res.json({ user: pub(u) });
}));

export default r;
