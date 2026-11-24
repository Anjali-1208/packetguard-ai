
import { Router } from "express";
import bcrypt from "bcryptjs";
import crypto from "crypto";
import { z } from "zod";
import rateLimit from "express-rate-limit";
import { OAuth2Client } from "google-auth-library";

import { prisma } from "../prisma.js";
import { config } from "../config.js";
import { signAccess, authenticate } from "../middleware/auth.js";
import { ApiError, asyncHandler, hash, hashIp } from "../services/helpers.js";
import { audit } from "../services/audit.js";

const r = Router();

// =====================================
// GOOGLE OAUTH CLIENT
// =====================================

const googleClient = new OAuth2Client(
  config.googleClientId,
  config.googleClientSecret,
  config.googleCallbackUrl
);

// =====================================
// VALIDATION
// =====================================

export const passwordSchema = z.string()
  .min(8, "at least 8 characters")
  .regex(/[A-Z]/, "needs an uppercase letter")
  .regex(/[a-z]/, "needs a lowercase letter")
  .regex(/[0-9]/, "needs a number");

const registerSchema = z.object({
  name: z.string().trim().min(2).max(80),
  email: z.string().trim().toLowerCase().email(),
  password: passwordSchema
});

const loginSchema = z.object({
  email: z.string().trim().toLowerCase().email(),
  password: z.string().min(1)
});

// =====================================
// RATE LIMITING
// =====================================

r.use(rateLimit({
  windowMs: 15 * 60 * 1000,
  limit: config.authRateLimit,
  standardHeaders: true,
  legacyHeaders: false,
  handler: (_req, res) => {
    res.status(429).json({
      error: {
        code: "RATE_LIMITED",
        message: "Too many attempts. Try again later."
      }
    });
  }
}));

// =====================================
// COOKIE OPTIONS
// =====================================

const cookieOpts = {
  httpOnly: true,
  sameSite: "lax",
  secure: config.cookieSecure,
  path: "/api/auth",
  maxAge: config.refreshTtlMs
};

// =====================================
// PUBLIC USER
// =====================================

const pub = (u) => ({
  id: u.id,
  name: u.name,
  email: u.email,
  role: u.role.toLowerCase()
});

// =====================================
// ISSUE TOKENS
// =====================================

async function issue(res, user) {
  const refresh = crypto.randomBytes(48).toString("hex");

  await prisma.refreshToken.create({
    data: {
      tokenHash: hash(refresh),
      userId: user.id,
      expiresAt: new Date(Date.now() + config.refreshTtlMs)
    }
  });

  res.cookie("pg_refresh", refresh, cookieOpts);

  return {
  accessToken: signAccess(user),
  expiresIn: 900,
  user: pub(user)
};
}

// =====================================
// REGISTER
// =====================================

r.post("/register", asyncHandler(async (req, res) => {

  if (!config.allowSelfRegister) {
    throw new ApiError(
      403,
      "REGISTRATION_DISABLED",
      "Self-registration is disabled. Ask an administrator."
    );
  }

  const b = registerSchema.parse(req.body);

  const existingUser = await prisma.user.findUnique({
    where: { email: b.email }
  });

  if (existingUser) {
    throw new ApiError(
      409,
      "EMAIL_EXISTS",
      "An account with this email already exists."
    );
  }

  const user = await prisma.user.create({
    data: {
      name: b.name,
      email: b.email,
      passwordHash: await bcrypt.hash(b.password, 12),
      role: "ANALYST"
    }
  });

  await audit(user.email, "REGISTER", `user:${user.id}`);

  res.status(201).json(await issue(res, user));
}));

// =====================================
// LOGIN
// =====================================

r.post("/login", asyncHandler(async (req, res) => {

  const { email, password } = loginSchema.parse(req.body);

  const user = await prisma.user.findUnique({
    where: { email }
  });

  const ipH = hashIp(req.ip);

  const bad = new ApiError(
    401,
    "INVALID_CREDENTIALS",
    "Incorrect email or password."
  );

  if (!user) {
    await bcrypt.compare(
      password,
      "$2a$12$invalidinvalidinvalidinvalidinvalidinvalidinvalidinvali"
    );

    await audit(email, "LOGIN_FAILED", "unknown-user", {
      ip: ipH
    });

    throw bad;
  }

  if (user.lockedUntil && user.lockedUntil > new Date()) {
    throw new ApiError(
      403,
      "ACCOUNT_LOCKED",
      "Account temporarily locked after repeated failed logins. Try again in 15 minutes."
    );
  }

  if (user.status !== "active") {
    throw new ApiError(
      403,
      "ACCOUNT_SUSPENDED",
      "This account has been suspended."
    );
  }

  if (
    !user.passwordHash ||
    !(await bcrypt.compare(password, user.passwordHash))
  ) {

    const attempts = user.failedAttempts + 1;
    const lock = attempts >= 5;

    await prisma.user.update({
      where: { id: user.id },
      data: {
        failedAttempts: lock ? 0 : attempts,
        lockedUntil: lock
          ? new Date(Date.now() + 15 * 60000)
          : null
      }
    });

    await audit(
      email,
      lock ? "ACCOUNT_LOCKOUT" : "LOGIN_FAILED",
      `user:${user.id}`,
      { ip: ipH, attempts }
    );

    throw bad;
  }

  await prisma.user.update({
    where: { id: user.id },
    data: {
      failedAttempts: 0,
      lockedUntil: null,
      lastLogin: new Date()
    }
  });

  await audit(email, "LOGIN", `user:${user.id}`, {
    ip: ipH
  });

  res.json(await issue(res, user));
}));

// =====================================
// GOOGLE OAUTH - START
// =====================================

r.get("/google", (_req, res) => {

  if (!config.googleClientId || !config.googleClientSecret) {
    throw new ApiError(
      500,
      "GOOGLE_CONFIG_MISSING",
      "Google OAuth credentials are not configured."
    );
  }

  const authUrl = googleClient.generateAuthUrl({
    access_type: "offline",
    prompt: "select_account",
    scope: [
      "openid",
      "email",
      "profile"
    ]
  });

  res.redirect(authUrl);
});

// =====================================
// GOOGLE OAUTH - CALLBACK
// =====================================

r.get("/google/callback", asyncHandler(async (req, res) => {

  const { code, error } = req.query;

  if (error || !code || typeof code !== "string") {
    throw new ApiError(
      401,
      "GOOGLE_AUTH_FAILED",
      "Google login was cancelled or failed."
    );
  }

  // Exchange authorization code

  const { tokens } = await googleClient.getToken(code);

  if (!tokens.id_token) {
    throw new ApiError(
      401,
      "GOOGLE_AUTH_FAILED",
      "Google did not return an ID token."
    );
  }

  // Verify Google identity

  const ticket = await googleClient.verifyIdToken({
    idToken: tokens.id_token,
    audience: config.googleClientId
  });

  const profile = ticket.getPayload();

  if (
    !profile ||
    !profile.email ||
    profile.email_verified !== true
  ) {
    throw new ApiError(
      401,
      "GOOGLE_EMAIL_UNVERIFIED",
      "Google email is not verified."
    );
  }

  const googleId = profile.sub;
  const email = profile.email.toLowerCase();

  // Find existing user

  let user = await prisma.user.findUnique({
    where: { email }
  });

  if (user) {

    if (user.googleId && user.googleId !== googleId) {
      throw new ApiError(
        409,
        "GOOGLE_ACCOUNT_MISMATCH",
        "This email is linked to another Google account."
      );
    }

    if (user.status !== "active") {
      throw new ApiError(
        403,
        "ACCOUNT_SUSPENDED",
        "This account has been suspended."
      );
    }

    // Link Google account to existing user

    user = await prisma.user.update({
      where: { id: user.id },
      data: {
        googleId,
        lastLogin: new Date()
      }
    });

  } else {

    // Create new Google user

    if (!config.allowSelfRegister) {
      throw new ApiError(
        403,
        "REGISTRATION_DISABLED",
        "Self-registration is disabled."
      );
    }

    user = await prisma.user.create({
      data: {
        name: profile.name || email.split("@")[0],
        email,
        googleId,

        passwordHash: await bcrypt.hash(
          crypto.randomBytes(32).toString("hex"),
          12
        ),

        role: "ANALYST",
        lastLogin: new Date()
      }
    });

  }

  // Audit Google login

  await audit(
    email,
    "GOOGLE_LOGIN",
    `user:${user.id}`
  );

  // Generate access token and refresh cookie

  await issue(res, user);

  // Redirect to frontend

  const frontendUrl = config.frontendOrigin;

res.redirect(`${frontendUrl}/?google=success`);

}));

// =====================================
// REFRESH SESSION
// =====================================

r.post("/refresh", asyncHandler(async (req, res) => {

  const token = req.cookies?.pg_refresh || req.body?.refreshToken;

  if (!token) {
    throw new ApiError(
      401,
      "UNAUTHENTICATED",
      "No session."
    );
  }

  const row = await prisma.refreshToken.findUnique({
    where: { tokenHash: hash(token) },
    include: { user: true }
  });

  if (
    !row ||
    row.revoked ||
    row.expiresAt < new Date() ||
    row.user.status !== "active"
  ) {
    throw new ApiError(
      401,
      "INVALID_TOKEN",
      "Session expired. Please sign in again."
    );
  }

  // Rotate refresh token

  await prisma.refreshToken.update({
    where: { id: row.id },
    data: { revoked: true }
  });

  res.json(await issue(res, row.user));

}));

// =====================================
// LOGOUT
// =====================================

r.post("/logout", asyncHandler(async (req, res) => {

  const token = req.cookies?.pg_refresh || req.body?.refreshToken;

  if (token) {

    const row = await prisma.refreshToken.findUnique({
      where: { tokenHash: hash(token) },
      include: { user: true }
    });

    if (row) {

      await prisma.refreshToken.update({
        where: { id: row.id },
        data: { revoked: true }
      });

      await audit(
        row.user.email,
        "LOGOUT",
        `user:${row.userId}`
      );

    }
  }

  res.clearCookie("pg_refresh", {
    path: "/api/auth",
    httpOnly: true,
    sameSite: "lax",
    secure: config.cookieSecure
  });

  res.json({ ok: true });

}));

// =====================================
// CURRENT USER
// =====================================

r.get("/me", authenticate, asyncHandler(async (req, res) => {

  const u = await prisma.user.findUnique({
    where: { id: req.user.id }
  });

  if (!u) {
    throw new ApiError(
      401,
      "UNAUTHENTICATED",
      "Account not found."
    );
  }

  res.json({ user: pub(u) });

}));

// =====================================
// EXPORT ROUTER
// =====================================

export default r;
