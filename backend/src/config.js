const env = process.env;
export const config = {
  port: Number(env.PORT || 5000),
  mongoUrl: env.MONGO_URL || "mongodb://localhost:27017/packetguard?directConnection=true",
  jwtSecret: env.JWT_SECRET || "dev-only-secret-change-me",
  accessTtl: env.ACCESS_TOKEN_TTL || "15m",
  refreshTtlMs: 7 * 24 * 3600 * 1000,
  cookieSecure: env.COOKIE_SECURE === "true",
  frontendOrigin: env.FRONTEND_ORIGIN || true, // true = reflect request origin (same-origin via nginx in compose)
  allowSelfRegister: env.ALLOW_SELF_REGISTER !== "false",
  seedDemoUsers: env.SEED_DEMO_USERS !== "false",
  mlUrl: env.ML_URL || "http://ml-service:8000",
  snifferUrl: env.SNIFFER_URL || "http://sniffer:8001",
  abuseIpdbKey: env.ABUSEIPDB_API_KEY || "",
  slackWebhook: env.SLACK_WEBHOOK_URL || "",
  smtp: { host: env.SMTP_HOST || "", port: Number(env.SMTP_PORT || 587), user: env.SMTP_USER || "", pass: env.SMTP_PASS || "", to: env.ALERT_EMAIL_TO || "", from: env.ALERT_EMAIL_FROM || "packetguard@localhost" },
  authRateLimit: Number(env.AUTH_RATE_LIMIT || 100),
};
if (config.jwtSecret === "dev-only-secret-change-me") console.warn("[warn] JWT_SECRET not set - using an insecure development secret");
