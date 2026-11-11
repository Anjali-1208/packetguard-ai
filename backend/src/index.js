import http from "http";
import express from "express";
import cors from "cors";
import helmet from "helmet";
import cookieParser from "cookie-parser";
import mongoose from "mongoose";
import { config } from "./config.js";
import { authenticate } from "./middleware/auth.js";
import { errorHandler, notFound } from "./middleware/errors.js";
import authRoutes from "./routes/auth.js";
import alertRoutes from "./routes/alerts.js";
import adminRoutes from "./routes/admin.js";
import { blockrules, stats, threatintel, notifications } from "./routes/misc.js";
import { initSocket } from "./socket.js";
import { startWatcher } from "./services/watcher.js";
import { seed, startRetentionJob } from "./services/seed.js";

const app = express();
app.set("trust proxy", 1);
app.use(helmet());
app.use(cors({ origin: config.frontendOrigin, credentials: true }));
app.use(express.json({ limit: "100kb" }));
app.use(cookieParser());

app.get("/health", (_req, res) => res.json({ status: "ok", mongo: mongoose.connection.readyState === 1 }));
app.use("/api/auth", authRoutes);
app.use("/api/alerts", alertRoutes);
app.use("/api/blockrules", blockrules);
app.use("/api/stats", stats);
app.use("/api/threatintel", threatintel);
app.use("/api/notifications", notifications);
app.use("/api/admin", adminRoutes);
app.use(notFound);
app.use(errorHandler);

const server = http.createServer(app);
app.set("io", initSocket(server));

async function connectMongo() {
  for (let i = 1; ; i++) {
    try { await mongoose.connect(config.mongoUrl, { serverSelectionTimeoutMS: 5000 }); console.log("[db] mongo connected"); return; }
    catch (e) { console.warn(`[db] waiting for mongo (${i}): ${e.message}`); await new Promise((r) => setTimeout(r, 3000)); }
  }
}

if (process.env.NODE_ENV !== "test") {
  server.listen(config.port, () => console.log(`[api] listening on :${config.port}`));
  await connectMongo();
  await seed();
  startWatcher(app.get("io"));
  startRetentionJob();
}
export { app };
