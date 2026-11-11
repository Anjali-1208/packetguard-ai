import { Server } from "socket.io";
import { config } from "./config.js";
import { verifyToken } from "./middleware/auth.js";
import { summary } from "./services/stats.js";

let io = null; let timer = null; let pending = false;

export function initSocket(httpServer) {
  io = new Server(httpServer, { cors: { origin: config.frontendOrigin, credentials: true } });
  // WebSocket auth: same JWT, verified at the handshake before any subscription (FR-AUTH-09)
  io.use((socket, next) => {
    try { const p = verifyToken(socket.handshake.auth?.token); socket.data.user = { id: p.userId, role: p.role }; next(); }
    catch { next(new Error("unauthorized")); }
  });
  io.on("connection", (socket) => {
    socket.join(`user:${socket.data.user.id}`);
    socket.on("join-room", () => socket.join(`user:${socket.data.user.id}`)); // server derives the user from the JWT, never from the client payload
  });
  return io;
}
export const getIo = () => io;

/** stats-updated is debounced to at most one emit per second. */
export function emitStatsDebounced() {
  if (!io) return;
  if (timer) { pending = true; return; }
  const fire = async () => {
    try { const s = await summary(); io.emit("stats-updated", { bySeverity: s.bySeverity, byStatus: s.byStatus }); } catch {}
    timer = null; if (pending) { pending = false; timer = setTimeout(fire, 1000); }
  };
  timer = setTimeout(fire, 1000);
}
