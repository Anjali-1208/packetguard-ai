import { defineConfig } from "vite";
import react from "@vitejs/plugin-react";
const target = process.env.VITE_API_TARGET || "http://localhost:5000";
export default defineConfig({
  plugins: [react()],
  server: { port: 3000, proxy: { "/api": target, "/socket.io": { target, ws: true } } },
});
