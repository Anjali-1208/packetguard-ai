
import { defineConfig } from "vite";
import react from "@vitejs/plugin-react";

const target = "http://127.0.0.1:5000";

export default defineConfig({
  plugins: [react()],

  server: {
    host: "localhost",
    port: 3001,
    strictPort: true,

    proxy: {
      "/api": {
        target,
        changeOrigin: true,
        secure: false
      },

      "/socket.io": {
        target,
        changeOrigin: true,
        ws: true
      }
    }
  }
});
