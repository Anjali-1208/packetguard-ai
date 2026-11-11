import React, { createContext, useContext, useEffect, useRef, useState, useCallback } from "react";
import { io } from "socket.io-client";
import { api, getToken, refreshSession, setAuthLostHandler, setToken } from "./api.js";

const Ctx = createContext(null);
export const useAuth = () => useContext(Ctx);

export function AuthProvider({ children }) {
  const [user, setUser] = useState(null);
  const [ready, setReady] = useState(false);
  const [socket, setSocket] = useState(null);
  const [connected, setConnected] = useState(false);
  const sockRef = useRef(null);

  const openSocket = useCallback(() => {
    sockRef.current?.disconnect();
    const s = io({ auth: (cb) => cb({ token: getToken() }), transports: ["websocket", "polling"] });
    s.on("connect", () => setConnected(true)); s.on("disconnect", () => setConnected(false));
    s.on("connect_error", async (err) => { if (err.message === "unauthorized") { const d = await refreshSession(); if (d) s.connect(); } });
    sockRef.current = s; setSocket(s);
  }, []);

  const logout = useCallback(async (silent) => {
    try { if (!silent) await api("/auth/logout", { method: "POST", body: {} }); } catch {}
    setToken(null); setUser(null); sockRef.current?.disconnect(); setSocket(null); setConnected(false);
  }, []);

  const establish = useCallback((d) => { setToken(d.accessToken); setUser(d.user); openSocket(); }, [openSocket]);

  useEffect(() => {
    setAuthLostHandler(() => logout(true));
    refreshSession().then((d) => { if (d) establish(d); }).finally(() => setReady(true));
  }, []); // eslint-disable-line

  // proactively renew the 15-minute access token (held in memory only, never localStorage)
  useEffect(() => {
    if (!user) return;
    const t = setInterval(async () => { const d = await refreshSession(); if (!d) logout(true); }, 12 * 60 * 1000);
    return () => clearInterval(t);
  }, [user, logout]);

  const login = async (email, password) => establish(await api("/auth/login", { method: "POST", body: { email, password } }));
  const register = async (name, email, password) => establish(await api("/auth/register", { method: "POST", body: { name, email, password } }));

  return <Ctx.Provider value={{ user, ready, socket, connected, login, register, logout }}>{children}</Ctx.Provider>;
}
