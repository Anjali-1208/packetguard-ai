import React, { useState } from "react";
import { useAuth } from "../auth.jsx";
import { Err } from "../components/ui.jsx";

export default function Login() {
  const { login, register } = useAuth();
  const [mode, setMode] = useState("login");
  const [f, setF] = useState({ name: "", email: "", password: "" });
  const [err, setErr] = useState(""); const [busy, setBusy] = useState(false);
  const set = (k) => (e) => setF({ ...f, [k]: e.target.value });

  const submit = async (e) => {
    e.preventDefault(); setErr(""); setBusy(true);
    try { mode === "login" ? await login(f.email, f.password) : await register(f.name, f.email, f.password); }
    catch (x) { setErr(x.message); } finally { setBusy(false); }
  };
  const fill = (email, password) => setF({ ...f, email, password });

  return (
    <div className="login">
      <div className="login-hero">
        <div className="radar"><i /><i /><i /></div>
        <h1>PacketGuard<span>AI</span></h1>
        <p>Hybrid, explainable intrusion detection. The model recommends; <b>you</b> decide.</p>
      </div>
      <form className="card login-form" onSubmit={submit}>
        <h2>{mode === "login" ? "Sign in" : "Create analyst account"}</h2>
        {mode === "register" && <label>Name<input value={f.name} onChange={set("name")} required minLength={2} /></label>}
        <label>Email<input type="email" value={f.email} onChange={set("email")} required autoFocus /></label>
        <label>Password<input type="password" value={f.password} onChange={set("password")} required />
          {mode === "register" && <small>8+ characters with upper-case, lower-case and a number.</small>}</label>
        <Err msg={err} />
        <button className="primary" disabled={busy}>{busy ? "Please wait…" : mode === "login" ? "Sign in" : "Create account"}</button>
        <button type="button" className="link-btn" onClick={() => { setMode(mode === "login" ? "register" : "login"); setErr(""); }}>
          {mode === "login" ? "Need an account? Register" : "Have an account? Sign in"}</button>
        {mode === "login" && <div className="demo"><span>Demo accounts</span>
          <button type="button" onClick={() => fill("analyst@packetguard.local", "Analyst123")}>Analyst</button>
          <button type="button" onClick={() => fill("admin@packetguard.local", "Admin123")}>Admin</button></div>}
      </form>
    </div>
  );
}
