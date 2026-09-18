import { useState } from "react";
import { Navigate, useNavigate } from "react-router-dom";
import { Shield } from "lucide-react";
import api from "../services/api";
import { connectSocket } from "../services/socket";
import { useAuth } from "../context/useAuth";

export default function Login() {
  const navigate = useNavigate();
  const { signIn } = useAuth();
  const [username, setUsername] = useState(""); const [password, setPassword] = useState(""); const [error, setError] = useState(""); const [busy, setBusy] = useState(false);
  if (sessionStorage.getItem("sentinelx_token")) return <Navigate to="/" replace />;
  const login = async (event) => { event.preventDefault(); setError(""); try { setBusy(true); const response = await api.post("/auth/login", { username, password }); signIn(response.data.user, response.data.token); connectSocket(); navigate("/"); } catch (requestError) { setError(requestError.response?.data?.message || "Unable to sign in"); } finally { setBusy(false); } };
  return <main className="flex min-h-screen items-center justify-center bg-slate-950 p-4"><form onSubmit={login} className="w-full max-w-md rounded-2xl border border-slate-800 bg-slate-900/70 p-7 shadow-2xl shadow-cyan-950/20"><div className="mb-7 text-center"><div className="mx-auto flex h-12 w-12 items-center justify-center rounded-xl bg-cyan-500/10 text-cyan-400"><Shield /></div><h1 className="mt-4 text-2xl font-bold text-white">SentinelX IDPS</h1><p className="mt-2 text-sm text-slate-500">Sign in to the security operations console.</p></div>{error && <p className="mb-4 rounded-lg border border-rose-500/30 bg-rose-500/10 p-3 text-sm text-rose-300">{error}</p>}<label className="block text-sm text-slate-300">Username<input autoComplete="username" value={username} onChange={(event) => setUsername(event.target.value)} className="mt-2 w-full rounded-xl border border-slate-700 bg-slate-950 px-3 py-2.5 text-white outline-none focus:border-cyan-500" required /></label><label className="mt-4 block text-sm text-slate-300">Password<input type="password" autoComplete="current-password" value={password} onChange={(event) => setPassword(event.target.value)} className="mt-2 w-full rounded-xl border border-slate-700 bg-slate-950 px-3 py-2.5 text-white outline-none focus:border-cyan-500" required /></label><button disabled={busy} className="mt-6 w-full rounded-xl bg-cyan-500 py-3 text-sm font-semibold text-slate-950 hover:bg-cyan-400 disabled:opacity-60">{busy ? "Signing in..." : "Sign in"}</button></form></main>;
}
