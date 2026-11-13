import { useState, type FormEvent } from "react";
import { ShieldCheck } from "lucide-react";
import { useAuth } from "../components/AuthContext";

export function Login() {
  const { state, login } = useAuth();
  const notice = state.status === "anonymous" ? state.notice : null;
  const [username, setUsername] = useState("");
  const [password, setPassword] = useState("");
  const [busy, setBusy] = useState(false);
  const [error, setError] = useState("");

  const submit = async (event: FormEvent) => {
    event.preventDefault();
    if (busy) return;
    setBusy(true);
    setError("");
    try {
      await login(username, password);
    } catch (reason) {
      // The message comes from the API client and never contains the password or a token.
      setError((reason as Error).message || "Sign-in failed. Try again.");
      setPassword("");
      setBusy(false);
    }
  };

  return (
    <div className="flex min-h-screen items-center justify-center bg-navy p-6 text-slate-200">
      <form onSubmit={submit} className="w-full max-w-sm space-y-5 rounded-xl border border-slate-800 bg-panel p-7" aria-labelledby="login-title">
        <div className="flex items-center gap-3">
          <div className="grid h-10 w-10 place-items-center rounded-lg bg-cyan/10 text-cyan"><ShieldCheck size={20} /></div>
          <div><h1 id="login-title" className="text-lg font-semibold tracking-tight">CloudRescue<span className="text-cyan">X</span></h1><p className="text-[11px] tracking-widest text-slate-500">SECURITY OPERATIONS</p></div>
        </div>
        <p className="text-sm text-slate-400">Sign in to view and manage incidents.</p>
        {notice && !error && <p role="status" className="rounded-lg border border-amber-900/60 bg-amber-950/20 p-3 text-sm text-amber-300">{notice}</p>}
        {error && <p role="alert" className="rounded-lg border border-red-900/60 bg-red-950/20 p-3 text-sm text-red-300">{error}</p>}
        <label className="block text-sm"><span className="text-slate-400">Username</span><input value={username} onChange={(event) => setUsername(event.target.value)} autoComplete="username" autoCapitalize="none" spellCheck={false} autoFocus required maxLength={256} className="mt-1 w-full rounded-lg border border-slate-700 bg-slate-900 px-3 py-2 text-sm outline-none focus:border-cyan" /></label>
        <label className="block text-sm"><span className="text-slate-400">Password</span><input type="password" value={password} onChange={(event) => setPassword(event.target.value)} autoComplete="current-password" required maxLength={256} className="mt-1 w-full rounded-lg border border-slate-700 bg-slate-900 px-3 py-2 text-sm outline-none focus:border-cyan" /></label>
        <button type="submit" disabled={busy || !username.trim() || !password} className="w-full rounded-lg bg-cyan px-3 py-2 text-sm font-medium text-slate-950 disabled:opacity-40">{busy ? "Signing in…" : "Sign in"}</button>
      </form>
    </div>
  );
}
