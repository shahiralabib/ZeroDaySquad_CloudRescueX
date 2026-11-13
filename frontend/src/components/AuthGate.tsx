import type { ReactNode } from "react";
import { ShieldCheck } from "lucide-react";
import { Login } from "../pages/Login";
import { useAuth } from "./AuthContext";

function Centered({ children }: { children: ReactNode }) {
  return <div className="flex min-h-screen items-center justify-center bg-navy p-6 text-slate-200"><div className="w-full max-w-sm rounded-xl border border-slate-800 bg-panel p-6 text-center"><div className="mx-auto mb-4 grid h-10 w-10 place-items-center rounded-lg bg-cyan/10 text-cyan"><ShieldCheck size={20} /></div>{children}</div></div>;
}

/** Nothing of the application (no layout, no page, no API call) is rendered until the server has confirmed the session. */
export function AuthGate({ children }: { children: ReactNode }) {
  const { state, logout, retry } = useAuth();
  if (state.status === "checking") return <Centered><p role="status" className="text-sm text-slate-400">Verifying your session…</p></Centered>;
  if (state.status === "anonymous") return <Login />;
  if (state.status === "error") {
    return <Centered><p role="alert" className="text-sm text-red-300">{state.message}</p><div className="mt-4 flex justify-center gap-2"><button onClick={retry} className="rounded-lg bg-cyan px-3 py-2 text-xs font-medium text-slate-950">Try again</button><button onClick={logout} className="rounded-lg border border-slate-700 px-3 py-2 text-xs text-slate-300">Sign out</button></div></Centered>;
  }
  return <>{children}</>;
}
