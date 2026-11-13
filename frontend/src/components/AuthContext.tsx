import { createContext, useCallback, useContext, useEffect, useMemo, useState, type ReactNode } from "react";
import { fetchMe, login as requestLogin, ApiError } from "../lib/api";
import { can as roleCan, clearSession, expiryFrom, expiryTimerDelay, endSession, isRole, onSessionEnded, restoreSession, startSession, type Permission, type SessionEndReason } from "../lib/auth";
import type { AuthUser } from "../types";

type AuthState =
  | { status: "checking" }
  | { status: "anonymous"; notice: string | null }
  | { status: "authenticated"; user: AuthUser }
  | { status: "error"; message: string };

type AuthContextValue = {
  state: AuthState;
  /** The signed-in user, from the server's answer to GET /auth/me; null until a session has been confirmed. */
  user: AuthUser | null;
  login: (username: string, password: string) => Promise<void>;
  logout: () => void;
  /** Check the stored session again after a failure that was not a rejection (for example the API was unreachable). */
  retry: () => void;
  /** Whether the interface should offer an action. The API still enforces it. */
  can: (permission: Permission) => boolean;
};

const ENDED_NOTICE: Record<SessionEndReason, string> = {
  expired: "Your session has expired. Sign in again.",
  rejected: "Your session is no longer valid. Sign in again.",
};

const AuthContext = createContext<AuthContextValue | null>(null);

/** Confirm who the server says the token belongs to. Anything unexpected is treated as no session. */
async function confirmedUser(): Promise<AuthUser> {
  const me = await fetchMe();
  if (typeof me?.username !== "string" || !me.username || !isRole(me.role)) throw new Error("The server returned an unusable identity.");
  return { username: me.username, role: me.role };
}

export function AuthProvider({ children }: { children: ReactNode }) {
  const [state, setState] = useState<AuthState>({ status: "checking" });
  const [attempt, setAttempt] = useState(0);

  // Restore a session after a page load (or retry after a failed check).
  useEffect(() => {
    let active = true;
    if (!restoreSession()) {
      setState({ status: "anonymous", notice: null });
      return;
    }
    setState({ status: "checking" });
    confirmedUser()
      .then((user) => { if (active) setState({ status: "authenticated", user }); })
      .catch((reason: unknown) => {
        if (!active) return;
        if (reason instanceof ApiError && reason.status === 401) return; // the client already ended the session; the listener below shows the notice
        // Anything else (API unreachable, 503, rate limited) says nothing about the token: keep it and offer a retry.
        setState({ status: "error", message: reason instanceof ApiError ? reason.message : "Your session could not be verified." });
      });
    return () => { active = false; };
  }, [attempt]);

  // The API refused the token, or it ran out: leave the application and go back to the sign-in page.
  useEffect(() => onSessionEnded((reason) => setState({ status: "anonymous", notice: ENDED_NOTICE[reason] })), []);

  // End the session at the moment it expires, even if the user is not clicking anything.
  const signedIn = state.status === "authenticated";
  useEffect(() => {
    if (!signedIn) return;
    const timer = window.setTimeout(() => endSession("expired"), expiryTimerDelay());
    return () => window.clearTimeout(timer);
  }, [signedIn]);

  const login = useCallback(async (username: string, password: string) => {
    const response = await requestLogin(username, password);
    const expiresAt = expiryFrom(response);
    if (expiresAt === null || typeof response.access_token !== "string") throw new Error("The server returned an unusable session.");
    startSession(response.access_token, expiresAt);
    try {
      setState({ status: "authenticated", user: await confirmedUser() });
    } catch (reason) {
      clearSession();
      throw reason instanceof ApiError ? reason : new Error("Your account could not be verified. Try again.");
    }
  }, []);

  const logout = useCallback(() => {
    clearSession();
    setState({ status: "anonymous", notice: "You have been signed out." });
  }, []);

  const retry = useCallback(() => setAttempt((count) => count + 1), []);

  const value = useMemo<AuthContextValue>(() => {
    const user = state.status === "authenticated" ? state.user : null;
    return { state, user, login, logout, retry, can: (permission) => roleCan(user?.role, permission) };
  }, [state, login, logout, retry]);

  return <AuthContext.Provider value={value}>{children}</AuthContext.Provider>;
}

export function useAuth(): AuthContextValue {
  const value = useContext(AuthContext);
  if (!value) throw new Error("useAuth must be used inside AuthProvider.");
  return value;
}
