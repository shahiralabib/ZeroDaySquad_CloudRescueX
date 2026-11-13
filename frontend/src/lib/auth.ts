// Session and permission helpers for the signed bearer-token authentication of the API.
//
// This module is deliberately free of React, `fetch` and `import.meta`, so the rules below can be unit tested with
// `npm test` and so it can never log or display a credential.
//
// What is kept, and where:
//   * The access token and its expiry time are held in memory and mirrored to `sessionStorage` (never `localStorage`), so
//     a page refresh restores the session and closing the tab ends it. Nothing else is stored: the username and role are
//     NOT kept, because anything in browser storage can be edited. They are read from `GET /api/v1/auth/me` each time the
//     session is restored, and that answer comes from the server's configuration.
//   * The stored expiry only saves a pointless request; the server decides whether a token is valid.
//
// Role checks in this file (`can`, `roleAtLeast`) only decide what the interface offers. The API enforces every one of
// them again, so hiding or disabling a control is a convenience and not a security boundary.

export type Role = "viewer" | "operator" | "admin";

const ROLE_RANK: Record<Role, number> = { viewer: 1, operator: 2, admin: 3 };

export function isRole(value: unknown): value is Role {
  return value === "viewer" || value === "operator" || value === "admin";
}

/** True if `actual` is at least as privileged as `minimum`. An unknown or missing role is never allowed. */
export function roleAtLeast(actual: unknown, minimum: Role): boolean {
  return isRole(actual) && ROLE_RANK[actual] >= ROLE_RANK[minimum];
}

/** The lowest role the API accepts for each action the interface can offer. Mirrors the backend access policy. */
export const PERMISSIONS = {
  runInvestigation: "operator",
  runHealthCheck: "operator",
  executeRecovery: "operator",
  retryRecovery: "operator",
  acknowledgeEscalation: "operator",
  viewIntegrations: "operator",
  approveRecovery: "admin",
  rejectRecovery: "admin",
  controlSimulation: "admin",
  injectFault: "admin",
} as const satisfies Record<string, Role>;

export type Permission = keyof typeof PERMISSIONS;

export function can(role: unknown, permission: Permission): boolean {
  return roleAtLeast(role, PERMISSIONS[permission]);
}

/** Why a control is unavailable, for tooltips. */
export function permissionHint(permission: Permission): string {
  return PERMISSIONS[permission] === "admin" ? "Requires the administrator role." : "Requires the operator or administrator role.";
}

/** Medium and high risk recovery actions need an administrator's approval, used by the same administrator who gave it. */
export function executeBlockedReason(role: unknown, risk: string): string | undefined {
  if (!can(role, "executeRecovery")) return permissionHint("executeRecovery");
  if (risk !== "low" && role !== "admin") return "Medium and high risk actions must be approved and executed by the same administrator.";
  return undefined;
}

// --- session ---------------------------------------------------------------------------------------------------------

export const SESSION_STORAGE_KEY = "cloudrescuex.session";
const MAX_TOKEN_LENGTH = 4096;
const TOKEN_PATTERN = /^[A-Za-z0-9._~+/=-]+$/;
const MAX_TIMER_MS = 2_147_483_647; // setTimeout's limit

export type StorageLike = Pick<Storage, "getItem" | "setItem" | "removeItem">;
export type SessionEndReason = "expired" | "rejected";

let token: string | null = null;
let expiresAt = 0;
const listeners = new Set<(reason: SessionEndReason) => void>();

/** The browser's sessionStorage, or null when it is unavailable (for example blocked by the browser). */
export function defaultStorage(): StorageLike | null {
  try {
    return typeof sessionStorage === "undefined" ? null : sessionStorage;
  } catch {
    return null;
  }
}

function isUsableToken(value: unknown): value is string {
  return typeof value === "string" && value.length > 0 && value.length <= MAX_TOKEN_LENGTH && TOKEN_PATTERN.test(value);
}

/** The session expiry (milliseconds since the epoch) for a login response, or null if it carries no usable lifetime.
 *  `expires_in` is relative and so is immune to a wrong clock on this computer; `expires_at` is the fallback. */
export function expiryFrom(response: { expires_in?: unknown; expires_at?: unknown }, now: number = Date.now()): number | null {
  const lifetime = response.expires_in;
  if (typeof lifetime === "number" && Number.isFinite(lifetime) && lifetime > 0) return now + lifetime * 1000;
  const absolute = response.expires_at;
  if (typeof absolute === "number" && Number.isFinite(absolute) && absolute * 1000 > now) return absolute * 1000;
  return null;
}

/** Begin a session after a successful login. */
export function startSession(accessToken: string, expiresAtMs: number, store: StorageLike | null = defaultStorage()): void {
  if (!isUsableToken(accessToken) || !Number.isFinite(expiresAtMs)) throw new Error("The server returned an unusable session.");
  token = accessToken;
  expiresAt = expiresAtMs;
  try {
    store?.setItem(SESSION_STORAGE_KEY, JSON.stringify({ token: accessToken, expiresAt: expiresAtMs }));
  } catch {
    /* storage full or blocked: the session still works until the page is reloaded */
  }
}

/** Load a session stored by an earlier page load. Returns false (and removes anything stored) if there is no valid one. */
export function restoreSession(now: number = Date.now(), store: StorageLike | null = defaultStorage()): boolean {
  let stored: unknown = null;
  try {
    const raw = store?.getItem(SESSION_STORAGE_KEY);
    stored = raw ? JSON.parse(raw) : null;
  } catch {
    stored = null;
  }
  const record = stored as { token?: unknown; expiresAt?: unknown } | null;
  if (record && isUsableToken(record.token) && typeof record.expiresAt === "number" && Number.isFinite(record.expiresAt) && record.expiresAt > now) {
    token = record.token;
    expiresAt = record.expiresAt;
    return true;
  }
  clearSession(store);
  return false;
}

/** Forget the session in memory and in storage. */
export function clearSession(store: StorageLike | null = defaultStorage()): void {
  token = null;
  expiresAt = 0;
  try {
    store?.removeItem(SESSION_STORAGE_KEY);
  } catch {
    /* nothing to remove */
  }
}

/** The token to send with a request, or null when there is no session or it has run out (which also ends it). */
export function getToken(now: number = Date.now()): string | null {
  if (token !== null && now >= expiresAt) {
    endSession("expired");
    return null;
  }
  return token;
}

/** Milliseconds until the session expires (0 when there is none). */
export function msUntilExpiry(now: number = Date.now()): number {
  return token === null ? 0 : Math.max(0, expiresAt - now);
}

/** The delay to hand to `setTimeout` for the expiry (it cannot take more than about 24 days). */
export function expiryTimerDelay(now: number = Date.now()): number {
  return Math.min(msUntilExpiry(now), MAX_TIMER_MS);
}

export function onSessionEnded(listener: (reason: SessionEndReason) => void): () => void {
  listeners.add(listener);
  return () => listeners.delete(listener);
}

/** The session is over (it ran out, or the server no longer accepts the token): forget it and tell the application. */
export function endSession(reason: SessionEndReason, store: StorageLike | null = defaultStorage()): void {
  clearSession(store);
  for (const listener of [...listeners]) listener(reason);
}

/** True if `sentToken` is still the current session's token (a late answer for an old token must not end a new session). */
export function isCurrentToken(sentToken: string): boolean {
  return token === sentToken;
}
