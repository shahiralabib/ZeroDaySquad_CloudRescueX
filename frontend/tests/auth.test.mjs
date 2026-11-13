// Unit tests for the session and permission rules (src/lib/auth.ts) and the build guard. Run with `npm test`.
// They use Node's built-in test runner, which runs the TypeScript source directly, so no extra packages are needed.
import assert from "node:assert/strict";
import { beforeEach, test } from "node:test";
import {
  can,
  clearSession,
  executeBlockedReason,
  expiryFrom,
  expiryTimerDelay,
  getToken,
  isCurrentToken,
  onSessionEnded,
  PERMISSIONS,
  restoreSession,
  roleAtLeast,
  SESSION_STORAGE_KEY,
  startSession,
} from "../src/lib/auth.ts";
import { suspiciousViteVariables } from "../scripts/check-env.mjs";

const TOKEN = "eyJ2IjoxfQ.signature_part-123";

function fakeStorage(initial = {}) {
  const data = new Map(Object.entries(initial));
  return {
    data,
    getItem: (key) => (data.has(key) ? data.get(key) : null),
    setItem: (key, value) => void data.set(key, String(value)),
    removeItem: (key) => void data.delete(key),
  };
}

let store;
beforeEach(() => {
  store = fakeStorage();
  clearSession(store);
});

// --- roles ------------------------------------------------------------------------------------------------------------

test("roles are ordered viewer < operator < admin and unknown roles never qualify", () => {
  assert.equal(roleAtLeast("viewer", "viewer"), true);
  assert.equal(roleAtLeast("viewer", "operator"), false);
  assert.equal(roleAtLeast("operator", "viewer"), true);
  assert.equal(roleAtLeast("operator", "admin"), false);
  assert.equal(roleAtLeast("admin", "operator"), true);
  for (const unknown of [undefined, null, "", "root", "ADMIN", 3, {}]) assert.equal(roleAtLeast(unknown, "viewer"), false);
});

test("each action needs the same role the API requires", () => {
  const table = {
    viewer: [],
    operator: ["runInvestigation", "runHealthCheck", "executeRecovery", "retryRecovery", "acknowledgeEscalation", "viewIntegrations"],
    admin: ["approveRecovery", "rejectRecovery", "controlSimulation", "injectFault"],
  };
  for (const [role, permissions] of Object.entries(table)) for (const permission of permissions) assert.equal(PERMISSIONS[permission], role);
  assert.equal(Object.keys(PERMISSIONS).length, table.operator.length + table.admin.length);
  for (const permission of Object.keys(PERMISSIONS)) {
    assert.equal(can("viewer", permission), false);
    assert.equal(can("admin", permission), true);
    assert.equal(can(undefined, permission), false);
  }
  assert.equal(can("operator", "runInvestigation"), true);
  assert.equal(can("operator", "approveRecovery"), false);
});

test("medium and high risk recovery can only be executed by an administrator", () => {
  assert.equal(executeBlockedReason("operator", "low"), undefined);
  assert.equal(executeBlockedReason("admin", "high"), undefined);
  assert.match(executeBlockedReason("operator", "high"), /same administrator/);
  assert.match(executeBlockedReason("operator", "medium"), /same administrator/);
  assert.match(executeBlockedReason("viewer", "low"), /operator/);
});

// --- session ----------------------------------------------------------------------------------------------------------

test("a session lives in sessionStorage and keeps only the token and its expiry", () => {
  const expiresAt = Date.now() + 60_000;
  startSession(TOKEN, expiresAt, store);
  assert.deepEqual(JSON.parse(store.getItem(SESSION_STORAGE_KEY)), { token: TOKEN, expiresAt });
  assert.equal(getToken(), TOKEN);
});

test("a stored session is restored after a reload, and the identity is never stored", () => {
  startSession(TOKEN, Date.now() + 60_000, store);
  clearSession(fakeStorage()); // a new page load: memory is empty, storage still holds the session
  store.setItem(SESSION_STORAGE_KEY, JSON.stringify({ token: TOKEN, expiresAt: Date.now() + 60_000, role: "admin", username: "mallory" }));
  assert.equal(restoreSession(Date.now(), store), true);
  assert.equal(getToken(), TOKEN);
  const stored = Object.keys(JSON.parse(store.getItem(SESSION_STORAGE_KEY)));
  assert.ok(stored.includes("token") && stored.includes("expiresAt"));
});

test("an expired, malformed or tampered stored session is discarded", () => {
  const cases = [
    JSON.stringify({ token: TOKEN, expiresAt: Date.now() - 1 }),
    JSON.stringify({ token: TOKEN }),
    JSON.stringify({ token: 12345, expiresAt: Date.now() + 60_000 }),
    JSON.stringify({ token: "has spaces and\nnewlines", expiresAt: Date.now() + 60_000 }),
    JSON.stringify({ token: "x".repeat(5000), expiresAt: Date.now() + 60_000 }),
    JSON.stringify({ token: TOKEN, expiresAt: "soon" }),
    "not json",
    "null",
    "[]",
  ];
  for (const raw of cases) {
    const local = fakeStorage({ [SESSION_STORAGE_KEY]: raw });
    assert.equal(restoreSession(Date.now(), local), false, raw);
    assert.equal(local.getItem(SESSION_STORAGE_KEY), null, "invalid data is removed");
    assert.equal(getToken(), null);
  }
});

test("nothing is restored when there is nothing stored or storage is unavailable", () => {
  assert.equal(restoreSession(Date.now(), store), false);
  assert.equal(restoreSession(Date.now(), null), false);
  const broken = { getItem: () => { throw new Error("blocked"); }, setItem: () => { throw new Error("blocked"); }, removeItem: () => { throw new Error("blocked"); } };
  assert.equal(restoreSession(Date.now(), broken), false);
  startSession(TOKEN, Date.now() + 60_000, broken); // still works for this page load
  assert.equal(getToken(), TOKEN);
});

test("clearing the session removes the token from memory and storage", () => {
  startSession(TOKEN, Date.now() + 60_000, store);
  clearSession(store);
  assert.equal(getToken(), null);
  assert.equal(store.getItem(SESSION_STORAGE_KEY), null);
  assert.equal(store.data.size, 0);
});

test("a token that has expired is not sent: asking for it ends the session", () => {
  const reasons = [];
  const stop = onSessionEnded((reason) => reasons.push(reason));
  startSession(TOKEN, 1_000, store);
  assert.equal(getToken(999), TOKEN);
  assert.equal(getToken(1_000), null);
  assert.deepEqual(reasons, ["expired"]);
  assert.equal(getToken(0), null, "the session is gone, not merely hidden");
  stop();
});

test("only the current token can be recognised, so a late answer for an old token cannot end a new session", () => {
  startSession(TOKEN, Date.now() + 60_000, store);
  assert.equal(isCurrentToken(TOKEN), true);
  assert.equal(isCurrentToken("an.older.token"), false);
  clearSession(store);
  assert.equal(isCurrentToken(TOKEN), false);
});

test("a login response that carries no usable token or lifetime is refused", () => {
  assert.throws(() => startSession("", Date.now() + 1000, store));
  assert.throws(() => startSession("bad token", Date.now() + 1000, store));
  assert.throws(() => startSession(TOKEN, Number.NaN, store));
  assert.equal(getToken(), null);
});

test("the expiry comes from expires_in (immune to a wrong clock) or else expires_at", () => {
  assert.equal(expiryFrom({ expires_in: 3600, expires_at: 1 }, 1_000_000), 1_000_000 + 3_600_000);
  assert.equal(expiryFrom({ expires_at: 2_000 }, 1_000_000), 2_000_000);
  assert.equal(expiryFrom({ expires_at: 1 }, 1_000_000), null, "already in the past");
  for (const bad of [{}, { expires_in: 0 }, { expires_in: -5 }, { expires_in: "3600" }, { expires_in: Number.NaN }, { expires_at: "soon" }]) assert.equal(expiryFrom(bad, 1_000_000), null);
});

test("the expiry timer never exceeds what setTimeout accepts", () => {
  startSession(TOKEN, Date.now() + 60 * 24 * 3600 * 1000, store);
  assert.equal(expiryTimerDelay(), 2_147_483_647);
});

test("the module never touches localStorage", () => {
  const touched = [];
  globalThis.localStorage = new Proxy({}, { get: (_, key) => { touched.push(String(key)); return () => null; } });
  try {
    startSession(TOKEN, Date.now() + 60_000, store);
    restoreSession(Date.now(), store);
    clearSession(store);
  } finally {
    delete globalThis.localStorage;
  }
  assert.deepEqual(touched, []);
});

// --- build guard ------------------------------------------------------------------------------------------------------

test("the build guard rejects VITE_ variables that look like secrets and accepts the public API address", () => {
  assert.deepEqual(suspiciousViteVariables({ VITE_API_BASE_URL: "http://localhost:8000", PATH: "x" }), []);
  assert.deepEqual(suspiciousViteVariables({ VITE_DEMO_ADMIN_TOKEN: "x", VITE_GEMINI_API_KEY: "y", VITE_API_BASE_URL: "z" }), ["VITE_DEMO_ADMIN_TOKEN", "VITE_GEMINI_API_KEY"]);
  assert.deepEqual(suspiciousViteVariables({ DEMO_ADMIN_TOKEN: "backend only" }), [], "only VITE_ names reach the bundle");
  assert.deepEqual(suspiciousViteVariables({}, ["VITE_API_BASE_URL=http://x\r\nVITE_APP_SECRET=abc\n# VITE_OLD_PASSWORD=zzz\nexport VITE_SERVICE_PASSWORD = q"]), ["VITE_APP_SECRET", "VITE_SERVICE_PASSWORD"]);
});
