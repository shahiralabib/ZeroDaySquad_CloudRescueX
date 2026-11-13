// Build guard: the frontend bundle is public, so it must never be built with a secret.
//
// Vite copies every VITE_* variable (from the environment and from .env files in this folder) into the JavaScript that is
// served to every visitor. This script fails the build if one of them looks like a credential. The only configuration
// the frontend needs is VITE_API_BASE_URL, which is a public address.
import { existsSync, readdirSync, readFileSync } from "node:fs";
import { dirname, join } from "node:path";
import { fileURLToPath } from "node:url";

const SECRET_NAME = /(TOKEN|SECRET|KEY|PASSWORD|PASSWD|CREDENTIAL)/i;

/** Names of VITE_* variables that look like secrets, from an environment object and from .env-style file contents. */
export function suspiciousViteVariables(environment, fileContents = []) {
  const names = new Set();
  for (const name of Object.keys(environment)) if (name.startsWith("VITE_") && SECRET_NAME.test(name)) names.add(name);
  for (const content of fileContents) {
    for (const line of content.split(/\r?\n/)) {
      const match = /^\s*(?:export\s+)?(VITE_[A-Za-z0-9_]*)\s*=\s*(.*)$/.exec(line);
      if (match && SECRET_NAME.test(match[1])) names.add(match[1]);
    }
  }
  return [...names].sort();
}

function envFileContents(folder) {
  if (!existsSync(folder)) return [];
  return readdirSync(folder)
    .filter((name) => name === ".env" || name.startsWith(".env."))
    .map((name) => readFileSync(join(folder, name), "utf8"));
}

if (process.argv[1] && fileURLToPath(import.meta.url) === process.argv[1]) {
  const folder = dirname(dirname(fileURLToPath(import.meta.url)));
  const found = suspiciousViteVariables(process.env, envFileContents(folder));
  if (found.length > 0) {
    console.error(`Refusing to build: ${found.join(", ")} would be embedded in the public JavaScript bundle.`);
    console.error("The frontend holds no secrets. Users sign in with a username and password and receive a short-lived token.");
    process.exit(1);
  }
}
