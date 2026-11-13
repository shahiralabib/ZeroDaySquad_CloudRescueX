# Environment variables

## Backend

| Variable | Local default | Purpose |
|---|---|---|
| `AUTH_SECRET` | empty (**required**) | Signing key for access tokens. See [Authentication](#authentication). |
| `AUTH_USERS_JSON` | empty (**required**) | The users, their roles and password hashes. See [Authentication](#authentication). |
| `AUTH_TOKEN_TTL_MINUTES` | `60` | Access token lifetime, 5 to 720 minutes. |
| `ENVIRONMENT` | `local` | `local`, `demo` and `test` serve the interactive API docs (`/docs`, `/redoc`, `/openapi.json`, public and read-only); any other value (for example `production`) does not serve them at all. |
| `DATABASE_URL` | SQLite URL | Local SQLAlchemy database (relative paths resolve against the working directory). Use a dedicated file for demos. Ignored by automated tests, which always use a temporary database. |
| `OPERATING_MODE` | `DEMO` | `DEMO` keeps all providers local; `LIVE` permits configured external adapters |
| `PORT` | `8000` locally / host supplied | HTTP listen port |
| `FRONTEND_ORIGINS` | Local origins | Exact allowed CORS origins, comma separated, no trailing slash |
| `AI_PROVIDER` | `local` | `local` or credential-gated `gemini` |
| `GEMINI_API_KEY` | empty | Server-only Gemini credential |
| `GEMINI_MODEL` | empty | Explicit verified Gemini model |
| `GOOGLE_CLOUD_PROJECT` | empty | Google Cloud project |
| `CLOUD_MONITORING_ENABLED` | `false` | Enable Monitoring adapter |
| `CLOUD_LOGGING_ENABLED` | `false` | Enable Logging adapter |
| `FIRESTORE_ENABLED` | `false` | Enable Firestore adapter |
| `STORAGE_BACKEND` | `sqlite` | `sqlite` locally or `firestore` for deployment |
| `FIRESTORE_DATABASE` | `(default)` | Firestore database name |
| `REQUEST_MAX_BODY_BYTES` | `1048576` | Request size limit |
| `RATE_LIMIT_PER_MINUTE` | `120` | Per-process request limit per client address |
| `FORWARDED_ALLOW_IPS` | uvicorn default (`127.0.0.1`) | Read by uvicorn, not by the application. Which proxy addresses may supply the real client address. See the [hosted checklist](#hosted-deployment-checklist). |

There is no `DEMO_ADMIN_TOKEN` in use. The shared `X-Demo-Admin-Token` header and the `VITE_DEMO_ADMIN_TOKEN` frontend variable no longer exist: the API ignores that header, and the frontend build refuses to run if a secret-looking `VITE_` variable is set. Remove them from any old `.env` file or hosting dashboard.

## Authentication

Authentication is configured only through the three variables below. Nothing has a usable default: with `AUTH_SECRET` or `AUTH_USERS_JSON` missing or invalid, login and every protected route answer `503 AUTH_NOT_CONFIGURED`, and the reason is written once to the API log (`Authentication is unavailable (...)`, never including a secret). The values are read once when the API starts; after any change, restart it.

### `AUTH_SECRET`

The key the API uses to sign and check access tokens. Requirements: at least 32 characters, at least 10 different characters, no leading or trailing whitespace. Anyone who has it can create valid tokens for any configured user, so treat it like a password: keep it in the host's secret store or your shell, never in the repository, a screenshot or a chat. Changing it invalidates every token that was issued.

Generate one (from `backend/`, virtual environment active):

```powershell
python -m app.auth generate-secret
```

### `AUTH_USERS_JSON`

A JSON array with one object per user, each with exactly these three keys:

```json
[{"username":"<name>","role":"<viewer|operator|admin>","password_hash":"<output of hash-password>"}]
```

- `username`: lowercase letters, digits, `.`, `_`, `-`; 3 to 64 characters; starts with a letter or digit. At most 50 users. Names are unique. Sign-in is not case sensitive, and only plain ASCII is accepted.
- `role`: `viewer`, `operator` or `admin` (see the roles table in the [README](../README.md#roles)). The server looks the role up here on every request, so a role claimed by a client or written in a token is never trusted.
- `password_hash`: a scrypt hash, never a password. Create it with the command below. Passwords must be at least 12 characters.

Create one entry per user. The command asks for the password twice without echoing it, and the password is never printed or stored:

```powershell
python -m app.auth hash-password --username alice --role admin
```

Combine the printed objects into one array. In PowerShell, wrap the whole value in single quotes (the hashes contain `$`):

```powershell
$env:AUTH_USERS_JSON = '[{"username":"...","role":"...","password_hash":"..."},{...}]'
```

Do not put real hashes or passwords in documentation, example files, tickets or the repository. A hash is not a password, but anyone holding it can try to crack it offline. To remove a user or change a role or password, edit the array and restart the API.

### `AUTH_TOKEN_TTL_MINUTES`

How long a token lasts after sign-in: 5 to 720 minutes, default `60`. Tokens cannot be refreshed; when one expires the user signs in again. Lowering the value also rejects older, longer-lived tokens after the next restart.

### Session and sign-out limits

- Signing out in the dashboard only deletes the token from the browser tab. The server keeps no list of sessions and has no revocation, so a token that was copied stays valid until it expires.
- To cut access immediately: remove the user from `AUTH_USERS_JSON` (that user's tokens are rejected) or change `AUTH_SECRET` (every token is rejected), then restart the API.
- Failed sign-in counters (5 per username and address, 20 per address, in 5 minutes) are kept in memory in one process. They reset on restart and are not shared between instances.
- The address used for those counters and for `RATE_LIMIT_PER_MINUTE` is the one the web server reports. Behind a hosting proxy that is the proxy's address unless forwarded headers are trusted (see below), which would make all users share one limit.

## Frontend

`VITE_API_BASE_URL` is the only variable the frontend uses. It is a build-time, public backend URL (for example `https://<your-api-host>`, with no trailing slash and no credentials). If it is unset the app calls port 8000 on the page's own host, which only suits local development.

The frontend contains no secrets, keys, tokens or shared passwords. `npm run build` stops with an error if any `VITE_` variable (in the environment or a `.env*` file in `frontend/`) has a name containing `TOKEN`, `SECRET`, `KEY`, `PASSWORD`, `PASSWD` or `CREDENTIAL`, because Vite copies those into the public JavaScript.

## Hosted deployment checklist

For a deployment such as Render, Cloud Run or any other host. Nothing here is configured by this repository; set it in the host's dashboard or secret manager and do not assume an existing deployment already has it.

**Backend service, required for sign-in to work**

| Variable | Value |
|---|---|
| `AUTH_SECRET` | A newly generated secret (host secret store). |
| `AUTH_USERS_JSON` | The user array on a single line. Paste the raw JSON as the value, without extra surrounding quotes. If your platform expands `$` in values, the hashes need that escaped. |

**Backend service, required for the dashboard to reach the API**

| Variable | Value |
|---|---|
| `FRONTEND_ORIGINS` | The exact HTTPS origin of the deployed frontend, for example `https://<your-frontend-host>` (no path, no trailing slash). The API otherwise rejects the browser's requests. |
| `PORT` | Supplied by most hosts (Render sets it); the backend container listens on it. |

**Backend service, recommended**

| Variable | Value |
|---|---|
| `AUTH_TOKEN_TTL_MINUTES` | Optional; default `60`. |
| `FORWARDED_ALLOW_IPS` | `*` on a host where every request arrives through its own proxy (as on Render). Without it, all visitors appear to come from the proxy: they share one sign-in lockout (20 failed attempts lock everyone out for 5 minutes) and one `RATE_LIMIT_PER_MINUTE` budget. Never use `*` if the API can also be reached directly, because clients could then forge their address. Not tested on Render in this project. |
| `RATE_LIMIT_PER_MINUTE` | Raise it (for example `600`) if several people use the dashboard at once; its pages poll the API. |
| `ENVIRONMENT` | `production` (or `demo`). `production` also turns the API docs off. |
| `DATABASE_URL` | SQLite is the default. A host with an ephemeral filesystem loses it, and every incident, on each redeploy unless a persistent disk is attached. |

**Frontend build**

| Variable / setting | Value |
|---|---|
| `VITE_API_BASE_URL` | The backend's public HTTPS URL, set as a build-time variable (a Docker build argument or a static-site build environment variable). |
| Single-page-app rewrite | A static host must rewrite every path to `/index.html` (on Render: a rewrite rule `/*` to `/index.html`), or a browser refresh on a page such as `/incidents` returns 404. The provided `nginx.conf` already does this. |

**Not needed, remove if present:** `DEMO_ADMIN_TOKEN`, `VITE_DEMO_ADMIN_TOKEN`.

After deploying, check: `GET /health` returns 200; `POST /api/v1/auth/login` with a wrong password returns 401 (a 503 means the authentication variables are missing or invalid, and the log says which); signing in on the dashboard shows the right username and role.
