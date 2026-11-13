# CloudRescue X

CloudRescue X is an AI-assisted cloud service resilience platform. Phase 2 provides a local-first FastAPI/SQLite monitoring and incident-management backend with a React/Vite operations dashboard. Seeded records and demo fault scenarios are simulated demonstration data and do not represent real infrastructure.

## Overview

CloudRescue X is a local-first, AI-assisted cloud service resilience prototype. It monitors an isolated demo service, creates persistent incidents from observed health checks, investigates evidence with a deterministic local provider or credential-gated Gemini, validates recovery through deterministic policy, executes only catalogued demo actions, independently verifies restoration, and escalates unresolved incidents.

The local application is suitable for a controlled hackathon demonstration. Google Cloud adapters are implemented but remain explicitly `not_configured` until authenticated requests succeed.

## Architecture and technology

- Backend: FastAPI, Pydantic Settings, SQLAlchemy async, SQLite, Alembic
- Frontend: React, TypeScript, Vite, Tailwind CSS, React Router
- AI: provider abstraction with deterministic local analysis and official Google Gen AI integration
- Integrations: credential-gated Monitoring, Logging, and Firestore adapters
- Deployment: separate Docker containers for FastAPI and Nginx frontend, prepared for Cloud Run

See [the architecture proposal](docs/ARCHITECTURE.md), [the demo script](docs/DEMO_SCRIPT.md), and [the deployment guide](docs/DEPLOYMENT_GUIDE.md).

## Features

- Service registration, configuration, status, thresholds, and health-check history.
- Automatic background monitoring after application startup with graceful shutdown.
- Persistent failure observations, thresholded incident detection, duplicate prevention, and recovery resolution.
- Explicit incident state transitions and append-only incident timelines.
- Isolated demo scenarios: `healthy`, `service_unavailable`, `configuration_failure`, and `dependency_unavailable`.
- Signed-in access with three roles (viewer, operator, admin): every API route has an explicit access policy (see [Authentication and roles](#authentication-and-roles)).
- Admin-only demo fault injection/reset, restricted to isolated simulated services.
- Provider-independent AI investigation with strict Pydantic output validation.
- Deterministic `local_deterministic` investigation provider with visible simulated status.
- Credential-gated Gemini provider using the official `google-genai` SDK, bounded timeout/retry handling, and authenticated status testing.
- Deterministic demo-only recovery policy, execution, independent verification, escalation, audit, and dashboard notifications.
- Persistent local infrastructure simulation with synthetic telemetry for web, database, authentication, firewall, and VPN resources.

Useful endpoints (all of them except `/health`, `/ready` and `POST /api/v1/auth/login` need a signed-in user; the complete role-by-role list is in [docs/API_SPECIFICATION.md](docs/API_SPECIFICATION.md#9-implemented-route-access-matrix)):

- `POST /api/v1/auth/login`
- `GET /api/v1/auth/me`
- `GET /api/v1/services`
- `GET /api/v1/services/{service_id}/health`
- `GET /api/v1/incidents`
- `GET /api/v1/incidents/{incident_id}/timeline`
- `GET /api/v1/dashboard/stats`
- `GET /api/v1/demo/scenarios`
- `POST /api/v1/demo/services/{service_id}/fault`
- `POST /api/v1/demo/services/{service_id}/reset`
- `GET /api/v1/ai/status`
- `POST /api/v1/incidents/{incident_id}/investigations`
- `GET /api/v1/recovery/actions`
- `GET /api/v1/escalations`
- `GET /api/v1/notifications`
- `GET /api/v1/simulation/resources`
- `GET /api/v1/simulation/events`
- `GET /api/v1/simulation/status`
- `POST /api/v1/simulation/start`
- `POST /api/v1/simulation/stop`
- `POST /api/v1/simulation/reset`

Simulation endpoints use only SQLite-persisted synthetic data. Events include `source=local_simulation` and `simulated=true`; they are not observations from live infrastructure.

## Local setup

### Backend

```powershell
cd backend
py -3.12 -m venv .venv
.\.venv\Scripts\Activate.ps1
python -m pip install -r requirements.txt
uvicorn app.main:app --reload --port 8000
```

On a new checkout or database, apply the schema before starting the API:

```powershell
$env:PYTHONPATH="."
alembic upgrade head
```

#### Dedicated demonstration database

The API and Alembic both read `DATABASE_URL`. To keep a presentation separate from any other data, point it at its own file, create the schema once, and start the API from the same shell:

```powershell
cd backend
$env:DATABASE_URL="sqlite+aiosqlite:///./cloudrescue_demo.db"
$env:PYTHONPATH="."
alembic upgrade head
uvicorn app.main:app --port 8000
```

The API logs `Database in use: sqlite file <absolute path>` at startup, warns if that file does not exist yet, and reports the database file name in `/health` and `/ready`. Nothing is created, reset, or overwritten automatically; the default remains `./cloudrescue.db`. `*.db` files are git-ignored.

### Frontend

```powershell
cd frontend
npm install
npm run dev
```

Open http://localhost:5173. The backend health endpoint is http://localhost:8000/health and the readiness endpoint is http://localhost:8000/ready.

For a reproducible setup, copy `.env.example` to `.env`, keep `AI_PROVIDER=local`, and do not add credentials to the repository. Nobody can sign in until authentication is configured: see the next section.

## Authentication and roles

The API uses signed bearer tokens. Users are defined by the server (`AUTH_USERS_JSON`) and sign in on the dashboard with a username and password. There are no default users, no default password and no shared admin token: until `AUTH_SECRET` and `AUTH_USERS_JSON` are set, login and every protected route answer `503 AUTH_NOT_CONFIGURED`. Only `GET /health`, `GET /ready` and `POST /api/v1/auth/login` (and, in the local, demo and test environments, the API docs) are public.

### Configure authentication (local)

Run these from the `backend` folder with the virtual environment active. The commands prompt for passwords instead of taking them on the command line, so nothing secret ends up in your shell history.

```powershell
# 1. A random signing secret for AUTH_SECRET (keep it private; do not commit it)
python -m app.auth generate-secret

# 2. One JSON entry per user: you are prompted for the password twice (at least 12 characters)
python -m app.auth hash-password --username alice --role admin
python -m app.auth hash-password --username olivia --role operator
python -m app.auth hash-password --username vera --role viewer
```

Each `hash-password` call prints one JSON object such as `{"username":"alice","role":"admin","password_hash":"scrypt$..."}`. Put all the objects into one JSON array and set the variables in the shell that starts the API (or in a `.env` file in the folder the API starts from, normally `backend/`, with the JSON in single quotes):

```powershell
$env:AUTH_SECRET = "<output of generate-secret>"
$env:AUTH_USERS_JSON = '[<entry 1>,<entry 2>,<entry 3>]'
uvicorn app.main:app --port 8000
```

Roles, usernames (lowercase `a-z 0-9 . _ -`, 3 to 64 characters) and the optional `AUTH_TOKEN_TTL_MINUTES` are described in the [environment variable reference](docs/ENVIRONMENT_VARIABLES.md#authentication). The configuration is read once when the API starts, so adding a user, removing a user, changing a role or changing the secret takes effect after a restart.

### Roles

Roles are cumulative: an admin can do everything an operator can, and an operator everything a viewer can. The server checks the role on every request from its own configuration; the dashboard only hides or disables controls the role cannot use.

| Role | Can do |
|---|---|
| **viewer** | Read everything in the dashboard: overview, services, incidents, timelines, investigations, recovery and verification history, escalations, notifications, simulation telemetry, AI provider status. |
| **operator** | Everything a viewer can, plus: run health checks, run investigations, mark an incident under investigation, acknowledge escalations, execute low-risk recovery actions, retry a safe recovery, and view cloud integration status. |
| **admin** | Everything an operator can, plus: register and edit services, control the simulation (start, tick, stop, reset), inject and reset demo faults, test the AI provider, change an incident's state by hand, approve and reject recovery actions, and execute medium and high risk actions. |

A medium or high risk recovery action needs a one-time approval by an admin, and the approval can only be used by the user who gave it. In practice an admin approves and then executes it; an operator cannot execute those actions.

### Sessions and signing out

- A login returns a token that lasts `AUTH_TOKEN_TTL_MINUTES` (60 by default). There is no refresh: when it runs out the dashboard returns to the sign-in page.
- The dashboard keeps the token in the browser tab's `sessionStorage` (never `localStorage`), so a refresh keeps you signed in and closing the tab signs you out. The username and role are always taken from the server (`GET /api/v1/auth/me`), never from stored data.
- **Sign out only forgets the token in the browser.** The server keeps no session list, so a copied token stays valid until it expires. To cut off a user or revoke every token immediately, remove the user from `AUTH_USERS_JSON` or change `AUTH_SECRET`, and restart the API.
- Failed sign-ins are rate limited (5 per username and address, 20 per address, in 5 minutes). The counters live in memory in one process and reset on restart.

## What is simulated and what is real

| Area | Status |
|---|---|
| Authentication, roles, audit records | Real: scrypt password hashes, HMAC-signed tokens, server-side role checks on every route, audit entries naming the signed-in user. |
| Monitored services, faults, health checks | Simulated: faults are injected into isolated demo services and the health checks read that state. No real service is probed in `DEMO` mode. |
| Infrastructure telemetry, threat intelligence | Simulated: deterministic synthetic events and an offline sample dataset, all labelled `simulated`. |
| Recovery actions and verification | Simulated effects on demo data. The workflow is real: policy checks, one-time approvals, execution records and independent verification checks run as described. |
| AI investigation | `local_deterministic` is a simulated, rule-based provider and is labelled as such. The Gemini provider is implemented and credential-gated but has not been run against a live project here. |
| Google Cloud Monitoring, Logging, Firestore | Adapters exist and report `not_configured` until an authenticated request succeeds. Nothing is read from or written to Google Cloud by default. |
| Storage | SQLite on one instance. Not suitable as the production source of truth. |

## Environment variables

Backend settings include `AUTH_SECRET`, `AUTH_USERS_JSON`, `AUTH_TOKEN_TTL_MINUTES`, `DATABASE_URL`, `FRONTEND_ORIGINS`, `AI_PROVIDER`, `GEMINI_API_KEY`, `GEMINI_MODEL`, `GOOGLE_CLOUD_PROJECT`, `CLOUD_MONITORING_ENABLED`, `CLOUD_LOGGING_ENABLED`, `FIRESTORE_ENABLED`, `STORAGE_BACKEND`, `REQUEST_MAX_BODY_BYTES`, and `RATE_LIMIT_PER_MINUTE`. Frontend builds use only `VITE_API_BASE_URL`, the public API address; the build fails if a `VITE_` variable that looks like a secret is set. The frontend holds no secrets or tokens of its own.

See the complete [environment variable reference](docs/ENVIRONMENT_VARIABLES.md).

## Validation

```powershell
cd backend
.\.venv\Scripts\Activate.ps1
pytest
cd ..\frontend
npm test
npx tsc --noEmit
npm run build
```

`backend/tests/conftest.py` redirects every test run to a temporary SQLite database in the system temp directory, applies the Alembic migrations to it, and deletes it afterwards. Tests never read `DATABASE_URL` or `.env` and refuse to run if the engine would point at `cloudrescue.db`.

The audit test report is in [docs/TEST_REPORT.md](docs/TEST_REPORT.md). Browser checks require both local servers to be running.

## Demo walkthrough

Follow [docs/DEMO_SCRIPT.md](docs/DEMO_SCRIPT.md) for the healthy-to-failure-to-investigation-to-recovery workflow and the policy-rejection escalation path.

## Docker

```powershell
docker compose up --build
```

Alembic is included in the backend dependencies. Apply migrations after installing dependencies with:

```powershell
cd backend
.\.venv\Scripts\Activate.ps1
$env:PYTHONPATH="."
alembic upgrade head
```

## Deployment

Use [docs/DEPLOYMENT_GUIDE.md](docs/DEPLOYMENT_GUIDE.md). Cloud Run must use managed persistent storage rather than SQLite, exact production CORS origins and secret-managed credentials (including `AUTH_SECRET` and `AUTH_USERS_JSON`). The required authentication variables are listed in [docs/ENVIRONMENT_VARIABLES.md](docs/ENVIRONMENT_VARIABLES.md#hosted-deployment-checklist).

## Known limitations

See [docs/KNOWN_LIMITATIONS.md](docs/KNOWN_LIMITATIONS.md). In particular, users are defined in an environment variable rather than an identity provider, sign-out does not revoke a token, the Firestore repository boundary is not yet wired through every existing SQLAlchemy route, and real Google integrations require credentials and authenticated tests.
