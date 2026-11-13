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
- Protected demo fault injection/reset using the local `X-Demo-Admin-Token`.
- Provider-independent AI investigation with strict Pydantic output validation.
- Deterministic `local_deterministic` investigation provider with visible simulated status.
- Credential-gated Gemini provider using the official `google-genai` SDK, bounded timeout/retry handling, and authenticated status testing.
- Deterministic demo-only recovery policy, execution, independent verification, escalation, audit, and dashboard notifications.
- Persistent local infrastructure simulation with synthetic telemetry for web, database, authentication, firewall, and VPN resources.

Useful endpoints:

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

For a reproducible setup, copy `.env.example` to `.env`, keep `AI_PROVIDER=local`, and do not add credentials to the repository. The default local administrator token is intended only for the isolated demo.

## Environment variables

Backend settings include `DATABASE_URL`, `FRONTEND_ORIGINS`, `AI_PROVIDER`, `GEMINI_API_KEY`, `GEMINI_MODEL`, `GOOGLE_CLOUD_PROJECT`, `CLOUD_MONITORING_ENABLED`, `CLOUD_LOGGING_ENABLED`, `FIRESTORE_ENABLED`, `STORAGE_BACKEND`, `REQUEST_MAX_BODY_BYTES`, and `RATE_LIMIT_PER_MINUTE`. Frontend builds may use `VITE_API_BASE_URL`; it must contain no credentials.

See the complete [environment variable reference](docs/ENVIRONMENT_VARIABLES.md).

## Validation

```powershell
cd backend
.\.venv\Scripts\Activate.ps1
pytest
cd ..\frontend
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

Use [docs/DEPLOYMENT_GUIDE.md](docs/DEPLOYMENT_GUIDE.md). Cloud Run must use managed persistent storage rather than SQLite, exact production CORS origins, secret-managed credentials, and real authentication/RBAC before public exposure.

## Known limitations

See [docs/KNOWN_LIMITATIONS.md](docs/KNOWN_LIMITATIONS.md). In particular, the prototype administrator token is not production identity management, the Firestore repository boundary is not yet wired through every existing SQLAlchemy route, and real Google integrations require credentials and authenticated tests.
