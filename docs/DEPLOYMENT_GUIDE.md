# Deployment Guide

## Local Windows PowerShell

Set up authentication first (see the [README](../README.md#authentication-and-roles)); without it the dashboard shows the sign-in page but nobody can sign in.

```powershell
# Run from the project root (the folder that contains docker-compose.yml)
Copy-Item .env.example .env
cd backend
py -3.12 -m venv .venv
.\.venv\Scripts\Activate.ps1
python -m pip install -r requirements.txt
alembic upgrade head
uvicorn app.main:app --reload --port 8000
```

In another PowerShell window:

```powershell
cd frontend   # from the project root
npm install
npm run dev
```

## Docker

Docker must be installed and available on PATH:

```powershell
# Run from the project root (the folder that contains docker-compose.yml)
docker compose up --build
```

The backend listens on `PORT` and runs migrations before Uvicorn. The frontend image supports the build-time `VITE_API_BASE_URL` argument.

## Cloud Run preparation

1. Enable Cloud Run, Artifact Registry, Firestore, Cloud Monitoring, and Cloud Logging APIs.
2. Create Firestore in the deployment project.
3. Use a least-privilege service account and Secret Manager for Gemini/API secrets.
4. Build and deploy the backend using the commands in [CLOUD_RUN_DEPLOYMENT.md](CLOUD_RUN_DEPLOYMENT.md).
5. Set `STORAGE_BACKEND=firestore`, `FIRESTORE_ENABLED=true`, the exact `GOOGLE_CLOUD_PROJECT`, and exact HTTPS `FRONTEND_ORIGINS`.
6. Build the frontend with `--build-arg VITE_API_BASE_URL=https://YOUR_BACKEND_URL`.
7. Verify `/health`, `/ready`, and `/api/v1/integrations/status`.

## Authentication in every deployment

Sign-in does not work until the host provides `AUTH_SECRET` and `AUTH_USERS_JSON` (and, for the browser to reach the API, `FRONTEND_ORIGINS` and the frontend build variable `VITE_API_BASE_URL`). Generate the secret and the password hashes as described in the [README](../README.md#authentication-and-roles), store them in the host's secret manager, and follow the [hosted deployment checklist](ENVIRONMENT_VARIABLES.md#hosted-deployment-checklist). The previous shared `local-demo-admin` token no longer exists. An external identity provider and distributed rate limiting are still required before unrestricted public use.
