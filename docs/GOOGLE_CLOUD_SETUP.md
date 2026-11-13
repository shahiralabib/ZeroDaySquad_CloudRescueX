# Google Cloud setup

CloudRescue X remains usable locally with `AI_PROVIDER=local`, `STORAGE_BACKEND=sqlite`, and all Google adapters disabled. A status of `not_configured` is expected until the corresponding flags, project, and credentials are supplied.

## Project and APIs

Create or select a Google Cloud project, enable billing as required by the selected services, and enable:

- Vertex AI / Gemini access required by the configured Gemini API path.
- Cloud Monitoring API.
- Cloud Logging API.
- Firestore in Native mode.
- Cloud Run API and Artifact Registry API for deployment.

For Cloud Run, use a dedicated service account with only the required Monitoring Viewer, Logging Viewer, and Datastore User permissions. Prefer Application Default Credentials on Cloud Run; do not put service-account JSON in the frontend or repository.

## Environment

Set these backend variables through Cloud Run secrets/environment configuration:

```text
ENVIRONMENT=production
FRONTEND_ORIGINS=https://your-frontend.example
GOOGLE_CLOUD_PROJECT=your-project-id
CLOUD_MONITORING_ENABLED=true
CLOUD_LOGGING_ENABLED=true
FIRESTORE_ENABLED=true
STORAGE_BACKEND=firestore
FIRESTORE_DATABASE=(default)
```

Gemini additionally requires `AI_PROVIDER=gemini`, `GEMINI_API_KEY`, and a verified `GEMINI_MODEL`. The `/api/v1/ai/status` response is not connected until `/api/v1/ai/test` succeeds.

## Local verification

Without credentials, use `GET /api/v1/integrations/status`. Each adapter reports `not_configured`, `connection_failed`, or `connected`; no configured flag alone is treated as a successful connection.
