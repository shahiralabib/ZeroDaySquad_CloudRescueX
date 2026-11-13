# Cloud Run deployment

The backend and frontend are separate containers. Cloud Run instances are stateless, so production persistence must use the Firestore adapter; SQLite is for local development only.

## Build and deploy

From PowerShell at the repository root:

```powershell
gcloud auth login
gcloud config set project YOUR_PROJECT_ID
gcloud builds submit --tag REGION-docker.pkg.dev/YOUR_PROJECT_ID/cloudrescue/cloudrescue-backend ./backend
gcloud run deploy cloudrescue-backend `
  --image REGION-docker.pkg.dev/YOUR_PROJECT_ID/cloudrescue/cloudrescue-backend `
  --region REGION `
  --allow-unauthenticated `
  --set-env-vars "ENVIRONMENT=production,STORAGE_BACKEND=firestore,FIRESTORE_ENABLED=true,CLOUD_MONITORING_ENABLED=true,CLOUD_LOGGING_ENABLED=true,GOOGLE_CLOUD_PROJECT=YOUR_PROJECT_ID,FRONTEND_ORIGINS=https://YOUR_FRONTEND_URL"
```

Deploy the frontend with the backend URL injected at build time:

```powershell
docker build --build-arg VITE_API_BASE_URL=https://YOUR_BACKEND_URL ./frontend
gcloud builds submit --tag REGION-docker.pkg.dev/YOUR_PROJECT_ID/cloudrescue/cloudrescue-frontend ./frontend
gcloud run deploy cloudrescue-frontend --image REGION-docker.pkg.dev/YOUR_PROJECT_ID/cloudrescue/cloudrescue-frontend --region REGION --allow-unauthenticated
```

The backend honors Cloud Run's `PORT` environment variable and exposes `/health` and `/ready`. Do not use a local SQLite volume or in-memory state as the production source of truth.

## HTTPS and access

Cloud Run provides HTTPS endpoints. Restrict `FRONTEND_ORIGINS` to the exact deployed frontend origin. Provide `AUTH_SECRET` and `AUTH_USERS_JSON` from Secret Manager (for example with `--set-secrets`) so users can sign in; without them every protected route answers 503. See the [hosted deployment checklist](ENVIRONMENT_VARIABLES.md#hosted-deployment-checklist). An external identity provider is still advisable before unrestricted public exposure.
