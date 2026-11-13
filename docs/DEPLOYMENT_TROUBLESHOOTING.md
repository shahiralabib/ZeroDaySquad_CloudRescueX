# Deployment troubleshooting

## Adapter reports `not_configured`

Check the relevant enable flag, `GOOGLE_CLOUD_PROJECT`, and Cloud Run environment variables. This state is safe and expected for local development.

## Adapter reports `connection_failed`

Check Cloud Run service-account permissions, enabled APIs, Firestore database mode, project ID, and application default credentials. Review structured Cloud Run logs; credentials are intentionally never included in request logs.

## Health or readiness fails

`/health` is a process check. `/ready` checks the configured database connection. Check the `PORT` value, migration startup output, and database configuration.

## Frontend API requests fail

Set `VITE_API_BASE_URL` at frontend image build time to the HTTPS backend URL and set the backend `FRONTEND_ORIGINS` to the exact frontend URL. Rebuild the frontend after changing the build argument.

## Firestore deployment

The Firestore adapter requires Native mode and a service account with Datastore User permissions. Do not deploy with `STORAGE_BACKEND=sqlite` when multiple Cloud Run instances are enabled.
