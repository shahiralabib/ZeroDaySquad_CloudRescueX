# Environment variables

## Backend

| Variable | Local default | Purpose |
|---|---|---|
| `DATABASE_URL` | SQLite URL | Local SQLAlchemy database (relative paths resolve against the working directory). Use a dedicated file for demos. Ignored by automated tests, which always use a temporary database. |
| `OPERATING_MODE` | `DEMO` | `DEMO` keeps all providers local; `LIVE` permits configured external adapters |
| `PORT` | `8000` locally / Cloud Run supplied | HTTP listen port |
| `FRONTEND_ORIGINS` | Local origins | Exact allowed CORS origins |
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
| `RATE_LIMIT_PER_MINUTE` | `120` | Per-process request limit |

## Frontend

`VITE_API_BASE_URL` is a build-time public backend URL. It must never contain credentials. `VITE_DEMO_ADMIN_TOKEN` is supported only for the local prototype and must not be used as production authentication.
