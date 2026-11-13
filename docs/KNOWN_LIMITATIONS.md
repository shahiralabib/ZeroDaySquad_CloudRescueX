# Known Limitations

- The local administrator mechanism is a shared `X-Demo-Admin-Token`, not production identity, role-based access control, or re-authentication.
- Non-local environments reject the default `local-demo-admin` value, but a real authentication provider is still required before public deployment.
- Existing operational endpoints primarily use SQLAlchemy directly. The Firestore adapter and repository boundary are implemented, but every route has not yet been migrated to Firestore persistence.
- The in-process rate limiter is not distributed and is unsuitable as the sole abuse control for horizontally scaled Cloud Run.
- Google Gemini, Monitoring, Logging, and Firestore have not been authenticated in this environment because credentials and project access are unavailable.
- Docker image builds could not be executed in this environment because Docker was unavailable on PATH.
- The local deterministic provider is simulated and must not be presented as genuine Gemini analysis.
- Demo fault injection and recovery actions are intentionally limited to isolated simulated services.
- Browser smoke testing depends on both local servers being available.
