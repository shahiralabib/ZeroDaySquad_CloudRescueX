
# Known Limitations

## Authentication and sessions

- Users, roles and password hashes come from the `AUTH_USERS_JSON` environment variable. There is no user database, no sign-up, no password change or reset, no multi-factor authentication and no external identity provider. Changing users or roles means editing the variable and restarting the API.
- Signing out only deletes the token in the browser. There is no server-side session list or revocation: a copied token stays valid until it expires (`AUTH_TOKEN_TTL_MINUTES`, 60 by default) unless the user is removed or `AUTH_SECRET` is changed and the API is restarted. There are no refresh tokens, so users sign in again when a token expires.
- Failed sign-ins are throttled (5 per username and address, 20 per address, in 5 minutes), but the counters are in memory in one process: they reset on restart and are not shared between instances. Behind a hosting proxy the client address is the proxy's unless forwarded headers are trusted (`FORWARDED_ALLOW_IPS`, see [ENVIRONMENT_VARIABLES.md](ENVIRONMENT_VARIABLES.md#hosted-deployment-checklist)); without that, all users share one lockout.
- The stored scrypt cost of a password hash is not checked against a minimum; hashes made with `python -m app.auth hash-password` use the intended cost.
- Authorization is by role only. There is no per-service or per-tenant ownership, and a medium or high risk recovery action can be completed only by the admin who approved it (an operator cannot execute those actions).
- A request whose JSON cannot be read is answered by the framework before the authentication check, so an anonymous caller can see a 422 or 400 for syntactically invalid JSON instead of a 401. No data is returned. Every well-formed request is checked first.
- `GET /api/v1/simulation/status` (a viewer read) creates the baseline simulation record the first time it is called.

## Platform and infrastructure

- Existing operational endpoints primarily use SQLAlchemy directly. The Firestore adapter and repository boundary are implemented, but every route has not yet been migrated to Firestore persistence. SQLite is a single-instance store: a host with an ephemeral filesystem loses all data on redeploy.
- The in-process request rate limiter is not distributed and is unsuitable as the sole abuse control for horizontally scaled deployments.
- Google Gemini, Monitoring, Logging, and Firestore have not been authenticated in this environment because credentials and project access are unavailable.
- Docker image builds could not be executed in this environment because Docker was unavailable on PATH. The `docker-compose.yml` authentication pass-through has not been run.
- No hosted deployment (Render or Cloud Run) was performed or changed as part of the authentication work; its environment must be configured as described in the deployment checklist.

## Simulation

- The local deterministic provider is simulated and must not be presented as genuine Gemini analysis.
- Demo fault injection, health checks, telemetry, threat intelligence and recovery actions are intentionally limited to isolated simulated services and data. No real infrastructure is monitored, attacked or changed.
- Browser smoke testing depends on both local servers being available. The login page and role-based controls were verified through TypeScript, the production build, unit tests of the session rules, and a run of the real API client against a live backend, but not through an automated browser test.
