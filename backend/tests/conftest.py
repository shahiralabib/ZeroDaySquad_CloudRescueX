"""Pytest bootstrap that keeps the test run away from the demonstration database.

``app.database`` builds its SQLAlchemy engine at import time from ``DATABASE_URL``
(falling back to ``./cloudrescue.db``). pytest imports this file before any test
module imports ``app``, so the environment is redirected here, at module level,
to a throwaway SQLite file in the system temp directory.

Safeguards:
* Refuse to run if ``app`` was imported before this file (the engine would already
  be bound to whatever database was configured).
* Overwrite ``DATABASE_URL`` unconditionally, so a shell or ``.env`` value pointing at
  the demonstration database cannot leak into a test run.
* Before the first test, verify the live engine really points at the temporary file
  and never at ``cloudrescue.db``; otherwise abort the whole session.
* The schema is created by running the real Alembic migrations against the temporary
  database, so migration drift is caught as well.
"""
from __future__ import annotations

import asyncio
import os
import shutil
import subprocess
import sys
import tempfile
from pathlib import Path

import pytest

BACKEND_DIR = Path(__file__).resolve().parents[1]
DEMO_DATABASE_FILE = BACKEND_DIR / "cloudrescue.db"

if str(BACKEND_DIR) not in sys.path:
    sys.path.insert(0, str(BACKEND_DIR))
if str(Path(__file__).resolve().parent) not in sys.path:
    sys.path.insert(0, str(Path(__file__).resolve().parent))  # lets test modules ``import auth_support``

from auth_support import (  # noqa: E402  (plain constants; imports nothing from ``app``)
    DEFAULT_TEST_USER,
    TEST_AUTH_SECRET,
    TEST_AUTH_USERS_JSON,
    TEST_TOKEN_TTL_MINUTES,
    TEST_USER_ROLES,
)

if "app.config" in sys.modules or "app.database" in sys.modules:
    raise RuntimeError(
        "The 'app' package was imported before tests/conftest.py. Its database engine may already "
        "be bound to a non-test database, so the test session was refused."
    )

_TEST_DB_DIR = Path(tempfile.mkdtemp(prefix="cloudrescuex-tests-")).resolve()
TEST_DATABASE_FILE = _TEST_DB_DIR / "cloudrescue_test.db"
os.environ["DATABASE_URL"] = f"sqlite+aiosqlite:///{TEST_DATABASE_FILE.as_posix()}"


def pytest_report_header(config: pytest.Config) -> list[str]:
    return [
        f"cloudrescue test database: {TEST_DATABASE_FILE}",
        f"cloudrescue demo database (never used by tests): {DEMO_DATABASE_FILE}",
    ]


@pytest.fixture(scope="session", autouse=True)
def isolated_test_database():
    from app.database import engine

    actual = Path(str(engine.url.database)).resolve()
    if engine.url.get_backend_name() != "sqlite" or actual != TEST_DATABASE_FILE:
        pytest.exit(f"Refusing to run: engine points at {engine.url!s}, expected {TEST_DATABASE_FILE}.", returncode=3)
    if actual == DEMO_DATABASE_FILE.resolve() or actual.name == DEMO_DATABASE_FILE.name:
        pytest.exit("Refusing to run: engine points at the demonstration database.", returncode=3)

    migration = subprocess.run(
        [sys.executable, "-m", "alembic", "upgrade", "head"],
        cwd=BACKEND_DIR,
        env=os.environ.copy(),
        capture_output=True,
        text=True,
        timeout=180,
    )
    if migration.returncode != 0:
        pytest.exit(f"Alembic migration of the temporary test database failed:\n{migration.stdout}\n{migration.stderr}", returncode=3)

    # Tests do not run the FastAPI lifespan, so apply the same baseline a started API would have
    # (the demo services). Some tests rely on at least one demo service existing.
    from app.database import seed_demo_data

    async def seed_baseline() -> None:
        await seed_demo_data()
        await engine.dispose()  # hand tests a fresh pool; seeding ran on a short-lived event loop

    asyncio.run(seed_baseline())

    yield TEST_DATABASE_FILE


def pytest_unconfigure(config: pytest.Config) -> None:
    """Remove the temporary database (also after collect-only runs). Only our own mkdtemp directory is touched."""
    database_module = sys.modules.get("app.database")
    if database_module is not None:
        try:
            asyncio.run(database_module.engine.dispose())
        except Exception:  # best effort: only releases file handles before cleanup
            pass
    if _TEST_DB_DIR.parent == Path(tempfile.gettempdir()).resolve() and _TEST_DB_DIR.name.startswith("cloudrescuex-tests-"):
        shutil.rmtree(_TEST_DB_DIR, ignore_errors=True)


# --- authentication for the test suite ---------------------------------------------------------------------------------
#
# Production code requires signed bearer tokens (app/auth.py). So that the existing API tests keep working once routes are
# protected, every test runs with a fixed, test-only authentication configuration, and every ``httpx.AsyncClient`` that
# talks to the application in-process sends a valid ``Authorization: Bearer`` header for ``test-admin`` by default.
#
# Anonymous requests are always explicit:
#   * one request:   ``client.get(url, headers=ANONYMOUS_HEADERS)``    (``from auth_support import ANONYMOUS_HEADERS``)
#   * one client:    ``AsyncClient(..., headers=ANONYMOUS_HEADERS)``
#   * a whole test or module:  ``@pytest.mark.anonymous`` / ``pytestmark = pytest.mark.anonymous``
# A client that sets its own ``Authorization`` header (or ``auth=``) keeps it, and a client for any other application or
# transport is never touched. Other users: ``auth_headers("test-viewer")``.
#
# Nothing here is a fallback for the application: the credentials exist only on the shared settings object, only while a
# test runs (pytest's ``monkeypatch`` restores it), and the application's own defaults stay empty.


def pytest_configure(config: pytest.Config) -> None:
    config.addinivalue_line(
        "markers", "anonymous: in-process HTTP clients created by this test send no Authorization header by default"
    )


class AuthTestHelper:
    """Hands out bearer headers for the fixed test users."""


    def __init__(self) -> None:
        from pydantic import SecretStr

        from app.config import Settings

        # Built from the fixed constants, not from the shared settings object, so a test that temporarily installs a
        # different configuration there still gets tokens for the test users.
        self._settings = Settings(
            _env_file=None,
            auth_secret=SecretStr(TEST_AUTH_SECRET),
            auth_users_json=SecretStr(TEST_AUTH_USERS_JSON),
            auth_token_ttl_minutes=TEST_TOKEN_TTL_MINUTES,
        )

    def headers(self, username: str = DEFAULT_TEST_USER) -> dict[str, str]:
        """``{"Authorization": "Bearer <fresh signed token>"}`` for one of the test users."""
        from app.auth import issue_token, load_auth_config

        if username not in TEST_USER_ROLES:
            raise ValueError(f"{username!r} is not a test user (known: {', '.join(TEST_USER_ROLES)}).")
        config = load_auth_config(self._settings)
        return {"Authorization": f"Bearer {issue_token(config, config.users[username]).token}"}


@pytest.fixture(autouse=True)
def authentication_environment(request: pytest.FixtureRequest, monkeypatch: pytest.MonkeyPatch) -> AuthTestHelper:
    from httpx import ASGITransport, AsyncClient
    from pydantic import SecretStr

    from app import main as main_module
    from app.auth import clear_auth_config_cache
    from app.config import get_settings

    settings = get_settings()
    monkeypatch.setattr(settings, "auth_secret", SecretStr(TEST_AUTH_SECRET))
    monkeypatch.setattr(settings, "auth_users_json", SecretStr(TEST_AUTH_USERS_JSON))
    monkeypatch.setattr(settings, "auth_token_ttl_minutes", TEST_TOKEN_TTL_MINUTES)
    clear_auth_config_cache()

    authentication = AuthTestHelper()
    if request.node.get_closest_marker("anonymous") is None:
        default_headers = authentication.headers(DEFAULT_TEST_USER)
        original_init = AsyncClient.__init__

        def init_with_default_authorization(self, *args, **kwargs):
            original_init(self, *args, **kwargs)
            transport = kwargs.get("transport")
            talks_to_the_application = isinstance(transport, ASGITransport) and transport.app is main_module.app
            if talks_to_the_application and kwargs.get("auth") is None and "authorization" not in self.headers:
                self.headers["Authorization"] = default_headers["Authorization"]

        monkeypatch.setattr(AsyncClient, "__init__", init_with_default_authorization)
    return authentication


@pytest.fixture
def auth_headers(authentication_environment: AuthTestHelper):
    """``auth_headers("test-viewer")`` -> ``{"Authorization": "Bearer ..."}``; defaults to ``test-admin``."""
    return authentication_environment.headers
