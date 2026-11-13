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
