"""Test-only authentication constants, shared by ``conftest.py`` and the test modules.

Everything here exists for the test suite alone. The secret, the users and the password are fixed, public values that
protect nothing: they are installed on the shared settings object by the ``authentication_environment`` fixture for the
length of each test and are never read by the application otherwise. The application has no built-in credentials; with
no ``AUTH_SECRET`` and ``AUTH_USERS_JSON`` configured it answers 503 on the authentication routes.

This module must stay free of imports from ``app``: ``conftest.py`` imports it before the application is loaded.
"""
from __future__ import annotations

import json

TEST_AUTH_SECRET = "test-suite-only-signing-secret-0123456789-abcdef"
TEST_PASSWORD = "test-only-password-for-the-suite"
# scrypt at the lowest accepted cost (N=1024) so that tests which log in stay fast. Made from TEST_PASSWORD.
TEST_PASSWORD_HASH = "scrypt$1024$8$1$md_TfFoyQlvjIntFw92nbw$XxdZRYfIpIQ41Q-mKlzhn_7_gT8s7NZFQWokI0CVnaE"

DEFAULT_TEST_USER = "test-admin"
TEST_USER_ROLES = {"test-admin": "admin", "test-operator": "operator", "test-viewer": "viewer"}
TEST_AUTH_USERS_JSON = json.dumps(
    [{"username": name, "role": role, "password_hash": TEST_PASSWORD_HASH} for name, role in TEST_USER_ROLES.items()]
)
TEST_TOKEN_TTL_MINUTES = 60

# Pass as ``headers=`` on one request to make that request anonymous even though the client is authenticated by default.
# An empty ``Authorization`` header overrides the client's default header and is rejected as "no credentials".
# For a whole test, use ``@pytest.mark.anonymous`` instead; for a whole client, pass ``headers=ANONYMOUS_HEADERS``.
ANONYMOUS_HEADERS = {"Authorization": ""}
