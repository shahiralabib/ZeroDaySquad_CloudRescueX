"""B3 stage 3: the authenticated test fixtures themselves (conftest.py and auth_support.py).

These tests pin down how a test gets an authenticated client by default, how it makes an anonymous request on purpose,
and that the fixture credentials exist only for tests. They use ``GET /api/v1/auth/me`` because it is the one route that
already requires a bearer token and reports who the caller is.
"""
import httpx
import pytest
from httpx import ASGITransport, AsyncClient

from app.auth import AuthConfig, Role, TokenError, authenticate_token, load_auth_config, verify_password
from app.config import Settings, get_settings
from app.main import app
from auth_support import (
    ANONYMOUS_HEADERS,
    DEFAULT_TEST_USER,
    TEST_AUTH_SECRET,
    TEST_AUTH_USERS_JSON,
    TEST_PASSWORD,
    TEST_PASSWORD_HASH,
    TEST_USER_ROLES,
)

UNAUTHENTICATED = {"detail": {"code": "UNAUTHENTICATED", "message": "Authentication is required, or the credentials are not valid."}}


def new_client(**kwargs) -> AsyncClient:
    return AsyncClient(transport=ASGITransport(app=app), base_url="http://test", **kwargs)


async def who_am_i(client: AsyncClient, **kwargs) -> httpx.Response:
    return await client.get("/api/v1/auth/me", **kwargs)


# --- the test configuration ------------------------------------------------------------------------------------------


def test_the_test_configuration_is_installed_for_every_test():
    config = load_auth_config()
    assert {name: user.role.value for name, user in config.users.items()} == TEST_USER_ROLES
    assert config.users[DEFAULT_TEST_USER].role is Role.ADMIN
    assert config.secret == TEST_AUTH_SECRET.encode()
    assert get_settings().auth_users_json.get_secret_value() == TEST_AUTH_USERS_JSON


def test_the_test_users_hash_belongs_to_the_documented_test_password():
    assert verify_password(TEST_PASSWORD, TEST_PASSWORD_HASH) is True
    assert verify_password(TEST_PASSWORD + "x", TEST_PASSWORD_HASH) is False


def test_the_application_itself_has_no_default_credentials():
    # The class defaults are what a deployment gets when nothing is configured: empty, so authentication answers 503.
    assert Settings.model_fields["auth_secret"].default.get_secret_value() == ""
    assert Settings.model_fields["auth_users_json"].default.get_secret_value() == ""


def test_a_test_token_is_worthless_under_any_other_secret(auth_headers):
    token = auth_headers()["Authorization"].removeprefix("Bearer ")
    other = AuthConfig(secret=b"a-completely-different-secret-0123456789", users=load_auth_config().users, token_ttl_seconds=3600)
    with pytest.raises(TokenError):
        authenticate_token(other, token)


# --- the default, authenticated client -------------------------------------------------------------------------------


@pytest.mark.asyncio
async def test_a_default_test_client_is_authenticated_as_test_admin():
    async with new_client() as client:
        response = await who_am_i(client)
    assert (response.status_code, response.json()) == (200, {"username": "test-admin", "role": "admin"})


@pytest.mark.asyncio
async def test_the_default_applies_to_clients_built_with_a_positional_transport():
    async with AsyncClient(transport=ASGITransport(app), base_url="http://test") as client:
        response = await who_am_i(client)
    assert response.status_code == 200 and response.json()["username"] == "test-admin"


@pytest.mark.asyncio
async def test_the_default_token_is_a_real_signed_token_with_the_configured_lifetime():
    async with new_client() as client:
        header = client.headers["Authorization"]
    scheme, _, token = header.partition(" ")
    assert scheme == "Bearer"
    principal = authenticate_token(load_auth_config(), token)
    assert (principal.username, principal.role) == ("test-admin", Role.ADMIN)


@pytest.mark.asyncio
async def test_each_test_user_can_be_used_through_auth_headers(auth_headers):
    async with new_client() as client:
        results = {name: (await who_am_i(client, headers=auth_headers(name))).json() for name in TEST_USER_ROLES}
    assert results == {name: {"username": name, "role": role} for name, role in TEST_USER_ROLES.items()}


def test_auth_headers_refuses_a_user_that_is_not_a_test_user(auth_headers):
    with pytest.raises(ValueError, match="not a test user"):
        auth_headers("alice")


@pytest.mark.asyncio
async def test_the_default_authentication_does_not_change_routes_that_do_not_use_it():
    async with new_client() as client:
        assert (await client.get("/health")).status_code == 200
        assert (await client.get("/api/v1/services")).status_code == 200


# --- explicitly anonymous requests -----------------------------------------------------------------------------------


@pytest.mark.asyncio
async def test_one_request_can_be_made_anonymous_with_an_empty_authorization_header():
    async with new_client() as client:
        anonymous = await who_am_i(client, headers=ANONYMOUS_HEADERS)
        authenticated_again = await who_am_i(client)  # the override applies to that request only
    assert (anonymous.status_code, anonymous.json()) == (401, UNAUTHENTICATED)
    assert authenticated_again.status_code == 200


@pytest.mark.asyncio
async def test_a_whole_client_can_be_made_anonymous():
    async with new_client(headers=ANONYMOUS_HEADERS) as client:
        first = await who_am_i(client)
        second = await who_am_i(client)
    assert [(first.status_code, first.json()), (second.status_code, second.json())] == [(401, UNAUTHENTICATED)] * 2


@pytest.mark.asyncio
async def test_a_client_that_sets_its_own_authorization_keeps_it(auth_headers):
    async with new_client(headers=auth_headers("test-viewer")) as client:
        response = await who_am_i(client)
    assert response.json() == {"username": "test-viewer", "role": "viewer"}


@pytest.mark.asyncio
async def test_a_per_request_user_overrides_the_default(auth_headers):
    async with new_client() as client:
        response = await who_am_i(client, headers=auth_headers("test-operator"))
    assert response.json() == {"username": "test-operator", "role": "operator"}


@pytest.mark.asyncio
async def test_a_bad_token_is_not_repaired_by_the_default():
    async with new_client() as client:
        response = await who_am_i(client, headers={"Authorization": "Bearer not-a-real-token"})
    assert (response.status_code, response.json()) == (401, UNAUTHENTICATED)


@pytest.mark.anonymous
@pytest.mark.asyncio
async def test_the_anonymous_marker_makes_every_client_in_the_test_anonymous(auth_headers):
    async with new_client() as client:
        assert "Authorization" not in client.headers
        anonymous = await who_am_i(client)
        explicit = await who_am_i(client, headers=auth_headers())  # a token can still be sent on purpose
    assert (anonymous.status_code, anonymous.json()) == (401, UNAUTHENTICATED)
    assert explicit.status_code == 200


@pytest.mark.anonymous
def test_the_anonymous_marker_leaves_the_authentication_configuration_in_place():
    assert set(load_auth_config().users) == set(TEST_USER_ROLES)


# --- the default is limited to clients of this application ------------------------------------------------------------


@pytest.mark.asyncio
async def test_clients_for_other_transports_and_applications_never_get_the_token():
    seen: list[httpx.Headers] = []

    def record(request: httpx.Request) -> httpx.Response:
        seen.append(request.headers)
        return httpx.Response(200)

    async def other_application(scope, receive, send):
        seen.append(httpx.Headers(scope["headers"]))
        await send({"type": "http.response.start", "status": 200, "headers": []})
        await send({"type": "http.response.body", "body": b""})

    async with AsyncClient(transport=httpx.MockTransport(record), base_url="http://example.test") as outbound:
        await outbound.get("/")
    async with AsyncClient(transport=ASGITransport(other_application), base_url="http://other.test") as other:
        await other.get("/")
    assert len(seen) == 2 and all("authorization" not in headers for headers in seen)


@pytest.mark.asyncio
async def test_a_client_with_an_explicit_auth_argument_is_left_alone():
    async with new_client(auth=("user", "pass")) as client:
        assert "Authorization" not in client.headers  # httpx adds Basic auth per request, from ``auth``


# --- isolation -------------------------------------------------------------------------------------------------------


@pytest.mark.asyncio
async def test_login_works_with_the_test_users_and_does_not_need_the_default_header():
    async with new_client(headers=ANONYMOUS_HEADERS) as client:
        response = await client.post("/api/v1/auth/login", json={"username": "Test-Viewer", "password": TEST_PASSWORD})
    assert response.status_code == 200 and response.json()["role"] == "viewer"
