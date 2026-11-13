"""B3 stage 2: POST /api/v1/auth/login, GET /api/v1/auth/me, login throttling and audit.

The authentication configuration is installed on the shared settings object for the duration of each test, the throttle
and its clock are replaced with fresh ones, and every test uses its own client address so that audit rows and throttle
buckets never overlap. Nothing here protects other routes (that is a later stage).
"""
import asyncio
import json
import logging
import threading
import time

import pytest
from httpx import ASGITransport, AsyncClient
from pydantic import SecretStr
from sqlalchemy import select

from app import auth, auth_routes
from app.auth import Principal, Role, authenticate_token, clear_auth_config_cache, hash_password, issue_token, load_auth_config, parse_password_hash, verify_password, verify_token
from app.auth_routes import DUMMY_PASSWORD_HASH, LoginThrottle, client_key
from app.config import Settings, get_settings
from app.database import AuditEvent, session_factory
from app.main import _request_windows, app

# These tests exercise authentication itself with their own users and secret, and several of them assert what happens
# when a request carries *no* credentials, so none of their clients may be authenticated by default.
pytestmark = pytest.mark.anonymous

SECRET = "stage2-api-secret-abcdefghijklmnop-0123456789"
PASSWORDS = {
    "alice": "alice-correct-passphrase",
    "bob": "bob-correct-passphrase",
    "carol": "carol-correct-passphrase",
    "kevin": "kevin-correct-passphrase",
}
ROLES = {"alice": "admin", "bob": "viewer", "carol": "operator", "kevin": "viewer"}
HASHES = {name: hash_password(password, n=1024) for name, password in PASSWORDS.items()}  # the lowest accepted cost: fast tests


def users_json(*names: str) -> str:
    return json.dumps([{"username": name, "role": ROLES[name], "password_hash": HASHES[name]} for name in names])


USERS_JSON = users_json("alice", "bob", "carol", "kevin")
GENERIC_401 = {"detail": {"code": "INVALID_CREDENTIALS", "message": "Invalid username or password."}}
GENERIC_UNAUTHENTICATED = {"detail": {"code": "UNAUTHENTICATED", "message": "Authentication is required, or the credentials are not valid."}}
NOT_CONFIGURED = {"detail": {"code": "AUTH_NOT_CONFIGURED", "message": "Authentication is not configured."}}
INVALID_REQUEST = {"detail": {"code": "INVALID_REQUEST", "message": "The request is not a valid login request."}}

# Requests that are not a readable login. Each carries (or is) a password that must never come back in a response.
LEAK_PASSWORD = "Leak-Check-Pw-7431!"
LEAK_NUMBER = 482915736501
JSON_TYPE = {"Content-Type": "application/json"}
MALFORMED_LOGINS = {
    "form-encoded": {"content": f"username=alice&password={LEAK_PASSWORD}".encode(), "headers": {"Content-Type": "application/x-www-form-urlencoded"}},
    "text-plain": {"content": json.dumps({"username": "alice", "password": LEAK_PASSWORD}).encode(), "headers": {"Content-Type": "text/plain"}},
    "numeric-password": {"json": {"username": "alice", "password": LEAK_NUMBER}},
    "list-password": {"json": {"username": "alice", "password": [LEAK_PASSWORD]}},
    "object-password": {"json": {"username": "alice", "password": {"value": LEAK_PASSWORD}}},
    "wrong-type-username": {"json": {"username": 5, "password": LEAK_PASSWORD}},
    "null-fields": {"json": {"username": None, "password": None}},
    "json-string-body": {"json": LEAK_PASSWORD},
    "json-array-body": {"json": ["alice", LEAK_PASSWORD]},
    "json-number-body": {"json": LEAK_NUMBER},
    "truncated-json": {"content": f'{{"username":"alice","password":"{LEAK_PASSWORD}"'.encode(), "headers": JSON_TYPE},
    "invalid-utf8": {"content": b'{"username":"alice","password":"' + LEAK_PASSWORD.encode() + b'\xff"}', "headers": JSON_TYPE},
    "empty-body": {},
}
MALFORMED_IDS = list(MALFORMED_LOGINS)
# Nothing that was sent, and none of FastAPI's validation vocabulary, may appear in the response.
LEAKS = (LEAK_PASSWORD, str(LEAK_NUMBER), "password", "username", "alice", "input", "loc", "ctx", "JSON decode", "dictionary")


class FakeClock:
    def __init__(self, start: float = 1000.0):
        self.now = start

    def __call__(self) -> float:
        return self.now

    def advance(self, seconds: float) -> None:
        self.now += seconds


@pytest.fixture
def clock(monkeypatch) -> FakeClock:
    """Install the test authentication configuration, a fresh throttle and a controllable throttle clock."""
    settings = get_settings()
    monkeypatch.setattr(settings, "auth_secret", SecretStr(SECRET))
    monkeypatch.setattr(settings, "auth_users_json", SecretStr(USERS_JSON))
    monkeypatch.setattr(settings, "auth_token_ttl_minutes", 60)
    clear_auth_config_cache()
    fake = FakeClock()
    monkeypatch.setattr(auth_routes, "_now", fake)
    monkeypatch.setattr(auth_routes, "login_throttle", LoginThrottle())
    auth_routes._reported_configuration_problems.clear()
    _request_windows.clear()
    yield fake
    clear_auth_config_cache()
    _request_windows.clear()


def client(ip: str = "198.51.100.10") -> AsyncClient:
    return AsyncClient(transport=ASGITransport(app=app, client=(ip, 4000)), base_url="http://test")


async def login(http: AsyncClient, username, password):
    return await http.post("/api/v1/auth/login", json={"username": username, "password": password})


async def me(http: AsyncClient, token: str | None = None, **headers):
    if token is not None:
        headers["Authorization"] = f"Bearer {token}"
    return await http.get("/api/v1/auth/me", headers=headers)


async def audit_rows(needle: str, event_type: str | None = None) -> list[AuditEvent]:
    async with session_factory() as session:
        query = select(AuditEvent).where(AuditEvent.message.contains(needle))
        if event_type:
            query = query.where(AuditEvent.event_type == event_type)
        return list((await session.scalars(query.order_by(AuditEvent.id))).all())


def spy_on_verification(monkeypatch) -> list[str]:
    """Record which stored hash each password check used, while still doing the real check."""
    stored_hashes: list[str] = []
    real = auth_routes.verify_password

    def spy(password, stored_hash):
        stored_hashes.append(stored_hash)
        return real(password, stored_hash)

    monkeypatch.setattr(auth_routes, "verify_password", spy)
    return stored_hashes


# --- successful login ------------------------------------------------------------------------------------------------


@pytest.mark.asyncio
async def test_a_valid_login_returns_a_signed_token_and_the_safe_identity(clock):
    async with client("198.51.100.1") as http:
        response = await login(http, "alice", PASSWORDS["alice"])
    body = response.json()

    assert response.status_code == 200
    assert set(body) == {"access_token", "token_type", "expires_in", "expires_at", "username", "role"}
    assert (body["token_type"], body["expires_in"], body["username"], body["role"]) == ("bearer", 3600, "alice", "admin")
    config = load_auth_config()
    assert authenticate_token(config, body["access_token"]) == Principal("alice", Role.ADMIN)
    claims = verify_token(config, body["access_token"])
    assert claims.expires_at == body["expires_at"] and claims.expires_at - claims.issued_at == 3600
    assert response.headers["cache-control"] == "no-store" and response.headers["pragma"] == "no-cache"
    for private in (PASSWORDS["alice"], "scrypt$", SECRET, HASHES["alice"]):
        assert private not in response.text


@pytest.mark.asyncio
@pytest.mark.parametrize("name", ["alice", "bob", "carol"])
async def test_each_role_gets_its_configured_role(clock, name):
    async with client("198.51.100.2") as http:
        body = (await login(http, name, PASSWORDS[name])).json()
    assert body["role"] == ROLES[name] and body["username"] == name


@pytest.mark.asyncio
@pytest.mark.parametrize("typed", ["ALICE", "Alice", "  alice  ", "\tAlice\r\n", "aLiCe"])
async def test_the_username_is_normalized_and_the_canonical_name_is_returned(clock, typed):
    async with client("198.51.100.3") as http:
        response = await login(http, typed, PASSWORDS["alice"])
    assert response.status_code == 200 and response.json()["username"] == "alice"


@pytest.mark.asyncio
async def test_every_login_issues_a_different_token(clock):
    async with client("198.51.100.4") as http:
        first = (await login(http, "alice", PASSWORDS["alice"])).json()["access_token"]
        second = (await login(http, "alice", PASSWORDS["alice"])).json()["access_token"]
    config = load_auth_config()
    assert first != second and verify_token(config, first).token_id != verify_token(config, second).token_id


@pytest.mark.asyncio
async def test_the_token_lifetime_follows_the_configuration(clock, monkeypatch):
    monkeypatch.setattr(get_settings(), "auth_token_ttl_minutes", 10)
    async with client("198.51.100.5") as http:
        body = (await login(http, "alice", PASSWORDS["alice"])).json()
    assert body["expires_in"] == 600 and body["expires_at"] - int(time.time()) in range(598, 602)


@pytest.mark.asyncio
async def test_a_login_token_works_on_auth_me(clock):
    async with client("198.51.100.6") as http:
        token = (await login(http, "carol", PASSWORDS["carol"])).json()["access_token"]
        response = await me(http, token)
    assert response.status_code == 200 and response.json() == {"username": "carol", "role": "operator"}


# --- generic failures ------------------------------------------------------------------------------------------------

BAD_CREDENTIALS = [
    ("alice", "wrong-password-xyz"),  # known user, wrong password
    ("nobody", "whatever-password"),  # unknown user
    ("", ""),
    ("alice", ""),
    ("", PASSWORDS["alice"]),
    ("\u212Aevin", PASSWORDS["kevin"]),  # Kelvin sign + the real password of "kevin": must not alias the user
    ("\u00a0alice\u00a0", PASSWORDS["alice"]),  # no-break-space padding + the real password
    ("ａｌｉｃｅ", PASSWORDS["alice"]),  # full-width letters
    ("a" * 300, "x"),  # over-long name
    ("alice", "p" * 5000),  # over-long password for a real user
    ("alice", PASSWORDS["alice"] + " "),
    ("ali\ud800ce", "x"),  # lone surrogate
]


@pytest.mark.asyncio
async def test_every_kind_of_invalid_credential_gets_the_same_generic_401(clock):
    seen = []
    for index, (username, password) in enumerate(BAD_CREDENTIALS):
        async with client(f"198.51.101.{index + 1}") as http:  # a separate address each time: no throttle interference
            response = await http.post("/api/v1/auth/login", content=json.dumps({"username": username, "password": password}, ensure_ascii=True).encode(), headers={"Content-Type": "application/json"})
        seen.append((response.status_code, response.json(), response.headers.get("www-authenticate")))
    assert seen == [(401, GENERIC_401, "Bearer")] * len(BAD_CREDENTIALS)


@pytest.mark.asyncio
@pytest.mark.parametrize("body", [{}, {"username": "alice"}, {"password": "x"}, {"username": "alice", "password": "x", "extra": 1}])
async def test_missing_or_extra_fields_are_an_ordinary_failed_login_not_a_validation_error(clock, body):
    async with client("198.51.100.20") as http:
        response = await http.post("/api/v1/auth/login", json=body)
    assert (response.status_code, response.json()) == (401, GENERIC_401)


def assert_nothing_echoed(response) -> None:
    complete_response = response.text + repr(sorted(response.headers.items()))  # the whole body, and the headers
    for leaked in LEAKS:
        assert leaked not in complete_response, leaked


@pytest.mark.asyncio
@pytest.mark.parametrize("kind", MALFORMED_IDS)
async def test_a_malformed_login_gets_a_fixed_422_that_echoes_nothing_that_was_sent(clock, caplog, kind):
    with caplog.at_level(logging.DEBUG):
        async with client("198.51.100.21") as http:
            response = await http.post("/api/v1/auth/login", **MALFORMED_LOGINS[kind])
    assert (response.status_code, response.json()) == (422, INVALID_REQUEST)
    assert_nothing_echoed(response)
    assert LEAK_PASSWORD not in "\n".join(record.getMessage() for record in caplog.records)


@pytest.mark.asyncio
async def test_malformed_logins_do_no_password_work_and_are_not_counted_or_audited(clock, monkeypatch):
    stored_hashes = spy_on_verification(monkeypatch)
    ip = "198.51.100.23"
    async with client(ip) as http:
        statuses = [(await http.post("/api/v1/auth/login", **request)).status_code for request in MALFORMED_LOGINS.values()]
        later = await login(http, "alice", PASSWORDS["alice"])  # a run of malformed requests locks nobody out
    assert statuses == [422] * len(MALFORMED_LOGINS) and later.status_code == 200
    assert stored_hashes == [HASHES["alice"]]  # only the real login checked a password
    assert [row.event_type for row in await audit_rows(ip)] == ["auth.login"]


@pytest.mark.asyncio
@pytest.mark.parametrize("kind", MALFORMED_IDS)
@pytest.mark.parametrize(("secret", "users"), [("", ""), (SECRET, "not json")], ids=["nothing-configured", "invalid-configuration"])
async def test_the_configuration_check_comes_first_so_a_malformed_login_gets_the_503_when_auth_is_unusable(clock, monkeypatch, kind, secret, users):
    settings = get_settings()
    monkeypatch.setattr(settings, "auth_secret", SecretStr(secret))
    monkeypatch.setattr(settings, "auth_users_json", SecretStr(users))
    clear_auth_config_cache()
    async with client("198.51.100.24") as http:
        response = await http.post("/api/v1/auth/login", **MALFORMED_LOGINS[kind])
    assert (response.status_code, response.json()) == (503, NOT_CONFIGURED)
    assert_nothing_echoed(response)


@pytest.mark.asyncio
async def test_the_login_routes_other_failures_are_not_swallowed_by_the_malformed_request_handling(clock):
    async with client("198.51.100.25") as http:
        for _ in range(5):
            await login(http, "alice", "wrong-password")
        locked = await login(http, "alice", PASSWORDS["alice"])
        wrong = await login(http, "nobody", "wrong-password")
    assert (locked.status_code, locked.json()["detail"]["code"]) == (429, "TOO_MANY_ATTEMPTS") and "retry-after" in locked.headers
    assert (wrong.status_code, wrong.json()) == (401, GENERIC_401)


def test_the_openapi_description_of_the_login_route_documents_the_fixed_422():
    login_operation = app.openapi()["paths"]["/api/v1/auth/login"]["post"]
    assert "never echoed" in login_operation["responses"]["422"]["description"]
    assert "content" not in login_operation["responses"]["422"]  # no validation-error schema (with its `input`) is advertised


@pytest.mark.asyncio
async def test_neither_passwords_nor_tokens_nor_hashes_are_logged(clock, caplog):
    wrong, token = "never-log-this-wrong-password", None
    with caplog.at_level(logging.DEBUG):
        async with client("198.51.100.22") as http:
            await login(http, "alice", wrong)
            await login(http, "nobody", wrong)
            token = (await login(http, "alice", PASSWORDS["alice"])).json()["access_token"]
            await me(http, token)
            await me(http, token + "x")
    logged = "\n".join(record.getMessage() for record in caplog.records)
    for private in (wrong, PASSWORDS["alice"], token, token.split(".")[1], HASHES["alice"], DUMMY_PASSWORD_HASH, SECRET):
        assert private not in logged
    assert "Login failed for alice" in logged and "Login failed for <unknown>" in logged


# --- dummy-hash verification -----------------------------------------------------------------------------------------


def test_the_dummy_hash_is_a_valid_default_cost_hash_that_belongs_to_no_user():
    parsed = parse_password_hash(DUMMY_PASSWORD_HASH)
    assert (parsed.n, parsed.r, parsed.p) == (auth.SCRYPT_N, auth.SCRYPT_R, auth.SCRYPT_P)
    assert DUMMY_PASSWORD_HASH not in HASHES.values()
    for password in list(PASSWORDS.values()) + ["", "password", "dummy", "scrypt"]:
        assert verify_password(password, DUMMY_PASSWORD_HASH) is False


@pytest.mark.asyncio
async def test_known_unknown_and_invalid_usernames_all_go_through_the_same_password_check(clock, monkeypatch):
    stored_hashes = spy_on_verification(monkeypatch)
    cases = [
        ("alice", PASSWORDS["alice"], HASHES["alice"]),
        ("alice", "wrong-password", HASHES["alice"]),
        ("nobody", "whatever", DUMMY_PASSWORD_HASH),
        ("\u212Aevin", PASSWORDS["kevin"], DUMMY_PASSWORD_HASH),
        ("", "", DUMMY_PASSWORD_HASH),
        ("a" * 300, "x", DUMMY_PASSWORD_HASH),
        ("ａｌｉｃｅ", "x", DUMMY_PASSWORD_HASH),
    ]
    for index, (username, password, expected_hash) in enumerate(cases):
        stored_hashes.clear()
        async with client(f"198.51.102.{index + 1}") as http:
            await login(http, username, password)
        assert stored_hashes == [expected_hash], username  # exactly one check, with the user's hash or the dummy


@pytest.mark.asyncio
async def test_a_matching_dummy_check_can_never_authenticate_an_unknown_name(clock, monkeypatch):
    monkeypatch.setattr(auth_routes, "verify_password", lambda password, stored_hash: True)  # even if every check "matched"
    for index, username in enumerate(["nobody", "\u212Aevin", "", "a" * 300]):
        async with client(f"198.51.103.{index + 1}") as http:
            response = await login(http, username, "anything")
        assert (response.status_code, response.json()) == (401, GENERIC_401), username


@pytest.mark.asyncio
async def test_password_checks_run_at_most_a_few_at_a_time(clock, monkeypatch):
    lock, state = threading.Lock(), {"now": 0, "peak": 0}

    def slow_check(password, stored_hash):
        with lock:
            state["now"] += 1
            state["peak"] = max(state["peak"], state["now"])
        time.sleep(0.05)
        with lock:
            state["now"] -= 1
        return False

    monkeypatch.setattr(auth_routes, "verify_password", slow_check)

    async def attempt(index: int):
        async with client(f"198.51.104.{index + 1}") as http:
            return (await login(http, f"nobody{index}", "x")).status_code

    statuses = await asyncio.gather(*(attempt(index) for index in range(12)))
    assert statuses == [401] * 12 and state["peak"] <= auth_routes.MAX_CONCURRENT_VERIFICATIONS


# --- throttling ------------------------------------------------------------------------------------------------------


@pytest.mark.asyncio
async def test_the_sixth_attempt_is_refused_with_retry_after_even_with_the_right_password(clock, monkeypatch):
    stored_hashes = spy_on_verification(monkeypatch)
    statuses = []
    async with client("198.51.105.1") as http:
        for _ in range(5):
            statuses.append((await login(http, "alice", "wrong-password")).status_code)
            clock.advance(1)
        refused = await login(http, "alice", PASSWORDS["alice"])
    assert statuses == [401] * 5
    assert refused.status_code == 429 and refused.headers["retry-after"] == "295"  # first failure leaves the window in 295 s
    assert refused.json() == {"detail": {"code": "TOO_MANY_ATTEMPTS", "message": "Too many failed login attempts. Try again later."}}
    assert len(stored_hashes) == 5  # the refused request did no password work


@pytest.mark.asyncio
async def test_the_window_expires_one_failure_at_a_time(clock):
    async with client("198.51.105.2") as http:
        for _ in range(5):
            await login(http, "alice", "wrong-password")
            clock.advance(1)  # failures at t=1000..1004; now 1005
        clock.advance(294)  # t=1299: the first failure (1000) is still inside the window
        still_limited = await login(http, "alice", PASSWORDS["alice"])
        clock.advance(1)  # t=1300: the first failure has expired, four remain
        allowed = await login(http, "alice", PASSWORDS["alice"])
    assert still_limited.status_code == 429 and still_limited.headers["retry-after"] == "1"
    assert allowed.status_code == 200


@pytest.mark.asyncio
async def test_the_limit_is_per_address_and_per_username(clock):
    async with client("198.51.105.3") as attacker, client("198.51.105.4") as other:
        for _ in range(5):
            await login(attacker, "alice", "wrong-password")
        locked = await login(attacker, "alice", PASSWORDS["alice"])
        different_user = await login(attacker, "bob", PASSWORDS["bob"])  # same address, another username
        different_address = await login(other, "alice", PASSWORDS["alice"])  # same username, another address
    assert locked.status_code == 429
    assert different_user.status_code == 200 and different_address.status_code == 200


@pytest.mark.asyncio
async def test_a_successful_login_clears_the_username_counter_for_that_address(clock):
    async with client("198.51.105.5") as http:
        for _ in range(3):
            assert (await login(http, "alice", "wrong-password")).status_code == 401
        assert (await login(http, "alice", PASSWORDS["alice"])).status_code == 200
        later = [(await login(http, "alice", "wrong-password")).status_code for _ in range(5)]
        sixth = await login(http, "alice", "wrong-password")
    assert later == [401] * 5 and sixth.status_code == 429  # a fresh count of five, not 3 + 5


@pytest.mark.asyncio
async def test_a_successful_login_does_not_use_up_the_address_limit(clock):
    async with client("198.51.105.6") as http:
        for _ in range(30):
            assert (await login(http, "alice", PASSWORDS["alice"])).status_code == 200
    assert auth_routes.login_throttle.size() == (0, 0)


@pytest.mark.asyncio
async def test_twenty_failures_from_one_address_lock_that_address_whatever_the_names(clock):
    async with client("198.51.105.7") as http, client("198.51.105.8") as other:
        statuses = [(await login(http, f"user{index:02d}", "x")).status_code for index in range(20)]
        clock.advance(10)
        refused = await login(http, "user99", "x")
        refused_real = await login(http, "bob", PASSWORDS["bob"])
        elsewhere = await login(other, "bob", PASSWORDS["bob"])
    assert statuses == [401] * 20
    assert refused.status_code == 429 and refused.headers["retry-after"] == "290"
    assert refused_real.status_code == 429 and elsewhere.status_code == 200


@pytest.mark.asyncio
async def test_spelling_variants_of_one_username_share_a_bucket(clock):
    variants = ["alice", "ALICE", "  Alice  ", "aLiCe\t", "Alice"]
    async with client("198.51.105.9") as http:
        statuses = [(await login(http, name, "wrong-password")).status_code for name in variants]
        refused_variant = await login(http, "ALICE\n", PASSWORDS["alice"])
        refused_plain = await login(http, "alice", PASSWORDS["alice"])
    assert statuses == [401] * 5 and refused_variant.status_code == 429 and refused_plain.status_code == 429


@pytest.mark.asyncio
async def test_unicode_look_alikes_cannot_spread_attempts_over_new_buckets(clock):
    look_alikes = ["\u212Aevin", "\u00a0kevin", "ｋｅｖｉｎ", "kévin", "ke\u200bvin"]
    async with client("198.51.105.10") as http:
        statuses = [(await login(http, name, "wrong-password")).status_code for name in look_alikes]
        sixth = await login(http, "k\u0435vin", "wrong-password")  # a new spelling (Cyrillic е): still the same bucket
        real_user = await login(http, "kevin", PASSWORDS["kevin"])  # the real name has its own bucket
    assert statuses == [401] * 5 and sixth.status_code == 429
    assert real_user.status_code == 200


@pytest.mark.asyncio
async def test_overlong_usernames_share_the_invalid_bucket_instead_of_growing_the_throttle(clock):
    async with client("198.51.105.11") as http:
        statuses = [(await login(http, "x" * (300 + index), "wrong")).status_code for index in range(5)]
        sixth = await login(http, "y" * 400, "wrong")
    assert statuses == [401] * 5 and sixth.status_code == 429
    assert auth_routes.login_throttle.size()[0] == 1


@pytest.mark.asyncio
async def test_simultaneous_attempts_cannot_exceed_the_limit(clock, monkeypatch):
    stored_hashes = spy_on_verification(monkeypatch)
    async with client("198.51.105.12") as http:
        responses = await asyncio.gather(*(login(http, "alice", "wrong-password") for _ in range(10)))
    assert sorted(response.status_code for response in responses) == [401] * 5 + [429] * 5
    assert len(stored_hashes) == 5  # the other five were refused before any password work


@pytest.mark.asyncio
async def test_ipv6_addresses_in_one_64_and_ipv4_mapped_addresses_share_a_bucket(clock):
    assert client_key("2001:db8:1:2::1") == client_key("2001:db8:1:2:ffff::9") != client_key("2001:db8:1:3::1")
    assert client_key("::ffff:198.51.100.77") == client_key("198.51.100.77") == "198.51.100.77"
    assert client_key(None) == "unknown" and client_key("testclient") == "testclient"
    async with client("2001:db8:1:2::1") as first, client("2001:db8:1:2:ffff::9") as second:
        for _ in range(3):
            await login(first, "alice", "wrong-password")
        for _ in range(2):
            await login(second, "alice", "wrong-password")
        assert (await login(first, "alice", "x")).status_code == 429
        assert (await login(second, "alice", "x")).status_code == 429
    async with client("198.51.100.77") as plain, client("::ffff:198.51.100.77") as mapped:
        for _ in range(3):
            await login(plain, "bob", "wrong-password")
        for _ in range(2):
            await login(mapped, "bob", "wrong-password")
        assert (await login(plain, "bob", "x")).status_code == 429


# --- the throttle itself ---------------------------------------------------------------------------------------------


def test_throttle_counts_limits_and_expires_attempts():
    throttle = LoginThrottle(pair_limit=3, ip_limit=5, window=100.0)
    assert throttle.retry_after("a", "u", 0.0) is None
    attempts = [throttle.reserve("a", "u", float(second)) for second in range(3)]
    assert [attempt.reached_pair_limit for attempt in attempts] == [False, False, True]
    assert throttle.retry_after("a", "u", 3.0) == 97  # the oldest (t=0) leaves the window at t=100
    assert throttle.retry_after("a", "other", 3.0) is None and throttle.retry_after("b", "u", 3.0) is None
    assert throttle.retry_after("a", "u", 100.0) is None  # t=0 expired at exactly 100; two remain


def test_throttle_release_gives_back_its_own_attempt_and_clears_the_pair():
    throttle = LoginThrottle(pair_limit=3, ip_limit=5, window=100.0)
    first = throttle.reserve("a", "u", 0.0)
    throttle.reserve("a", "v", 1.0)
    throttle.reserve("a", "u", 2.0)
    throttle.release(first)
    assert throttle.size() == (1, 1)  # ("a","v") remains; the ip entry still holds the two other attempts
    assert throttle.retry_after("a", "u", 3.0) is None
    only = throttle.reserve("c", None, 5.0)
    throttle.release(only)
    assert ("c", None) not in throttle._pairs and "c" not in throttle._ips


def test_throttle_memory_is_bounded_and_expired_entries_are_pruned():
    throttle = LoginThrottle(pair_limit=5, ip_limit=20, window=100.0, max_entries=50)
    for index in range(2000):
        throttle.reserve(f"10.0.{index // 250}.{index % 250}", f"user{index}", float(index) / 100)
    pairs, ips = throttle.size()
    assert pairs <= 50 and ips <= 50
    throttle.sweep(10_000.0)
    assert throttle.size() == (0, 0)  # everything expired


def test_a_single_key_can_never_hold_more_than_its_limit():
    throttle = LoginThrottle(pair_limit=3, ip_limit=4, window=100.0)
    for second in range(50):
        throttle.reserve("a", "u", float(second))
    assert len(throttle._pairs[("a", "u")]) == 3 and len(throttle._ips["a"]) == 4


def test_retry_after_prunes_expired_entries_and_forgets_empty_keys():
    throttle = LoginThrottle(pair_limit=2, ip_limit=3, window=10.0)
    throttle.reserve("a", "u", 0.0)
    assert throttle.retry_after("a", "u", 50.0) is None
    assert throttle.size() == (0, 0)


# --- audit -----------------------------------------------------------------------------------------------------------


@pytest.mark.asyncio
async def test_a_successful_login_is_audited_without_secrets(clock):
    ip = "198.51.106.1"
    async with client(ip) as http:
        body = (await login(http, "ALICE", PASSWORDS["alice"])).json()
    rows = await audit_rows(ip, "auth.login")
    assert [row.message for row in rows] == [f"User alice logged in from {ip}."]
    for private in (body["access_token"], PASSWORDS["alice"], HASHES["alice"], SECRET, "scrypt$"):
        assert private not in rows[0].message


@pytest.mark.asyncio
async def test_failed_attempts_below_the_limit_are_not_audited(clock):
    ip = "198.51.106.2"
    async with client(ip) as http:
        for _ in range(4):
            await login(http, "alice", "wrong-password")
        await login(http, "nobody", "wrong-password")
    assert await audit_rows(ip) == []


@pytest.mark.asyncio
async def test_a_lockout_is_audited_once_and_refused_requests_add_nothing(clock):
    ip = "198.51.106.3"
    async with client(ip) as http:
        for _ in range(5):
            await login(http, "alice", "wrong-password")
        for _ in range(4):
            assert (await login(http, "alice", PASSWORDS["alice"])).status_code == 429
    rows = await audit_rows(ip)
    assert [(row.event_type, row.message) for row in rows] == [
        ("auth.login_locked", f"Login locked for alice from {ip}: 5 failed attempts within 300 seconds.")
    ]


@pytest.mark.asyncio
async def test_the_address_lockout_is_audited_once(clock):
    ip = "198.51.106.4"
    async with client(ip) as http:
        for index in range(20):
            await login(http, f"user{index:02d}", "x")
        await login(http, "user99", "x")
    rows = await audit_rows(ip)
    assert [(row.event_type, row.message) for row in rows] == [
        ("auth.login_locked", f"Login locked for address {ip}: 20 failed attempts within 300 seconds.")
    ]


@pytest.mark.asyncio
async def test_a_lockout_never_records_an_attempted_name_that_is_not_a_configured_user(clock):
    ip = "198.51.106.5"
    typed_as_username = "my-secret-passw0rd!"  # people sometimes type the password into the username box
    async with client(ip) as http:
        for _ in range(5):
            await login(http, typed_as_username, "x")
    rows = await audit_rows(ip, "auth.login_locked")
    assert [row.message for row in rows] == [f"Login locked for <unknown> from {ip}: 5 failed attempts within 300 seconds."]
    assert typed_as_username not in rows[0].message


@pytest.mark.asyncio
async def test_a_correct_fifth_attempt_is_a_login_not_a_lockout(clock):
    ip = "198.51.106.6"
    async with client(ip) as http:
        for _ in range(4):
            await login(http, "alice", "wrong-password")
        assert (await login(http, "alice", PASSWORDS["alice"])).status_code == 200
    assert [row.event_type for row in await audit_rows(ip)] == ["auth.login"]


@pytest.mark.asyncio
async def test_no_token_is_issued_when_the_login_audit_record_cannot_be_stored(clock, monkeypatch):
    async def failing_audit(session, events):
        raise RuntimeError("audit store unavailable")

    monkeypatch.setattr(auth_routes, "_audit", failing_audit)
    async with client("198.51.106.7") as http:
        response = await login(http, "alice", PASSWORDS["alice"])
    assert response.status_code == 500 and "access_token" not in response.text and "eyJ" not in response.text


@pytest.mark.asyncio
async def test_a_failed_lockout_audit_does_not_turn_the_refusal_into_a_server_error(clock, monkeypatch):
    async def failing_audit(session, events):
        raise RuntimeError("audit store unavailable")

    monkeypatch.setattr(auth_routes, "_audit", failing_audit)
    async with client("198.51.106.8") as http:
        statuses = [(await login(http, "alice", "wrong-password")).status_code for _ in range(5)]
        sixth = await login(http, "alice", "wrong-password")
    assert statuses == [401] * 5 and sixth.status_code == 429


# --- GET /auth/me ----------------------------------------------------------------------------------------------------


def token_for(name: str, *, now: float | None = None, ttl_minutes: int | None = None) -> str:
    settings = get_settings()
    if ttl_minutes is not None:
        original = settings.auth_token_ttl_minutes
        settings.auth_token_ttl_minutes = ttl_minutes
        try:
            config = load_auth_config()
        finally:
            settings.auth_token_ttl_minutes = original
    else:
        config = load_auth_config()
    return issue_token(config, config.users[name], now=now).token


@pytest.mark.asyncio
async def test_me_returns_the_configured_username_and_role(clock):
    async with client("198.51.107.1") as http:
        response = await me(http, token_for("bob"))
    assert response.status_code == 200 and response.json() == {"username": "bob", "role": "viewer"}
    assert response.headers["cache-control"] == "no-store"


@pytest.mark.asyncio
async def test_me_accepts_the_bearer_scheme_in_any_case(clock):
    async with client("198.51.107.2") as http:
        response = await http.get("/api/v1/auth/me", headers={"Authorization": f"bEaReR {token_for('bob')}"})
    assert response.status_code == 200


@pytest.mark.asyncio
async def test_me_refuses_every_kind_of_bad_credential_with_the_same_generic_401(clock):
    good = token_for("alice")
    other = auth.load_auth_config(Settings(auth_secret="another-secret-ZYXWVUTSRQPONMLK-9876543210", auth_users_json=USERS_JSON))
    other_secret_token = issue_token(other, other.users["alice"]).token
    payload, signature = good.split(".")
    bad_signature = signature[:-2] + ("BB" if not signature.endswith("BB") else "CC")
    bad_payload = payload[:-1] + ("A" if payload[-1] != "A" else "B")
    headers_and_tokens = [
        {},  # no header
        {"Authorization": ""},
        {"Authorization": "Bearer"},
        {"Authorization": "Bearer "},
        {"Authorization": f"Basic {good}"},
        {"Authorization": f"Token {good}"},
        {"Authorization": good},  # no scheme
        {"Authorization": f"Bearer {good} extra"},
        {"Authorization": f"Bearer  {good}"},  # two spaces
        {"Authorization": "Bearer not-a-token"},
        {"Authorization": f"Bearer {payload}.{bad_signature}"},  # tampered signature
        {"Authorization": f"Bearer {bad_payload}.{signature}"},  # tampered payload
        {"Authorization": f"Bearer {other_secret_token}"},  # signed with another secret
        {"Authorization": f"Bearer {token_for('alice', now=time.time() - 7200)}"},  # expired
        {"Authorization": f"Bearer {token_for('alice', now=time.time() + 3600)}"},  # issued in the future
        {"Authorization": f"Bearer {token_for('alice', ttl_minutes=720)}"},  # lifetime longer than configured
        {"Authorization": f"Bearer {'x' * 5000}"},
    ]
    results = []
    for index, headers in enumerate(headers_and_tokens):
        async with client(f"198.51.107.{index + 10}") as http:
            response = await http.get("/api/v1/auth/me", headers=headers)
        results.append((response.status_code, response.json(), response.headers.get("www-authenticate")))
    assert results == [(401, GENERIC_UNAUTHENTICATED, "Bearer")] * len(headers_and_tokens)


@pytest.mark.asyncio
async def test_me_refuses_two_authorization_headers(clock):
    good = token_for("alice")
    async with client("198.51.107.40") as http:
        response = await http.get("/api/v1/auth/me", headers=[("Authorization", f"Bearer {good}"), ("Authorization", f"Bearer {good}")])
    assert (response.status_code, response.json()) == (401, GENERIC_UNAUTHENTICATED)


@pytest.mark.asyncio
async def test_me_rejects_a_user_removed_from_the_configuration(clock, monkeypatch):
    token = token_for("bob")
    async with client("198.51.107.41") as http:
        assert (await me(http, token)).status_code == 200
        monkeypatch.setattr(get_settings(), "auth_users_json", SecretStr(users_json("alice", "carol", "kevin")))  # as after a restart
        response = await me(http, token)
    assert (response.status_code, response.json()) == (401, GENERIC_UNAUTHENTICATED)


@pytest.mark.asyncio
async def test_me_reports_the_current_configured_role_not_the_role_in_the_token(clock, monkeypatch):
    viewer_token = token_for("bob")
    promoted = json.dumps([{"username": "bob", "role": "admin", "password_hash": HASHES["bob"]}])
    async with client("198.51.107.42") as http:
        before = (await me(http, viewer_token)).json()
        monkeypatch.setattr(get_settings(), "auth_users_json", SecretStr(promoted))
        after = (await me(http, viewer_token)).json()
    assert before["role"] == "viewer" and after == {"username": "bob", "role": "admin"}


@pytest.mark.asyncio
async def test_me_does_not_count_against_the_login_throttle(clock):
    token = token_for("alice")
    async with client("198.51.107.43") as http:
        for _ in range(30):
            assert (await me(http, token)).status_code == 200
        assert (await login(http, "alice", PASSWORDS["alice"])).status_code == 200
    assert auth_routes.login_throttle.size() == (0, 0)


# --- configuration problems and scope --------------------------------------------------------------------------------


@pytest.mark.asyncio
@pytest.mark.parametrize(
    ("secret", "users"),
    [("", ""), ("   ", "\n"), ("short", USERS_JSON), (SECRET, ""), (SECRET, "not json"), (SECRET, json.dumps([{"username": "Alice", "role": "admin", "password_hash": HASHES["alice"]}]))],
    ids=["nothing", "blank", "weak-secret", "no-users", "bad-json", "bad-user"],
)
async def test_login_and_me_answer_503_when_authentication_is_not_usable(clock, monkeypatch, secret, users, caplog):
    settings = get_settings()
    monkeypatch.setattr(settings, "auth_secret", SecretStr(secret))
    monkeypatch.setattr(settings, "auth_users_json", SecretStr(users))
    clear_auth_config_cache()
    with caplog.at_level(logging.INFO):
        async with client("198.51.108.1") as http:
            attempt = await login(http, "alice", PASSWORDS["alice"])
            current = await me(http, "whatever")
    assert (attempt.status_code, attempt.json()) == (503, NOT_CONFIGURED)
    assert (current.status_code, current.json()) == (503, NOT_CONFIGURED)
    logged = "\n".join(record.getMessage() for record in caplog.records)
    for private in (secret.strip(), PASSWORDS["alice"], HASHES["alice"]):
        assert not private or private not in logged
    assert logged.count("Authentication is unavailable") == 1  # reported once, not once per request


def test_the_auth_routes_are_registered():
    routes = {(method, route.path) for route in app.routes for method in getattr(route, "methods", set())}
    assert ("POST", "/api/v1/auth/login") in routes and ("GET", "/api/v1/auth/me") in routes


@pytest.mark.asyncio
async def test_only_the_intentionally_public_routes_work_without_credentials(clock):
    # The complete access policy is pinned in tests/test_route_access.py; this is the minimal anonymous check.
    async with client("198.51.108.2") as http:
        assert (await http.get("/health")).status_code == 200
        denied = await http.get("/api/v1/services")
    assert (denied.status_code, denied.json()) == (401, GENERIC_UNAUTHENTICATED)
