"""Stage 1 of B3: password hashing, signed bearer tokens and validated auth configuration (app/auth.py).

Nothing here touches the API or a database. Tokens are forged with an independent implementation of the documented
format (base64url JSON payload + HMAC-SHA256), so the tests also pin the wire format.
"""
import ast
import base64
import dataclasses
import hashlib
import hmac
import inspect
import json
import subprocess
import sys
import textwrap
from pathlib import Path
from types import MappingProxyType

import pytest
from pydantic import ValidationError

from app import auth
from app.auth import (
    AuthConfig,
    AuthConfigurationError,
    AuthNotConfiguredError,
    AuthUser,
    ExpiredTokenError,
    FutureTokenError,
    InvalidClockError,
    InvalidPasswordError,
    InvalidSignatureError,
    MalformedTokenError,
    PasswordHashError,
    Principal,
    Role,
    TokenError,
    TokenLifetimeError,
    UnknownUserError,
    UnsupportedTokenVersionError,
    authenticate_token,
    clear_auth_config_cache,
    hash_password,
    is_valid_username,
    issue_token,
    load_auth_config,
    normalize_username,
    role_allows,
    verify_password,
    verify_token,
)
from app.config import Settings

BACKEND_DIR = Path(__file__).resolve().parents[1]
SECRET = "unit-test-secret-abcdefghijklmnop-0123456789"  # 43 characters, many distinct ones; not a real secret
OTHER_SECRET = "a-different-unit-test-secret-ZYXWVUTSRQPONM-987654"
NOW = 1_700_000_000
CHEAP = {"n": 1024}  # the lowest accepted scrypt cost, to keep the tests fast
PASSWORD = "correct horse battery staple"


@pytest.fixture(autouse=True)
def fresh_config_cache():
    clear_auth_config_cache()
    yield
    clear_auth_config_cache()


def cheap_hash(password: str = PASSWORD) -> str:
    return hash_password(password, **CHEAP)


def users_json(*entries: tuple[str, str]) -> str:
    password_hash = cheap_hash()
    return json.dumps([{"username": name, "role": role, "password_hash": password_hash} for name, role in entries])


def settings_for(secret: str = SECRET, users: str | None = None, **extra) -> Settings:
    return Settings(
        auth_secret=secret,
        auth_users_json=users if users is not None else users_json(("alice", "admin"), ("bob", "viewer")),
        **extra,
    )


def config_for(**kwargs) -> AuthConfig:
    return load_auth_config(settings_for(**kwargs))


def b64(data: bytes) -> str:
    return base64.urlsafe_b64encode(data).rstrip(b"=").decode("ascii")


def sign(encoded_payload: str, secret: str = SECRET) -> str:
    return b64(hmac.new(secret.encode(), encoded_payload.encode("ascii"), hashlib.sha256).digest())


def forge(payload: dict | str, secret: str = SECRET) -> str:
    """A correctly signed token around an arbitrary payload (a dict, or raw text to test unparseable payloads)."""
    raw = payload if isinstance(payload, str) else json.dumps(payload)
    encoded = b64(raw.encode("utf-8"))
    return f"{encoded}.{sign(encoded, secret)}"


def good_payload(**overrides) -> dict:
    payload = {"v": 1, "sub": "alice", "role": "admin", "iat": NOW, "exp": NOW + 3600, "jti": "abcdefghijklmnopqrstuv"}
    payload.update(overrides)
    return payload


def payload_of(token: str) -> dict:
    encoded = token.split(".")[0]
    return json.loads(base64.urlsafe_b64decode(encoded + "=" * (-len(encoded) % 4)))


def assert_safe(error: Exception, *sensitive: str) -> None:
    """Messages are fixed text: they never echo secrets, passwords, hashes or token contents."""
    text = f"{error!s} {error!r}"
    for value in sensitive:
        assert value and value not in text


# --- passwords -------------------------------------------------------------------------------------------------------


def test_the_correct_password_verifies_and_incorrect_ones_do_not():
    stored = cheap_hash()
    assert verify_password(PASSWORD, stored) is True
    for wrong in (PASSWORD.upper(), PASSWORD + " ", " " + PASSWORD, PASSWORD[:-1], "", "x", "Password1!"):
        assert verify_password(wrong, stored) is False


def test_hashes_use_the_documented_format_default_cost_and_a_fresh_salt_each_time():
    first, second = hash_password(PASSWORD), hash_password(PASSWORD)
    assert first != second  # random salt
    scheme, n, r, p, salt, digest = first.split("$")
    assert (scheme, n, r, p) == ("scrypt", "16384", "8", "1")
    assert len(base64.urlsafe_b64decode(salt + "==")) == 16 and len(base64.urlsafe_b64decode(digest + "==")) == 32
    assert verify_password(PASSWORD, first) and verify_password(PASSWORD, second)
    assert PASSWORD not in first


def test_each_password_hash_uses_the_cost_stored_in_it():
    low, high = hash_password(PASSWORD, n=1024, r=8, p=1), hash_password(PASSWORD, n=2048, r=4, p=2)
    assert verify_password(PASSWORD, low) and verify_password(PASSWORD, high)
    assert not verify_password("wrong password!", high)


@pytest.mark.parametrize("password", ["", "x" * 257, None, 12345, b"bytes", "lone surrogate \ud800"])
def test_unusable_passwords_cannot_be_hashed_and_never_verify(password):
    with pytest.raises(InvalidPasswordError) as raised:
        hash_password(password)
    assert raised.value.code == "PASSWORD_INVALID"
    assert verify_password(password, cheap_hash()) is False  # rejected without running scrypt


def test_the_longest_accepted_password_is_256_characters():
    password = "p" * 256
    assert verify_password(password, cheap_hash(password)) is True
    assert verify_password("p" * 257, cheap_hash(password)) is False


def test_unicode_passwords_are_compared_exactly():
    stored = cheap_hash("pässwörd-日本語-😀")
    assert verify_password("pässwörd-日本語-😀", stored) is True
    assert verify_password("passwörd-日本語-😀", stored) is False


@pytest.mark.parametrize(("n", "r", "p"), [(512, 8, 1), (2**16, 8, 1), (1500, 8, 1), (1024, 0, 1), (1024, 17, 1), (1024, 8, 0), (1024, 8, 5), (-1024, 8, 1), (True, 8, 1)])
def test_scrypt_costs_outside_the_accepted_range_are_refused_when_hashing(n, r, p):
    with pytest.raises(PasswordHashError):
        hash_password(PASSWORD, n=n, r=r, p=p)


def valid_hash_parts() -> list[str]:
    return cheap_hash().split("$")


@pytest.mark.parametrize(
    "mutate",
    [
        lambda parts: ["bcrypt"] + parts[1:],
        lambda parts: parts[:-1],  # too few parts
        lambda parts: parts + ["extra"],
        lambda parts: [parts[0], "abc"] + parts[2:],  # non-numeric cost
        lambda parts: [parts[0], "01024"] + parts[2:],  # leading zero
        lambda parts: [parts[0], "+1024"] + parts[2:],
        lambda parts: [parts[0], "1048576"] + parts[2:],  # N = 2**20: far above the accepted range
        lambda parts: [parts[0], "1500"] + parts[2:],  # not a power of two
        lambda parts: parts[:2] + ["0"] + parts[3:],  # r = 0
        lambda parts: parts[:3] + ["99"] + parts[4:],  # p too large
        lambda parts: parts[:4] + ["!!!"] + parts[5:],  # salt is not base64url
        lambda parts: parts[:4] + [parts[4] + "="] + parts[5:],  # padded: not canonical
        lambda parts: parts[:4] + ["AAAA"] + parts[5:],  # salt too short
        lambda parts: parts[:5] + [""],  # empty digest
        lambda parts: parts[:5] + ["AAAA"],  # digest too short
        lambda parts: parts[:5] + [parts[5] + "é"],  # non-ASCII
    ],
)
def test_malformed_stored_hashes_are_a_configuration_fault_not_a_wrong_password(mutate):
    stored = "$".join(mutate(valid_hash_parts()))
    with pytest.raises(PasswordHashError) as raised:
        verify_password(PASSWORD, stored)
    assert raised.value.code == "PASSWORD_HASH_INVALID"
    assert_safe(raised.value, stored, PASSWORD)


@pytest.mark.parametrize("stored", [None, 123, b"scrypt$1024$8$1$a$b", "", "x" * 600])
def test_stored_hashes_of_the_wrong_type_or_size_are_rejected(stored):
    with pytest.raises(PasswordHashError):
        verify_password(PASSWORD, stored)


def test_password_and_signature_comparisons_are_constant_time(monkeypatch):
    calls = []
    real = hmac.compare_digest

    def spy(a, b):
        calls.append(type(a))
        return real(a, b)

    monkeypatch.setattr(auth.hmac, "compare_digest", spy)
    verify_password(PASSWORD, cheap_hash())
    after_password = len(calls)
    verify_token(config_for(), forge(good_payload()), now=NOW)
    assert after_password == 1 and len(calls) == 2


# --- configuration: secret -------------------------------------------------------------------------------------------


def test_a_missing_configuration_is_reported_as_not_configured():
    with pytest.raises(AuthNotConfiguredError) as raised:
        load_auth_config(Settings(auth_secret="", auth_users_json=""))
    assert isinstance(raised.value, AuthConfigurationError) and raised.value.code == "AUTH_NOT_CONFIGURED"
    with pytest.raises(AuthNotConfiguredError):
        load_auth_config(Settings(auth_secret="   ", auth_users_json="\n"))


def test_a_secret_is_required_even_when_users_are_configured():
    with pytest.raises(AuthConfigurationError) as raised:
        load_auth_config(Settings(auth_secret="", auth_users_json=users_json(("alice", "admin"))))
    assert not isinstance(raised.value, AuthNotConfiguredError) and raised.value.code == "AUTH_CONFIGURATION_INVALID"


def test_users_are_required_even_when_a_secret_is_configured():
    with pytest.raises(AuthConfigurationError):
        load_auth_config(Settings(auth_secret=SECRET, auth_users_json=""))


def test_the_secret_must_be_at_least_32_characters():
    thirty_one, thirty_two = "abcdefghijklmnopqrstuvwxyz01234", "abcdefghijklmnopqrstuvwxyz012345"
    assert len(thirty_one) == 31 and len(thirty_two) == 32
    with pytest.raises(AuthConfigurationError) as raised:
        config_for(secret=thirty_one)
    assert_safe(raised.value, thirty_one)
    assert config_for(secret=thirty_two).secret == thirty_two.encode()


@pytest.mark.parametrize("weak", ["a" * 40, "ab" * 30, " " + SECRET, SECRET + " ", SECRET + "\n", "12345678" * 5])
def test_repetitive_or_padded_secrets_are_refused_without_echoing_them(weak):
    with pytest.raises(AuthConfigurationError) as raised:
        config_for(secret=weak)
    assert_safe(raised.value, weak.strip())


# --- configuration: users --------------------------------------------------------------------------------------------


def entry(**overrides) -> dict:
    value = {"username": "carol", "role": "operator", "password_hash": cheap_hash()}
    value.update(overrides)
    return value


@pytest.mark.parametrize(
    "users",
    [
        "not json at all",
        "{",
        "{}",
        "[]",
        '"alice"',
        "null",
        json.dumps({"username": "alice"}),  # an object, not an array
        json.dumps(["alice"]),  # entries must be objects
        json.dumps([{"username": "carol", "role": "admin"}]),  # missing password_hash
        json.dumps([{**entry(), "extra": 1}]),  # unknown key
        json.dumps([entry(username="")]),
        json.dumps([entry(username="Carol")]),  # uppercase is not a valid username
        json.dumps([entry(username="ab")]),  # too short
        json.dumps([entry(username="a" * 65)]),
        json.dumps([entry(username=".carol")]),
        json.dumps([entry(username="car ol")]),
        json.dumps([entry(username="carol\n")]),
        json.dumps([entry(username="cärol")]),
        json.dumps([entry(username=7)]),
        json.dumps([entry(role="root")]),
        json.dumps([entry(role="Admin")]),  # roles are lowercase only
        json.dumps([entry(role="")]),
        json.dumps([entry(role=None)]),
        json.dumps([entry(password_hash="plaintext-password")]),
        json.dumps([entry(password_hash="scrypt$1024$8$1$AAAA$AAAA")]),
        json.dumps([entry(password_hash=None)]),
        json.dumps([entry(), entry(role="admin")]),  # duplicate username
        json.dumps([entry(username=f"user{i:03d}") for i in range(51)]),  # more than 50 users
    ],
)
def test_malformed_user_configuration_is_rejected_without_echoing_it(users):
    with pytest.raises(AuthConfigurationError) as raised:
        config_for(users=users)
    assert raised.value.code == "AUTH_CONFIGURATION_INVALID"
    assert_safe(raised.value, "plaintext-password", "scrypt$1024", cheap_hash().split("$")[-1], users if len(users) > 6 else "\0")


def test_a_valid_configuration_loads_every_user_with_the_right_role():
    config = config_for(users=json.dumps([entry(username="viewer.one", role="viewer"), entry(username="ops_2", role="operator"), entry(username="root-admin", role="admin")]))
    assert {name: user.role for name, user in config.users.items()} == {"viewer.one": Role.VIEWER, "ops_2": Role.OPERATOR, "root-admin": Role.ADMIN}
    assert config.token_ttl_seconds == 3600


def test_the_token_lifetime_defaults_to_60_minutes_and_is_bounded():
    assert Settings().auth_token_ttl_minutes == 60
    assert config_for(auth_token_ttl_minutes=5).token_ttl_seconds == 300
    assert config_for(auth_token_ttl_minutes=720).token_ttl_seconds == 43200
    for invalid in (0, 4, 721, -1):
        with pytest.raises(ValidationError):
            Settings(auth_token_ttl_minutes=invalid)


def test_configuration_is_parsed_once_per_distinct_value_and_failures_are_not_cached():
    settings = settings_for()
    assert load_auth_config(settings) is load_auth_config(settings)
    assert load_auth_config(settings_for(users=users_json(("dave", "viewer")))) is not load_auth_config(settings)
    for _ in range(2):
        with pytest.raises(AuthConfigurationError):
            load_auth_config(settings_for(secret="short"))


def test_secrets_never_appear_in_reprs_or_settings_output():
    settings = settings_for()
    config = load_auth_config(settings)
    issued = issue_token(config, config.users["alice"], now=NOW)
    password_hash = config.users["alice"].password_hash
    for text in (repr(settings), str(settings), repr(config), repr(config.users["alice"]), repr(issued), str(issued)):
        assert SECRET not in text and password_hash not in text and issued.token not in text
    assert "alice" in repr(config.users["alice"])  # non-sensitive fields stay useful for debugging


def test_usernames_are_looked_up_case_insensitively_and_trimmed():
    config = config_for()
    assert config.find_user("ALICE").username == "alice" and config.find_user("  Alice \n").username == "alice"
    assert config.find_user("nobody") is None
    for value in (None, 5, b"alice", ["alice"], ""):
        assert config.find_user(value) is None


@pytest.mark.parametrize("name", ["abc", "a.b", "user_name-01", "a" * 64, "0day", "x1."])
def test_valid_usernames(name):
    assert is_valid_username(name)


@pytest.mark.parametrize(
    "name",
    ["", "ab", "a" * 65, "Alice", "-abc", ".abc", "_abc", "ab c", "abc\n", "abc ", "ab@c", "añb", "\u212Aevin", "ａｌｉｃｅ", None, 7, b"abc"],
)
def test_invalid_usernames(name):
    assert not is_valid_username(name)


# --- login-name normalization (M1) -----------------------------------------------------------------------------------


@pytest.mark.parametrize(
    ("typed", "expected"),
    [("alice", "alice"), ("ALICE", "alice"), ("Alice", "alice"), ("  Alice \n", "alice"), ("\tAlice\r\n", "alice"), ("\x0bAlice\x0c", "alice"), ("a.B_c-D", "a.b_c-d")],
)
def test_ascii_names_are_trimmed_of_ascii_whitespace_and_lowercased(typed, expected):
    config = config_for()
    assert normalize_username(typed) == expected
    assert config.find_user(typed) is (config.users["alice"] if expected == "alice" else None)


@pytest.mark.parametrize(
    "typed",
    [
        "\u212Aevin",  # KELVIN SIGN: .lower() would turn it into the ASCII letter "k"
        "\u00a0alice\u00a0",  # no-break space padding
        "\u2003alice",  # em space
        "alice\u3000",  # ideographic space
        "\u200balice",  # zero-width space
        "ａｌｉｃｅ",  # full-width letters
        "alicé",
        "ALİCE",  # dotted capital I
        "al\u0131ce",  # dotless i
        "ali\ud800ce",  # lone surrogate
    ],
)
def test_non_ascii_login_names_match_no_user(typed):
    users = json.dumps([
        {"username": "kevin", "role": "admin", "password_hash": cheap_hash()},
        {"username": "alice", "role": "viewer", "password_hash": cheap_hash()},
    ])
    config = config_for(users=users)
    assert normalize_username(typed) is None
    assert config.find_user(typed) is None


def test_the_kelvin_sign_can_no_longer_alias_a_user():
    config = config_for(users=json.dumps([{"username": "kevin", "role": "admin", "password_hash": cheap_hash()}]))
    assert "\u212Aevin".lower() == "kevin"  # the hazard: Unicode lowercasing yields ASCII
    assert config.find_user("\u212Aevin") is None and normalize_username("\u212Aevin") is None
    assert config.find_user("KEVIN") is config.users["kevin"]


@pytest.mark.parametrize("typed", [None, 5, b"alice", ["alice"], object()])
def test_non_text_login_names_normalize_to_none(typed):
    assert normalize_username(typed) is None and config_for().find_user(typed) is None


def test_only_ascii_whitespace_is_trimmed_and_inner_characters_are_kept():
    config = config_for()
    assert normalize_username("ali ce") == "ali ce" and config.find_user("ali ce") is None
    assert normalize_username("ali\x00ce") == "ali\x00ce" and config.find_user("ali\x00ce") is None
    assert normalize_username("") == "" and config.find_user("") is None
    assert normalize_username(" \t\r\n\x0b\x0c ") == ""


def test_configured_usernames_must_still_be_lowercase_ascii():
    for username in ("Alice", "\u212Aevin", "alicé"):
        with pytest.raises(AuthConfigurationError):
            config_for(users=json.dumps([entry(username=username)]))


# --- roles -----------------------------------------------------------------------------------------------------------


@pytest.mark.parametrize(
    ("actual", "minimum", "allowed"),
    [
        ("viewer", "viewer", True), ("viewer", "operator", False), ("viewer", "admin", False),
        ("operator", "viewer", True), ("operator", "operator", True), ("operator", "admin", False),
        ("admin", "viewer", True), ("admin", "operator", True), ("admin", "admin", True),
        (Role.OPERATOR, Role.VIEWER, True), (Role.VIEWER, Role.ADMIN, False),
    ],
)
def test_role_ordering(actual, minimum, allowed):
    assert role_allows(actual, minimum) is allowed


@pytest.mark.parametrize("unknown", ["root", "Admin", "", None, 3])
def test_an_unknown_actual_role_is_never_allowed_and_an_unknown_requirement_is_an_error(unknown):
    assert role_allows(unknown, "viewer") is False
    with pytest.raises(ValueError):
        role_allows("admin", unknown)


# --- tokens ----------------------------------------------------------------------------------------------------------


def test_a_token_round_trips_with_the_documented_claims():
    config = config_for()
    issued = issue_token(config, config.users["alice"], now=NOW)
    claims = verify_token(config, issued.token, now=NOW + 10)

    assert claims == issued.claims
    assert (claims.version, claims.username, claims.claimed_role) == (1, "alice", Role.ADMIN)
    assert (claims.issued_at, claims.expires_at) == (NOW, NOW + 3600)
    assert set(payload_of(issued.token)) == {"v", "sub", "role", "iat", "exp", "jti"}
    assert payload_of(issued.token)["role"] == "admin" and len(claims.token_id) >= 16


def test_every_token_has_a_unique_id():
    config = config_for()
    ids = {issue_token(config, config.users["bob"], now=NOW).claims.token_id for _ in range(50)}
    assert len(ids) == 50


def test_the_token_lifetime_follows_the_configuration():
    config = config_for(auth_token_ttl_minutes=10)
    issued = issue_token(config, config.users["bob"], now=NOW)
    assert issued.claims.expires_at - issued.claims.issued_at == 600
    verify_token(config, issued.token, now=NOW + 599)
    with pytest.raises(ExpiredTokenError):
        verify_token(config, issued.token, now=NOW + 600)


def test_expiry_is_exclusive_at_the_exact_second():
    config = config_for()
    token = issue_token(config, config.users["alice"], now=NOW).token
    assert verify_token(config, token, now=NOW + 3599.9).username == "alice"
    for later in (NOW + 3600, NOW + 3601, NOW + 10**6):
        with pytest.raises(ExpiredTokenError) as raised:
            verify_token(config, token, now=later)
        assert raised.value.code == "TOKEN_EXPIRED" and isinstance(raised.value, TokenError)


def test_a_token_issued_in_the_future_is_rejected_beyond_a_small_clock_skew():
    config = config_for()
    token = issue_token(config, config.users["alice"], now=NOW).token
    assert verify_token(config, token, now=NOW - 5).username == "alice"  # within the skew allowance
    for earlier in (NOW - 6, NOW - 3600, NOW - 10**6):
        with pytest.raises(FutureTokenError) as raised:
            verify_token(config, token, now=earlier)
        assert raised.value.code == "TOKEN_NOT_YET_VALID"


def test_a_token_signed_with_another_secret_is_rejected():
    config = config_for()
    foreign = issue_token(config_for(secret=OTHER_SECRET), config.users["alice"], now=NOW).token
    with pytest.raises(InvalidSignatureError) as raised:
        verify_token(config, foreign, now=NOW)
    assert raised.value.code == "TOKEN_SIGNATURE_INVALID"
    assert_safe(raised.value, SECRET, OTHER_SECRET, foreign)


def test_changing_any_part_of_a_signed_token_invalidates_it():
    config = config_for()
    token = issue_token(config, config.users["bob"], now=NOW).token
    payload, signature = token.split(".")

    def flip(text: str, index: int) -> str:
        return text[:index] + ("A" if text[index] != "A" else "B") + text[index + 1:]

    tampered = [f"{flip(payload, 5)}.{signature}", f"{payload}.{flip(signature, 5)}", f"{payload}.{flip(signature, len(signature) - 1)}"]
    # Escalation attempt: a viewer's token whose payload claims the admin role, keeping the viewer's signature.
    claims = payload_of(token)
    claims["role"] = "admin"
    tampered.append(f"{b64(json.dumps(claims, separators=(',', ':'), sort_keys=True).encode())}.{signature}")
    # Extending the lifetime of a genuine token.
    claims = payload_of(token)
    claims["exp"] += 10**6
    tampered.append(f"{b64(json.dumps(claims).encode())}.{signature}")
    for candidate in tampered:
        with pytest.raises(TokenError) as raised:
            verify_token(config, candidate, now=NOW)
        assert isinstance(raised.value, (InvalidSignatureError, MalformedTokenError))
        assert_safe(raised.value, candidate, signature)
    assert not any(authenticate_ok(config, candidate) for candidate in tampered)


def authenticate_ok(config: AuthConfig, token: str) -> bool:
    try:
        authenticate_token(config, token, now=NOW)
    except TokenError:
        return False
    return True


@pytest.mark.parametrize(
    "token",
    [None, 123, b"abc.def", ["a", "b"], "", ".", "abc", "a.b.c", ".sig", "payload.", " . ", "abc.def ", "ab c.def", "a+b.c/d", "abc=.def", "é.é", "x" * 2049, "a.b\n", "\x00.\x00"],
)
def test_malformed_tokens_are_rejected_without_echoing_them(token):
    with pytest.raises(MalformedTokenError) as raised:
        verify_token(config_for(), token, now=NOW)
    assert raised.value.code == "TOKEN_MALFORMED" and str(raised.value) == "The token is malformed."


def test_the_signature_is_checked_before_the_payload_is_read():
    # Unsigned garbage in the payload position must fail on the signature, never reach JSON parsing.
    encoded = b64(b"\xff\xfe not json")
    with pytest.raises(InvalidSignatureError):
        verify_token(config_for(), f"{encoded}.{sign(encoded, OTHER_SECRET)}", now=NOW)


@pytest.mark.parametrize(
    "payload",
    [
        "not json",
        "[1, 2, 3]",
        "null",
        '"alice"',
        "[" * 5000 + "]" * 5000,  # deeply nested
        '{"v": 1, "sub": "alice", "role": "admin", "iat": NaN, "exp": Infinity, "jti": "abcdefghijklmnopqrstuv"}',
        {k: v for k, v in good_payload().items() if k != "jti"},  # missing claim
        {**good_payload(), "extra": "claim"},  # unexpected claim
        good_payload(v="1"),
        good_payload(v=1.0),
        good_payload(v=True),
        good_payload(sub="Alice"),
        good_payload(sub="al"),
        good_payload(sub=["alice"]),
        good_payload(role="root"),
        good_payload(role="ADMIN"),
        good_payload(role=1),
        good_payload(iat="1700000000"),
        good_payload(iat=NOW + 0.5),
        good_payload(iat=True),
        good_payload(iat=-5),
        good_payload(exp=str(NOW + 3600)),
        good_payload(exp=NOW),  # expires at issue time
        good_payload(exp=NOW - 1),  # expires before issue
        good_payload(exp=NOW + 720 * 60 + 1),  # longer than any allowed lifetime
        good_payload(jti="short"),
        good_payload(jti="has spaces in it, too long to pass"),
        good_payload(jti=None),
    ],
)
def test_correctly_signed_tokens_with_invalid_claims_are_malformed(payload):
    with pytest.raises(MalformedTokenError):
        verify_token(config_for(), forge(payload), now=NOW + 1)


def test_a_signed_token_with_another_version_is_unsupported_not_malformed():
    for version in (0, 2, 99, -1):
        with pytest.raises(UnsupportedTokenVersionError) as raised:
            verify_token(config_for(), forge(good_payload(v=version)), now=NOW + 1)
        assert raised.value.code == "TOKEN_VERSION_UNSUPPORTED"
    # A future version may carry different claims; it is still reported as an unsupported version.
    with pytest.raises(UnsupportedTokenVersionError):
        verify_token(config_for(), forge({"v": 2, "something": "else"}), now=NOW + 1)


def test_an_independently_forged_token_in_the_documented_format_is_accepted():
    claims = verify_token(config_for(), forge(good_payload()), now=NOW + 1)
    assert (claims.username, claims.claimed_role, claims.expires_at) == ("alice", Role.ADMIN, NOW + 3600)


def test_a_non_canonical_payload_encoding_is_rejected():
    encoded = b64(json.dumps(good_payload()).encode())
    padded = encoded + "=" * (-len(encoded) % 4)
    if padded != encoded:
        with pytest.raises(MalformedTokenError):
            verify_token(config_for(), f"{padded}.{sign(padded)}", now=NOW + 1)


def test_error_messages_are_fixed_text_that_never_contain_token_or_secret():
    config = config_for()
    token = issue_token(config, config.users["alice"], now=NOW).token
    cases = [
        (ExpiredTokenError, token, NOW + 10**6),
        (FutureTokenError, token, NOW - 10**6),
        (InvalidSignatureError, token[:-3] + "AAA" if not token.endswith("AAA") else token[:-3] + "BBB", NOW),
        (MalformedTokenError, "not-a-token", NOW),
    ]
    for expected, candidate, when in cases:
        with pytest.raises(expected) as raised:
            verify_token(config, candidate, now=when)
        assert_safe(raised.value, token, token.split(".")[0], token.split(".")[1], SECRET, "alice")


# --- principals follow the current configuration ---------------------------------------------------------------------


def test_the_principal_comes_from_the_configured_user():
    config = config_for()
    token = issue_token(config, config.users["alice"], now=NOW).token
    assert authenticate_token(config, token, now=NOW + 1) == Principal(username="alice", role=Role.ADMIN)


def test_a_changed_role_applies_to_existing_tokens_and_the_token_claim_is_not_trusted():
    before = config_for(users=users_json(("alice", "viewer")))
    token = issue_token(before, before.users["alice"], now=NOW).token
    assert authenticate_token(before, token, now=NOW + 1).role is Role.VIEWER
    after = config_for(users=users_json(("alice", "admin")))  # restart with a promoted user
    assert authenticate_token(after, token, now=NOW + 1).role is Role.ADMIN
    demoted = config_for(users=users_json(("alice", "viewer")))
    admin_token = issue_token(after, after.users["alice"], now=NOW).token
    assert authenticate_token(demoted, admin_token, now=NOW + 1).role is Role.VIEWER


def test_a_user_removed_from_the_configuration_is_rejected_even_with_a_genuine_token():
    config = config_for()
    token = issue_token(config, config.users["bob"], now=NOW).token
    remaining = config_for(users=users_json(("alice", "admin")))
    with pytest.raises(UnknownUserError) as raised:
        authenticate_token(remaining, token, now=NOW + 1)
    assert raised.value.code == "TOKEN_USER_UNKNOWN" and isinstance(raised.value, TokenError)


def test_changing_the_secret_invalidates_every_token():
    config = config_for()
    token = issue_token(config, config.users["alice"], now=NOW).token
    with pytest.raises(InvalidSignatureError):
        authenticate_token(config_for(secret=OTHER_SECRET), token, now=NOW + 1)


def test_the_clock_defaults_to_real_time():
    config = config_for()
    token = issue_token(config, config.users["alice"]).token
    assert verify_token(config, token).username == "alice"
    with pytest.raises(ExpiredTokenError):
        verify_token(config, issue_token(config, config.users["alice"], now=1_000_000).token)


# --- token lifetime follows the current configuration (L2) -----------------------------------------------------------


def test_a_token_longer_lived_than_the_current_configuration_is_rejected_after_the_lifetime_is_shortened():
    long_config = config_for(auth_token_ttl_minutes=720)
    token = issue_token(long_config, long_config.users["alice"], now=NOW).token
    assert verify_token(long_config, token, now=NOW + 60).username == "alice"  # fine while 720 minutes is configured

    short_config = config_for(auth_token_ttl_minutes=5)  # the lifetime is shortened and the application restarted
    for when in (NOW + 1, NOW + 60, NOW + 299, NOW + 3 * 3600, NOW + 10**6):  # at any time, expired or not
        with pytest.raises(TokenLifetimeError) as raised:
            verify_token(short_config, token, now=when)
        assert raised.value.code == "TOKEN_LIFETIME_EXCEEDED" and isinstance(raised.value, TokenError)
        assert_safe(raised.value, token, SECRET)
    with pytest.raises(TokenLifetimeError):
        authenticate_token(short_config, token, now=NOW + 60)


def test_the_lifetime_limit_is_inclusive_and_one_second_more_is_rejected():
    config = config_for()  # 60 minutes
    assert verify_token(config, forge(good_payload(exp=NOW + 3600)), now=NOW + 1).username == "alice"
    assert verify_token(config, forge(good_payload(exp=NOW + 60)), now=NOW + 1).username == "alice"  # shorter is always fine
    with pytest.raises(TokenLifetimeError):  # not "malformed": it is below the absolute cap, just longer than configured
        verify_token(config, forge(good_payload(exp=NOW + 3601)), now=NOW + 1)


def test_tokens_issued_under_a_shorter_lifetime_stay_valid_when_the_lifetime_is_lengthened():
    short = config_for(auth_token_ttl_minutes=5)
    token = issue_token(short, short.users["alice"], now=NOW).token
    longer = config_for(auth_token_ttl_minutes=60)
    assert verify_token(longer, token, now=NOW + 299).username == "alice"
    with pytest.raises(ExpiredTokenError):  # its own, shorter expiry still applies
        verify_token(longer, token, now=NOW + 300)


def test_expiry_and_future_issue_checks_still_apply_within_the_configured_lifetime():
    config = config_for(auth_token_ttl_minutes=5)
    token = issue_token(config, config.users["alice"], now=NOW).token
    assert verify_token(config, token, now=NOW + 299).username == "alice"
    with pytest.raises(ExpiredTokenError):
        verify_token(config, token, now=NOW + 300)
    with pytest.raises(FutureTokenError):
        verify_token(config, token, now=NOW - 6)


def test_the_absolute_lifetime_cap_still_rejects_oversized_lifetimes_as_malformed():
    with pytest.raises(MalformedTokenError):
        verify_token(config_for(auth_token_ttl_minutes=720), forge(good_payload(exp=NOW + 720 * 60 + 1)), now=NOW + 1)


# --- the token's claimed role has no authority (L3) ------------------------------------------------------------------


def test_token_claims_carry_the_role_only_under_the_name_claimed_role():
    config = config_for()
    token = issue_token(config, config.users["alice"], now=NOW).token
    claims = verify_token(config, token, now=NOW + 1)
    field_names = {item.name for item in dataclasses.fields(auth.TokenClaims)}

    assert claims.claimed_role is Role.ADMIN
    assert "claimed_role" in field_names and "role" not in field_names
    assert not hasattr(claims, "role")  # nothing can read an authoritative-looking role off the claims
    assert payload_of(token)["role"] == "admin"  # the wire format is unchanged


def test_a_signed_token_claiming_a_higher_role_does_not_raise_the_principals_role():
    config = config_for()  # bob is a viewer
    token = forge(good_payload(sub="bob", role="admin"))
    assert verify_token(config, token, now=NOW + 1).claimed_role is Role.ADMIN  # what the token says
    principal = authenticate_token(config, token, now=NOW + 1)
    assert principal == Principal(username="bob", role=Role.VIEWER)
    assert role_allows(principal.role, "viewer") and not role_allows(principal.role, "operator")


def test_a_signed_token_claiming_a_lower_role_does_not_reduce_the_principals_role():
    config = config_for()  # alice is an admin
    principal = authenticate_token(config, forge(good_payload(sub="alice", role="viewer")), now=NOW + 1)
    assert principal == Principal(username="alice", role=Role.ADMIN)


def test_authenticate_token_never_reads_the_claimed_role_and_principals_have_no_claims():
    tree = ast.parse(textwrap.dedent(inspect.getsource(authenticate_token)))
    attributes = {node.attr for node in ast.walk(tree) if isinstance(node, ast.Attribute)}
    assert "claimed_role" not in attributes and "role" in attributes  # the role comes from the configured user
    assert [item.name for item in dataclasses.fields(Principal)] == ["username", "role"]


def test_no_other_application_module_uses_the_claimed_role():
    offenders = [
        path.name for path in (BACKEND_DIR / "app").glob("*.py") if path.name != "auth.py" and "claimed_role" in path.read_text(encoding="utf-8")
    ]
    assert offenders == []


# --- AUTH_SECRET encoding (L4) ---------------------------------------------------------------------------------------


@pytest.mark.parametrize(
    "secret",
    ["abcdefghijklmnopqrstuvwxyz\ud800012345", "\udfff" + SECRET[1:], SECRET[:20] + "\ud83d" + SECRET[20:], SECRET + "\udc00"],
)
def test_a_secret_with_an_unencodable_character_is_a_fixed_message_configuration_error(secret):
    with pytest.raises(AuthConfigurationError) as raised:
        config_for(secret=secret)
    error = raised.value
    assert not isinstance(error, UnicodeError) and error.code == "AUTH_CONFIGURATION_INVALID"
    assert str(error) == "AUTH_SECRET contains a character that cannot be encoded as text."
    assert error.__cause__ is None and error.__suppress_context__  # the UnicodeEncodeError (which names the character) is dropped
    assert_safe(error, secret, "ud800", "udfff")


def test_a_valid_non_ascii_secret_is_accepted_and_encoded_as_utf8():
    secret = "clé-secrète-日本語-🔒-abcdefghijklmnop-0123456789"
    assert config_for(secret=secret).secret == secret.encode("utf-8")


# --- duplicate keys in AUTH_USERS_JSON (L5) --------------------------------------------------------------------------


def raw_object(*pairs: tuple[str, object]) -> str:
    """JSON text with the keys exactly as given, including repeats (a dict could not express them)."""
    return "{" + ",".join(f"{json.dumps(key)}:{json.dumps(value)}" for key, value in pairs) + "}"


@pytest.mark.parametrize("duplicated", ["username", "role", "password_hash"])
@pytest.mark.parametrize("second_value", ["same", "different"])
def test_a_repeated_key_in_a_user_object_is_rejected(duplicated, second_value):
    password_hash = cheap_hash()
    pairs = [("username", "alice"), ("role", "viewer"), ("password_hash", password_hash)]
    first = dict(pairs)[duplicated]
    other = {"username": "mallory", "role": "admin", "password_hash": cheap_hash("another password")}[duplicated]
    pairs.append((duplicated, first if second_value == "same" else other))
    with pytest.raises(AuthConfigurationError) as raised:
        config_for(users="[" + raw_object(*pairs) + "]")
    assert str(raised.value) == "AUTH_USERS_JSON must not repeat a key within an object."
    assert_safe(raised.value, password_hash)


def test_a_repeated_key_is_rejected_wherever_it_occurs():
    password_hash = cheap_hash()
    valid = [("username", "alice"), ("role", "viewer"), ("password_hash", password_hash)]
    second_user = raw_object(("username", "bob"), ("role", "admin"), ("role", "viewer"), ("password_hash", password_hash))
    nested = raw_object(*valid, ("extra", {"a": 1}))
    nested = nested[:-1] + ',"extra":{"a":1,"a":2}}'  # a duplicate nested inside an otherwise unexpected key
    for users in (f"[{raw_object(*valid)},{second_user}]", f"[{nested}]"):
        with pytest.raises(AuthConfigurationError):
            config_for(users=users)


def test_the_same_key_names_in_different_user_objects_are_fine():
    password_hash = cheap_hash()
    users = "[" + ",".join(raw_object(("username", name), ("role", "viewer"), ("password_hash", password_hash)) for name in ("alice", "bob")) + "]"
    assert sorted(config_for(users=users).users) == ["alice", "bob"]


# --- one definition of the token lifetime bounds (L8) ----------------------------------------------------------------


def test_the_token_lifetime_bounds_are_defined_once_and_shared():
    from app import config as config_module

    assert (auth.MIN_TOKEN_TTL_MINUTES, auth.MAX_TOKEN_TTL_MINUTES) == (config_module.AUTH_TOKEN_TTL_MIN_MINUTES, config_module.AUTH_TOKEN_TTL_MAX_MINUTES) == (5, 720)
    assert Settings().auth_token_ttl_minutes == config_module.AUTH_TOKEN_TTL_DEFAULT_MINUTES == 60
    low, high = config_module.AUTH_TOKEN_TTL_MIN_MINUTES, config_module.AUTH_TOKEN_TTL_MAX_MINUTES
    for accepted in (low, high):
        assert Settings(auth_token_ttl_minutes=accepted).auth_token_ttl_minutes == accepted
    for rejected in (low - 1, high + 1):
        with pytest.raises(ValidationError):
            Settings(auth_token_ttl_minutes=rejected)


def test_the_auth_module_applies_the_same_bounds_even_if_settings_validation_is_bypassed():
    for bypassed in (4, 721, 0, -1):
        settings = settings_for()
        settings.auth_token_ttl_minutes = bypassed  # pydantic does not validate assignment
        with pytest.raises(AuthConfigurationError) as raised:
            load_auth_config(settings)
        assert "token lifetime" in str(raised.value)


# --- the cached user table is read-only (L-A) ------------------------------------------------------------------------


def test_the_cached_user_table_cannot_be_mutated_and_later_loads_are_unaffected():
    settings = settings_for()
    config = load_auth_config(settings)
    expected = {"alice": Role.ADMIN, "bob": Role.VIEWER}
    intruder = AuthUser("mallory", Role.ADMIN, cheap_hash())

    assert isinstance(config.users, MappingProxyType)
    with pytest.raises(TypeError):
        config.users["mallory"] = intruder  # add a user
    with pytest.raises(TypeError):
        config.users["bob"] = AuthUser("bob", Role.ADMIN, cheap_hash())  # promote an existing user
    with pytest.raises(TypeError):
        del config.users["alice"]  # remove a user
    for method in ("update", "pop", "popitem", "setdefault", "clear"):
        assert not hasattr(config.users, method)
    with pytest.raises(dataclasses.FrozenInstanceError):
        config.users = {"mallory": intruder}  # the attribute itself cannot be replaced either
    with pytest.raises(dataclasses.FrozenInstanceError):
        config.token_ttl_seconds = 10**9

    assert {name: user.role for name, user in config.users.items()} == expected
    again = load_auth_config(settings)  # the cached object, as every later caller receives it
    assert again is config and {name: user.role for name, user in again.users.items()} == expected
    assert "mallory" not in again.users and again.find_user("mallory") is None


def test_a_copy_of_the_user_table_is_independent_of_the_cached_one():
    settings = settings_for()
    config = load_auth_config(settings)
    copy = config.users.copy()
    copy["mallory"] = AuthUser("mallory", Role.ADMIN, cheap_hash())
    copy.pop("alice")
    assert sorted(config.users) == ["alice", "bob"] and sorted(load_auth_config(settings).users) == ["alice", "bob"]


def test_a_failed_attempt_to_add_a_user_does_not_make_that_users_tokens_valid():
    config = config_for()
    with pytest.raises(TypeError):
        config.users["mallory"] = AuthUser("mallory", Role.ADMIN, cheap_hash())
    token = forge(good_payload(sub="mallory", role="admin"))  # genuinely signed, but mallory is not configured
    with pytest.raises(UnknownUserError):
        authenticate_token(config, token, now=NOW + 1)


def test_read_access_to_the_user_table_still_works():
    config = config_for()
    assert "alice" in config.users and len(config.users) == 2 and sorted(config.users) == ["alice", "bob"]
    assert config.users["alice"].role is Role.ADMIN and config.users.get("nobody") is None
    assert config.find_user("ALICE") is config.users["alice"]
    assert "password" not in repr(config) and cheap_hash().split("$")[-1] not in repr(config)


# --- a non-finite verification time is refused (L-B) -----------------------------------------------------------------


@pytest.mark.parametrize("bad_now", [float("nan"), float("inf"), float("-inf"), -float("nan")], ids=["nan", "+inf", "-inf", "-nan"])
def test_a_non_finite_verification_time_is_rejected_instead_of_accepting_every_token(bad_now):
    config = config_for()
    genuine = issue_token(config, config.users["alice"], now=NOW).token
    expired = forge(good_payload(iat=NOW - 7200, exp=NOW - 3600))  # signed, within the configured lifetime, long expired
    for token in (genuine, expired):
        with pytest.raises(InvalidClockError) as raised:
            verify_token(config, token, now=bad_now)
        assert raised.value.code == "AUTH_CLOCK_INVALID" and str(raised.value) == "The verification time must be a finite number."
        assert isinstance(raised.value, auth.AuthError) and not isinstance(raised.value, TokenError)
        assert_safe(raised.value, token, SECRET)
    with pytest.raises(InvalidClockError):
        authenticate_token(config, genuine, now=bad_now)


def test_the_clock_is_validated_before_the_token_is_examined():
    config = config_for()
    for token in ("not-a-token", None, "", 12345):
        with pytest.raises(InvalidClockError):
            verify_token(config, token, now=float("nan"))


@pytest.mark.parametrize("bad_now", ["1700000000", b"1700000000", True, False, [NOW], 10**400, -(10**400), object()])
def test_other_unusable_verification_times_are_rejected_too(bad_now):
    config = config_for()
    token = issue_token(config, config.users["alice"], now=NOW).token
    with pytest.raises(InvalidClockError):
        verify_token(config, token, now=bad_now)


def test_finite_integer_and_float_times_and_the_default_clock_still_work():
    config = config_for()
    token = issue_token(config, config.users["alice"], now=NOW).token
    assert verify_token(config, token, now=NOW + 1).username == "alice"
    assert verify_token(config, token, now=float(NOW + 1)).username == "alice"
    assert verify_token(config, token, now=NOW + 0.5).username == "alice"
    with pytest.raises(ExpiredTokenError):
        verify_token(config, token, now=float(NOW + 3600))
    assert verify_token(config, issue_token(config, config.users["alice"]).token).username == "alice"  # now=None
    assert verify_token(config, issue_token(config, config.users["alice"]).token, now=None).username == "alice"


# --- integer and float cache keys do not alias (typed cache) ---------------------------------------------------------


def test_the_configuration_cache_is_typed():
    assert auth._load.cache_parameters()["typed"] is True


def test_an_integer_lifetime_in_the_cache_is_not_returned_for_the_equal_float():
    users = users_json(("alice", "admin"))
    cached = auth._load(SECRET, users, 60)
    assert auth._load(SECRET, users, 60) is cached  # same typed arguments share an entry
    with pytest.raises(AuthConfigurationError) as raised:
        auth._load(SECRET, users, 60.0)  # equal to 60 but not an int: must be validated, not served from the cache
    assert "token lifetime" in str(raised.value)
    assert auth._load(SECRET, users, 60) is cached  # the valid entry is unaffected


def test_a_float_lifetime_is_rejected_even_when_the_equal_integer_was_loaded_first_and_last():
    for order in ("int-first", "float-first"):
        clear_auth_config_cache()
        users = users_json(("alice", "admin"))
        if order == "int-first":
            assert auth._load(SECRET, users, 60).token_ttl_seconds == 3600
        with pytest.raises(AuthConfigurationError):
            auth._load(SECRET, users, 60.0)
        assert auth._load(SECRET, users, 60).token_ttl_seconds == 3600
        with pytest.raises(AuthConfigurationError):
            auth._load(SECRET, users, 60.0)


def test_the_same_holds_through_load_auth_config_when_settings_validation_is_bypassed():
    settings = settings_for()
    assert load_auth_config(settings).token_ttl_seconds == 3600
    settings.auth_token_ttl_minutes = 60.0  # pydantic does not validate assignment
    with pytest.raises(AuthConfigurationError):
        load_auth_config(settings)
    settings.auth_token_ttl_minutes = True
    with pytest.raises(AuthConfigurationError):
        load_auth_config(settings)
    settings.auth_token_ttl_minutes = 60
    assert load_auth_config(settings).token_ttl_seconds == 3600


# --- command line helper ---------------------------------------------------------------------------------------------


class Console:
    def __init__(self, *passwords: str):
        self.answers = iter(passwords)
        self.out: list[str] = []
        self.err: list[str] = []

    def run(self, *argv: str) -> int:
        return auth.main(list(argv), prompt=lambda _label: next(self.answers), out=self.out.append, err=self.err.append)


def test_generate_secret_prints_a_new_strong_secret_each_time():
    first, second = Console(), Console()
    assert first.run("generate-secret") == 0 and second.run("generate-secret") == 0
    secrets_printed = [first.out[0], second.out[0]]
    assert secrets_printed[0] != secrets_printed[1]
    for value in secrets_printed:
        assert len(value) >= 43
        config_for(secret=value)  # accepted by the configuration validator
    assert first.err == []


def test_hash_password_prints_a_hash_that_verifies_and_never_prints_the_password():
    console = Console("a long enough passphrase", "a long enough passphrase")
    assert console.run("hash-password") == 0
    assert verify_password("a long enough passphrase", console.out[0]) is True
    assert "a long enough passphrase" not in " ".join(console.out + console.err)


def test_hash_password_can_print_a_complete_users_entry_that_the_validator_accepts():
    console = Console("another long passphrase", "another long passphrase")
    assert console.run("hash-password", "--username", "ops.team", "--role", "operator") == 0
    entry_json = console.out[0]
    config = config_for(users="[" + entry_json + "]")
    assert config.users["ops.team"].role is Role.OPERATOR
    assert verify_password("another long passphrase", config.users["ops.team"].password_hash)
    assert any("AUTH_USERS_JSON" in line for line in console.err)  # guidance goes to stderr, data to stdout


def test_hash_password_refuses_mismatched_or_short_passwords_without_printing_a_hash():
    mismatch = Console("a long enough passphrase", "a different passphrase!")
    assert mismatch.run("hash-password") == 1 and mismatch.out == []
    short = Console("tooshort", "tooshort")
    assert short.run("hash-password") == 1 and short.out == []
    assert "tooshort" not in " ".join(short.out + short.err)


@pytest.mark.parametrize(
    "argv",
    [
        ["hash-password", "--username", "alice"],  # username without role
        ["hash-password", "--role", "admin"],  # role without username
        ["hash-password", "--username", "Alice", "--role", "admin"],  # invalid username
        ["hash-password", "--username", "alice", "--role", "root"],  # invalid role
        ["unknown-command"],
        [],
    ],
)
def test_invalid_cli_arguments_exit_with_the_argparse_error_code(argv):
    with pytest.raises(SystemExit) as raised:
        Console("a long enough passphrase", "a long enough passphrase").run(*argv)
    assert raised.value.code == 2


def test_the_module_runs_as_a_script_without_importing_the_database():
    code = (
        "import sys, runpy; "
        "sys.argv = ['app.auth', 'generate-secret']; "
        "import app.auth; "
        "print('database-imported=' + str('app.database' in sys.modules))"
    )
    result = subprocess.run([sys.executable, "-c", code], cwd=BACKEND_DIR, capture_output=True, text=True, timeout=60)
    assert result.returncode == 0 and result.stdout.strip() == "database-imported=False"
    script = subprocess.run([sys.executable, "-m", "app.auth", "generate-secret"], cwd=BACKEND_DIR, capture_output=True, text=True, timeout=60)
    assert script.returncode == 0 and len(script.stdout.strip()) >= 43 and script.stderr == ""
