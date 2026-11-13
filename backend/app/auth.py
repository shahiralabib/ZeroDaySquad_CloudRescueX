"""Authentication primitives: password hashing, signed bearer tokens and validated auth configuration.

This module is deliberately self-contained (standard library only) and has no database access, no web framework
imports and no side effects at import time, so it can also run as a small command line helper::

    python -m app.auth generate-secret
    python -m app.auth hash-password [--username NAME --role viewer|operator|admin]

Nothing here is wired into the API yet. Design notes:

* Passwords are hashed with scrypt and stored as ``scrypt$N$r$p$salt$digest`` (unpadded base64url). Verification
  recomputes the digest with the stored parameters and compares in constant time.
* A bearer token is ``<payload>.<signature>``: the payload is compact JSON (``v``, ``sub``, ``role``, ``iat``, ``exp``,
  ``jti``) and the signature is HMAC-SHA256 over the encoded payload. The signature is verified, in constant time,
  before the payload is parsed. There is no algorithm header, so there is nothing to downgrade.
* ``verify_token`` only validates a token's *claims* (signature, structure, version, lifetime, time window). Its result
  carries the role the token *claims* (``TokenClaims.claimed_role``), which is informational and must never decide
  access. ``authenticate_token`` is the authorization entry point: it verifies the token, then resolves the user and
  role from the current configuration and returns a ``Principal``.
* A token's lifetime (``exp - iat``) may not exceed the currently configured lifetime, so shortening
  ``AUTH_TOKEN_TTL_MINUTES`` takes effect, at the next restart, for tokens that were issued with a longer lifetime.
* The user list and secret come from ``AUTH_USERS_JSON`` and ``AUTH_SECRET`` and are validated strictly. They are
  parsed once per distinct value and cached, so a running process uses the configuration it started with; a changed
  configuration takes effect when the application restarts. The role that applies to a request comes from the
  configured user (``authenticate_token``), never from the token's own role claim.
* Login names are ASCII only. A typed name is trimmed of ASCII whitespace and lowercased; any non-ASCII input matches
  no user, so look-alike characters (for example the Kelvin sign, which lowercases to ``k``) can never alias a user.
* Every error carries a fixed message and a stable ``code``. Messages never contain the secret, a password, a hash or
  any part of a token, so they are safe to log.
"""
from __future__ import annotations

import argparse
import base64
import binascii
import getpass
import hashlib
import hmac
import json
import math
import re
import secrets
import sys
import time
from collections.abc import Callable, Mapping, Sequence
from dataclasses import dataclass, field
from enum import StrEnum
from functools import lru_cache
from types import MappingProxyType

from app.config import AUTH_TOKEN_TTL_MAX_MINUTES, AUTH_TOKEN_TTL_MIN_MINUTES, Settings, get_settings

# --- errors ----------------------------------------------------------------------------------------------------------


class AuthError(Exception):
    """Base class. ``code`` is stable and machine readable; the message is fixed text that never echoes input."""

    code = "AUTH_ERROR"


class AuthConfigurationError(AuthError):
    """The authentication configuration is invalid."""

    code = "AUTH_CONFIGURATION_INVALID"


class AuthNotConfiguredError(AuthConfigurationError):
    """Neither AUTH_SECRET nor AUTH_USERS_JSON is set."""

    code = "AUTH_NOT_CONFIGURED"


class PasswordHashError(AuthError):
    """A stored password hash is malformed or uses parameters outside the accepted range."""

    code = "PASSWORD_HASH_INVALID"


class InvalidPasswordError(AuthError):
    """A password cannot be hashed (empty, too long or not encodable)."""

    code = "PASSWORD_INVALID"


class InvalidClockError(AuthError):
    """The time supplied for token verification is not a finite number (a programming error, not a bad token)."""

    code = "AUTH_CLOCK_INVALID"


class TokenError(AuthError):
    """A bearer token was rejected."""

    code = "INVALID_TOKEN"


class MalformedTokenError(TokenError):
    code = "TOKEN_MALFORMED"


class InvalidSignatureError(TokenError):
    code = "TOKEN_SIGNATURE_INVALID"


class UnsupportedTokenVersionError(TokenError):
    code = "TOKEN_VERSION_UNSUPPORTED"


class ExpiredTokenError(TokenError):
    code = "TOKEN_EXPIRED"


class FutureTokenError(TokenError):
    code = "TOKEN_NOT_YET_VALID"


class TokenLifetimeError(TokenError):
    """The token's lifetime is longer than the currently configured token lifetime allows."""

    code = "TOKEN_LIFETIME_EXCEEDED"


class UnknownUserError(TokenError):
    """The token is genuine but its user is no longer in the configuration."""

    code = "TOKEN_USER_UNKNOWN"


# --- roles and usernames ---------------------------------------------------------------------------------------------


class Role(StrEnum):
    VIEWER = "viewer"
    OPERATOR = "operator"
    ADMIN = "admin"


_ROLE_RANK = {Role.VIEWER: 1, Role.OPERATOR: 2, Role.ADMIN: 3}

# Lowercase only, so a username has exactly one spelling in the configuration, in tokens and in audit records.
USERNAME_PATTERN = re.compile(r"[a-z0-9][a-z0-9._-]{2,63}")


def role_allows(actual: Role | str, minimum: Role | str) -> bool:
    """True if ``actual`` is at least as privileged as ``minimum``. An unknown ``actual`` role is never allowed."""
    try:
        needed = _ROLE_RANK[Role(minimum)]
    except ValueError:
        raise ValueError("Unknown minimum role.") from None
    try:
        held = _ROLE_RANK[Role(actual)]
    except ValueError:
        return False
    return held >= needed


def is_valid_username(value: object) -> bool:
    return isinstance(value, str) and USERNAME_PATTERN.fullmatch(value) is not None


_ASCII_WHITESPACE = " \t\n\r\x0b\x0c"


def normalize_username(value: object) -> str | None:
    """How a typed login name is matched against configured usernames (which are lowercase ASCII).

    Only ASCII text is accepted: anything else returns None and matches no user. Non-ASCII input is refused *before*
    any case mapping because Unicode lowercasing can produce ASCII (``"\\u212a"``, the Kelvin sign, becomes ``"k"``), and
    Unicode whitespace such as a non-breaking space must not be silently trimmed. Only ASCII whitespace is stripped.
    """
    if not isinstance(value, str) or not value.isascii():
        return None
    return value.strip(_ASCII_WHITESPACE).lower()


# --- base64url helpers -----------------------------------------------------------------------------------------------

_B64URL = re.compile(r"[A-Za-z0-9_-]+")


def _b64e(data: bytes) -> str:
    return base64.urlsafe_b64encode(data).rstrip(b"=").decode("ascii")


def _b64d(text: str) -> bytes:
    """Strict unpadded base64url: only the URL-safe alphabet, and only the canonical encoding of the bytes."""
    if not isinstance(text, str) or not _B64URL.fullmatch(text):
        raise ValueError("not base64url")
    try:
        raw = base64.urlsafe_b64decode(text + "=" * (-len(text) % 4))
    except (binascii.Error, ValueError):
        raise ValueError("not base64url") from None
    if _b64e(raw) != text:
        raise ValueError("non-canonical base64url")
    return raw


# --- passwords -------------------------------------------------------------------------------------------------------

SCRYPT_N = 16384  # about 45 ms on a development machine; N=32768 exceeds Python's default scrypt memory limit
SCRYPT_R = 8
SCRYPT_P = 1
SCRYPT_SALT_BYTES = 16
SCRYPT_KEY_BYTES = 32
MAX_PASSWORD_CHARS = 256
_SCRYPT_MAXMEM = 128 * 1024 * 1024
_SCRYPT_N_EXPONENTS = range(10, 16)  # N = 2**10 .. 2**15
_SCRYPT_R_RANGE = range(1, 17)
_SCRYPT_P_RANGE = range(1, 5)
_SALT_BYTES_RANGE = range(16, 65)
_KEY_BYTES_RANGE = range(16, 65)
_MAX_HASH_CHARS = 512


@dataclass(frozen=True)
class _ScryptHash:
    n: int
    r: int
    p: int
    salt: bytes = field(repr=False)
    digest: bytes = field(repr=False)


def _check_scrypt_cost(n: int, r: int, p: int) -> bool:
    return (
        type(n) is int and type(r) is int and type(p) is int
        and n > 0 and n & (n - 1) == 0 and n.bit_length() - 1 in _SCRYPT_N_EXPONENTS
        and r in _SCRYPT_R_RANGE and p in _SCRYPT_P_RANGE
    )


def _password_bytes(password: object) -> bytes | None:
    """The UTF-8 bytes to hash, or None if the value cannot be a password."""
    if not isinstance(password, str) or not 1 <= len(password) <= MAX_PASSWORD_CHARS:
        return None
    try:
        return password.encode("utf-8")
    except UnicodeEncodeError:
        return None


def hash_password(password: str, *, n: int = SCRYPT_N, r: int = SCRYPT_R, p: int = SCRYPT_P) -> str:
    """Hash a password with a fresh random salt. The cost parameters are stored in the result."""
    data = _password_bytes(password)
    if data is None:
        raise InvalidPasswordError(f"A password must be 1 to {MAX_PASSWORD_CHARS} characters of valid text.")
    if not _check_scrypt_cost(n, r, p):
        raise PasswordHashError("The scrypt cost parameters are outside the accepted range.")
    salt = secrets.token_bytes(SCRYPT_SALT_BYTES)
    digest = hashlib.scrypt(data, salt=salt, n=n, r=r, p=p, dklen=SCRYPT_KEY_BYTES, maxmem=_SCRYPT_MAXMEM)
    return f"scrypt${n}${r}${p}${_b64e(salt)}${_b64e(digest)}"


def parse_password_hash(stored: str) -> _ScryptHash:
    """Strictly parse a stored hash; any deviation from the format raises ``PasswordHashError``."""
    invalid = PasswordHashError("The stored password hash is malformed or uses unsupported parameters.")
    if not isinstance(stored, str) or not stored.isascii() or len(stored) > _MAX_HASH_CHARS:
        raise invalid
    parts = stored.split("$")
    # The cost parameters must be plain canonical decimal numbers (ASCII digits, no sign, no leading zeros).
    if len(parts) != 6 or parts[0] != "scrypt" or not all(part.isdigit() and str(int(part)) == part for part in parts[1:4]):
        raise invalid
    n, r, p = int(parts[1]), int(parts[2]), int(parts[3])
    if not _check_scrypt_cost(n, r, p):
        raise invalid
    try:
        salt, digest = _b64d(parts[4]), _b64d(parts[5])
    except ValueError:
        raise invalid from None
    if len(salt) not in _SALT_BYTES_RANGE or len(digest) not in _KEY_BYTES_RANGE:
        raise invalid
    return _ScryptHash(n, r, p, salt, digest)


def verify_password(password: str, stored_hash: str) -> bool:
    """True if ``password`` matches ``stored_hash``. The digest comparison is constant time.

    A password that cannot be valid (wrong type, empty, longer than ``MAX_PASSWORD_CHARS``) is rejected without running
    scrypt. A malformed ``stored_hash`` raises ``PasswordHashError`` because it is a configuration fault, not a wrong
    password.
    """
    expected = parse_password_hash(stored_hash)
    data = _password_bytes(password)
    if data is None:
        return False
    derived = hashlib.scrypt(
        data, salt=expected.salt, n=expected.n, r=expected.r, p=expected.p, dklen=len(expected.digest), maxmem=_SCRYPT_MAXMEM
    )
    return hmac.compare_digest(derived, expected.digest)


# --- configuration ---------------------------------------------------------------------------------------------------

MIN_SECRET_CHARS = 32
MIN_SECRET_DISTINCT_CHARS = 10  # a sanity guard against obvious placeholders, not an entropy measure
MAX_USERS = 50
MIN_TOKEN_TTL_MINUTES = AUTH_TOKEN_TTL_MIN_MINUTES  # defined once, in app.config, with the settings validation
MAX_TOKEN_TTL_MINUTES = AUTH_TOKEN_TTL_MAX_MINUTES
_USER_KEYS = frozenset({"username", "role", "password_hash"})


@dataclass(frozen=True)
class AuthUser:
    username: str
    role: Role
    password_hash: str = field(repr=False)


@dataclass(frozen=True)
class AuthConfig:
    secret: bytes = field(repr=False)
    # Read-only: configurations are cached and shared, so a caller must not be able to add, replace or remove a user.
    users: Mapping[str, AuthUser]
    token_ttl_seconds: int

    def find_user(self, username: object) -> AuthUser | None:
        """Case-insensitive lookup of a typed login name; None if unknown, not text, or not ASCII."""
        normalized = normalize_username(username)
        return None if normalized is None else self.users.get(normalized)


def _reject_duplicate_keys(pairs: list[tuple[str, object]]) -> dict[str, object]:
    """``json`` keeps the last of two equal keys silently; a repeated key here is a configuration mistake."""
    keys = [key for key, _ in pairs]
    if len(keys) != len(set(keys)):
        raise AuthConfigurationError("AUTH_USERS_JSON must not repeat a key within an object.")
    return dict(pairs)


def _parse_users(users_json: str) -> dict[str, AuthUser]:
    try:
        raw = json.loads(users_json, object_pairs_hook=_reject_duplicate_keys)
    except (ValueError, RecursionError):
        raise AuthConfigurationError("AUTH_USERS_JSON is not valid JSON.") from None
    if not isinstance(raw, list) or not raw:
        raise AuthConfigurationError("AUTH_USERS_JSON must be a non-empty JSON array of users.")
    if len(raw) > MAX_USERS:
        raise AuthConfigurationError(f"AUTH_USERS_JSON may list at most {MAX_USERS} users.")
    users: dict[str, AuthUser] = {}
    for index, entry in enumerate(raw, start=1):
        where = f"AUTH_USERS_JSON entry {index}"
        if not isinstance(entry, dict) or set(entry) != _USER_KEYS:
            raise AuthConfigurationError(f"{where} must be an object with exactly: username, role, password_hash.")
        username, role, password_hash = entry["username"], entry["role"], entry["password_hash"]
        if not is_valid_username(username):
            raise AuthConfigurationError(f"{where} has an invalid username (3-64 characters: a-z, 0-9, '.', '_', '-').")
        if not isinstance(role, str) or role not in {item.value for item in Role}:
            raise AuthConfigurationError(f"{where} has an invalid role (viewer, operator or admin).")
        try:
            parse_password_hash(password_hash)
        except PasswordHashError:
            raise AuthConfigurationError(f"{where} has an invalid password_hash.") from None
        if username in users:
            raise AuthConfigurationError(f"{where} repeats a username.")
        users[username] = AuthUser(username, Role(role), password_hash)
    return users


def _check_secret(secret: str) -> None:
    if not secret:
        raise AuthConfigurationError("AUTH_SECRET is not set.")
    if secret != secret.strip():
        raise AuthConfigurationError("AUTH_SECRET must not start or end with whitespace.")
    if len(secret) < MIN_SECRET_CHARS:
        raise AuthConfigurationError(f"AUTH_SECRET must be at least {MIN_SECRET_CHARS} characters.")
    if len(set(secret)) < MIN_SECRET_DISTINCT_CHARS:
        raise AuthConfigurationError("AUTH_SECRET is too repetitive to be a secure secret.")
    try:
        secret.encode("utf-8")
    except UnicodeEncodeError:
        # Fixed message on purpose: the encoding error itself names the offending character and its position.
        raise AuthConfigurationError("AUTH_SECRET contains a character that cannot be encoded as text.") from None


@lru_cache(maxsize=8, typed=True)  # typed: 60 and 60.0 (or True and 1) must not share a cache entry
def _load(secret: str, users_json: str, ttl_minutes: int) -> AuthConfig:
    if not secret.strip() and not users_json.strip():
        raise AuthNotConfiguredError("Authentication is not configured: set AUTH_SECRET and AUTH_USERS_JSON.")
    _check_secret(secret)
    if not users_json.strip():
        raise AuthConfigurationError("AUTH_USERS_JSON is not set.")
    if type(ttl_minutes) is not int or not MIN_TOKEN_TTL_MINUTES <= ttl_minutes <= MAX_TOKEN_TTL_MINUTES:
        raise AuthConfigurationError(
            f"The token lifetime must be {MIN_TOKEN_TTL_MINUTES} to {MAX_TOKEN_TTL_MINUTES} minutes."
        )
    users = MappingProxyType(_parse_users(users_json))  # the dict is referenced only by this read-only view
    return AuthConfig(secret=secret.encode("utf-8"), users=users, token_ttl_seconds=ttl_minutes * 60)


def load_auth_config(settings: Settings | None = None) -> AuthConfig:
    """Validated authentication configuration, parsed once per distinct configuration value.

    Raises ``AuthNotConfiguredError`` when nothing is configured and ``AuthConfigurationError`` when the configuration
    is invalid. Failures are not cached. The messages are safe to log.
    """
    active = settings or get_settings()
    return _load(active.auth_secret.get_secret_value(), active.auth_users_json.get_secret_value(), active.auth_token_ttl_minutes)


def clear_auth_config_cache() -> None:
    """Forget parsed configurations (used by tests; a running application restarts to pick up changes)."""
    _load.cache_clear()


# --- tokens ----------------------------------------------------------------------------------------------------------

TOKEN_VERSION = 1
CLOCK_SKEW_SECONDS = 5  # how far in the future a token's issue time may be (clock differences between instances)
MAX_TOKEN_CHARS = 2048
_MAX_TOKEN_LIFETIME_SECONDS = MAX_TOKEN_TTL_MINUTES * 60
_TOKEN_ID = re.compile(r"[A-Za-z0-9_-]{16,64}")
_CLAIM_KEYS = frozenset({"v", "sub", "role", "iat", "exp", "jti"})


@dataclass(frozen=True)
class TokenClaims:
    """What a verified token *says*. Nothing here is an authorization decision.

    ``claimed_role`` is the role written into the token when it was issued. It can be out of date (the configured role
    may have changed since) and it is deliberately not called ``role``: access decisions must use the ``Principal``
    returned by ``authenticate_token``, whose role comes from the current configuration.
    """

    version: int
    username: str
    claimed_role: Role
    issued_at: int
    expires_at: int
    token_id: str


@dataclass(frozen=True)
class IssuedToken:
    token: str = field(repr=False)
    claims: TokenClaims


@dataclass(frozen=True)
class Principal:
    """The authenticated caller, as established from the current configuration."""

    username: str
    role: Role


def _verification_time(now: object) -> float:
    """The clock for a verification: the real time, or an explicitly supplied finite number (used by tests).

    NaN compares false with everything, so a NaN clock would make every token look current; infinities would make every
    token look expired or not yet valid. Anything that is not a finite int or float is refused rather than guessed at.
    """
    if now is None:
        return time.time()
    if isinstance(now, bool) or not isinstance(now, (int, float)):
        raise InvalidClockError("The verification time must be a finite number.")
    try:
        finite = math.isfinite(now)
    except OverflowError:  # an int too large to convert to a float
        finite = False
    if not finite:
        raise InvalidClockError("The verification time must be a finite number.")
    return now


def _sign(secret: bytes, encoded_payload: str) -> bytes:
    return hmac.new(secret, encoded_payload.encode("ascii"), hashlib.sha256).digest()


def issue_token(config: AuthConfig, user: AuthUser, *, now: float | None = None) -> IssuedToken:
    """Sign a new bearer token for ``user`` that expires ``config.token_ttl_seconds`` after ``now``."""
    issued_at = int(time.time() if now is None else now)
    claims = TokenClaims(
        version=TOKEN_VERSION,
        username=user.username,
        claimed_role=user.role,
        issued_at=issued_at,
        expires_at=issued_at + config.token_ttl_seconds,
        token_id=secrets.token_urlsafe(16),
    )
    payload = {
        "v": claims.version,
        "sub": claims.username,
        "role": claims.claimed_role.value,
        "iat": claims.issued_at,
        "exp": claims.expires_at,
        "jti": claims.token_id,
    }
    encoded = _b64e(json.dumps(payload, separators=(",", ":"), sort_keys=True).encode("utf-8"))
    return IssuedToken(token=f"{encoded}.{_b64e(_sign(config.secret, encoded))}", claims=claims)


def verify_token(config: AuthConfig, token: object, *, now: float | None = None) -> TokenClaims:
    """Validate a token's claims and return them; raise a ``TokenError`` subclass otherwise.

    Checks, in order: shape, signature (constant time), payload structure and types, version, lifetime policy, then
    time. The payload is not parsed until the signature has been verified.

    This validates what the token *claims*; it is not an authorization decision. It does not check that the user still
    exists, and the returned ``claimed_role`` may be out of date. Use ``authenticate_token`` to obtain the
    ``Principal`` (current user, current configured role) that access decisions must be based on.

    ``now`` is for tests; it must be a finite number or ``InvalidClockError`` (not a ``TokenError``) is raised before
    the token is looked at.
    """
    current = _verification_time(now)
    if not isinstance(token, str) or not token or len(token) > MAX_TOKEN_CHARS:
        raise MalformedTokenError("The token is malformed.")
    parts = token.split(".")
    if len(parts) != 2 or not all(parts):
        raise MalformedTokenError("The token is malformed.")
    encoded_payload, encoded_signature = parts
    try:
        signature = _b64d(encoded_signature)
    except ValueError:
        raise MalformedTokenError("The token is malformed.") from None
    if not _B64URL.fullmatch(encoded_payload):
        raise MalformedTokenError("The token is malformed.")
    if not hmac.compare_digest(signature, _sign(config.secret, encoded_payload)):
        raise InvalidSignatureError("The token signature is not valid.")

    try:
        payload = json.loads(_b64d(encoded_payload).decode("utf-8"))
    except (ValueError, RecursionError):
        raise MalformedTokenError("The token is malformed.") from None
    if not isinstance(payload, dict) or type(payload.get("v")) is not int:
        raise MalformedTokenError("The token is malformed.")
    if payload["v"] != TOKEN_VERSION:  # checked first: a future version may legitimately carry different claims
        raise UnsupportedTokenVersionError("The token version is not supported.")
    if set(payload) != _CLAIM_KEYS:
        raise MalformedTokenError("The token is malformed.")
    username, role, issued_at, expires_at, token_id = payload["sub"], payload["role"], payload["iat"], payload["exp"], payload["jti"]
    if (
        not is_valid_username(username)
        or not isinstance(role, str) or role not in {item.value for item in Role}
        or type(issued_at) is not int or type(expires_at) is not int
        or not isinstance(token_id, str) or not _TOKEN_ID.fullmatch(token_id)
        or issued_at < 0 or not issued_at < expires_at <= issued_at + _MAX_TOKEN_LIFETIME_SECONDS
    ):
        raise MalformedTokenError("The token is malformed.")
    if expires_at - issued_at > config.token_ttl_seconds:
        # Genuine, but issued under a longer lifetime than is configured now (for example after the lifetime was
        # shortened). Rejected regardless of the clock so a lifetime change cannot be sidestepped by older tokens.
        raise TokenLifetimeError("The token's lifetime exceeds the configured token lifetime.")

    if issued_at > current + CLOCK_SKEW_SECONDS:
        raise FutureTokenError("The token was issued in the future.")
    if current >= expires_at:
        raise ExpiredTokenError("The token has expired.")
    return TokenClaims(TOKEN_VERSION, username, Role(role), issued_at, expires_at, token_id)


def authenticate_token(config: AuthConfig, token: object, *, now: float | None = None) -> Principal:
    """The authorization entry point: verify ``token`` and return the principal for its user *as currently configured*.

    The role is taken from the configuration, never from the token's ``claimed_role``, so a configured role change
    applies to existing tokens and a user removed from the configuration is rejected (``UnknownUserError``).
    """
    claims = verify_token(config, token, now=now)
    user = config.users.get(claims.username)
    if user is None:
        raise UnknownUserError("The token's user is not configured.")
    return Principal(username=user.username, role=user.role)


# --- command line helper ---------------------------------------------------------------------------------------------

CLI_MIN_PASSWORD_CHARS = 12


def main(
    argv: Sequence[str] | None = None,
    *,
    prompt: Callable[[str], str] = getpass.getpass,
    out: Callable[[str], None] = print,
    err: Callable[[str], None] | None = None,
) -> int:
    """``python -m app.auth``. Returns the process exit code (argument errors exit with 2 via argparse)."""
    report = err or (lambda message: print(message, file=sys.stderr))
    parser = argparse.ArgumentParser(
        prog="python -m app.auth", description="Helpers for configuring CloudRescueX authentication."
    )
    commands = parser.add_subparsers(dest="command", required=True)
    commands.add_parser("generate-secret", help="Print a new random value for AUTH_SECRET.")
    hasher = commands.add_parser(
        "hash-password",
        help="Prompt for a password and print its hash (or, with --username and --role, a complete AUTH_USERS_JSON entry).",
    )
    hasher.add_argument("--username", help="Lowercase login name (3-64 characters: a-z, 0-9, '.', '_', '-').")
    hasher.add_argument("--role", choices=[role.value for role in Role])
    args = parser.parse_args(argv)

    if args.command == "generate-secret":
        out(secrets.token_urlsafe(48))
        return 0

    if bool(args.username) != bool(args.role):
        parser.error("--username and --role must be given together.")
    if args.username and not is_valid_username(args.username):
        parser.error("--username must be 3-64 characters of a-z, 0-9, '.', '_' or '-', starting with a letter or digit.")
    password = prompt("Password: ")
    if password != prompt("Confirm password: "):
        report("The passwords do not match.")
        return 1
    if len(password) < CLI_MIN_PASSWORD_CHARS:
        report(f"Use a password of at least {CLI_MIN_PASSWORD_CHARS} characters.")
        return 1
    try:
        password_hash = hash_password(password)
    except InvalidPasswordError as error:
        report(str(error))
        return 1
    if args.username:
        out(json.dumps({"username": args.username, "role": args.role, "password_hash": password_hash}, separators=(",", ":")))
        report("Add this object to the AUTH_USERS_JSON array.")
    else:
        out(password_hash)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
