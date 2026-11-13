"""Authentication API (B3 stage 2): ``POST /auth/login`` and ``GET /auth/me``.

This module holds the login endpoints, the login throttle, the bearer-token dependency (``current_principal``) and the
role dependencies (``require_viewer`` / ``require_operator`` / ``require_admin``) that ``app.main`` puts on every route.

Security properties, in the order a login request meets them:

* Not configured: ``503 AUTH_NOT_CONFIGURED`` (the same answer for a missing and for an invalid configuration; the
  specific reason is logged, never returned).
* Throttle first: five failed attempts per (client address, normalized username) and twenty per client address within
  300 seconds. A limited request is refused with ``429`` and ``Retry-After`` *before* any password work. Every attempt is
  counted when it starts, not when it fails, so any number of simultaneous attempts cannot exceed the limit; a successful
  login gives its own attempt back and clears the (address, username) counter.
* Uniform work: the password is always checked with ``verify_password`` against either the configured user's hash or
  one fixed dummy hash, so unknown, malformed and non-ASCII usernames cost the same as a wrong password and the response
  never says which part was wrong. The dummy result can never authenticate anyone.
* Throttle keys use ``normalize_username``; every name that is not plain ASCII shares one "invalid" bucket per address,
  so spelling variants (case, whitespace, Unicode look-alikes) cannot spread attempts across buckets. IPv6 clients are
  bucketed by /64 and IPv4-mapped IPv6 addresses count as their IPv4 address.
* Audit: successful logins and lockouts are recorded in ``audit_events``. Messages contain only the client address and a
  *configured* username (never an attempted one), and never a password, hash, secret or token.
* No token is issued unless the successful-login audit record was stored.
* A request that cannot be read as a login (not JSON, not an object, a field of the wrong type, undecodable bytes) never
  reaches the handler and is answered by ``_AuthRoute`` with a fixed ``422 INVALID_REQUEST``. FastAPI's own validation
  response echoes the offending input, which for a login can be the whole body, password included, so it is never sent.
  The configuration check still comes first (an unconfigured server answers 503 to every login request, malformed or not).
  Malformed requests do no password work and are not counted by the throttle, since they cannot be used to guess.

Known limits: throttle state is per process and in memory (it resets on restart and is not shared between instances),
and the client address is whatever the ASGI server reports (behind a proxy that is the proxy until forwarded headers are
configured).
"""
from __future__ import annotations

import asyncio
import ipaddress
import logging
import math
import threading
import time
from collections import OrderedDict, deque
from collections.abc import Awaitable, Callable
from dataclasses import dataclass

from fastapi import APIRouter, Depends, HTTPException, Request, Response, status
from fastapi.exceptions import RequestValidationError
from fastapi.routing import APIRoute
from fastapi.security import HTTPBearer
from pydantic import BaseModel, ConfigDict
from sqlalchemy.ext.asyncio import AsyncSession
from starlette.exceptions import HTTPException as StarletteHTTPException

from app.auth import (
    AuthConfig,
    AuthConfigurationError,
    Principal,
    Role,
    TokenError,
    authenticate_token,
    issue_token,
    load_auth_config,
    normalize_username,
    role_allows,
    verify_password,
)
from app.config import get_settings
from app.database import AuditEvent, get_session

logger = logging.getLogger("cloudrescue.auth")

LOGIN_PAIR_LIMIT = 5  # failed attempts per (client address, normalized username)
LOGIN_IP_LIMIT = 20  # failed attempts per client address
LOGIN_WINDOW_SECONDS = 300
MAX_TRACKED_ENTRIES = 10_000  # per table; bounds the throttle's memory
MAX_USERNAME_CHARS = 256  # longer names are treated as invalid (and never stored as throttle keys)
MAX_CONCURRENT_VERIFICATIONS = 4  # scrypt is memory hungry (about 16 MiB each at the default cost)

# The password this hash was made from was random and discarded. Same scrypt cost as the CLI-generated hashes
# (N=16384, r=8, p=1) so checking against it takes as long as checking a real user. If a configured hash uses a different
# cost, a login for that user takes a different time than the dummy; the cost floor is enforced with the deployment work.
DUMMY_PASSWORD_HASH = "scrypt$16384$8$1$BZbC781d4aHXnqNlBLEN6Q$ETADuAC0ACghlsF5YezPr33_rpDF9idyUIAjzEJ40sI"

AUDIT_LOGIN = "auth.login"
AUDIT_LOGIN_LOCKED = "auth.login_locked"

_now = time.monotonic  # the throttle clock; tests replace it


# --- client identity -------------------------------------------------------------------------------------------------


def client_key(host: str | None) -> str:
    """A stable throttle key for a client address: one spelling per client, IPv6 grouped by /64."""
    if not host:
        return "unknown"
    try:
        address = ipaddress.ip_address(host)
    except ValueError:
        return host[:64]
    if isinstance(address, ipaddress.IPv6Address):
        if address.ipv4_mapped is not None:
            return str(address.ipv4_mapped)
        return "v6:" + str(ipaddress.ip_network((address, 64), strict=False))
    return str(address)


# --- throttle --------------------------------------------------------------------------------------------------------


@dataclass(frozen=True)
class LoginAttempt:
    """One counted attempt, returned by ``LoginThrottle.reserve``."""

    ip: str
    name: str | None
    at: float
    reached_pair_limit: bool  # this attempt brought the (address, username) count to the limit
    reached_ip_limit: bool  # this attempt brought the address count to the limit


class LoginThrottle:
    """Sliding-window limits on failed logins, kept in memory with a hard bound on the number of tracked keys.

    All methods are synchronous and never await, so inside one event loop each call is atomic. ``name`` is the
    normalized username, or ``None`` for every name that is not plain ASCII (one shared bucket).
    """

    SWEEP_INTERVAL_SECONDS = 60.0

    def __init__(
        self,
        *,
        pair_limit: int = LOGIN_PAIR_LIMIT,
        ip_limit: int = LOGIN_IP_LIMIT,
        window: float = float(LOGIN_WINDOW_SECONDS),
        max_entries: int = MAX_TRACKED_ENTRIES,
    ):
        self.pair_limit, self.ip_limit, self.window, self.max_entries = pair_limit, ip_limit, window, max_entries
        self._pairs: OrderedDict[tuple[str, str | None], deque[float]] = OrderedDict()
        self._ips: OrderedDict[str, deque[float]] = OrderedDict()
        self._last_sweep: float | None = None

    def _expire(self, entries: deque[float], now: float) -> None:
        cutoff = now - self.window
        while entries and entries[0] <= cutoff:
            entries.popleft()

    def retry_after(self, ip: str, name: str | None, now: float) -> int | None:
        """Whole seconds until another attempt is allowed, or None if this client may try now."""
        waits: list[float] = []
        for table, key, limit in ((self._pairs, (ip, name), self.pair_limit), (self._ips, ip, self.ip_limit)):
            entries = table.get(key)
            if entries is None:
                continue
            self._expire(entries, now)
            if not entries:
                del table[key]
            elif len(entries) >= limit:
                waits.append(entries[0] + self.window - now)
        return max(1, math.ceil(max(waits))) if waits else None

    def reserve(self, ip: str, name: str | None, now: float) -> LoginAttempt:
        """Count an attempt that is about to be checked. Call ``retry_after`` first, without awaiting in between."""
        if self._last_sweep is None or now - self._last_sweep >= self.SWEEP_INTERVAL_SECONDS:
            self.sweep(now)
        pair = self._entries(self._pairs, (ip, name), self.pair_limit, now)
        by_ip = self._entries(self._ips, ip, self.ip_limit, now)
        pair.append(now)
        by_ip.append(now)
        return LoginAttempt(ip, name, now, len(pair) == self.pair_limit, len(by_ip) == self.ip_limit)

    def _entries(self, table: OrderedDict, key, limit: int, now: float) -> deque[float]:
        entries = table.get(key)
        if entries is not None:
            table.move_to_end(key)
            self._expire(entries, now)
            return entries
        if len(table) >= self.max_entries:
            self.sweep(now)
            while len(table) >= self.max_entries:
                table.popitem(last=False)  # least recently used; bounded memory beats perfect recall
        entries = table[key] = deque(maxlen=limit)
        return entries

    def release(self, attempt: LoginAttempt) -> None:
        """A successful login: forget its own count and clear the (address, username) failures."""
        self._pairs.pop((attempt.ip, attempt.name), None)
        entries = self._ips.get(attempt.ip)
        if entries is not None:
            try:
                entries.remove(attempt.at)
            except ValueError:
                pass
            if not entries:
                del self._ips[attempt.ip]

    def sweep(self, now: float) -> None:
        """Drop every expired entry (and every key left empty)."""
        self._last_sweep = now
        for table in (self._pairs, self._ips):
            for key in [key for key, entries in table.items() if self._prune(entries, now)]:
                del table[key]

    def _prune(self, entries: deque[float], now: float) -> bool:
        self._expire(entries, now)
        return not entries

    def size(self) -> tuple[int, int]:
        return len(self._pairs), len(self._ips)


login_throttle = LoginThrottle()

# --- request / response models ---------------------------------------------------------------------------------------


class LoginRequest(BaseModel):
    """Both fields default to empty so that a missing field is an ordinary failed login (401), not a 422.

    A default 422 would echo the request body in its ``input`` detail, which could include the password. Lengths are
    checked in the handler for the same reason, and requests that still fail validation (wrong types, not an object) get
    the fixed response from ``_AuthRoute`` instead of FastAPI's.
    """

    model_config = ConfigDict(extra="ignore")

    username: str = ""
    password: str = ""


class LoginResponse(BaseModel):
    access_token: str
    token_type: str = "bearer"
    expires_in: int  # seconds
    expires_at: int  # Unix time, seconds
    username: str
    role: str


class MeResponse(BaseModel):
    username: str
    role: str


# --- shared helpers --------------------------------------------------------------------------------------------------

_reported_configuration_problems: set[str] = set()
_NO_STORE = {"Cache-Control": "no-store", "Pragma": "no-cache"}


def _require_configuration() -> AuthConfig:
    try:
        return load_auth_config()
    except AuthConfigurationError as error:
        # The message is fixed text and safe to log. Logged once per distinct problem so a misconfigured deployment does
        # not fill the log with one line per request.
        problem = f"{error.code}: {error}"
        if problem not in _reported_configuration_problems:
            _reported_configuration_problems.add(problem)
            logger.error("Authentication is unavailable (%s)", problem)
        raise HTTPException(
            status_code=status.HTTP_503_SERVICE_UNAVAILABLE,
            detail={"code": "AUTH_NOT_CONFIGURED", "message": "Authentication is not configured."},
        ) from None


def _invalid_credentials() -> HTTPException:
    return HTTPException(
        status_code=status.HTTP_401_UNAUTHORIZED,
        detail={"code": "INVALID_CREDENTIALS", "message": "Invalid username or password."},
        headers={"WWW-Authenticate": "Bearer"},
    )


def _unauthenticated() -> HTTPException:
    return HTTPException(
        status_code=status.HTTP_401_UNAUTHORIZED,
        detail={"code": "UNAUTHENTICATED", "message": "Authentication is required, or the credentials are not valid."},
        headers={"WWW-Authenticate": "Bearer"},
    )


def _invalid_request() -> HTTPException:
    """The only answer to a malformed request: fixed text, never the input, the field names or the parser's complaint."""
    return HTTPException(
        status_code=status.HTTP_422_UNPROCESSABLE_ENTITY,
        detail={"code": "INVALID_REQUEST", "message": "The request is not a valid login request."},
    )


def _too_many_attempts(retry_after: int) -> HTTPException:
    return HTTPException(
        status_code=status.HTTP_429_TOO_MANY_REQUESTS,
        detail={"code": "TOO_MANY_ATTEMPTS", "message": "Too many failed login attempts. Try again later."},
        headers={"Retry-After": str(retry_after)},
    )


_verification_slots = threading.BoundedSemaphore(MAX_CONCURRENT_VERIFICATIONS)


async def _verify(password: str, stored_hash: str) -> bool:
    """Run ``verify_password`` off the event loop, at most a few at a time.

    Waiting is done with short sleeps (not by blocking a worker thread), and the same call is made for every login
    whether or not the username exists.
    """
    while not _verification_slots.acquire(blocking=False):
        await asyncio.sleep(0.005)
    try:
        return await asyncio.to_thread(verify_password, password, stored_hash)
    finally:
        _verification_slots.release()


async def _audit(session: AsyncSession, events: list[tuple[str, str]]) -> None:
    for event_type, message in events:
        session.add(AuditEvent(event_type=event_type, message=message, is_demo=get_settings().demo_mode))
    await session.commit()


def _bearer_token(request: Request) -> str | None:
    """The token from a single ``Authorization: Bearer <token>`` header, or None if it is absent or not of that form."""
    values = request.headers.getlist("authorization")
    if len(values) != 1:
        return None
    parts = values[0].split(" ")
    if len(parts) != 2 or parts[0].lower() != "bearer" or not parts[1]:
        return None
    return parts[1]


# Only declares the bearer scheme so the OpenAPI document (and /docs) offer an "Authorize" button. The header is read and
# checked by ``current_principal`` itself; with ``auto_error=False`` this never rejects anything.
_bearer_scheme = HTTPBearer(auto_error=False, description="Signed access token from POST /api/v1/auth/login")


async def current_principal(request: Request, _declared_scheme=Depends(_bearer_scheme)) -> Principal:
    """FastAPI dependency: the authenticated caller, resolved from the *current* configuration.

    Every failure to authenticate (no header, wrong scheme, malformed, tampered, expired, over-long lifetime, removed
    user) gets the same 401; the specific reason goes to the log as a fixed code.
    """
    config = _require_configuration()
    token = _bearer_token(request)
    if token is None:
        raise _unauthenticated()
    try:
        return authenticate_token(config, token)
    except TokenError as error:
        logger.info("Bearer token rejected (%s)", error.code)
        raise _unauthenticated() from None


# --- role based access -----------------------------------------------------------------------------------------------


def _forbidden() -> HTTPException:
    return HTTPException(
        status_code=status.HTTP_403_FORBIDDEN,
        detail={"code": "FORBIDDEN", "message": "You do not have permission to perform this action."},
    )


def require_role(minimum: Role | str):
    """FastAPI dependency factory: the caller must be authenticated and hold at least the ``minimum`` role.

    Order of answers: 503 if authentication is not configured, 401 if there is no valid bearer token (or its user was
    removed), 403 if the user's *current configured* role is lower than ``minimum``. Roles are ordered viewer < operator <
    admin, so an admin passes every check. The returned dependency yields the ``Principal`` (username and role come from
    the server's configuration, never from the request), and carries ``required_role`` so a route's policy can be read
    back from the dependency tree (the route inventory test does exactly that).
    """
    required = Role(minimum)

    async def dependency(principal: Principal = Depends(current_principal)) -> Principal:
        if not role_allows(principal.role, required):
            # Fixed text in the response; the log names the user and the roles, never a token.
            logger.warning("Access denied for %s (%s): %s role required", principal.username, principal.role.value, required.value)
            raise _forbidden()
        return principal

    dependency.__name__ = f"require_{required.value}"
    dependency.required_role = required  # type: ignore[attr-defined]
    return dependency


require_viewer = require_role(Role.VIEWER)  # any signed-in user: reads
require_operator = require_role(Role.OPERATOR)  # operational actions: investigate, acknowledge, execute recovery
require_admin = require_role(Role.ADMIN)  # configuration, simulation and fault controls, approval and rejection


# --- routes ----------------------------------------------------------------------------------------------------------


class _AuthRoute(APIRoute):
    """Replaces FastAPI's request-validation response, which echoes the submitted input, with a fixed one.

    FastAPI reads and validates the body before the handler runs, and reports a problem as ``RequestValidationError``
    (wrong type, not an object, invalid JSON) or, for bytes the JSON parser cannot handle at all, as a 400
    ``HTTPException``. Both are caught here, before they can become a response. The configuration check runs first so that
    an unconfigured server answers 503 whatever was sent, then the fixed 422 is raised. Nothing from the exception (its
    ``input``, ``loc``, ``msg`` or ``ctx``) is kept, logged or chained.
    """

    def get_route_handler(self) -> Callable[[Request], Awaitable[Response]]:
        original = super().get_route_handler()

        async def handler(request: Request) -> Response:
            try:
                return await original(request)
            except RequestValidationError:
                pass  # malformed: answered below, outside the except block so that nothing is chained to the error
            except StarletteHTTPException as error:  # FastAPI raises Starlette's class, not its own subclass
                if error.status_code != status.HTTP_400_BAD_REQUEST:
                    raise  # the handler's own 401 / 429 / 503 answers
            _require_configuration()  # raises the 503 when authentication is unusable
            raise _invalid_request()

        return handler


router = APIRouter(prefix="/auth", tags=["authentication"], route_class=_AuthRoute)


@router.post(
    "/login",
    response_model=LoginResponse,
    responses={
        401: {"description": "Invalid credentials"},
        422: {"description": "Malformed request (fixed response; the input is never echoed)"},
        429: {"description": "Too many failed attempts"},
        503: {"description": "Authentication is not configured"},
    },
)
async def login(
    payload: LoginRequest,
    request: Request,
    response: Response,
    session: AsyncSession = Depends(get_session),
) -> LoginResponse:
    config = _require_configuration()
    ip = client_key(request.client.host if request.client else None)
    name = normalize_username(payload.username) if len(payload.username) <= MAX_USERNAME_CHARS else None

    now = _now()
    retry_after = login_throttle.retry_after(ip, name, now)
    if retry_after is not None:
        raise _too_many_attempts(retry_after)
    attempt = login_throttle.reserve(ip, name, now)  # no await since retry_after: the count cannot be overshot

    user = config.users.get(name) if name is not None else None
    stored_hash = user.password_hash if user is not None else DUMMY_PASSWORD_HASH
    password_matches = await _verify(payload.password, stored_hash)

    if user is None or not password_matches:
        who = user.username if user is not None else "<unknown>"
        logger.warning("Login failed for %s from %s", who, ip)
        events: list[tuple[str, str]] = []
        if attempt.reached_pair_limit:
            events.append((AUDIT_LOGIN_LOCKED, f"Login locked for {who} from {ip}: {LOGIN_PAIR_LIMIT} failed attempts within {LOGIN_WINDOW_SECONDS} seconds."))
        if attempt.reached_ip_limit:
            events.append((AUDIT_LOGIN_LOCKED, f"Login locked for address {ip}: {LOGIN_IP_LIMIT} failed attempts within {LOGIN_WINDOW_SECONDS} seconds."))
        if events:
            try:
                await _audit(session, events)
            except Exception as error:  # a failed audit write must not turn a refused login into a server error
                await session.rollback()
                logger.error("Could not store the login lockout audit record (%s)", type(error).__name__)
        raise _invalid_credentials()

    # No token without a stored audit record: if this raises, the caller gets a 500 and no token.
    await _audit(session, [(AUDIT_LOGIN, f"User {user.username} logged in from {ip}.")])
    login_throttle.release(attempt)
    issued = issue_token(config, user)
    response.headers.update(_NO_STORE)
    return LoginResponse(
        access_token=issued.token,
        expires_in=issued.claims.expires_at - issued.claims.issued_at,
        expires_at=issued.claims.expires_at,
        username=user.username,
        role=user.role.value,
    )


@router.get("/me", response_model=MeResponse)
async def me(response: Response, principal: Principal = Depends(current_principal)) -> MeResponse:
    response.headers.update(_NO_STORE)
    return MeResponse(username=principal.username, role=principal.role.value)
