"""Gemini provider compatibility (B1): the SDK client must build, configuration failures must be provider errors,
and a provider failure must never leave an investigation stuck in "running".

Nothing here calls the Gemini API or needs a real key: the key is a fake string and socket connections are blocked.
Live Gemini calls are intentionally not tested (deferred).
"""
import builtins
import logging
import socket
from types import SimpleNamespace
from uuid import uuid4

import pytest
from httpx import ASGITransport, AsyncClient

from app import main as main_module
from app.ai import (
    AIProvider,
    AIProviderError,
    GeminiAuthenticationError,
    GeminiConfigurationError,
    GeminiProvider,
    InvestigationInput,
    LocalDemoProvider,
    MissingCredentialsError,
    ProviderStatus,
)
from app.config import Settings
from app.logging import JsonFormatter
from app.main import _request_windows, app

FAKE_KEY = "fake-key-not-a-real-credential"


@pytest.fixture(autouse=True)
def isolate(monkeypatch):
    _request_windows.clear()

    real_connect = socket.socket.connect

    # Loopback stays allowed because asyncio's event loop uses a loopback socket pair on Windows.
    def refuse_external(self, address, *args, **kwargs):
        host = address[0] if isinstance(address, tuple) else address
        if host not in {"127.0.0.1", "::1", "localhost"}:
            raise AssertionError(f"A network connection to {host} was attempted; these tests must not use the network.")
        return real_connect(self, address, *args, **kwargs)

    monkeypatch.setattr(socket.socket, "connect", refuse_external)


def settings(**overrides) -> Settings:
    values = {"gemini_api_key": FAKE_KEY, "gemini_model": "test-model"}
    values.update(overrides)
    return Settings(**values)


def evidence() -> InvestigationInput:
    return InvestigationInput.model_validate(
        {
            "service_metadata": {"name": "Demo API", "status": "unhealthy"},
            "health_checks": [{"evidence_id": "health_check:1", "status": "unhealthy", "error_message": "timeout"}],
            "available_recovery_actions": ["restart_demo_application"],
        }
    )


def break_http_options(monkeypatch) -> None:
    """Reproduce the original defect: pass the unsupported max_retries argument to the SDK's HttpOptions."""
    from google.genai import types

    original = types.HttpOptions
    monkeypatch.setattr(types, "HttpOptions", lambda **kwargs: original(**kwargs, max_retries=2))


# --- Client construction -----------------------------------------------------------------------------------------


def test_the_real_sdk_client_is_built_with_supported_options_and_without_network(monkeypatch):
    """Builds a real google-genai Client and checks the options handed to its public constructor.

    A spy records the keyword arguments and delegates to the real constructor, so the SDK still validates them. No
    private SDK attribute is read.
    """
    import google.genai as genai

    real_client = genai.Client
    captured: dict = {}

    def spy(**kwargs):
        captured.update(kwargs)
        return real_client(**kwargs)

    monkeypatch.setattr(genai, "Client", spy)
    client = GeminiProvider(settings(gemini_timeout_seconds=12))._client()

    options = captured["http_options"]
    assert isinstance(client, real_client)
    assert captured["api_key"] == FAKE_KEY
    assert options.timeout == 12000  # milliseconds
    assert options.retry_options.attempts == 1  # the provider's own loop is the single retry layer


def test_the_sdk_http_options_contract_has_retry_options_and_no_max_retries():
    from google.genai import types

    assert "max_retries" not in types.HttpOptions.model_fields
    assert "retry_options" in types.HttpOptions.model_fields
    with pytest.raises(Exception):
        types.HttpOptions(timeout=1000, max_retries=2)


def test_missing_credentials_are_reported_before_any_sdk_call():
    for empty in ({"gemini_api_key": ""}, {"gemini_model": ""}):
        with pytest.raises(MissingCredentialsError):
            GeminiProvider(settings(**empty))._client()


# --- SDK configuration failure -----------------------------------------------------------------------------------


def assert_configuration_error(error: GeminiConfigurationError) -> None:
    assert isinstance(error, AIProviderError)
    assert error.code == "GEMINI_CLIENT_ERROR"
    assert str(error) == "The Gemini client could not be configured."
    assert FAKE_KEY not in str(error)


def test_the_original_max_retries_defect_becomes_a_provider_error(monkeypatch):
    break_http_options(monkeypatch)
    with pytest.raises(GeminiConfigurationError) as raised:
        GeminiProvider(settings())._client()
    assert_configuration_error(raised.value)


def test_a_client_constructor_failure_becomes_a_provider_error_that_does_not_echo_the_key(monkeypatch):
    def failing_client(**_kwargs):
        raise RuntimeError(f"cannot build client for {FAKE_KEY}")

    monkeypatch.setattr("google.genai.Client", failing_client)
    with pytest.raises(GeminiConfigurationError) as raised:
        GeminiProvider(settings())._client()
    assert_configuration_error(raised.value)


def test_a_retry_options_failure_becomes_a_provider_error(monkeypatch):
    def failing_retry_options(**_kwargs):
        raise ValueError("unsupported retry option")

    monkeypatch.setattr("google.genai.types.HttpRetryOptions", failing_retry_options)
    with pytest.raises(GeminiConfigurationError) as raised:
        GeminiProvider(settings())._client()
    assert_configuration_error(raised.value)


def emitted(record: logging.LogRecord) -> str:
    """The line the application's JSON log formatter would actually write for this record."""
    return JsonFormatter().format(record)


def test_a_configuration_failure_logs_the_exception_class_but_never_its_message_or_traceback(monkeypatch, caplog):
    def failing_client(**_kwargs):
        raise RuntimeError(f"cannot build client for {FAKE_KEY}")

    monkeypatch.setattr("google.genai.Client", failing_client)
    with caplog.at_level(logging.INFO, logger="cloudrescue.ai"):
        with pytest.raises(GeminiConfigurationError):
            GeminiProvider(settings())._client()

    records = [record for record in caplog.records if record.name == "cloudrescue.ai"]
    assert len(records) == 1
    line = emitted(records[0])
    assert "RuntimeError" in line  # the diagnosing information is in the emitted message
    assert "Gemini client configuration failed" in line
    assert FAKE_KEY not in line and "cannot build client" not in line
    assert records[0].exc_info is None and "Traceback" not in line and '"exception"' not in line


def block_google_import(monkeypatch, error: Exception) -> None:
    real_import = builtins.__import__

    def guarded(name, globals=None, locals=None, fromlist=(), level=0):
        if name == "google" and fromlist and "genai" in fromlist:
            raise error
        return real_import(name, globals, locals, fromlist, level)

    monkeypatch.setattr(builtins, "__import__", guarded)


def test_a_missing_sdk_package_is_a_plain_provider_error(monkeypatch):
    block_google_import(monkeypatch, ImportError("No module named google.genai"))
    with pytest.raises(AIProviderError) as raised:
        GeminiProvider(settings())._client()
    assert not isinstance(raised.value, GeminiConfigurationError)
    assert "not installed" in str(raised.value)


def test_an_sdk_import_time_failure_becomes_a_configuration_error(monkeypatch):
    block_google_import(monkeypatch, RuntimeError(f"import exploded {FAKE_KEY}"))
    with pytest.raises(GeminiConfigurationError) as raised:
        GeminiProvider(settings())._client()
    assert_configuration_error(raised.value)


@pytest.mark.asyncio
async def test_investigate_and_test_connection_raise_the_configuration_error_not_a_raw_sdk_error(monkeypatch):
    break_http_options(monkeypatch)
    provider = GeminiProvider(settings())
    with pytest.raises(GeminiConfigurationError):
        await provider.investigate(evidence())
    with pytest.raises(GeminiConfigurationError):
        await provider.test_connection()


# --- Provider error handling -------------------------------------------------------------------------------------


class RaisingClient:
    """A stand-in for the SDK client whose generate_content call fails with the given error."""

    def __init__(self, error: Exception):
        def generate_content(**_kwargs):
            raise error

        self.models = SimpleNamespace(generate_content=generate_content)


@pytest.mark.asyncio
async def test_an_unexpected_sdk_error_is_a_provider_error_with_a_fixed_message(monkeypatch):
    provider = GeminiProvider(settings())
    monkeypatch.setattr(provider, "_client", lambda: RaisingClient(RuntimeError(f"internal failure {FAKE_KEY}")))
    with pytest.raises(AIProviderError) as raised:
        await provider.investigate(evidence())
    assert raised.value.code == "AI_PROVIDER_ERROR"
    assert str(raised.value) == "Gemini investigation request failed."
    assert FAKE_KEY not in str(raised.value)


@pytest.mark.asyncio
async def test_an_authentication_error_keeps_its_specific_code(monkeypatch):
    provider = GeminiProvider(settings())
    monkeypatch.setattr(provider, "_client", lambda: RaisingClient(RuntimeError("401 unauthorized: invalid api key")))
    with pytest.raises(GeminiAuthenticationError) as raised:
        await provider.investigate(evidence())
    assert raised.value.code == "GEMINI_AUTHENTICATION_FAILED"


@pytest.mark.asyncio
async def test_the_ai_test_endpoint_reports_a_configuration_failure_as_503_with_a_code(monkeypatch):
    break_http_options(monkeypatch)
    monkeypatch.setattr(main_module, "get_provider", lambda *_a, **_k: GeminiProvider(settings()))
    async with AsyncClient(transport=ASGITransport(app=app), base_url="http://test") as client:
        response = await client.post("/api/v1/ai/test")
    assert response.status_code == 503
    assert response.json()["detail"] == {"code": "GEMINI_CLIENT_ERROR", "message": "The Gemini client could not be configured."}


# --- Investigation state after a provider failure ---------------------------------------------------------------------


class ExplodingProvider(AIProvider):
    """A provider that violates the contract by raising something other than AIProviderError."""

    name = "exploding_test_provider"
    simulated = True

    async def investigate(self, evidence):
        raise ValueError(f"internal detail that must not leak {FAKE_KEY}")

    async def status(self) -> ProviderStatus:
        return ProviderStatus(self.name, True, True, True, "test provider")


async def new_incident(client: AsyncClient) -> dict:
    service = (
        await client.post(
            "/api/v1/services",
            json={"name": f"B1 provider failure {uuid4()}", "environment": "demo", "simulation_status": True, "failure_threshold": 1},
        )
    ).json()
    await client.post(f"/api/v1/demo/services/{service['id']}/fault", json={"scenario": "service_unavailable"})
    return next(item for item in (await client.get("/api/v1/incidents")).json() if item["service_id"] == service["id"])


async def assert_failed_not_running(client: AsyncClient, incident_id: int, response, expected_code: str) -> list[dict]:
    body = response.json()
    assert response.status_code == 201
    assert body["status"] == "failed" and body["error_code"] == expected_code and body["result"] is None
    investigations = (await client.get(f"/api/v1/incidents/{incident_id}/investigations")).json()
    assert investigations and all(item["status"] != "running" for item in investigations)
    incident = (await client.get(f"/api/v1/incidents/{incident_id}")).json()
    assert incident["state"] == "ESCALATED"
    escalations = (await client.get(f"/api/v1/incidents/{incident_id}/escalation")).json()
    assert len(escalations) == 1 and not acknowledged_or_leaks(escalations[0])
    return escalations


def acknowledged_or_leaks(escalation: dict) -> bool:
    text = str(escalation)
    return escalation["acknowledged"] or FAKE_KEY in text or "internal detail" in text


@pytest.mark.asyncio
async def test_a_gemini_configuration_failure_ends_the_investigation_as_failed_and_escalates(monkeypatch):
    break_http_options(monkeypatch)
    monkeypatch.setattr(main_module, "get_provider", lambda *_a, **_k: GeminiProvider(settings()))
    async with AsyncClient(transport=ASGITransport(app=app), base_url="http://test") as client:
        incident = await new_incident(client)
        response = await client.post(f"/api/v1/incidents/{incident['id']}/investigations")
        escalations = await assert_failed_not_running(client, incident["id"], response, "GEMINI_CLIENT_ERROR")
    assert escalations[0]["reason"] == "The Gemini client could not be configured."


@pytest.mark.asyncio
async def test_a_provider_that_raises_an_unexpected_error_still_finishes_the_investigation(monkeypatch):
    monkeypatch.setattr(main_module, "get_provider", lambda *_a, **_k: ExplodingProvider())
    async with AsyncClient(transport=ASGITransport(app=app), base_url="http://test") as client:
        incident = await new_incident(client)
        response = await client.post(f"/api/v1/incidents/{incident['id']}/investigations")
        escalations = await assert_failed_not_running(client, incident["id"], response, "AI_PROVIDER_ERROR")
    assert escalations[0]["reason"] == "The AI provider failed unexpectedly."
    assert "internal detail" not in response.text and FAKE_KEY not in response.text


@pytest.mark.asyncio
async def test_an_unexpected_provider_error_logs_the_class_name_but_never_its_message_or_traceback(monkeypatch, caplog):
    monkeypatch.setattr(main_module, "get_provider", lambda *_a, **_k: ExplodingProvider())
    async with AsyncClient(transport=ASGITransport(app=app), base_url="http://test") as client:
        incident = await new_incident(client)
        with caplog.at_level(logging.INFO, logger="cloudrescue.api"):
            response = await client.post(f"/api/v1/incidents/{incident['id']}/investigations")

    records = [record for record in caplog.records if record.name == "cloudrescue.api" and "unexpected error" in record.getMessage()]
    assert response.status_code == 201 and len(records) == 1
    line = emitted(records[0])
    assert "ValueError" in line and ExplodingProvider.name in line
    assert FAKE_KEY not in line and "internal detail" not in line
    assert records[0].exc_info is None and "Traceback" not in line and '"exception"' not in line


@pytest.mark.asyncio
async def test_the_local_provider_investigation_contract_is_unchanged():
    assert isinstance(main_module.get_provider(), LocalDemoProvider)
    async with AsyncClient(transport=ASGITransport(app=app), base_url="http://test") as client:
        incident = await new_incident(client)
        response = await client.post(f"/api/v1/incidents/{incident['id']}/investigations")
        incident_after = (await client.get(f"/api/v1/incidents/{incident['id']}")).json()
    body = response.json()
    assert response.status_code == 201
    assert set(body) == {"id", "incident_id", "provider", "status", "simulated", "confidence", "result", "error_code", "created_at"}
    assert body["provider"] == "local_deterministic" and body["simulated"] is True and body["status"] == "completed"
    assert body["error_code"] is None and body["result"]["recommended_action"] == "restart_demo_application"
    assert incident_after["state"] == "INVESTIGATING"
