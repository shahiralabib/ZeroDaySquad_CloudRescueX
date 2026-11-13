import asyncio
from datetime import datetime, timezone

import pytest

from app.cloud_adapters import CloudLoggingAdapter, CloudMonitoringAdapter, FirestoreAdapter
from app.config import Settings
from app.main import require_demo_admin, settings as app_settings


@pytest.mark.asyncio
async def test_google_adapters_are_explicitly_not_configured_without_project():
    settings = Settings(
        google_cloud_project="",
        cloud_monitoring_enabled=True,
        cloud_logging_enabled=True,
        firestore_enabled=True,
    )

    statuses = await asyncio.gather(
        CloudMonitoringAdapter(settings).status(),
        CloudLoggingAdapter(settings).status(),
        FirestoreAdapter(settings).status(),
    )

    assert {status.state for status in statuses} == {"not_configured"}
    assert all(status.connected is False for status in statuses)
    assert all(status.simulated is False for status in statuses)


@pytest.mark.asyncio
async def test_monitoring_and_logging_operations_fail_explicitly_when_unconfigured():
    settings = Settings()
    monitoring = CloudMonitoringAdapter(settings)
    logging_adapter = CloudLoggingAdapter(settings)

    with pytest.raises(RuntimeError, match="not configured"):
        await monitoring.read_time_series(
            metric_type="custom.googleapis.com/availability",
            filter_expression="resource.type = \"global\"",
            start_time=datetime.now(timezone.utc),
            end_time=datetime.now(timezone.utc),
        )
    with pytest.raises(RuntimeError, match="not configured"):
        await logging_adapter.query_logs(
            service="demo-api",
            start_time=datetime.now(timezone.utc),
            end_time=datetime.now(timezone.utc),
        )


def test_default_admin_token_is_rejected_outside_local_environment(monkeypatch):
    monkeypatch.setattr(app_settings, "environment", "production")
    monkeypatch.setattr(app_settings, "demo_admin_token", "local-demo-admin")

    with pytest.raises(Exception) as error:
        require_demo_admin("local-demo-admin")

    assert getattr(error.value, "status_code", None) == 503
