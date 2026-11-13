from __future__ import annotations

import asyncio
import logging
from dataclasses import dataclass
from datetime import datetime, timezone
from typing import Any

from app.config import Settings

logger = logging.getLogger("cloudrescue.integrations")


@dataclass(frozen=True)
class IntegrationStatus:
    name: str
    state: str
    configured: bool
    connected: bool
    simulated: bool
    message: str


@dataclass(frozen=True)
class MonitoringObservation:
    metric_type: str
    value: float
    observed_at: datetime
    resource: str
    evidence: dict[str, Any]


@dataclass(frozen=True)
class LogEvidence:
    timestamp: datetime
    severity: str
    message: str
    resource: str
    evidence: dict[str, Any]


class GoogleAdapterError(RuntimeError):
    pass


class CloudMonitoringAdapter:
    name = "google_cloud_monitoring"

    def __init__(self, settings: Settings):
        self.settings = settings

    def _client(self):
        if self.settings.demo_mode or not self.settings.cloud_monitoring_enabled or not self.settings.google_cloud_project:
            raise GoogleAdapterError("Cloud Monitoring is not configured.")
        try:
            from google.cloud import monitoring_v3
        except ImportError as exc:
            raise GoogleAdapterError("google-cloud-monitoring is not installed.") from exc
        return monitoring_v3.MetricServiceClient()

    async def status(self) -> IntegrationStatus:
        if not self.settings.cloud_monitoring_enabled or not self.settings.google_cloud_project:
            return IntegrationStatus(self.name, "not_configured", False, False, False, "Cloud Monitoring is disabled or project is missing.")
        if self.settings.demo_mode:
            return IntegrationStatus(self.name, "demo_mode", False, False, True, "Disabled in DEMO mode; local telemetry is active.")
        try:
            client = self._client()
            parent = f"projects/{self.settings.google_cloud_project}"
            await asyncio.to_thread(lambda: next(iter(client.list_metric_descriptors(request={"name": parent, "page_size": 1})), None))
            return IntegrationStatus(self.name, "connected", True, True, False, "Authenticated Cloud Monitoring request succeeded.")
        except Exception:
            logger.exception("Cloud Monitoring connection test failed")
            return IntegrationStatus(self.name, "connection_failed", True, False, False, "Cloud Monitoring authentication or API access failed.")

    async def read_time_series(
        self,
        *,
        metric_type: str,
        filter_expression: str,
        start_time: datetime,
        end_time: datetime,
    ) -> list[MonitoringObservation]:
        client = self._client()
        from google.cloud import monitoring_v3

        request = {
            "name": f"projects/{self.settings.google_cloud_project}",
            "filter": f'metric.type = "{metric_type}" AND ({filter_expression})',
            "interval": monitoring_v3.TimeInterval(
                start_time=start_time.astimezone(timezone.utc),
                end_time=end_time.astimezone(timezone.utc),
            ),
            "view": monitoring_v3.ListTimeSeriesRequest.TimeSeriesView.FULL,
        }
        series = await asyncio.to_thread(lambda: list(client.list_time_series(request=request)))
        observations: list[MonitoringObservation] = []
        for item in series:
            for point in item.points:
                value = point.value.double_value or point.value.int64_value or 0
                timestamp = point.interval.end_time
                observations.append(
                    MonitoringObservation(
                        metric_type=metric_type,
                        value=float(value),
                        observed_at=timestamp,
                        resource=item.resource.type,
                        evidence={"source": "google_cloud_monitoring", "metric_type": metric_type, "simulated": False},
                    )
                )
        return observations

    async def evaluate_health(self, metric_type: str, filter_expression: str, threshold: float, start_time: datetime, end_time: datetime) -> dict[str, Any]:
        observations = await self.read_time_series(metric_type=metric_type, filter_expression=filter_expression, start_time=start_time, end_time=end_time)
        latest = observations[-1] if observations else None
        return {"healthy": latest is not None and latest.value >= threshold, "threshold": threshold, "observation": latest.evidence | {"value": latest.value} if latest else None, "observed": bool(latest)}


class CloudLoggingAdapter:
    name = "google_cloud_logging"

    def __init__(self, settings: Settings):
        self.settings = settings

    def _client(self):
        if self.settings.demo_mode or not self.settings.cloud_logging_enabled or not self.settings.google_cloud_project:
            raise GoogleAdapterError("Cloud Logging is not configured.")
        try:
            from google.cloud import logging as cloud_logging
        except ImportError as exc:
            raise GoogleAdapterError("google-cloud-logging is not installed.") from exc
        return cloud_logging.Client(project=self.settings.google_cloud_project)

    async def status(self) -> IntegrationStatus:
        if not self.settings.cloud_logging_enabled or not self.settings.google_cloud_project:
            return IntegrationStatus(self.name, "not_configured", False, False, False, "Cloud Logging is disabled or project is missing.")
        if self.settings.demo_mode:
            return IntegrationStatus(self.name, "demo_mode", False, False, True, "Disabled in DEMO mode; local audit data is active.")
        try:
            client = self._client()
            await asyncio.to_thread(lambda: next(iter(client.list_entries(filter_='logName:*', page_size=1)), None))
            return IntegrationStatus(self.name, "connected", True, True, False, "Authenticated Cloud Logging request succeeded.")
        except Exception:
            logger.exception("Cloud Logging connection test failed")
            return IntegrationStatus(self.name, "connection_failed", True, False, False, "Cloud Logging authentication or API access failed.")

    async def query_logs(self, *, service: str, start_time: datetime, end_time: datetime, filter_expression: str = "") -> list[LogEvidence]:
        client = self._client()
        time_filter = f'timestamp >= "{start_time.astimezone(timezone.utc).isoformat()}" AND timestamp <= "{end_time.astimezone(timezone.utc).isoformat()}"'
        service_filter = f'labels."service_name" = "{service}"'
        query = f"{time_filter} AND {service_filter}"
        if filter_expression:
            query = f"{query} AND ({filter_expression})"
        entries = await asyncio.to_thread(lambda: list(client.list_entries(filter_=query, page_size=100)))
        return [
            LogEvidence(
                timestamp=entry.timestamp or datetime.now(timezone.utc),
                severity=str(entry.severity or "DEFAULT"),
                message=str(entry.payload),
                resource=str(entry.resource),
                evidence={"source": "google_cloud_logging", "service": service, "untrusted": True, "simulated": False},
            )
            for entry in entries
        ]


class FirestoreAdapter:
    name = "google_cloud_firestore"

    def __init__(self, settings: Settings):
        self.settings = settings

    def _client(self):
        if not self.settings.firestore_enabled or not self.settings.google_cloud_project:
            raise GoogleAdapterError("Firestore is not configured.")
        try:
            from google.cloud import firestore
        except ImportError as exc:
            raise GoogleAdapterError("google-cloud-firestore is not installed.") from exc
        return firestore.Client(project=self.settings.google_cloud_project, database=self.settings.firestore_database)

    async def status(self) -> IntegrationStatus:
        if not self.settings.firestore_enabled or not self.settings.google_cloud_project:
            return IntegrationStatus(self.name, "not_configured", False, False, False, "Firestore is disabled or project is missing.")
        if self.settings.demo_mode:
            return IntegrationStatus(self.name, "demo_mode", False, False, True, "Disabled in DEMO mode; SQLite persistence is active.")
        try:
            client = self._client()
            await asyncio.to_thread(lambda: next(iter(client.collections()), None))
            return IntegrationStatus(self.name, "connected", True, True, False, "Authenticated Firestore request succeeded.")
        except Exception:
            logger.exception("Firestore connection test failed")
            return IntegrationStatus(self.name, "connection_failed", True, False, False, "Firestore authentication or API access failed.")


async def integration_statuses(settings: Settings) -> list[IntegrationStatus]:
    return await asyncio.gather(
        CloudMonitoringAdapter(settings).status(),
        CloudLoggingAdapter(settings).status(),
        FirestoreAdapter(settings).status(),
    )
