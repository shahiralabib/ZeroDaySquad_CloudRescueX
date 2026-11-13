from __future__ import annotations

import asyncio
from typing import Any, Protocol

from app.config import Settings


class IncidentStore(Protocol):
    async def create_incident(self, incident_id: str, data: dict[str, Any]) -> None: ...
    async def update_incident(self, incident_id: str, data: dict[str, Any]) -> None: ...
    async def append_timeline(self, incident_id: str, event: dict[str, Any]) -> None: ...
    async def create_escalation(self, incident_id: str, data: dict[str, Any]) -> None: ...
    async def create_notification(self, notification_id: str, data: dict[str, Any]) -> None: ...


class SQLiteIncidentStore:
    """Local adapter boundary; existing SQLAlchemy persistence remains authoritative locally."""

    def __init__(self, session_factory):
        self.session_factory = session_factory

    async def _unsupported(self, operation: str) -> None:
        raise NotImplementedError(f"{operation} uses the existing SQLAlchemy repository in local mode.")

    async def create_incident(self, incident_id: str, data: dict[str, Any]) -> None:
        await self._unsupported("create_incident")

    async def update_incident(self, incident_id: str, data: dict[str, Any]) -> None:
        await self._unsupported("update_incident")

    async def append_timeline(self, incident_id: str, event: dict[str, Any]) -> None:
        await self._unsupported("append_timeline")

    async def create_escalation(self, incident_id: str, data: dict[str, Any]) -> None:
        await self._unsupported("create_escalation")

    async def create_notification(self, notification_id: str, data: dict[str, Any]) -> None:
        await self._unsupported("create_notification")


class FirestoreIncidentStore:
    def __init__(self, settings: Settings):
        if not settings.google_cloud_project:
            raise ValueError("GOOGLE_CLOUD_PROJECT is required for Firestore.")
        try:
            from google.cloud import firestore
        except ImportError as exc:
            raise RuntimeError("google-cloud-firestore is not installed.") from exc
        self._client = firestore.Client(project=settings.google_cloud_project, database=settings.firestore_database)

    async def _set(self, collection: str, document_id: str, data: dict[str, Any]) -> None:
        await asyncio.to_thread(self._client.collection(collection).document(document_id).set, data, merge=True)

    async def create_incident(self, incident_id: str, data: dict[str, Any]) -> None:
        await self._set("incidents", incident_id, data)

    async def update_incident(self, incident_id: str, data: dict[str, Any]) -> None:
        await self._set("incidents", incident_id, data)

    async def append_timeline(self, incident_id: str, event: dict[str, Any]) -> None:
        await self._set(f"incidents/{incident_id}/timeline", str(event["id"]), event)

    async def create_escalation(self, incident_id: str, data: dict[str, Any]) -> None:
        await self._set(f"incidents/{incident_id}/escalations", str(data["id"]), data)

    async def create_notification(self, notification_id: str, data: dict[str, Any]) -> None:
        await self._set("notifications", notification_id, data)


def get_incident_store(settings: Settings, session_factory) -> IncidentStore:
    if settings.storage_backend.lower() == "firestore" or settings.firestore_enabled:
        return FirestoreIncidentStore(settings)
    return SQLiteIncidentStore(session_factory)
