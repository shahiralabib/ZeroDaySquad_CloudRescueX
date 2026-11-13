from typing import Protocol

from sqlalchemy.ext.asyncio import AsyncSession

from app.database import Notification


class NotificationProvider(Protocol):
    async def create_escalation_notification(
        self,
        session: AsyncSession,
        *,
        incident_id: int,
        severity: str,
        service_name: str,
        reason: str,
    ) -> Notification | None: ...


class LocalNotificationProvider:
    async def create_escalation_notification(
        self,
        session: AsyncSession,
        *,
        incident_id: int,
        severity: str,
        service_name: str,
        reason: str,
    ) -> Notification | None:
        deduplication_key = f"escalation:{incident_id}:{reason}"
        from sqlalchemy import select

        if await session.scalar(select(Notification).where(Notification.deduplication_key == deduplication_key)):
            return None
        notification = Notification(
            incident_id=incident_id,
            kind="escalation",
            severity=severity,
            service_name=service_name,
            reason=reason,
            dashboard_link=f"/incidents/{incident_id}",
            deduplication_key=deduplication_key,
        )
        session.add(notification)
        return notification
