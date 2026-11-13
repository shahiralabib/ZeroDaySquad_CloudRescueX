"""Escalation actions: acknowledge and reject-recovery persist an outcome, keep history, and never resolve anything."""
import asyncio
import json
from uuid import uuid4

import pytest
from httpx import ASGITransport, AsyncClient
from sqlalchemy import select

from app.database import AuditEvent, Escalation, IncidentEvent, RecoveryApproval, session_factory
from app.main import _request_windows, app
from auth_support import ANONYMOUS_HEADERS


@pytest.fixture(autouse=True)
def clear_rate_limit_window():
    _request_windows.clear()


def new_client() -> AsyncClient:
    return AsyncClient(transport=ASGITransport(app=app), base_url="http://test")


async def escalated_incident(client: AsyncClient) -> dict:
    """An outage incident whose first recovery attempt is rejected by policy, which creates a pending escalation."""
    service = (
        await client.post(
            "/api/v1/services",
            json={"name": f"Escalation {uuid4()}", "environment": "demo", "simulation_status": True, "failure_threshold": 1},
        )
    ).json()
    await client.post(f"/api/v1/demo/services/{service['id']}/fault", json={"scenario": "configuration_failure"})
    incident = next(i for i in (await client.get("/api/v1/incidents")).json() if i["service_id"] == service["id"])
    # A medium-risk action without approval is refused and escalates the incident.
    refused = await client.post(
        f"/api/v1/incidents/{incident['id']}/recovery", json={"action_id": "restore_known_good_configuration"}
    )
    assert refused.status_code == 409
    return incident


async def escalations_of(client: AsyncClient, incident_id: int) -> list[dict]:
    return (await client.get(f"/api/v1/incidents/{incident_id}/escalation")).json()


async def pending_ids(client: AsyncClient) -> set[int]:
    return {item["id"] for item in (await client.get("/api/v1/escalations?status=pending")).json()}


async def acknowledge(client: AsyncClient, incident_id: int, escalation_id: int | None = None, token: bool = True):
    suffix = f"?escalation_id={escalation_id}" if escalation_id is not None else ""
    return await client.post(
        f"/api/v1/incidents/{incident_id}/acknowledge{suffix}",
        headers=None if token else ANONYMOUS_HEADERS,  # token=False is an explicitly anonymous request
    )


async def reject(client: AsyncClient, incident_id: int, escalation_id: int | None = None, reason: str = "Not safe to run"):
    params = {"reason": reason}
    if escalation_id is not None:
        params["escalation_id"] = escalation_id
    return await client.post(f"/api/v1/incidents/{incident_id}/reject-recovery", params=params)


# --- Acknowledge ----------------------------------------------------------------------------------------------------


@pytest.mark.asyncio
async def test_acknowledge_persists_the_status_and_removes_the_item_from_the_pending_list():
    async with new_client() as client:
        incident = await escalated_incident(client)
        [escalation] = await escalations_of(client, incident["id"])
        assert escalation["status"] == "pending" and escalation["id"] in await pending_ids(client)

        response = await acknowledge(client, incident["id"], escalation["id"])
        listed = (await client.get("/api/v1/escalations")).json()
        pending_after = await pending_ids(client)

    body = response.json()
    assert response.status_code == 200
    assert body["status"] == "acknowledged" and body["acknowledged"] is True
    assert body["assigned_administrator"] == "test-admin" and body["acknowledged_at"]
    assert escalation["id"] not in pending_after  # gone from the pending list...
    stored = next(item for item in listed if item["id"] == escalation["id"])  # ...but kept in history
    assert stored["status"] == "acknowledged" and stored["reason"] == escalation["reason"]

    async with session_factory() as session:  # persisted in the database, not just in the response
        row = await session.get(Escalation, escalation["id"])
        assert row.acknowledged is True and row.assigned_administrator == "test-admin" and row.acknowledged_at is not None


@pytest.mark.asyncio
async def test_a_processed_item_stays_out_of_the_pending_list_after_a_refresh():
    async with new_client() as client:
        incident = await escalated_incident(client)
        [escalation] = await escalations_of(client, incident["id"])
        await acknowledge(client, incident["id"], escalation["id"])

    # A new client (a page refresh / another session) reads only persisted state.
    async with new_client() as fresh:
        assert escalation["id"] not in await pending_ids(fresh)
        assert (await escalations_of(fresh, incident["id"]))[0]["status"] == "acknowledged"


@pytest.mark.asyncio
async def test_acknowledging_does_not_resolve_the_incident_or_change_service_health():
    async with new_client() as client:
        incident = await escalated_incident(client)
        before = (await client.get(f"/api/v1/incidents/{incident['id']}")).json()
        service_before = (await client.get(f"/api/v1/services/{incident['service_id']}")).json()
        await acknowledge(client, incident["id"])
        after = (await client.get(f"/api/v1/incidents/{incident['id']}")).json()
        service_after = (await client.get(f"/api/v1/services/{incident['service_id']}")).json()

    assert after["state"] == before["state"] == "ESCALATED" and after["resolution_timestamp"] is None
    assert service_after["status"] == service_before["status"] == "unhealthy"


@pytest.mark.asyncio
async def test_acknowledge_without_an_id_targets_the_newest_pending_escalation():
    async with new_client() as client:
        incident = await escalated_incident(client)
        [first] = await escalations_of(client, incident["id"])
        await acknowledge(client, incident["id"], first["id"])
        # A new problem escalates the same incident again, giving it a second, pending escalation.
        again = await reject(client, incident["id"])
        assert again.status_code == 409  # nothing pending: the first one is already processed
        async with session_factory() as session:
            second = Escalation(incident_id=incident["id"], reason="Second escalation", severity="high")
            session.add(second)
            await session.commit()
            second_id = second.id

        response = await acknowledge(client, incident["id"])
        statuses = {item["id"]: item["status"] for item in await escalations_of(client, incident["id"])}

    assert response.status_code == 200 and response.json()["id"] == second_id
    assert statuses == {first["id"]: "acknowledged", second_id: "acknowledged"}


# --- Reject recovery ------------------------------------------------------------------------------------------------


@pytest.mark.asyncio
async def test_reject_recovery_persists_a_rejected_status_and_removes_the_item_from_the_pending_list():
    async with new_client() as client:
        incident = await escalated_incident(client)
        [escalation] = await escalations_of(client, incident["id"])

        response = await reject(client, incident["id"], escalation["id"], reason="Configuration restore is too risky")
        history = await escalations_of(client, incident["id"])
        pending_after = await pending_ids(client)

    body = response.json()
    assert response.status_code == 200 and body["id"] == escalation["id"]
    assert body["status"] == "rejected" and body["rejection_reason"] == "Configuration restore is too risky"
    assert body["assigned_administrator"] == "test-admin" and body["acknowledged_at"]
    assert escalation["id"] not in pending_after
    assert len(history) == 1  # no extra escalation was created, and the original record is preserved
    assert history[0]["status"] == "rejected" and history[0]["reason"] == escalation["reason"]
    assert history[0]["policy_decisions"][-1]["decision"] == "recovery_rejected"
    assert history[0]["policy_decisions"][-1]["decided_by"] == "test-admin"

    async with session_factory() as session:
        row = await session.get(Escalation, escalation["id"])
        assert row.acknowledged is True and "recovery_rejected" in row.policy_decisions_json


@pytest.mark.asyncio
async def test_reject_recovery_keeps_the_incident_open_and_the_service_unhealthy_and_records_the_decision():
    async with new_client() as client:
        incident = await escalated_incident(client)
        await reject(client, incident["id"])
        after = (await client.get(f"/api/v1/incidents/{incident['id']}")).json()
        service = (await client.get(f"/api/v1/services/{incident['service_id']}")).json()
        timeline = (await client.get(f"/api/v1/incidents/{incident['id']}/timeline")).json()
        executions = (await client.get(f"/api/v1/incidents/{incident['id']}/recovery")).json()

    assert after["state"] == "ESCALATED" and after["resolution_timestamp"] is None and after["verification_outcome"] is None
    assert service["status"] == "unhealthy"
    assert executions == []  # nothing was executed
    decision = next(e for e in timeline if e["event_type"] == "POLICY_DECISION" and e["metadata"].get("decision") == "recovery_rejected")
    assert "Not safe to run" in decision["description"]
    async with session_factory() as session:
        audit = (await session.scalars(select(AuditEvent).where(AuditEvent.event_type == "recovery.rejected"))).all()
    assert any(f"incident {incident['id']}" in event.message for event in audit)


@pytest.mark.asyncio
async def test_rejecting_revokes_approvals_that_have_not_been_used():
    async with new_client() as client:
        incident = await escalated_incident(client)
        approval = await client.post(
            f"/api/v1/incidents/{incident['id']}/recovery/approve", json={"action_id": "restore_known_good_configuration"}
        )
        assert approval.status_code == 200
        await reject(client, incident["id"])
        attempt = await client.post(
            f"/api/v1/incidents/{incident['id']}/recovery", json={"action_id": "restore_known_good_configuration"}
        )

    assert attempt.status_code == 409  # the approved-but-unused recovery can no longer run
    async with session_factory() as session:
        rows = (await session.scalars(select(RecoveryApproval).where(RecoveryApproval.incident_id == incident["id"]))).all()
    assert rows and all(row.revoked for row in rows)


@pytest.mark.asyncio
async def test_rejecting_an_incident_that_was_never_escalated_escalates_it_and_records_the_rejection_once():
    async with new_client() as client:
        service = (
            await client.post(
                "/api/v1/services",
                json={"name": f"Reject {uuid4()}", "environment": "demo", "simulation_status": True, "failure_threshold": 1},
            )
        ).json()
        await client.post(f"/api/v1/demo/services/{service['id']}/fault", json={"scenario": "service_unavailable"})
        incident = next(i for i in (await client.get("/api/v1/incidents")).json() if i["service_id"] == service["id"])
        assert await escalations_of(client, incident["id"]) == []

        first = await reject(client, incident["id"])
        second = await reject(client, incident["id"])
        history = await escalations_of(client, incident["id"])
        state = (await client.get(f"/api/v1/incidents/{incident['id']}")).json()

    assert first.status_code == 200 and first.json()["status"] == "rejected"
    assert second.status_code == 409  # a repeat does not create another record
    assert len(history) == 1 and history[0]["status"] == "rejected"
    assert state["state"] == "ESCALATED"
    assert history[0]["id"] not in await pending_ids_fresh()


async def pending_ids_fresh() -> set[int]:
    async with new_client() as client:
        return await pending_ids(client)


# --- Duplicates, errors and authorization ---------------------------------------------------------------------------


@pytest.mark.asyncio
@pytest.mark.parametrize("first_action", ["acknowledge", "reject"])
@pytest.mark.parametrize("second_action", ["acknowledge", "reject"])
async def test_an_escalation_can_only_be_processed_once(first_action, second_action):
    async with new_client() as client:
        incident = await escalated_incident(client)
        [escalation] = await escalations_of(client, incident["id"])
        act = {"acknowledge": acknowledge, "reject": reject}
        first = await act[first_action](client, incident["id"], escalation["id"])
        second = await act[second_action](client, incident["id"], escalation["id"])
        timeline = (await client.get(f"/api/v1/incidents/{incident['id']}/timeline")).json()
        history = await escalations_of(client, incident["id"])

    assert first.status_code == 200
    assert second.status_code == 409 and second.json()["detail"]["code"] == "ESCALATION_ALREADY_PROCESSED"
    expected = "acknowledged" if first_action == "acknowledge" else "rejected"
    assert history[0]["status"] == expected  # the first decision stands
    marker = "ADMIN_ACKNOWLEDGED" if first_action == "acknowledge" else "POLICY_DECISION"
    decisions = [e for e in timeline if e["event_type"] == marker and (first_action == "acknowledge" or e["metadata"].get("decision") == "recovery_rejected")]
    assert len(decisions) == 1  # no duplicate timeline entry


@pytest.mark.asyncio
async def test_simultaneous_submissions_process_the_escalation_exactly_once():
    async with new_client() as client:
        incident = await escalated_incident(client)
        [escalation] = await escalations_of(client, incident["id"])
        results = await asyncio.gather(*[acknowledge(client, incident["id"], escalation["id"]) for _ in range(4)])
        timeline = (await client.get(f"/api/v1/incidents/{incident['id']}/timeline")).json()

    assert sorted(r.status_code for r in results) == [200, 409, 409, 409]
    assert len([e for e in timeline if e["event_type"] == "ADMIN_ACKNOWLEDGED"]) == 1


@pytest.mark.asyncio
async def test_error_responses_are_specific():
    async with new_client() as client:
        incident = await escalated_incident(client)
        other = await escalated_incident(client)
        [mine] = await escalations_of(client, incident["id"])
        wrong_incident = await acknowledge(client, other["id"], mine["id"])  # escalation belongs to a different incident
        missing = await acknowledge(client, incident["id"], 99999999)
        unknown_incident = await acknowledge(client, 99999999)
        no_token = await acknowledge(client, incident["id"], mine["id"], token=False)
        bad_filter = await client.get("/api/v1/escalations?status=bogus")
        bad_escalation_id = await client.post(f"/api/v1/incidents/{incident['id']}/acknowledge?escalation_id=0")
        still_pending = await pending_ids(client)

    assert wrong_incident.status_code == 404 and missing.status_code == 404 and unknown_incident.status_code == 404
    assert no_token.status_code == 401
    assert bad_filter.status_code == 422 and bad_escalation_id.status_code == 422
    assert mine["id"] in still_pending  # none of the failed attempts changed anything


@pytest.mark.asyncio
async def test_status_filter_and_history_listing():
    async with new_client() as client:
        a, b, c = await escalated_incident(client), await escalated_incident(client), await escalated_incident(client)
        [ea], [eb], [ec] = [await escalations_of(client, i["id"]) for i in (a, b, c)]
        await acknowledge(client, a["id"], ea["id"])
        await reject(client, b["id"], eb["id"])
        everything = {item["id"]: item["status"] for item in (await client.get("/api/v1/escalations")).json()}
        by_status = {s: {item["id"] for item in (await client.get(f"/api/v1/escalations?status={s}")).json()} for s in ("pending", "acknowledged", "rejected")}

    assert everything[ea["id"]] == "acknowledged" and everything[eb["id"]] == "rejected" and everything[ec["id"]] == "pending"
    assert ea["id"] in by_status["acknowledged"] and eb["id"] in by_status["rejected"] and ec["id"] in by_status["pending"]
    assert not ({ea["id"], eb["id"]} & by_status["pending"])
    assert by_status["pending"].isdisjoint(by_status["acknowledged"]) and by_status["pending"].isdisjoint(by_status["rejected"])


@pytest.mark.asyncio
async def test_escalations_created_before_this_change_keep_their_meaning():
    """Rows written by older versions (acknowledged flag only, empty decisions) map to the new statuses."""
    async with new_client() as client:
        incident = await escalated_incident(client)
        async with session_factory() as session:
            old_ack = Escalation(incident_id=incident["id"], reason="legacy ack", severity="high", acknowledged=True, policy_decisions_json="[]")
            old_open = Escalation(incident_id=incident["id"], reason="legacy open", severity="high", policy_decisions_json="not json")
            session.add_all([old_ack, old_open])
            await session.commit()
            ack_id, open_id = old_ack.id, old_open.id
        statuses = {item["id"]: item["status"] for item in await escalations_of(client, incident["id"])}

    assert statuses[ack_id] == "acknowledged" and statuses[open_id] == "pending"
