"""Create one deterministic, mid-confidence GridShield incident for dashboard E2E testing.

Run from the project root with the smartgrid_gpu environment active:
    $env:GRIDSHIELD_REPOSITORY = "postgres"
    $env:GRIDSHIELD_EMAIL_NOTIFICATIONS_ENABLED = "false"
    python scripts/gridshield_postgres_review_smoke.py

This writes one uniquely named test incident to PostgreSQL and pauses the
PostgreSQL-backed LangGraph at the human attack-review interrupt. It does not
approve the event or make it eligible for training.
"""
from datetime import datetime, timezone
from uuid import uuid4
import os

os.environ["GRIDSHIELD_REPOSITORY"] = "postgres"
os.environ["GRIDSHIELD_EMAIL_NOTIFICATIONS_ENABLED"] = "false"
import sys
from pathlib import Path

PROJECT_ROOT = Path(__file__).resolve().parents[1]
if str(PROJECT_ROOT) not in sys.path:
    sys.path.insert(0, str(PROJECT_ROOT))
from gridshield import agents
from gridshield.postgres_checkpointer import postgres_checkpointer
from gridshield.repository import PostgresSampleRepository
from gridshield.workflow import build_graph


def fake_monitoring(_state):
    event_id = f"smoke-review-{uuid4().hex[:12]}"
    return {
        "event_id": event_id,
        "event_timestamp": datetime.now(timezone.utc).isoformat(),
        "measurements": {
            "voltageMU1": 0.82,
            "frequencyMU1": 49.7,
            "currentMU1": 1.15,
        },
    }


def fake_classification(_state):
    return {
        "predicted_class": 1,
        "class_probabilities": {
            "healthy": 0.25,
            "attack": 0.50,
            "fault": 0.25,
        },
        "attack_probability": 0.50,
    }


# Replace only the live data/model inputs; keep the real routing, candidate
# persistence, notification gate, interrupts, and PostgreSQL checkpointer.
agents.grid_monitoring_node = fake_monitoring
agents.classification_node = fake_classification

with postgres_checkpointer() as checkpointer:
    initial = fake_monitoring({})
    event_id = initial["event_id"]
    # Use the same event ID for the candidate and checkpoint thread, as the
    # Flask approval endpoints require.
    agents.grid_monitoring_node = lambda _state: initial
    graph = build_graph(checkpointer=checkpointer)
    config = {"configurable": {"thread_id": event_id}}
    graph.invoke({}, config=config)
    snapshot = graph.get_state(config)

    active = []
    for task in getattr(snapshot, "tasks", ()):
        for interrupt_item in getattr(task, "interrupts", ()):
            payload = getattr(interrupt_item, "value", {}) or {}
            active.append(payload)

repo = PostgresSampleRepository()
sample = repo.get(event_id)
if not sample:
    raise SystemExit(f"FAIL: event {event_id} was not found in PostgreSQL")
if sample.get("confidence_route") != "human_review":
    raise SystemExit(f"FAIL: expected human_review route, got {sample.get('confidence_route')!r}")
if sample.get("status") != "awaiting_human_review":
    raise SystemExit(f"FAIL: unexpected persisted status {sample.get('status')!r}")
if not any(p.get("request_type") == "human_attack_review" and p.get("event_id") == event_id for p in active):
    raise SystemExit(f"FAIL: matching human-review interrupt not found: {active!r}")

print("PASS: PostgreSQL review smoke event created and checkpoint paused.")
print(f"Event ID: {event_id}")
print("Attack probability: 0.50")
print("Route: human_review")
print("Database status: awaiting_human_review")
print("Training eligibility: false")
print("Next: refresh http://127.0.0.1:5000/dashboard; this event should appear in Attack verification queue.")
