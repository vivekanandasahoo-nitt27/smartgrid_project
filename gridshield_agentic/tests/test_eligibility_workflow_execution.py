
from langgraph.types import Command

from gridshield import agents
from gridshield.repository import JsonSampleRepository
from gridshield.workflow import build_graph


def test_approved_attack_reaches_eligibility_management(
    tmp_path, monkeypatch
):
    repository = JsonSampleRepository(tmp_path / "samples.json")

    monkeypatch.setattr(
        agents,
        "get_sample_repository",
        lambda: repository,
    )

    # Deterministic classification for this test.
    monkeypatch.setattr(
        agents,
        "classification_node",
        lambda state: {
            "predicted_class": 1,
            "class_probabilities": {
                "healthy": 0.25,
                "attack": 0.50,
                "fault": 0.25,
            },
            "attack_probability": 0.50,
        },
    )

    monkeypatch.setattr(
        agents,
        "grid_monitoring_node",
        lambda state: {
            "event_id": "workflow-event-001",
            "event_timestamp": "2026-10-10T00:00:00+00:00",
            "measurements": {
                "voltage": 0.85,
                "frequency": 50.0,
            },
        },
    )

    monkeypatch.setattr(
        agents,
        "root_cause_analysis_node",
        lambda state: {
            "root_cause_report": "Test incident",
            "root_cause_findings": {},
        },
    )

    monkeypatch.setattr(
        agents,
        "event_reporting_node",
        lambda state: {
            "incident_report_status": "created",
        },
    )

    graph = build_graph()
    config = {
        "configurable": {
            "thread_id": "eligibility-workflow-test-001",
        }
    }

    # Start the workflow; it should pause for human review.
    graph.invoke({}, config=config)

    snapshot = graph.get_state(config)
    assert snapshot.interrupts, "Expected human-review interrupt"

    # Approve the attack during human review.
    graph.invoke(
        Command(
            resume={
                "decision": "confirmed_attack",
                "officer_username": "test-officer",
                "thread_id": "pytest-review",
            }
        ),
        config=config,
    )

    # The workflow should pause for separate data-admission approval.
    snapshot = graph.get_state(config)
    assert snapshot.interrupts, "Expected data-admission interrupt"

    # Approve admission into the candidate training dataset.
    graph.invoke(
        Command(
            resume={
                "decision": "approved",
                "officer_username": "test-officer",
                "thread_id": "pytest-admission",
            }
        ),
        config=config,
    )

    stored = repository.get("workflow-event-001")

    assert stored is not None
    assert stored["status"] == "eligible_for_training"
    assert stored["eligible_for_training"] is True
    assert repository.count_eligible() == 1
