
from langgraph.types import Command

from gridshield import agents
from gridshield.workflow import build_graph
from gridshield.repository import JsonSampleRepository


def test_approved_attack_reaches_eligibility_management(
    tmp_path, monkeypatch
):
    repository = JsonSampleRepository(tmp_path / "samples.json")
    monkeypatch.setattr(
        agents,
        "get_sample_repository",
        lambda: repository,
    )

    # Use the real graph but deterministic test classification.
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
            "thread_id": "eligibility-workflow-test-001"
        }
    }

    initial_state = {}
    paused = graph.invoke(initial_state, config=config)

    snapshot = graph.get_state(config)
    assert snapshot.interrupts, "Expected human-review interrupt"

    # Resume the first interrupt: confirm the attack.
    graph.invoke(
        Command(resume={"decision": "confirmed_attack"}),
        config=config,
    )

    snapshot = graph.get_state(config)
    assert snapshot.interrupts, "Expected data-admission interrupt"

    # Resume the second interrupt: approve dataset admission.
    result = graph.invoke(
        Command(resume={"decision": "approved"}),
        config=config,
    )

    stored = repository.get("workflow-event-001")
    
    assert stored["status"] == "stored_pending_eligibility"
    assert stored["eligible_for_training"] is False
    assert repository.count_eligible() == 0
    assert result["sample_eligible"] is False
    assert result["eligibility_status"] == "awaiting_explicit_validation"

