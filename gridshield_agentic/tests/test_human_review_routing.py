
from langgraph.checkpoint.memory import InMemorySaver
from langgraph.types import Command

from gridshield.workflow import build_graph


def test_human_review_route_reaches_attack_review_interrupt(monkeypatch):
    from gridshield import agents, communication_agent

    monkeypatch.setattr(
        agents,
        "grid_monitoring_node",
        lambda state: {
            **state,
            "event_id": "route-human-review-001",
            "measurements": {"voltageMU1": 0.75},
        },
    )
    monkeypatch.setattr(
        agents,
        "classification_node",
        lambda state: {
            **state,
            "predicted_class": 1,
        },
    )
    monkeypatch.setattr(
        agents,
        "confidence_monitor_node",
        lambda state: {
            **state,
            "confidence_route": "human_review",
            "attack_probability": 0.50,
        },
    )
    monkeypatch.setattr(
        agents,
        "root_cause_analysis_node",
        lambda state: {**state, "root_cause_findings": []},
    )
    monkeypatch.setattr(
        agents,
        "event_reporting_node",
        lambda state: state,
    )
    monkeypatch.setattr(
        communication_agent,
        "attack_review_notification_node",
        lambda state: state,
    )

    graph = build_graph(checkpointer=InMemorySaver())
    config = {"configurable": {"thread_id": "route-human-review-test"}}

    paused = graph.invoke(
        {
            "event_id": "route-human-review-001",
            "measurements": {"voltageMU1": 0.75},
            "predicted_class": 1,
            "attack_probability": 0.50,
            "confidence_route": "human_review",
            "audit_events": [],
        },
        config=config,
    )

    snapshot = graph.get_state(config)

    assert snapshot.interrupts, "Expected the officer-review interrupt"
    assert snapshot.values["candidate_sample"]["confidence_route"] == "human_review"
    assert snapshot.values["candidate_sample"]["eligible_for_training"] is False
    assert snapshot.values["human_review_status"] == "pending"

    resumed = graph.invoke(
        Command(resume={"decision": "confirmed_attack"}),
        config=config,
    )

    assert resumed["human_review_status"] == "confirmed_attack"
    assert resumed["human_verified_attack"] is True
    assert resumed["candidate_sample"]["eligible_for_training"] is False
    assert resumed["data_admission_status"] == "pending"

    admission_snapshot = graph.get_state(config)
    assert admission_snapshot.interrupts, (
        "Confirmed attack should pause for separate data-admission approval"
    )
