from langgraph.checkpoint.memory import InMemorySaver

from gridshield import agents, communication_agent
from gridshield.workflow import build_graph


def test_potential_new_attack_does_not_enter_officer_review(monkeypatch):
    monkeypatch.setattr(agents, "grid_monitoring_node", lambda state: {
        **state, "event_id": "potential-no-review-001",
        "measurements": {"voltageMU1": 0.75},
    })
    monkeypatch.setattr(agents, "classification_node", lambda state: {
        **state, "predicted_class": 1, "attack_probability": 0.78,
    })
    monkeypatch.setattr(agents, "confidence_monitor_node", lambda state: {
        **state, "confidence_route": "potential_new_attack",
        "attack_probability": 0.78,
    })
    monkeypatch.setattr(agents, "root_cause_analysis_node", lambda state: state)
    monkeypatch.setattr(agents, "event_reporting_node", lambda state: state)
    monkeypatch.setattr(agents, "high_confidence_node", lambda state: state)
    monkeypatch.setattr(communication_agent, "attack_review_notification_node", lambda state: state)

    graph = build_graph(checkpointer=InMemorySaver())
    config = {"configurable": {"thread_id": "potential-no-review-test"}}
    result = graph.invoke({
        "event_id": "potential-no-review-001",
        "measurements": {"voltageMU1": 0.75},
        "predicted_class": 1,
        "attack_probability": 0.78,
        "confidence_route": "potential_new_attack",
        "audit_events": [],
    }, config=config)

    snapshot = graph.get_state(config)
    assert not snapshot.interrupts
    assert "candidate_sample" not in result
    assert result["confidence_route"] == "potential_new_attack"
