
from gridshield.agents import root_cause_analysis_node


def test_rca_detects_configured_voltage_limit():
    state = {
        "event_id": "rca-test-001",
        "measurements": {
            "voltageMU1": 0.75,
            "frequencyMU1": 50.0,
        },
        "engineering_limits": {
            "voltageMU1": {"min": 0.90, "max": 1.10},
        },
        "predicted_class": 1,
        "attack_probability": 0.78,
        "confidence_route": "potential_new_attack",
        "audit_events": [],
    }

    result = root_cause_analysis_node(state)

    findings = result["root_cause_findings"]["findings"]

    assert any(
        finding["type"] == "below_engineering_limit"
        and finding["feature"] == "voltageMU1"
        for finding in findings
    )


def test_rca_does_not_invent_a_cause():
    state = {
        "event_id": "rca-test-002",
        "measurements": {"frequencyMU1": 50.0},
        "predicted_class": 1,
        "attack_probability": 0.75,
        "confidence_route": "potential_new_attack",
        "audit_events": [],
    }

    result = root_cause_analysis_node(state)

    assert result["root_cause_findings"]["findings"] == []
    assert "does not rule out an attack" in (
        result["root_cause_findings"]["conclusion"]
    )
