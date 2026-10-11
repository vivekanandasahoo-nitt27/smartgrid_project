
import json

from gridshield import agents


def test_event_report_includes_root_cause_findings(tmp_path, monkeypatch):
    monkeypatch.setattr(agents, "REPORT_DIR", tmp_path)

    state = {
        "event_id": "report-test-001",
        "event_timestamp": "2026-10-09T12:00:00+00:00",
        "predicted_class": 1,
        "attack_probability": 0.78,
        "confidence_route": "potential_new_attack",
        "root_cause_report": "Voltage deviation detected.",
        "root_cause_findings": {
            "measurement_count": 1,
            "findings": [
                {
                    "type": "below_engineering_limit",
                    "feature": "voltageMU1",
                    "value": 0.75,
                    "limit": 0.90,
                }
            ],
        },
    }

    result = agents.event_reporting_node(state)

    report_path = tmp_path / "report-test-001.json"
    assert result["incident_report_status"] == "created"
    assert report_path.exists()

    report = json.loads(report_path.read_text(encoding="utf-8"))
    assert report["root_cause_findings"]["measurement_count"] == 1
    assert report["root_cause_findings"]["findings"][0]["feature"] == "voltageMU1"
