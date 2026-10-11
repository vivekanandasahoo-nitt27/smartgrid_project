
import json

from gridshield.agents import evaluation_report_node


def test_evaluation_report_persists_metrics(tmp_path, monkeypatch):
    import gridshield.agents as agents

    monkeypatch.setattr(agents, "REPORT_DIR", tmp_path)

    state = {
        "candidate_model_version": "candidate-v1",
        "training_run_id": "run-test-1",
        "evaluation_status": "pending_policy",
        "evaluation_class_labels": [0, 1, 2],
        "confusion_matrix": [
            [2, 0, 0],
            [0, 2, 0],
            [0, 0, 2],
        ],
        "evaluation_metrics": {
            "accuracy": 1.0,
            "test_sample_count": 6,
        },
        "audit_events": [],
    }

    result = evaluation_report_node(state)

    report_path = tmp_path / "evaluation_candidate-v1.json"

    assert report_path.exists()
    saved = json.loads(report_path.read_text(encoding="utf-8"))

    assert saved["evaluation_status"] == "pending_policy"
    assert saved["confusion_matrix"] == state["confusion_matrix"]
    assert saved["metrics"] == state["evaluation_metrics"]
    assert result["evaluation_report_path"] == str(report_path)
    assert result["audit_events"][-1]["event_type"] == (
        "evaluation_report_created"
    )


def test_evaluation_report_does_not_approve_deployment(tmp_path, monkeypatch):
    import gridshield.agents as agents

    monkeypatch.setattr(agents, "REPORT_DIR", tmp_path)

    result = evaluation_report_node({
        "evaluation_status": "failed",
        "evaluation_metrics": {},
        "confusion_matrix": [],
        "evaluation_class_labels": [],
        "audit_events": [],
    })

    assert result["evaluation_report"]["evaluation_status"] == "failed"
    assert "deployment_approval_status" not in result
