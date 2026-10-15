
import json

from gridshield.agents import evaluation_report_node


def _valid_state():
    return {
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
            "macro_average": {"f1_score": 1.0},
            "recall_per_class": {
                "0": 1.0,
                "1": 1.0,
                "2": 1.0,
            },
            "support_per_class": {
                "0": 2,
                "1": 2,
                "2": 2,
            },
            "test_sample_count": 6,
        },
        "audit_events": [],
    }


def test_evaluation_report_passes_and_persists_metrics(
    tmp_path, monkeypatch
):
    import gridshield.agents as agents

    monkeypatch.setattr(agents, "REPORT_DIR", tmp_path)
    monkeypatch.setenv("GRIDSHIELD_MIN_ACCURACY", "0.90")
    monkeypatch.setenv("GRIDSHIELD_MIN_MACRO_F1", "0.85")
    monkeypatch.setenv("GRIDSHIELD_MIN_CLASS_RECALL", "0.80")

    result = agents.evaluation_report_node(_valid_state())

    report_path = tmp_path / "evaluation_candidate-v1.json"
    assert report_path.exists()

    saved = json.loads(report_path.read_text(encoding="utf-8"))

    assert result["evaluation_status"] == "passed"
    assert saved["evaluation_status"] == "passed"
    assert saved["metrics"]["accuracy"] == 1.0
    assert saved["reasons"] == []


def test_evaluation_report_fails_when_accuracy_is_too_low(
    tmp_path, monkeypatch
):
    import gridshield.agents as agents

    monkeypatch.setattr(agents, "REPORT_DIR", tmp_path)
    monkeypatch.setenv("GRIDSHIELD_MIN_ACCURACY", "0.90")

    state = _valid_state()
    state["evaluation_metrics"]["accuracy"] = 0.80

    result = agents.evaluation_report_node(state)

    assert result["evaluation_status"] == "failed"
    assert any(
        "Accuracy is below" in reason
        for reason in result["evaluation_report"]["reasons"]
    )


def test_evaluation_report_fails_when_a_class_recall_is_too_low(
    tmp_path, monkeypatch
):
    import gridshield.agents as agents

    monkeypatch.setattr(agents, "REPORT_DIR", tmp_path)
    monkeypatch.setenv("GRIDSHIELD_MIN_CLASS_RECALL", "0.80")

    state = _valid_state()
    state["evaluation_metrics"]["recall_per_class"]["1"] = 0.50

    result = agents.evaluation_report_node(state)

    assert result["evaluation_status"] == "failed"
    assert any(
        "Recall for class 1 is below" in reason
        for reason in result["evaluation_report"]["reasons"]
    )


def test_evaluation_report_fails_when_class_is_missing(
    tmp_path, monkeypatch
):
    import gridshield.agents as agents

    monkeypatch.setattr(agents, "REPORT_DIR", tmp_path)

    state = _valid_state()
    state["evaluation_class_labels"] = [0, 1]

    result = agents.evaluation_report_node(state)

    assert result["evaluation_status"] == "failed"
    assert any(
        "must cover classes 0, 1, and 2" in reason
        for reason in result["evaluation_report"]["reasons"]
    )
