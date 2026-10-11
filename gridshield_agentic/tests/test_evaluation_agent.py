
import joblib
import pandas as pd
import pytest

from sklearn.tree import DecisionTreeClassifier

from gridshield.agents import evaluate_candidate_metrics_node


def create_test_artifacts(tmp_path):
    """Create a small, deterministic candidate model and test dataset."""
    feature_columns = ["feature_a", "feature_b"]

    X_train = pd.DataFrame(
        [
            [0, 0],
            [0, 1],
            [1, 0],
            [1, 1],
            [2, 2],
            [2, 3],
            [3, 2],
            [3, 3],
            [4, 4],
            [4, 5],
            [5, 4],
            [5, 5],
        ],
        columns=feature_columns,
    )
    y_train = [0, 0, 0, 0, 1, 1, 1, 1, 2, 2, 2, 2]

    model = DecisionTreeClassifier(random_state=42)
    model.fit(X_train, y_train)

    model_path = tmp_path / "candidate.pkl"
    feature_path = tmp_path / "features.pkl"

    joblib.dump(model, model_path)
    joblib.dump(feature_columns, feature_path)

    X_test = pd.DataFrame(
        [[0, 0], [2, 2], [4, 4], [0, 1], [2, 3], [4, 5]],
        columns=feature_columns,
    )
    y_test = pd.DataFrame({"class": [0, 1, 2, 0, 1, 2]})

    x_path = tmp_path / "X_test.csv"
    y_path = tmp_path / "y_test.csv"

    X_test.to_csv(x_path, index=False)
    y_test.to_csv(y_path, index=False)

    return model_path, feature_path, x_path, y_path


def test_evaluation_calculates_metrics_and_confusion_matrix(tmp_path):
    model_path, feature_path, x_path, y_path = create_test_artifacts(
        tmp_path
    )

    state = {
        "candidate_model_path": str(model_path),
        "candidate_feature_columns_path": str(feature_path),
        "evaluation_dataset_path": str(x_path),
        "evaluation_label_path": str(y_path),
        "candidate_model_version": "test-candidate",
    }

    result = evaluate_candidate_metrics_node(state)

    assert result["evaluation_status"] == "pending_policy"
    assert result["accuracy"] == pytest.approx(1.0)
    assert result["confusion_matrix"] == [
        [2, 0, 0],
        [0, 2, 0],
        [0, 0, 2],
    ]
    assert result["evaluation_class_labels"] == [0, 1, 2]
    assert result["evaluation_metrics"]["test_sample_count"] == 6

    for label in ["0", "1", "2"]:
        assert result["precision"][label] == pytest.approx(1.0)
        assert result["recall"][label] == pytest.approx(1.0)
        assert result["f1_score"][label] == pytest.approx(1.0)

    assert result["audit_events"][-1]["event_type"] == (
        "candidate_metrics_calculated"
    )


def test_evaluation_blocks_when_candidate_artifacts_are_missing():
    result = evaluate_candidate_metrics_node({})

    assert result["evaluation_status"] == "error"
    assert result["evaluation_metrics"] == {}
    assert result["evaluation_report"]["status"] == "error"
    assert result["audit_events"][-1]["event_type"] == "evaluation_failed"


def test_evaluation_rejects_feature_column_mismatch(tmp_path):
    model_path, feature_path, x_path, y_path = create_test_artifacts(
        tmp_path
    )

    X_test = pd.read_csv(x_path)
    X_test = X_test[["feature_b", "feature_a"]]
    X_test.to_csv(x_path, index=False)

    state = {
        "candidate_model_path": str(model_path),
        "candidate_feature_columns_path": str(feature_path),
        "evaluation_dataset_path": str(x_path),
        "evaluation_label_path": str(y_path),
    }

    result = evaluate_candidate_metrics_node(state)

    assert result["evaluation_status"] == "error"
    assert "feature columns do not match" in (
        result["evaluation_report"]["reason"]
    )
