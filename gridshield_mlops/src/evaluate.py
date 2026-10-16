import json
from datetime import datetime, timezone
import joblib
import numpy as np
import pandas as pd
from sklearn.metrics import accuracy_score, f1_score, precision_recall_fscore_support, confusion_matrix, classification_report
from src.common import TEST_X, TEST_Y, MODEL_PATH, FEATURES_PATH, TRAINING_METADATA_PATH, EVALUATION_REPORT_PATH, EVALUATION_METRICS_PATH, ensure_output_dirs, load_params, mlflow_setup, write_json

def main():
    ensure_output_dirs()
    for p in [TEST_X, TEST_Y, MODEL_PATH, FEATURES_PATH, TRAINING_METADATA_PATH]:
        if not p.is_file():
            raise FileNotFoundError(f"Missing required file: {p}")
    X = pd.read_csv(TEST_X)
    yf = pd.read_csv(TEST_Y)
    if yf.shape[1] != 1 or len(X) != len(yf):
        raise ValueError("Evaluation features and labels do not match.")
    with FEATURES_PATH.open(encoding="utf-8") as f:
        features = json.load(f)
    if list(X.columns) != features:
        raise ValueError("Evaluation feature order differs from candidate schema.")
    if X.isna().any().any() or not np.isfinite(X.to_numpy(dtype=float)).all():
        raise ValueError("Evaluation features contain missing/non-finite values.")
    y = pd.to_numeric(yf.iloc[:, 0], errors="raise").astype(int).to_numpy()
    if set(np.unique(y)) != {0, 1, 2}:
        raise ValueError("Evaluation set must include labels 0, 1, 2.")
    model = joblib.load(MODEL_PATH)
    if list(model.classes_) != [0, 1, 2]:
        raise ValueError(f"Expected model classes [0,1,2], got {list(model.classes_)}")
    pred = model.predict(X)
    labels = [0, 1, 2]
    names = {0: "healthy", 1: "attack", 2: "fault"}
    acc = float(accuracy_score(y, pred))
    macro_f1 = float(f1_score(y, pred, labels=labels, average="macro", zero_division=0))
    precision, recall, f1, support = precision_recall_fscore_support(y, pred, labels=labels, zero_division=0)
    per_class = {names[c]: {"label": c, "precision": float(precision[i]), "recall": float(recall[i]), "f1": float(f1[i]), "support": int(support[i])} for i, c in enumerate(labels)}
    policy = load_params()["policy"]
    recall_pass = all(per_class[names[c]]["support"] > 0 and per_class[names[c]]["recall"] >= float(policy["min_class_recall"]) for c in labels)
    passed = acc >= float(policy["min_accuracy"]) and macro_f1 >= float(policy["min_macro_f1"]) and recall_pass
    with TRAINING_METADATA_PATH.open(encoding="utf-8") as f:
        meta = json.load(f)
    metrics = {"accuracy": acc, "macro_f1": macro_f1, **{f"{n}_recall": v["recall"] for n, v in per_class.items()}}
    report = {
        "candidate_id": meta["candidate_id"], "mlflow_run_id": meta["mlflow_run_id"],
        "evaluated_at_utc": datetime.now(timezone.utc).isoformat(),
        "evaluation_status": "passed" if passed else "failed", "deployment_authorized": False,
        "policy": policy, "metrics": metrics, "per_class": per_class,
        "confusion_matrix_labels": labels, "confusion_matrix": confusion_matrix(y, pred, labels=labels).tolist(),
        "classification_report": classification_report(y, pred, labels=labels, target_names=["healthy", "attack", "fault"], output_dict=True, zero_division=0),
        "evaluation_rows": len(X), "feature_count": X.shape[1],
        "evaluation_data": "fixed holdout split",
        "note": "Passing evaluation is evidence for review, not permission to deploy."
    }
    write_json(EVALUATION_REPORT_PATH, report)
    write_json(EVALUATION_METRICS_PATH, metrics)
    mlflow = mlflow_setup()
    with mlflow.start_run(run_id=meta["mlflow_run_id"]):
        mlflow.log_metrics(metrics)
        mlflow.log_param("evaluation_rows", len(X))
        mlflow.set_tag("gridshield.evaluation_status", report["evaluation_status"])
        mlflow.set_tag("gridshield.deployment_authorized", "false")
        mlflow.log_artifact(str(EVALUATION_REPORT_PATH), artifact_path="evaluation")
        mlflow.log_artifact(str(EVALUATION_METRICS_PATH), artifact_path="evaluation")
    print(json.dumps(report, indent=2))
    if not passed:
        raise SystemExit("Candidate failed evaluation policy; do not proceed to approval.")

if __name__ == "__main__":
    main()
