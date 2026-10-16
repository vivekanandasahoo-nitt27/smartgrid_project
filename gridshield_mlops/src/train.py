import json
import platform
from datetime import datetime, timezone
import joblib
import pandas as pd
import sklearn
from sklearn.ensemble import RandomForestClassifier
from src.common import TRAIN_X, TRAIN_Y, MODEL_PATH, FEATURES_PATH, TRAINING_METADATA_PATH, VALIDATION_REPORT_PATH, ensure_output_dirs, load_params, mlflow_setup, write_json

def main():
    ensure_output_dirs()
    if not VALIDATION_REPORT_PATH.exists():
        raise FileNotFoundError("Run `python -m src.validate_data` first.")
    with VALIDATION_REPORT_PATH.open(encoding="utf-8") as f:
        if json.load(f).get("validation_status") != "passed":
            raise RuntimeError("Validation has not passed; refusing to train.")
    X = pd.read_csv(TRAIN_X)
    yf = pd.read_csv(TRAIN_Y)
    if yf.shape[1] != 1 or len(X) != len(yf):
        raise ValueError("Train features and labels do not match.")
    y = pd.to_numeric(yf.iloc[:, 0], errors="raise").astype(int)
    params = load_params()["random_forest"]
    mlflow = mlflow_setup()
    with mlflow.start_run(run_name="gridshield-random-forest-candidate") as run:
        mlflow.log_params(params)
        mlflow.log_param("train_rows", len(X))
        mlflow.log_param("feature_count", X.shape[1])
        mlflow.log_param("sklearn_version", sklearn.__version__)
        mlflow.log_param("python_version", platform.python_version())
        model = RandomForestClassifier(**params)
        model.fit(X, y)
        joblib.dump(model, MODEL_PATH)
        with FEATURES_PATH.open("w", encoding="utf-8") as f:
            json.dump(list(X.columns), f, indent=2)
        metadata = {
            "candidate_id": run.info.run_id, "mlflow_run_id": run.info.run_id,
            "created_at_utc": datetime.now(timezone.utc).isoformat(),
            "model_type": "RandomForestClassifier", "training_rows": len(X),
            "feature_count": X.shape[1], "classes": [int(c) for c in model.classes_],
            "model_path": str(MODEL_PATH), "feature_columns_path": str(FEATURES_PATH),
            "training_data": "fixed baseline split",
            "deployment_authorized": False
        }
        write_json(TRAINING_METADATA_PATH, metadata)
        for path in [MODEL_PATH, FEATURES_PATH, TRAINING_METADATA_PATH]:
            mlflow.log_artifact(str(path), artifact_path="candidate")
        mlflow.set_tag("gridshield.stage", "candidate_training")
        mlflow.set_tag("gridshield.deployment_authorized", "false")
        print(json.dumps(metadata, indent=2))

if __name__ == "__main__":
    main()
