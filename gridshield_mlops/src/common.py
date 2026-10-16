import json
import os
from pathlib import Path
import yaml

ROOT = Path(__file__).resolve().parents[1]
TRAIN_X = ROOT / "data/baseline_split/X_train.csv"
TRAIN_Y = ROOT / "data/baseline_split/y_train.csv"
TEST_X = ROOT / "data/evaluation/X_test.csv"
TEST_Y = ROOT / "data/evaluation/y_test.csv"
CANDIDATE_DIR = ROOT / "artifacts/candidates"
REPORT_DIR = ROOT / "reports"
MODEL_PATH = CANDIDATE_DIR / "candidate_model.joblib"
FEATURES_PATH = CANDIDATE_DIR / "feature_columns.json"
TRAINING_METADATA_PATH = REPORT_DIR / "training_metadata.json"
EVALUATION_REPORT_PATH = REPORT_DIR / "evaluation_report.json"
EVALUATION_METRICS_PATH = REPORT_DIR / "evaluation_metrics.json"
VALIDATION_REPORT_PATH = REPORT_DIR / "data_validation.json"

def load_params():
    with (ROOT / "params.yaml").open(encoding="utf-8") as f:
        return yaml.safe_load(f)

def ensure_output_dirs():
    CANDIDATE_DIR.mkdir(parents=True, exist_ok=True)
    REPORT_DIR.mkdir(parents=True, exist_ok=True)

def write_json(path, payload):
    path.parent.mkdir(parents=True, exist_ok=True)
    with path.open("w", encoding="utf-8") as f:
        json.dump(payload, f, indent=2, allow_nan=False)

def mlflow_setup():
    import mlflow
    uri = os.getenv("MLFLOW_TRACKING_URI", "").strip()
    if uri:
        mlflow.set_tracking_uri(uri)
    mlflow.set_experiment(os.getenv("MLFLOW_EXPERIMENT_NAME", "gridshield-candidate-training"))
    return mlflow
