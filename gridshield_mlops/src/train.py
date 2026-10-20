from __future__ import annotations
import hashlib, json, platform
from datetime import datetime, timezone
import joblib, numpy as np, pandas as pd, sklearn
from sklearn.ensemble import RandomForestClassifier
from src.common import (TRAIN_X, TRAIN_Y, TEST_X, MODEL_PATH, FEATURES_PATH, TRAINING_METADATA_PATH,
    VALIDATION_REPORT_PATH, ensure_output_dirs, load_params, mlflow_setup, write_json)
ROOT = TRAIN_X.parents[2]
APPROVED_CSV = ROOT / "data/approved_postgres/approved_samples.csv"
APPROVED_MANIFEST = ROOT / "data/approved_postgres/manifest.json"

def row_hashes(frame):
    return {hashlib.sha256(row.tobytes()).hexdigest() for row in frame.to_numpy(dtype=np.float64)}

def main():
    ensure_output_dirs()
    if not VALIDATION_REPORT_PATH.exists(): raise FileNotFoundError("Run `python -m src.validate_data` first.")
    with VALIDATION_REPORT_PATH.open(encoding="utf-8") as f:
        if json.load(f).get("validation_status") != "passed": raise RuntimeError("Validation has not passed; refusing to train.")
    X_base, yf = pd.read_csv(TRAIN_X), pd.read_csv(TRAIN_Y)
    X_test = pd.read_csv(TEST_X)
    if yf.shape[1] != 1 or len(X_base) != len(yf): raise ValueError("Baseline train features and labels do not match.")
    if list(X_base.columns) != list(X_test.columns): raise ValueError("Baseline/evaluation feature schema differs.")
    for name, frame in [("baseline", X_base), ("evaluation", X_test)]:
        if frame.isna().any().any() or not np.isfinite(frame.to_numpy(dtype=float)).all(): raise ValueError(f"{name} data has missing/non-finite features.")
    y_base = pd.to_numeric(yf.iloc[:, 0], errors="raise").astype(int)
    if not set(y_base.unique()).issubset({0,1,2}): raise ValueError("Baseline labels must be in {0,1,2}.")
    X, y = X_base.copy(), y_base.copy()
    added_ids, skipped_duplicate_ids = [], []
    snapshot_rows = 0
    if not APPROVED_CSV.is_file(): raise FileNotFoundError(f"Run `python -m src.snapshot_approved_samples` first: {APPROVED_CSV}")
    approved = pd.read_csv(APPROVED_CSV)
    if "event_id" not in approved.columns or "label" not in approved.columns: raise ValueError("Approved snapshot needs event_id and label columns.")
    features = [c for c in approved.columns if c not in {"event_id", "label"}]
    if features != list(X_base.columns): raise ValueError("Approved snapshot feature names/order differ from baseline.")
    if approved["event_id"].isna().any() or approved["event_id"].duplicated().any(): raise ValueError("Snapshot has missing/duplicate event IDs.")
    snapshot_rows = len(approved)
    if snapshot_rows:
        labels = pd.to_numeric(approved["label"], errors="raise").astype(int)
        if not (labels == 1).all(): raise ValueError("Only verified attack samples with label 1 may be added.")
        Xa = approved[features].apply(pd.to_numeric, errors="raise")
        if Xa.isna().any().any() or not np.isfinite(Xa.to_numpy(dtype=float)).all(): raise ValueError("Approved snapshot has invalid features.")
        eval_hashes = row_hashes(X_test)
        overlaps = [str(approved.iloc[i]["event_id"]) for i,row in enumerate(Xa.to_numpy(dtype=np.float64)) if hashlib.sha256(row.tobytes()).hexdigest() in eval_hashes]
        if overlaps: raise RuntimeError(f"Approved samples exactly overlap fixed evaluation rows; refusing training. Event IDs: {overlaps}")
        seen = row_hashes(X_base); keep = []
        for i,row in enumerate(Xa.to_numpy(dtype=np.float64)):
            digest = hashlib.sha256(row.tobytes()).hexdigest(); event_id = str(approved.iloc[i]["event_id"])
            if digest in seen: skipped_duplicate_ids.append(event_id); continue
            seen.add(digest); keep.append(i); added_ids.append(event_id)
        if keep:
            X = pd.concat([X_base, Xa.iloc[keep].reset_index(drop=True)], ignore_index=True)
            y = pd.concat([y_base, pd.Series([1]*len(keep), dtype="int64", name=y_base.name)], ignore_index=True)
    if len(X) != len(y) or set(y.unique()) != {0,1,2}: raise ValueError("Combined training data must have matching rows and labels 0,1,2.")
    params = load_params()["random_forest"]
    mlflow = mlflow_setup()
    with mlflow.start_run(run_name="gridshield-random-forest-candidate") as run:
        mlflow.log_params(params)
        for key,value in {"train_rows_total":len(X), "baseline_train_rows":len(X_base), "approved_snapshot_rows":snapshot_rows,
            "approved_rows_added":len(added_ids), "approved_duplicate_rows_skipped":len(skipped_duplicate_ids),
            "feature_count":X.shape[1], "sklearn_version":sklearn.__version__, "python_version":platform.python_version()}.items(): mlflow.log_param(key,value)
        model = RandomForestClassifier(**params); model.fit(X,y); joblib.dump(model, MODEL_PATH)
        FEATURES_PATH.write_text(json.dumps(list(X.columns), indent=2), encoding="utf-8")
        metadata = {"candidate_id":run.info.run_id,"mlflow_run_id":run.info.run_id,"created_at_utc":datetime.now(timezone.utc).isoformat(),
          "model_type":"RandomForestClassifier","training_rows":len(X),"baseline_training_rows":len(X_base),
          "approved_snapshot_rows_read":snapshot_rows,"approved_rows_added":len(added_ids),"approved_event_ids_added":added_ids,
          "approved_duplicate_event_ids_skipped":skipped_duplicate_ids,"feature_count":X.shape[1],"classes":[int(c) for c in model.classes_],
          "model_path":str(MODEL_PATH),"feature_columns_path":str(FEATURES_PATH),
          "training_data":"fixed baseline split plus approved PostgreSQL snapshot","approved_snapshot_path":str(APPROVED_CSV),
          "approved_manifest_path":str(APPROVED_MANIFEST),"evaluation_data":"fixed holdout split; read-only","deployment_authorized":False}
        write_json(TRAINING_METADATA_PATH, metadata)
        for p in [MODEL_PATH, FEATURES_PATH, TRAINING_METADATA_PATH]: mlflow.log_artifact(str(p), artifact_path="candidate")
        if APPROVED_MANIFEST.is_file(): mlflow.log_artifact(str(APPROVED_MANIFEST), artifact_path="data_provenance")
        mlflow.set_tag("gridshield.stage","candidate_training"); mlflow.set_tag("gridshield.deployment_authorized","false")
        mlflow.set_tag("gridshield.training_data","baseline_plus_approved_postgres_snapshot")
        print(json.dumps(metadata, indent=2))

if __name__ == "__main__": main()
