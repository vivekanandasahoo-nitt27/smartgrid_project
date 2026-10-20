from __future__ import annotations

import json
import os
import shutil
import subprocess
import sys
from datetime import datetime
from pathlib import Path

import joblib
from dotenv import load_dotenv

ROOT = Path(__file__).resolve().parents[1]
ARTIFACTS = ROOT / "artifacts"
REPORTS = ROOT / "reports"
VERSION = "mlops-b1686b54a323428caad43452cd126ae5"
EVENT_ID = VERSION

CANDIDATE_DIR = ARTIFACTS / "candidates" / VERSION
CANDIDATE_MODEL = CANDIDATE_DIR / "candidate_model.joblib"
CANDIDATE_FEATURES = CANDIDATE_DIR / "feature_columns.json"
REPORT_PATH = REPORTS / f"evaluation_{VERSION.removeprefix('mlops-')}.json"
ACTIVE_MODEL = ARTIFACTS / "smartgrid_rf_model3.pkl"
ACTIVE_FEATURES = ARTIFACTS / "feature_columns3.pkl"
BACKUP_ROOT = ARTIFACTS / "backups"


def read_candidate_features(path: Path) -> list[str]:
    data = json.loads(path.read_text(encoding="utf-8"))
    if isinstance(data, list):
        features = data
    elif isinstance(data, dict):
        features = data.get("feature_columns", data.get("features"))
    else:
        features = None
    if not isinstance(features, list) or not features:
        raise ValueError("feature_columns.json must contain a non-empty feature list.")
    if not all(isinstance(item, str) and item.strip() for item in features):
        raise ValueError("Feature names must be non-empty strings.")
    if len(features) != len(set(features)):
        raise ValueError("Duplicate feature names found.")
    return features


def connect_db():
    load_dotenv(ROOT / ".env", override=False)
    required = ("PGHOST", "PGDATABASE", "PGUSER", "PGPASSWORD")
    missing = [key for key in required if not os.environ.get(key)]
    if missing:
        raise RuntimeError(
            "Missing PostgreSQL environment variables in .env: " + ", ".join(missing)
        )
    import psycopg

    return psycopg.connect(
        host=os.environ["PGHOST"],
        dbname=os.environ["PGDATABASE"],
        user=os.environ["PGUSER"],
        password=os.environ["PGPASSWORD"],
        port=os.environ.get("PGPORT", "5432"),
    )


def verify_approval() -> dict:
    from psycopg.rows import dict_row

    with connect_db() as conn:
        conn.row_factory = dict_row
        with conn.cursor() as cur:
            cur.execute(
                """
                SELECT candidate_model_version, event_id, decision,
                       officer_username, thread_id, deployment_performed
                FROM gridshield_model_deployment_audit
                WHERE candidate_model_version = %s
                  AND event_id = %s
                  AND decision = 'approved'
                ORDER BY created_at DESC
                LIMIT 1
                """,
                (VERSION, EVENT_ID),
            )
            row = cur.fetchone()
    if not row:
        raise RuntimeError("No matching approved PostgreSQL audit row found.")
    if row["deployment_performed"]:
        raise RuntimeError("Audit already says deployment_performed=True; refusing redeployment.")
    return dict(row)


def smoke_test_active_model() -> None:
    # Run in a fresh Python process so gridshield.model cannot reuse a cached old model.
    code = r'''
import sys
import numpy as np
import pandas as pd
sys.path.insert(0, sys.argv[1])
from gridshield.model import load_model
model, features = load_model()
if len(features) != int(model.n_features_in_):
    raise RuntimeError("Feature count mismatch")
if not hasattr(model, "predict_proba"):
    raise RuntimeError("predict_proba missing")
row = pd.DataFrame([np.zeros(len(features), dtype=float)], columns=features)
prediction = model.predict(row)
probabilities = model.predict_proba(row)
if len(prediction) != 1 or probabilities.shape[0] != 1:
    raise RuntimeError("Unexpected prediction shape")
if not np.isfinite(probabilities).all():
    raise RuntimeError("Non-finite probabilities")
if abs(float(probabilities[0].sum()) - 1.0) > 1e-5:
    raise RuntimeError("Probabilities do not sum to 1")
print("Fresh-process smoke test passed")
print("Features:", len(features))
print("Predicted class on zero-valued technical test row:", int(prediction[0]))
'''
    result = subprocess.run(
        [sys.executable, "-c", code, str(ROOT)],
        cwd=str(ROOT),
        text=True,
        capture_output=True,
        timeout=60,
    )
    if result.returncode != 0:
        raise RuntimeError("Smoke test failed:\n" + result.stdout + "\n" + result.stderr)
    print(result.stdout.strip())


def mark_deployed() -> None:
    # Update only the newest matching approved row, and only if it is not already marked.
    with connect_db() as conn:
        with conn.cursor() as cur:
            cur.execute(
                """
                UPDATE gridshield_model_deployment_audit
                SET deployment_performed = TRUE
                WHERE ctid = (
                    SELECT ctid
                    FROM gridshield_model_deployment_audit
                    WHERE candidate_model_version = %s
                      AND event_id = %s
                      AND decision = 'approved'
                      AND deployment_performed = FALSE
                    ORDER BY created_at DESC
                    LIMIT 1
                )
                """,
                (VERSION, EVENT_ID),
            )
            if cur.rowcount != 1:
                raise RuntimeError(
                    f"Expected to update one approved audit row; updated {cur.rowcount}."
                )


def main() -> None:
    print("GridShield safe local deployment")
    print("Candidate:", VERSION)
    print("Project:", ROOT)

    required_paths = (
        CANDIDATE_MODEL,
        CANDIDATE_FEATURES,
        REPORT_PATH,
        ACTIVE_MODEL,
        ACTIVE_FEATURES,
    )
    for path in required_paths:
        if not path.is_file():
            raise FileNotFoundError(f"Required file is missing: {path}")

    audit = verify_approval()
    print(
        f"Approval verified: officer={audit['officer_username']}; "
        f"deployment_performed={audit['deployment_performed']}"
    )

    report = json.loads(REPORT_PATH.read_text(encoding="utf-8"))
    evaluation_status = str(report.get("evaluation_status", "")).lower()
    if evaluation_status not in {"passed", "pass", "approved_for_review"}:
        raise RuntimeError(f"Evaluation report did not pass: {evaluation_status!r}")
    if report.get("deployment_authorized") is not False:
        raise RuntimeError(
            "Expected deployment_authorized=false in the evaluation report. "
            "This script requires a separate approved audit record and will not bypass that gate."
        )

    candidate_model = joblib.load(CANDIDATE_MODEL)
    candidate_features = read_candidate_features(CANDIDATE_FEATURES)
    active_features = list(joblib.load(ACTIVE_FEATURES))

    if not hasattr(candidate_model, "predict_proba"):
        raise RuntimeError("Candidate model does not provide predict_proba.")
    if int(getattr(candidate_model, "n_features_in_", -1)) != len(candidate_features):
        raise RuntimeError("Candidate model feature count differs from feature_columns.json.")
    if candidate_features != active_features:
        raise RuntimeError(
            "Candidate feature names/order differ from the active feature list. "
            "No active files have been changed."
        )
    if sorted(int(label) for label in candidate_model.classes_) != [0, 1, 2]:
        raise RuntimeError(f"Unexpected candidate classes: {candidate_model.classes_!r}")

    print("Evaluation status:", evaluation_status)
    print("Accuracy:", report.get("metrics", {}).get("accuracy"))
    print("Macro F1:", report.get("metrics", {}).get("macro_f1"))
    print("Pre-deployment checks passed; feature count:", len(candidate_features))
    print("A zero-input smoke test is only a technical check, not an accuracy test.")

    timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
    backup_dir = BACKUP_ROOT / f"{timestamp}_{VERSION}"
    BACKUP_ROOT.mkdir(parents=True, exist_ok=True)
    backup_dir.mkdir(parents=True, exist_ok=False)
    shutil.copy2(ACTIVE_MODEL, backup_dir / ACTIVE_MODEL.name)
    shutil.copy2(ACTIVE_FEATURES, backup_dir / ACTIVE_FEATURES.name)
    print("Active model backup:", backup_dir)

    temp_model = ARTIFACTS / f".smartgrid_rf_model3_{timestamp}.tmp"
    temp_features = ARTIFACTS / f".feature_columns3_{timestamp}.tmp"
    switching_started = False
    try:
        joblib.dump(candidate_model, temp_model)
        joblib.dump(candidate_features, temp_features)
        model_check = joblib.load(temp_model)
        features_check = list(joblib.load(temp_features))
        if int(model_check.n_features_in_) != len(features_check):
            raise RuntimeError("Serialized temporary model/feature validation failed.")
        if features_check != active_features:
            raise RuntimeError("Serialized temporary feature order differs from active order.")

        # Set flag before first replacement so even a partial switch triggers restoration.
        switching_started = True
        os.replace(temp_model, ACTIVE_MODEL)
        os.replace(temp_features, ACTIVE_FEATURES)
        smoke_test_active_model()
        mark_deployed()
    except Exception:
        if switching_started:
            shutil.copy2(backup_dir / ACTIVE_MODEL.name, ACTIVE_MODEL)
            shutil.copy2(backup_dir / ACTIVE_FEATURES.name, ACTIVE_FEATURES)
            print("Deployment failed; original active files were restored from backup.")
        raise
    finally:
        temp_model.unlink(missing_ok=True)
        temp_features.unlink(missing_ok=True)

    print("\nLOCAL DEPLOYMENT SUCCEEDED")
    print("Active model:", ACTIVE_MODEL)
    print("Active feature list:", ACTIVE_FEATURES)
    print("Backup retained at:", backup_dir)
    print("PostgreSQL audit: deployment_performed=True")
    print(
        "Restart the Flask app/inference process before testing. A running process may have "
        "the previous model cached in memory."
    )


if __name__ == "__main__":
    try:
        main()
    except Exception as exc:
        print(f"\nDEPLOYMENT ABORTED: {exc}", file=sys.stderr)
        sys.exit(1)
