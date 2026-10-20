from __future__ import annotations
import hashlib, json, os
from datetime import datetime, timezone
from pathlib import Path
import pandas as pd
from dotenv import load_dotenv
import psycopg
from psycopg import sql
from psycopg.rows import dict_row

ROOT = Path(__file__).resolve().parents[1]
AGENTIC_ROOT = ROOT.parent / "gridshield_agentic"
TRAIN_X = ROOT / "data/baseline_split/X_train.csv"
OUT_DIR = ROOT / "data/approved_postgres"
OUT_CSV = OUT_DIR / "approved_samples.csv"
OUT_MANIFEST = OUT_DIR / "manifest.json"

def sha256_file(path: Path) -> str:
    h = hashlib.sha256()
    with path.open("rb") as f:
        for chunk in iter(lambda: f.read(1024 * 1024), b""):
            h.update(chunk)
    return h.hexdigest()

def main():
    if not TRAIN_X.is_file():
        raise FileNotFoundError(f"Missing baseline schema file: {TRAIN_X}")
    features = list(pd.read_csv(TRAIN_X, nrows=0).columns)
    if not features or len(features) != len(set(features)):
        raise ValueError("Baseline feature schema is empty or has duplicate columns.")
    env_path = AGENTIC_ROOT / ".env"
    if not env_path.is_file():
        raise FileNotFoundError(f"Cannot find {env_path}; keep credentials in .env and do not paste them into chat.")
    load_dotenv(env_path)
    cfg = {"host": os.getenv("PGHOST", "localhost"), "port": os.getenv("PGPORT", "5432"),
           "dbname": os.getenv("PGDATABASE", "gridshield_db"), "user": os.getenv("PGUSER", "postgres"),
           "password": os.getenv("PGPASSWORD", "")}
    if not cfg["password"]:
        raise RuntimeError("PGPASSWORD is missing from gridshield_agentic/.env")
    feature_sql = sql.SQL(", ").join(sql.SQL("n.{}").format(sql.Identifier(c)) for c in features)
    query = sql.SQL("""
        SELECT n.event_id, n.label, {features}
        FROM gridshield_new_training_data AS n
        JOIN gridshield_attack_events AS a ON a.event_id = n.event_id
        WHERE n.eligible_for_training IS TRUE AND n.label = 1
          AND a.eligible_for_training IS TRUE
          AND a.status = 'eligible_for_training'
          AND a.human_review_status = 'confirmed_attack'
          AND a.human_verified_attack IS TRUE
          AND a.data_admission_status = 'approved'
          AND a.verified_label = 1
        ORDER BY a.eligibility_approved_at ASC NULLS LAST, n.event_id ASC
    """).format(features=feature_sql)
    with psycopg.connect(**cfg, row_factory=dict_row) as conn:
        with conn.cursor() as cur:
            cur.execute(query)
            rows = cur.fetchall()
    OUT_DIR.mkdir(parents=True, exist_ok=True)
    records, seen = [], set()
    for row in rows:
        event_id = row["event_id"]
        if not isinstance(event_id, str) or not event_id.strip() or event_id in seen:
            raise ValueError("Invalid or duplicate event_id in eligible PostgreSQL rows.")
        seen.add(event_id)
        rec = {"event_id": event_id}
        for c in features:
            v = row[c]
            if isinstance(v, bool) or not isinstance(v, (int, float)) or not pd.notna(v) or not float("-inf") < float(v) < float("inf"):
                raise ValueError(f"Invalid numeric feature {c} for event {event_id}")
            rec[c] = float(v)
        if row["label"] != 1:
            raise ValueError(f"Only verified attack label 1 is allowed: {event_id}")
        rec["label"] = 1
        records.append(rec)
    columns = ["event_id", *features, "label"]
    snapshot = pd.DataFrame(records, columns=columns)
    snapshot.to_csv(OUT_CSV, index=False, lineterminator="\n")
    manifest = {"snapshot_created_at_utc": datetime.now(timezone.utc).isoformat(),
      "source": "read-only SELECT from gridshield_new_training_data joined to gridshield_attack_events",
      "approval_gates": ["training row eligible=true and label=1", "event eligible=true", "status=eligible_for_training",
       "human_review_status=confirmed_attack", "human_verified_attack=true", "data_admission_status=approved", "verified_label=1"],
      "row_count": len(snapshot), "feature_count": len(features), "feature_columns": features,
      "event_ids": snapshot["event_id"].tolist(), "csv_sha256": sha256_file(OUT_CSV),
      "database_rows_modified": False, "evaluation_dataset_modified": False}
    OUT_MANIFEST.write_text(json.dumps(manifest, indent=2), encoding="utf-8")
    print(json.dumps({"snapshot_csv": str(OUT_CSV), "manifest": str(OUT_MANIFEST),
      "eligible_approved_rows": len(snapshot), "event_ids": manifest["event_ids"], "database_rows_modified": False}, indent=2))

if __name__ == "__main__":
    main()
