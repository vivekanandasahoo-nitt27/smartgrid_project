
import hashlib
import json
import os
from pathlib import Path
import numpy as np
import pandas as pd
import psycopg
from dotenv import load_dotenv
from psycopg.types.json import Jsonb


# Project root: parent of the scripts folder
BASE_DIR = Path(__file__).resolve().parents[1]
load_dotenv(BASE_DIR / ".env")

DATASETS = [
    {
        "role": "training",
        "X": BASE_DIR / "data" / "baseline_split" / "X_train.csv",
        "y": BASE_DIR / "data" / "baseline_split" / "y_train.csv",
    },
    {
        "role": "evaluation",
        "X": BASE_DIR / "data" / "evaluation" / "X_test.csv",
        "y": BASE_DIR / "data" / "evaluation" / "y_test.csv",
    },
]

BATCH_SIZE = 500


def connect_db():
    required = ["PGHOST", "PGDATABASE", "PGUSER", "PGPASSWORD"]
    missing = [key for key in required if not os.getenv(key)]

    if missing:
        raise RuntimeError(
            f"Missing environment variables in .env: {missing}"
        )

    return psycopg.connect(
        host=os.environ["PGHOST"],
        port=os.getenv("PGPORT", "5432"),
        dbname=os.environ["PGDATABASE"],
        user=os.environ["PGUSER"],
        password=os.environ["PGPASSWORD"],
    )


def load_dataset(x_path: Path, y_path: Path):
    if not x_path.exists() or not y_path.exists():
        raise FileNotFoundError(
            f"Dataset files not found: {x_path} or {y_path}"
        )

    X = pd.read_csv(x_path)
    y_df = pd.read_csv(y_path)

    if X.empty or y_df.empty:
        raise ValueError("A dataset file is empty.")

    if len(X) != len(y_df):
        raise ValueError(
            f"Feature/label row mismatch: {len(X)} vs {len(y_df)}"
        )

    if not X.columns.is_unique:
        raise ValueError("Feature column names must be unique.")

    if X.shape[1] != 61:
        raise ValueError(
            f"Expected 61 features, found {X.shape[1]}."
        )

    if X.isna().any().any() or y_df.isna().any().any():
        raise ValueError("Missing values detected. Fix them before ingestion.")

    if len(y_df.columns) != 1:
        raise ValueError("Expected exactly one label column.")

    labels = pd.to_numeric(y_df.iloc[:, 0], errors="raise")

    if not labels.isin([0, 1, 2]).all():
        raise ValueError("Labels must be 0=healthy, 1=attack, 2=fault.")

    X = X.apply(pd.to_numeric, errors="raise")

    # Reject infinities and non-finite numeric values.
    import numpy as np
    if not np.isfinite(X.to_numpy(dtype=float)).all():
        raise ValueError(
            "Infinite or non-finite feature values detected."
        )

    import numpy as np
    if not np.isfinite(X.to_numpy(dtype=float)).all():
        raise ValueError("Non-finite feature values detected.")

    return X, labels.astype(int)


def make_record_hash(measurements, label):
    # Hash features + label, independent of source filename.
    canonical = json.dumps(
        {"measurements": measurements, "label": int(label)},
        sort_keys=True,
        separators=(",", ":"),
        allow_nan=False,
    )
    return hashlib.sha256(canonical.encode("utf-8")).hexdigest()


def ingest_one_dataset(conn, dataset):
    X, labels = load_dataset(dataset["X"], dataset["y"])
    role = dataset["role"]
    source = dataset["X"].name

    inserted = 0
    duplicates = 0

    sql = """
        INSERT INTO gridshield_samples (
            measurements,
            label,
            source_file,
            dataset_role,
            record_hash,
            eligible_for_training,
            admission_status
        )
        VALUES (%s, %s, %s, %s, %s, %s, %s)
        ON CONFLICT (record_hash) DO NOTHING
    """

    with conn.cursor() as cur:
        for start in range(0, len(X), BATCH_SIZE):
            end = min(start + BATCH_SIZE, len(X))
            rows = []

            for i in range(start, end):
                measurements = {
                    str(column): float(value)
                    for column, value in X.iloc[i].items()
                }
                label = int(labels.iloc[i])
                record_hash = make_record_hash(measurements, label)

                # Baseline training rows are eligible after validation.
                # Evaluation rows are never eligible for training.
                eligible = role == "training"

                rows.append(
                    (
                        Jsonb(measurements),
                        label,
                        source,
                        role,
                        record_hash,
                        eligible,
                        "initial_import",
                    )
                )

            cur.executemany(sql, rows)
            # Count inserts vs conflicts in the database using RETURNING
            # in the next verification query; do not guess row counts here.
            print(f"{role}: processed rows {start + 1}-{end}")

    conn.commit()
    return len(X)


def main():
    total_processed = 0

    with connect_db() as conn:
        for dataset in DATASETS:
            print(f"\nLoading {dataset['role']} dataset...")
            total_processed += ingest_one_dataset(conn, dataset)

        print("\nIngestion finished.")
        print(f"Total rows processed: {total_processed}")

        with conn.cursor() as cur:
            cur.execute("""
                SELECT dataset_role, label, COUNT(*)
                FROM gridshield_samples
                GROUP BY dataset_role, label
                ORDER BY dataset_role, label
            """)
            print("\nDatabase counts by role and label:")
            for row in cur.fetchall():
                print(row)

            cur.execute("""
                SELECT dataset_role, COUNT(*)
                FROM gridshield_samples
                GROUP BY dataset_role
                ORDER BY dataset_role
            """)
            print("\nDatabase counts by dataset role:")
            for row in cur.fetchall():
                print(row)


if __name__ == "__main__":
    main()
