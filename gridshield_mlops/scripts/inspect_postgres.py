
from pathlib import Path
import sys

import psycopg
from dotenv import load_dotenv
from psycopg.rows import dict_row

# Reuse the existing agentic project's DB configuration.
AGENTIC_ROOT = Path(__file__).resolve().parents[2] / "gridshield_agentic"
load_dotenv(AGENTIC_ROOT / ".env")

import os

config = {
    "host": os.getenv("PGHOST", "localhost"),
    "port": int(os.getenv("PGPORT", "5432")),
    "dbname": os.getenv("PGDATABASE", "gridshield_db"),
    "user": os.getenv("PGUSER", "postgres"),
    "password": os.getenv("PGPASSWORD"),
    "connect_timeout": 5,
}

if not config["password"]:
    sys.exit("PGPASSWORD missing from gridshield_agentic/.env")

with psycopg.connect(**config, row_factory=dict_row) as conn:
    # Enforce read-only access for this inspection.
    conn.execute("SET TRANSACTION READ ONLY")

    print("\n=== 1. Counts by dataset role and label ===")
    with conn.cursor() as cur:
        cur.execute("""
            SELECT dataset_role, label, COUNT(*) AS rows
            FROM public.gridshield_samples
            GROUP BY dataset_role, label
            ORDER BY dataset_role, label
        """)
        for row in cur.fetchall():
            print(dict(row))

        print("\n=== 2. Dataset roles ===")
        cur.execute("""
            SELECT dataset_role, COUNT(*) AS rows
            FROM public.gridshield_samples
            GROUP BY dataset_role
            ORDER BY dataset_role
        """)
        for row in cur.fetchall():
            print(dict(row))

        print("\n=== 3. Eligibility/admission status ===")
        cur.execute("""
            SELECT eligible_for_training, admission_status, COUNT(*) AS rows
            FROM public.gridshield_samples
            GROUP BY eligible_for_training, admission_status
            ORDER BY eligible_for_training, admission_status
        """)
        for row in cur.fetchall():
            print(dict(row))

        print("\n=== 4. Feature schema from one row per role ===")
        cur.execute("""
            SELECT DISTINCT ON (dataset_role)
                   dataset_role, measurements
            FROM public.gridshield_samples
            WHERE measurements IS NOT NULL
            ORDER BY dataset_role, id
        """)
        for row in cur.fetchall():
            measurements = row["measurements"]
            print(
                row["dataset_role"],
                "feature_count =", len(measurements),
                "feature_names =", sorted(measurements.keys())
            )

        print("\n=== 5. Operational attack-event statuses ===")
        cur.execute("""
            SELECT status, human_review_status,
                   data_admission_status, verified_label, COUNT(*) AS rows
            FROM public.gridshield_attack_events
            GROUP BY status, human_review_status,
                     data_admission_status, verified_label
            ORDER BY status, human_review_status
        """)
        for row in cur.fetchall():
            print(dict(row))

print("\nRead-only inspection complete. No rows were changed.")
