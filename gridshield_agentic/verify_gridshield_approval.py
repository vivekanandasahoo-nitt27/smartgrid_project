
import os
from pathlib import Path

from dotenv import load_dotenv
import psycopg
from psycopg.rows import dict_row

PROJECT_ROOT = Path(__file__).resolve().parent
load_dotenv(PROJECT_ROOT / ".env", override=False)

event_id = "smoke-review-53f7368198a4"

db_config = {
    "host": os.getenv("PGHOST", "localhost"),
    "port": os.getenv("PGPORT", "5432"),
    "dbname": os.getenv("PGDATABASE", "gridshield_db"),
    "user": os.getenv("PGUSER", "postgres"),
    "password": os.getenv("PGPASSWORD"),
}

if not db_config["password"]:
    raise RuntimeError("PGPASSWORD is missing from .env")

with psycopg.connect(**db_config, row_factory=dict_row) as conn:
    with conn.cursor() as cur:
        cur.execute(
            """
            SELECT event_id, status, human_review_status,
                   human_verified_attack, data_admission_status,
                   eligible_for_training, verified_label,
                   eligibility_approved_at
            FROM gridshield_attack_events
            WHERE event_id = %s
            """,
            (event_id,),
        )
        event = cur.fetchone()

        print("\n=== INCIDENT RECORD ===")
        print(event if event else "EVENT NOT FOUND")

        cur.execute(
            """
            SELECT event_id, stage, decision, officer_username,
                   thread_id, created_at
            FROM gridshield_officer_audit
            WHERE event_id = %s
            ORDER BY created_at ASC, audit_id ASC
            """,
            (event_id,),
        )
        audit = cur.fetchall()

        print("\n=== OFFICER AUDIT TRAIL ===")
        for entry in audit:
            print(entry)

        cur.execute(
            """
            SELECT COUNT(*) AS eligible_count
            FROM gridshield_attack_events
            WHERE eligible_for_training = TRUE
              AND status = 'eligible_for_training'
              AND human_review_status = 'confirmed_attack'
              AND human_verified_attack = TRUE
              AND data_admission_status = 'approved'
              AND verified_label = 1
            """
        )
        print("\n=== ELIGIBLE SAMPLE COUNT ===")
        print(cur.fetchone()["eligible_count"])
        print("RETRAINING THRESHOLD: 100")
