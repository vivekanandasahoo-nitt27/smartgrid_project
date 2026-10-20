
from pathlib import Path

import psycopg
from dotenv import load_dotenv
import os
from psycopg import sql

ROOT = Path(__file__).resolve().parent
load_dotenv(ROOT / ".env")

config = {
    "host": os.getenv("PGHOST", "localhost"),
    "port": int(os.getenv("PGPORT", "5432")),
    "dbname": os.getenv("PGDATABASE", "gridshield_db"),
    "user": os.getenv("PGUSER", "postgres"),
    "password": os.getenv("PGPASSWORD"),
    "connect_timeout": 5,
}

if not config["password"]:
    raise RuntimeError("PGPASSWORD is missing from gridshield_agentic/.env")

TABLES = ["gridshield_samples", "gridshield_attack_events"]

with psycopg.connect(**config) as conn:
    conn.execute("SET TRANSACTION READ ONLY")

    print("Connected database:", config["dbname"])

    with conn.cursor() as cur:
        for table in TABLES:
            cur.execute(
                """
                SELECT EXISTS (
                    SELECT 1
                    FROM information_schema.tables
                    WHERE table_schema = 'public'
                      AND table_name = %s
                )
                """,
                (table,),
            )

            exists = cur.fetchone()[0]
            print(f"\nTable: {table}")
            print("Exists:", exists)

            if not exists:
                continue

            cur.execute(
                """
                SELECT column_name, data_type
                FROM information_schema.columns
                WHERE table_schema = 'public'
                  AND table_name = %s
                ORDER BY ordinal_position
                """,
                (table,),
            )

            print("Columns:")
            for column_name, data_type in cur.fetchall():
                print(f"  {column_name}: {data_type}")

            cur.execute(
                sql.SQL("SELECT COUNT(*) FROM {}").format(
                    sql.Identifier("public", table)
                )
            )
            print("Row count:", cur.fetchone()[0])

print("\nRead-only database verification completed.")
