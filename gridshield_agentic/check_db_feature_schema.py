
import os
import pickle
from pathlib import Path

import psycopg
from dotenv import load_dotenv

ROOT = Path(__file__).resolve().parent
load_dotenv(ROOT / ".env")

artifact_path = ROOT / "artifacts" / "feature_columns3.pkl"

with artifact_path.open("rb") as file:
    model_features = pickle.load(file)

model_features = list(model_features)

metadata_columns = {
    "event_id",
    "label",
    "eligible_for_training",
    "created_at",
}

with psycopg.connect(
    host=os.getenv("PGHOST", "localhost"),
    port=os.getenv("PGPORT", "5432"),
    dbname=os.getenv("PGDATABASE", "gridshield_db"),
    user=os.getenv("PGUSER", "postgres"),
    password=os.getenv("PGPASSWORD"),
) as conn:
    with conn.cursor() as cur:
        cur.execute(
            """
            SELECT column_name
            FROM information_schema.columns
            WHERE table_schema = 'public'
              AND table_name = 'gridshield_new_training_data'
            ORDER BY ordinal_position
            """
        )
        db_columns = [row[0] for row in cur.fetchall()]

db_features = [
    name for name in db_columns
    if name not in metadata_columns
]

missing_in_db = [
    name for name in model_features if name not in db_features
]
extra_in_db = [
    name for name in db_features if name not in model_features
]

print(f"Model feature count: {len(model_features)}")
print(f"Database feature count: {len(db_features)}")
print(f"Model features unique: {len(set(model_features)) == len(model_features)}")
print(f"Database features unique: {len(set(db_features)) == len(db_features)}")
print(f"Missing in database: {missing_in_db}")
print(f"Extra in database: {extra_in_db}")
print(
    "Same feature order:",
    model_features == db_features,
)

if (
    len(model_features) == 61
    and len(db_features) == 61
    and not missing_in_db
    and not extra_in_db
    and len(set(model_features)) == 61
    and len(set(db_features)) == 61
):
    print("\nPASS: Database and model feature names match.")
else:
    print("\nFAIL: Do not insert or train until the schema mismatch is resolved.")
