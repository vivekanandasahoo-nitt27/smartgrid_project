
import sys
import uuid
import pickle
from pathlib import Path

from dotenv import load_dotenv

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))
load_dotenv(ROOT / ".env")

from gridshield.repository import PostgresSampleRepository

artifact_path = ROOT / "artifacts" / "feature_columns3.pkl"

with artifact_path.open("rb") as file:
    feature_columns = list(pickle.load(file))

if len(feature_columns) != 61 or len(set(feature_columns)) != 61:
    raise RuntimeError("Expected exactly 61 unique model features")

# Clearly synthetic values for an integration smoke test only.
measurements = {
    name: round((index + 1) / 100.0, 6)
    for index, name in enumerate(feature_columns)
}

event_id = f"db-smoke-test-{uuid.uuid4().hex[:12]}"

sample = {
    "event_id": event_id,
    "measurements": measurements,
    "attack_probability": 0.55,
    "confidence_route": "human_review",
}

repository = PostgresSampleRepository()
result = repository.register_pending_review(sample)

print("Event ID:", event_id)
print("Inserted:", result["inserted"])
print("Repository result:", result["reason"])
print("Stored status:", result["sample"]["status"])
print("Human review:", result["sample"]["human_review_status"])
print("Training eligible:", result["sample"]["eligible_for_training"])

stored = repository.get(event_id)

assert stored is not None, "Incident was not found in PostgreSQL"
assert len(stored["measurements"]) == 61, "Expected 61 stored features"
assert stored["status"] == "awaiting_human_review"
assert stored["human_review_status"] == "pending"
assert stored["eligible_for_training"] is False

print("\nPASS: 61-feature incident persisted and remains ineligible.")
