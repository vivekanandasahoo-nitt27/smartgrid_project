
from pathlib import Path
import pandas as pd

from gridshield.repository import PostgresSampleRepository

ROOT = Path(__file__).resolve().parents[1]
PREVIEW = ROOT / "data" / "evaluation" / "demo_review_preview.csv"

def main():
    if not PREVIEW.exists():
        raise FileNotFoundError(
            f"Run preview_demo_reviews.py first: {PREVIEW}"
        )

    df = pd.read_csv(PREVIEW)

    required = {
        "ground_truth_class",
        "predicted_class",
        "attack_probability",
    }
    missing = required - set(df.columns)
    if missing:
        raise ValueError(f"Preview is missing columns: {sorted(missing)}")

    feature_columns = [
        c for c in df.columns
        if c not in required
    ]

    if len(feature_columns) != 61:
        raise ValueError(
            f"Expected 61 measurement features, found {len(feature_columns)}"
        )

    if df.empty:
        print("No samples are in the 30%-70% review band.")
        return

    if not df["attack_probability"].between(
        0.30, 0.70, inclusive="neither"
    ).all():
        raise ValueError("Preview contains samples outside the review band.")

    repository = PostgresSampleRepository()

    # Refuse to overwrite or silently reuse existing event IDs.
    existing = {
        row["event_id"]
        for row in repository.list_suspicious_events(
            min_confidence=0.30,
            max_confidence=0.70,
            limit=5000,
        )
    }

    inserted = 0

    for index, row in df.iterrows():
        event_id = f"demo-review-test-row-{int(index):05d}"

        if event_id in existing:
            print(f"SKIP existing event: {event_id}")
            continue

        measurements = {}
        for column in feature_columns:
            value = row[column]
            if pd.isna(value):
                raise ValueError(
                    f"Missing value in row {index}, feature {column}"
                )
            measurements[column] = float(value)

        result = repository.register_pending_review({
            "event_id": event_id,
            "measurements": measurements,
            "attack_probability": float(row["attack_probability"]),
            "confidence_route": "human_review",
        })

        if result.get("inserted"):
            inserted += 1
            print(
                f"INSERTED {event_id} | "
                f"attack_probability={row['attack_probability']:.3%} | "
                f"features={len(measurements)}"
            )
        else:
            print(
                f"NOT INSERTED {event_id}: "
                f"{result.get('reason', 'unknown reason')}"
            )

    print(f"\nNew events inserted: {inserted}")
    print("All inserted events use the pending-review workflow.")
    print("No ground-truth label was used as an officer decision.")
    print("No event was approved for model training by this script.")

if __name__ == "__main__":
    main()
