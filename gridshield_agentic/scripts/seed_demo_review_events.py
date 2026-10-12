"""Start real, resumable LangGraph human-review workflows for demo rows.

This script intentionally does NOT decide whether any event is an attack and
never marks a sample as eligible for training. It only starts each workflow
until the human_attack_review interrupt is active.
"""

from contextlib import ExitStack
from datetime import datetime, timezone
import os
from pathlib import Path
import sys

import pandas as pd
from dotenv import load_dotenv

ROOT = Path(__file__).resolve().parents[1]
PREVIEW = ROOT / "data" / "evaluation" / "demo_review_preview.csv"

# Make `gridshield` imports reliable when launched as `python scripts/...py`.
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

load_dotenv(ROOT / ".env", override=False)

# These demo workflows must persist to the same PostgreSQL backend as Flask.
os.environ["GRIDSHIELD_REPOSITORY"] = "postgres"
# Do not send real emails from a demo-seeding command.
os.environ["GRIDSHIELD_EMAIL_NOTIFICATIONS_ENABLED"] = "false"

from gridshield import agents  # noqa: E402
from gridshield.model import classify_measurements  # noqa: E402
from gridshield.postgres_checkpointer import postgres_checkpointer  # noqa: E402
from gridshield.repository import PostgresSampleRepository  # noqa: E402
from gridshield.routing import route_attack_probability  # noqa: E402
from gridshield.workflow import build_graph  # noqa: E402


REQUIRED_COLUMNS = {
    "ground_truth_class",
    "predicted_class",
    "attack_probability",
}
REVIEW_TYPE = "human_attack_review"


def _active_review_interrupt(snapshot, event_id):
    """Return True only when this thread is paused at its own attack review."""
    for task in getattr(snapshot, "tasks", ()):
        for interrupt_item in getattr(task, "interrupts", ()):
            payload = getattr(interrupt_item, "value", {}) or {}
            if (
                payload.get("event_id") == event_id
                and payload.get("request_type") == REVIEW_TYPE
            ):
                return True
    return False


def _read_preview():
    if not PREVIEW.exists():
        raise FileNotFoundError(
            f"Run scripts/preview_demo_reviews.py first: {PREVIEW}"
        )

    df = pd.read_csv(PREVIEW)
    missing = REQUIRED_COLUMNS - set(df.columns)
    if missing:
        raise ValueError(f"Preview is missing columns: {sorted(missing)}")

    feature_columns = [column for column in df.columns if column not in REQUIRED_COLUMNS]
    if len(feature_columns) != 61:
        raise ValueError(
            f"Expected exactly 61 measurement features, found {len(feature_columns)}"
        )
    if df.empty:
        print("No samples are in the strict 30%-70% review band.")
        return df, feature_columns
    if not df["attack_probability"].between(
        0.30, 0.70, inclusive="neither"
    ).all():
        raise ValueError("Preview contains probabilities outside the strict review band.")
    return df, feature_columns


def main():
    df, feature_columns = _read_preview()
    if df.empty:
        return

    repository = PostgresSampleRepository()
    started = 0
    already_paused = 0
    skipped = 0
    failed = 0

    # Keep the PostgreSQL connection pool/checkpointer alive while each graph
    # is started and its interrupt is written to the checkpoint tables.
    with ExitStack() as stack:
        saver = stack.enter_context(postgres_checkpointer())
        graph = build_graph(checkpointer=saver)

        for index, row in df.iterrows():
            event_id = f"demo-review-test-row-{int(index):05d}"
            measurements = {}
            for column in feature_columns:
                value = row[column]
                if pd.isna(value):
                    raise ValueError(f"Missing value in row {index}, feature {column}")
                measurements[column] = float(value)

            # Check the currently loaded model before starting the graph. The
            # graph itself performs classification again and owns the final
            # prediction; ground-truth labels are never passed into the graph.
            predicted = classify_measurements(measurements)
            actual_probability = float(predicted["attack_probability"])
            actual_class = int(predicted["predicted_class"])
            expected_probability = float(row["attack_probability"])
            expected_class = int(row["predicted_class"])

            if route_attack_probability(actual_probability) != "human_review":
                print(
                    f"SKIP {event_id}: current model routes to "
                    f"{route_attack_probability(actual_probability)!r}, not human_review"
                )
                skipped += 1
                continue
            if actual_class != expected_class or abs(actual_probability - expected_probability) > 1e-5:
                print(
                    f"SKIP {event_id}: preview/model mismatch "
                    f"(preview class={expected_class}, p={expected_probability:.6f}; "
                    f"current class={actual_class}, p={actual_probability:.6f}). "
                    "Re-run preview_demo_reviews.py first."
                )
                skipped += 1
                continue

            # Do not restart an already-decided database event.
            existing = repository.get(event_id)
            if existing is not None and not (
                existing.get("status") == "awaiting_human_review"
                and existing.get("human_review_status") == "pending"
                and existing.get("eligible_for_training") is False
            ):
                print(
                    f"SKIP {event_id}: database record is not pending review "
                    f"(status={existing.get('status')!r}, "
                    f"review={existing.get('human_review_status')!r})"
                )
                skipped += 1
                continue

            config = {"configurable": {"thread_id": event_id}}
            snapshot = graph.get_state(config)

            if _active_review_interrupt(snapshot, event_id):
                print(f"ALREADY PAUSED {event_id}: active human-review interrupt exists")
                already_paused += 1
                continue

            # Never overwrite or restart a thread that has prior checkpoint
            # history but no active matching interrupt.
            if snapshot.values or snapshot.next or snapshot.tasks:
                print(
                    f"SKIP {event_id}: checkpoint history exists but there is no "
                    "matching active human-review interrupt. Inspect this thread manually."
                )
                skipped += 1
                continue

            initial_state = {
                "event_id": event_id,
                "event_timestamp": datetime.now(timezone.utc).isoformat(),
                "measurements": measurements,
            }

            try:
                graph.invoke(initial_state, config=config)
                paused_snapshot = graph.get_state(config)
                if _active_review_interrupt(paused_snapshot, event_id):
                    print(
                        f"PAUSED {event_id} | "
                        f"p_attack={actual_probability:.3%} | features={len(measurements)}"
                    )
                    started += 1
                else:
                    print(
                        f"ERROR {event_id}: graph returned without the expected active "
                        "human-review interrupt. Check server/script logs before retrying."
                    )
                    failed += 1
            except Exception as exc:
                print(f"ERROR {event_id}: {type(exc).__name__}: {exc}")
                failed += 1

    print("\nDemo review workflow initialization complete.")
    print(f"New active review interrupts: {started}")
    print(f"Already active: {already_paused}")
    print(f"Skipped: {skipped}")
    print(f"Failed: {failed}")
    print("No officer decisions were made; no samples were approved for training.")
    print("Email notifications were disabled for this demo run.")


if __name__ == "__main__":
    main()
