
import json
import re
import shutil
import sys
from pathlib import Path

# Project directories
MLOPS_ROOT = Path(__file__).resolve().parents[1]
AGENTIC_ROOT = MLOPS_ROOT.parent / "gridshield_agentic"

sys.path.insert(0, str(AGENTIC_ROOT))

from gridshield.postgres_checkpointer import postgres_checkpointer
from gridshield.workflow import build_graph


def read_json(path):
    with path.open("r", encoding="utf-8") as file:
        return json.load(file)


def resolve_inside(path_value, allowed_root):
    """Resolve a path and reject paths outside the expected directory."""
    path = Path(path_value)
    if not path.is_absolute():
        path = MLOPS_ROOT / path

    path = path.resolve()
    allowed_root = allowed_root.resolve()

    if not path.is_relative_to(allowed_root):
        raise ValueError(f"Path is outside the permitted directory: {path}")

    if not path.is_file():
        raise FileNotFoundError(f"Required file not found: {path}")

    return path


def main():
    metadata_path = MLOPS_ROOT / "reports" / "training_metadata.json"
    evaluation_path = MLOPS_ROOT / "reports" / "evaluation_report.json"
    mlops_candidate_root = MLOPS_ROOT / "artifacts" / "candidates"

    if not metadata_path.is_file() or not evaluation_path.is_file():
        raise FileNotFoundError(
            "Run validation, training, and evaluation first. "
            "The required metadata or evaluation report is missing."
        )

    metadata = read_json(metadata_path)
    report = read_json(evaluation_path)

    # Only passing candidates can enter human approval.
    if report.get("evaluation_status") != "passed":
        raise SystemExit(
            "Candidate did not pass evaluation. It will not be published."
        )

    if report.get("deployment_authorized") is not False:
        raise SystemExit(
            "Expected deployment_authorized=false. "
            "Refusing to publish an incorrectly marked report."
        )

    candidate_id = str(
        metadata.get("candidate_id") or metadata.get("mlflow_run_id") or ""
    ).strip()

    if not candidate_id or not re.fullmatch(r"[A-Za-z0-9_-]{1,100}", candidate_id):
        raise ValueError("Missing or unsafe candidate ID in training metadata.")

    model_source = resolve_inside(
        metadata.get("model_path", "artifacts/candidates/candidate_model.joblib"),
        mlops_candidate_root,
    )
    features_source = resolve_inside(
        metadata.get(
            "feature_columns_path",
            "artifacts/candidates/feature_columns.json",
        ),
        mlops_candidate_root,
    )

    candidate_version = f"mlops-{candidate_id}"
    event_id = candidate_version

    # Copy into the directories that the existing Flask portal scans.
    agentic_candidate_root = (
        AGENTIC_ROOT / "artifacts" / "candidates" / candidate_version
    ).resolve()
    agentic_candidate_root.mkdir(parents=True, exist_ok=False)

    model_destination = agentic_candidate_root / "candidate_model.joblib"
    features_destination = agentic_candidate_root / "feature_columns.json"

    try:
        shutil.copy2(model_source, model_destination)
        shutil.copy2(features_source, features_destination)

        # Keep the original metrics and expose macro F1 in the shape
        # expected by the existing dashboard.
        published_report = dict(report)
        metrics = dict(report.get("metrics") or {})
        metrics["macro_average"] = {
            "f1_score": metrics.get("macro_f1")
        }

        published_report.update({
            "candidate_model_version": candidate_version,
            "event_id": event_id,
            "evaluation_status": "passed",
            "deployment_authorized": False,
            "candidate_model_path": str(model_destination),
            "candidate_feature_columns_path": str(features_destination),
            "training_run_id": metadata.get("mlflow_run_id"),
            "metrics": metrics,
            "source_evaluation_report": str(evaluation_path.resolve()),
        })

        agentic_report_dir = AGENTIC_ROOT / "reports"
        agentic_report_dir.mkdir(parents=True, exist_ok=True)
        published_report_path = (
            agentic_report_dir / f"evaluation_{candidate_id}.json"
        ).resolve()

        with published_report_path.open("x", encoding="utf-8") as file:
            json.dump(published_report, file, indent=2, allow_nan=False)

        published_report["evaluation_report_path"] = str(
            published_report_path
        )

        initial_state = {
            "workflow_type": "mlops_candidate_review",
            "event_id": event_id,
            "candidate_model_version": candidate_version,
            "training_run_id": metadata.get("mlflow_run_id"),
            "candidate_model_path": str(model_destination),
            "candidate_feature_columns_path": str(features_destination),
            "evaluation_status": "passed",
            "evaluation_report": published_report,
            "evaluation_report_path": str(published_report_path),
            "audit_events": [],
        }

        # Persist the workflow and its human-approval interrupt.
        with postgres_checkpointer() as saver:
            graph = build_graph(checkpointer=saver)
            graph.invoke(
                initial_state,
                config={"configurable": {"thread_id": event_id}},
            )

        print("Candidate published for human review.")
        print(f"Candidate version: {candidate_version}")
        print(f"Evaluation report: {published_report_path}")
        print("Check the GridShield officer portal for the approval request.")
        print("The active model has not been changed.")

    except Exception:
        # Remove newly-created files if publishing failed before completion.
        # Do not touch the active model or the PostgreSQL sample table.
        shutil.rmtree(agentic_candidate_root, ignore_errors=True)
        raise


if __name__ == "__main__":
    main()
