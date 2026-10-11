from datetime import datetime, timezone
from uuid import uuid4

from gridshield.model import classify_measurements
from gridshield.routing import route_attack_probability
import os

from gridshield.repository import (
    JsonSampleRepository,
    PostgresSampleRepository,
)
from datetime import datetime, timezone
import json
from pathlib import Path
from langgraph.types import interrupt
import numpy as np
from sklearn.metrics import (
    accuracy_score,
    confusion_matrix,
    precision_recall_fscore_support,
)

REPORT_DIR = Path(__file__).resolve().parents[1] / "reports"
SAMPLE_REPOSITORY_PATH = (
    Path(__file__).resolve().parents[1] / "data" / "samples.json"
)

_sample_repository = None


def get_sample_repository():
    """Lazily initialize the configured sample repository."""
    global _sample_repository

    if _sample_repository is None:
        from dotenv import load_dotenv

        project_root = Path(__file__).resolve().parents[1]
        load_dotenv(project_root / ".env")

        backend = os.getenv(
            "GRIDSHIELD_REPOSITORY", "json"
        ).strip().lower()

        if backend == "postgres":
            _sample_repository = PostgresSampleRepository()
        elif backend == "json":
            _sample_repository = JsonSampleRepository(
                SAMPLE_REPOSITORY_PATH
            )
        else:
            raise ValueError(
                f"Unsupported GRIDSHIELD_REPOSITORY: {backend}"
            )

    return _sample_repository

def _audit(state, event_type, **details):
    existing = list(state.get("audit_events", []))
    existing.append({
        "timestamp": datetime.now(timezone.utc).isoformat(),
        "event_type": event_type,
        **details,
    })
    return existing


def grid_monitoring_node(state):
    """Initial local/simulation ingress node; hardware adapter comes later."""
    return {
        "event_id": state.get("event_id") or str(uuid4()),
        "event_timestamp": state.get("event_timestamp")
            or datetime.now(timezone.utc).isoformat(),
        "audit_events": _audit(state, "measurements_received"),
    }


def classification_node(state):
    result = classify_measurements(state["measurements"])
    return {**result, "audit_events": _audit(
        state, "classification_completed",
        predicted_class=result["predicted_class"],
        attack_probability=result["attack_probability"],
    )}


def confidence_monitor_node(state):
    route = route_attack_probability(state["attack_probability"])
    return {
        "confidence_route": route,
        "audit_events": _audit(state, "confidence_routed", route=route),
    }



import math
from numbers import Real


def root_cause_analysis_node(state):
    """Analyze available electrical measurements and produce RCA findings."""

    measurements = state.get("measurements", {})
    baseline = state.get("baseline_measurements", {})
    limits = state.get("engineering_limits", {})

    if not isinstance(measurements, dict):
        raise ValueError("measurements must be a dictionary")

    findings = []
    valid_measurements = {}

    # Keep only finite numeric measurements.
    for name, value in measurements.items():
        if (
            isinstance(value, Real)
            and not isinstance(value, bool)
            and math.isfinite(float(value))
        ):
            valid_measurements[name] = float(value)

    if not valid_measurements:
        findings.append({
            "type": "insufficient_measurements",
            "message": "No valid numeric measurements were available.",
        })

    for name, value in valid_measurements.items():
        feature_limits = limits.get(name, {})

        # Check only explicitly configured engineering limits.
        if isinstance(feature_limits, dict):
            minimum = feature_limits.get("min")
            maximum = feature_limits.get("max")

            if minimum is not None and value < minimum:
                findings.append({
                    "type": "below_engineering_limit",
                    "feature": name,
                    "value": value,
                    "limit": minimum,
                })

            if maximum is not None and value > maximum:
                findings.append({
                    "type": "above_engineering_limit",
                    "feature": name,
                    "value": value,
                    "limit": maximum,
                })

        # Compare with a baseline only when one is available.
        baseline_value = baseline.get(name)

        if (
            isinstance(baseline_value, Real)
            and not isinstance(baseline_value, bool)
            and math.isfinite(float(baseline_value))
        ):
            baseline_value = float(baseline_value)

            findings.append({
                "type": "baseline_comparison",
                "feature": name,
                "current_value": value,
                "baseline_value": baseline_value,
                "absolute_deviation": abs(value - baseline_value),
            })

    # Summarize evidence without claiming a proven attack cause.
    summary = {
        "event_id": state.get("event_id"),
        "predicted_class": state.get("predicted_class"),
        "attack_probability": state.get("attack_probability"),
        "confidence_route": state.get("confidence_route"),
        "measurement_count": len(valid_measurements),
        "findings": findings,
        "conclusion": (
            "Measurement anomalies or deviations were identified; "
            "their cause requires further investigation."
            if findings
            else
            "No configured-limit violations or baseline comparisons "
            "were identified. This does not rule out an attack."
        ),
    }

    return {
        "root_cause_report": summary["conclusion"],
        "root_cause_findings": summary,
        "audit_events": _audit(
            state,
            "root_cause_analysis_completed",
            finding_count=len(findings),
            measurement_count=len(valid_measurements),
        ),
    }



def event_reporting_node(state):
    """Create a persistent local incident report."""

    REPORT_DIR.mkdir(parents=True, exist_ok=True)

    report = {
        "event_id": state["event_id"],
        "timestamp": state.get(
            "event_timestamp",
            datetime.now(timezone.utc).isoformat(),
        ),
        "root_cause_findings": state.get("root_cause_findings", {}),
        "predicted_class": state["predicted_class"],
        "attack_probability": state["attack_probability"],
        "confidence_route": state["confidence_route"],
        "root_cause_report": state.get("root_cause_report"),
        "model_version": state.get("model_version", "unknown"),
        "report_status": "created",
    }

    report_path = REPORT_DIR / f"{state['event_id']}.json"
    report_path.write_text(
        json.dumps(report, indent=2),
        encoding="utf-8",
    )

    return {
        "incident_report_status": "created",
        "incident_report_path": str(report_path),
    }




def candidate_collection_node(state):
    """Create an auditable candidate; do not treat it as training data."""

    event_id = state.get("event_id")
    measurements = state.get("measurements")
    attack_probability = state.get("attack_probability")
    confidence_route = state.get("confidence_route")

    if not event_id:
        raise ValueError("Candidate collection requires an event_id")

    if not isinstance(measurements, dict) or not measurements:
        raise ValueError("Candidate collection requires measurements")

    if not isinstance(attack_probability, (int, float)):
        raise ValueError("Candidate requires a numeric attack probability")

    if not 0.0 <= attack_probability <= 1.0:
        raise ValueError("Attack probability must be between 0 and 1")

    if confidence_route not in {
        "potential_new_attack",
        "human_review",
    }:
        raise ValueError(
            "Only potential-new-attack or human-review events "
            "may enter this candidate path"
        )

    candidate = {
        "event_id": event_id,
        "measurements": measurements,
        "attack_probability": float(attack_probability),
        "confidence_route": confidence_route,
        "status": "awaiting_human_review",
        "eligible_for_training": False,
    }

    return {
        "candidate_sample": candidate,
        "human_review_status": "pending",
        "human_verified_attack": False,
        "data_admission_status": "pending",
        "sample_eligible": False,
        "audit_events": _audit(
            state,
            "attack_candidate_created",
            event_id=event_id,
            status="awaiting_human_review",
        ),
    }




def human_review_node(state):
    """Pause the graph until a human reviews the attack candidate."""

    decision = interrupt({
        "request_type": "human_attack_review",
        "event_id": state["event_id"],
        "attack_probability": state["attack_probability"],
        "predicted_class": state["predicted_class"],
        "message": (
            "Review this event and select one outcome: "
            "confirmed_attack, not_attack, unresolved, or pending_review."
        ),
        "allowed_decisions": [
            "confirmed_attack",
            "not_attack",
            "unresolved",
            "pending_review",
        ],
    })

    if not isinstance(decision, dict):
        raise ValueError("Human-review response must be a dictionary")

    outcome = decision.get("decision")

    allowed_outcomes = {
        "confirmed_attack",
        "not_attack",
        "unresolved",
        "pending_review",
    }

    if outcome not in allowed_outcomes:
        raise ValueError(f"Invalid human-review decision: {outcome!r}")

    return {
        "human_review_status": outcome,
        "human_verified_attack": outcome == "confirmed_attack",
        "audit_events": _audit(
            state,
            "human_review_completed",
            outcome=outcome,
        ),
    }



def below_threshold_node(state):
    return {
        "audit_events": _audit(
            state, "not_auto_admitted",
            attack_probability=state["attack_probability"],
        )
    }


def high_confidence_node(state):
    # High confidence does not bypass the dataset-admission process.
    return {
        "audit_events": _audit(state, "high_confidence_attack_detected"),
    }



def data_admission_node(state):
    """Request separate admission approval for a human-confirmed attack."""

    candidate = state.get("candidate_sample")
    if not isinstance(candidate, dict):
        raise ValueError("Data admission requires a candidate sample")

    if state.get("human_review_status") != "confirmed_attack":
        raise ValueError(
            "Data admission requires human confirmation of the attack"
        )

    if state.get("human_verified_attack") is not True:
        raise ValueError("Human verification flag is missing or false")

    if candidate.get("event_id") != state.get("event_id"):
        raise ValueError("Candidate event ID does not match the current event")

    decision = interrupt({
        "request_type": "data_admission",
        "event_id": state["event_id"],
        "attack_probability": state["attack_probability"],
        "message": "Approve or reject this confirmed attack for dataset admission?",
        "allowed_decisions": ["approved", "rejected"],
    })

    if not isinstance(decision, dict):
        raise ValueError("Data-admission response must be a dictionary")

    outcome = decision.get("decision")

    if outcome == "approved":
        status = "approved"
    elif outcome == "rejected":
        status = "rejected"
    else:
        raise ValueError(f"Invalid data-admission decision: {outcome!r}")

    return {
        "data_admission_status": status,
        # Approval is not the same as dataset eligibility.
        "sample_eligible": False,
        "audit_events": _audit(
            state,
            "data_admission_decided",
            event_id=state["event_id"],
            outcome=status,
        ),
    }





import math
from numbers import Real



def dataset_management_node(state):
    """Validate and persist an approved candidate without promoting eligibility."""

    candidate = state.get("candidate_sample")

    if not isinstance(candidate, dict):
        raise ValueError("Candidate sample is missing")

    if state.get("human_review_status") != "confirmed_attack":
        raise ValueError("Dataset admission requires a confirmed attack")

    if state.get("human_verified_attack") is not True:
        raise ValueError("Human verification is missing")

    if state.get("data_admission_status") != "approved":
        raise ValueError("Candidate has not been approved for admission")

    event_id = state.get("event_id")

    if not event_id or candidate.get("event_id") != event_id:
        raise ValueError("Candidate event ID mismatch")

    measurements = candidate.get("measurements")

    if not isinstance(measurements, dict) or not measurements:
        raise ValueError("Candidate measurements are missing")

    invalid_features = [
        name
        for name, value in measurements.items()
        if (
            not isinstance(name, str)
            or not name.strip()
            or not isinstance(value, Real)
            or isinstance(value, bool)
            or not math.isfinite(float(value))
        )
    ]

    if invalid_features:
        raise ValueError(f"Invalid measurement features: {invalid_features}")

    # Prepare a validated record for persistence.
    validated_candidate = {
        **candidate,
        "status": "validated_pending_persistence",
        "eligible_for_training": False,
    }

    repository = get_sample_repository()
    result = repository.admit(validated_candidate)

    inserted = result["inserted"]
    stored_sample = result["sample"]

    # Do not overwrite an existing sample with a duplicate.
    return {
        "candidate_sample": stored_sample,
        "repository_inserted": inserted,
        "repository_status": result["reason"],
        "sample_eligible": False,
        "audit_events": _audit(
            state,
            "dataset_sample_persisted" if inserted else "duplicate_sample_detected",
            event_id=event_id,
            inserted=inserted,
            repository_status=result["reason"],
        ),
    }


def eligibility_management_node(state):
    """Promote a persisted sample only after all required gates pass."""

    event_id = state.get("event_id")
    candidate = state.get("candidate_sample")

    if not isinstance(event_id, str) or not event_id.strip():
        raise ValueError("Eligibility requires a valid event ID")

    if not isinstance(candidate, dict) or candidate.get("event_id") != event_id:
        raise ValueError("Eligibility candidate event ID mismatch")

    if state.get("human_review_status") != "confirmed_attack":
        raise ValueError("Eligibility requires confirmed human review")

    if state.get("human_verified_attack") is not True:
        raise ValueError("Eligibility requires human attack verification")

    if state.get("data_admission_status") != "approved":
        raise ValueError("Eligibility requires approved data admission")

    repository = get_sample_repository()
    persisted_sample = repository.get(event_id)

    if persisted_sample is None:
        raise ValueError("Candidate is not persisted in the repository")

    if persisted_sample.get("status") not in {
        "stored_pending_eligibility",
        "eligible_for_training",
    }:
        raise ValueError("Persisted sample is not in an eligible state for review")

    # The repository status proves dataset_management completed validation
    # and persistence. Recheck the required workflow approval gates above.
    
    result = repository.promote_to_eligible(
        event_id,
        human_review_status=state["human_review_status"],
        human_verified_attack=state["human_verified_attack"],
        data_admission_status=state["data_admission_status"],
        validation_passed=(
            (
                persisted_sample.get("status")
                == "stored_pending_eligibility"
                and persisted_sample.get("eligible_for_training") is False
            )
            or (
                persisted_sample.get("status")
                == "eligible_for_training"
                and persisted_sample.get("eligible_for_training") is True
            )
        ),
    )


    promoted_sample = result["sample"]
    is_eligible = promoted_sample.get("eligible_for_training") is True

    return {
        "candidate_sample": promoted_sample,
        "sample_eligible": is_eligible,
        "eligibility_status": (
            "approved" if is_eligible else result["reason"]
        ),
        "audit_events": _audit(
            state,
            "sample_eligibility_decided",
            event_id=event_id,
            promoted=result["promoted"],
            eligible=is_eligible,
            reason=result["reason"],
        ),
    }




def sample_threshold_node(state):
    count = get_sample_repository().count_eligible()

    return {
        "eligible_attack_sample_count": count,
        "audit_events": _audit(
            state,
            "eligible_sample_count_checked",
            count=count,
        ),
    }




def retraining_node(state):
    """Guard the retraining stage; actual training remains unimplemented."""

    eligible_count = get_sample_repository().count_eligible()

    if eligible_count < 100:
        return {
            "training_run_id": None,
            "retraining_status": "blocked_insufficient_eligible_samples",
            "eligible_attack_sample_count": eligible_count,
            "audit_events": _audit(
                state,
                "retraining_blocked",
                eligible_count=eligible_count,
                required_count=100,
            ),
        }

    return {
        "training_run_id": None,
        "retraining_status": "ready_for_training",
        "eligible_attack_sample_count": eligible_count,
        "audit_events": _audit(
            state,
            "retraining_gate_passed",
            eligible_count=eligible_count,
            required_count=100,
        ),
    }



def evaluation_node(state):
    return {
        "evaluation_status": "not_run",
        "evaluation_report": {},
        "audit_events": _audit(state, "evaluation_placeholder"),
    }



def evaluate_candidate_metrics_node(state):
    """Evaluate a candidate model and store its metrics in GridShieldState."""
    import joblib
    import pandas as pd
    from sklearn.metrics import (
        accuracy_score,
        confusion_matrix,
        precision_recall_fscore_support,
    )

    model_path = state.get("candidate_model_path")
    feature_path = state.get("candidate_feature_columns_path")
    x_path = state.get(
        "evaluation_dataset_path",
        "data/evaluation/X_test.csv",
    )
    y_path = state.get(
        "evaluation_label_path",
        "data/evaluation/y_test.csv",
    )

    # Never silently evaluate the production model as a candidate.
    if not model_path or not feature_path:
        reason = "Candidate model path or feature-column path is missing."
        return {
            "evaluation_status": "error",
            "evaluation_metrics": {},
            "evaluation_report": {
                "status": "error",
                "reason": reason,
            },
            "audit_events": _audit(
                state, "evaluation_failed", reason=reason
            ),
        }

    try:
        model = joblib.load(model_path)
        feature_columns = list(joblib.load(feature_path))

        X_test = pd.read_csv(x_path)
        y_frame = pd.read_csv(y_path)

        if len(y_frame.columns) != 1:
            raise ValueError(
                "Expected exactly one target column in y_test.csv."
            )

        if list(X_test.columns) != feature_columns:
            raise ValueError(
                "Test feature columns do not match the candidate "
                "model's saved feature-column order."
            )

        if len(X_test) != len(y_frame):
            raise ValueError("Test features and labels have different row counts.")

        if X_test.empty:
            raise ValueError("Evaluation dataset is empty.")

        if X_test.isna().any().any() or y_frame.isna().any().any():
            raise ValueError("Evaluation dataset contains missing values.")

        y_true = y_frame.iloc[:, 0]

        if not set(y_true.unique()).issubset(set(model.classes_)):
            raise ValueError(
                "Test labels contain classes not supported by the model."
            )

        labels = [int(label) for label in model.classes_]
        y_pred = model.predict(X_test)

        cm = confusion_matrix(y_true, y_pred, labels=labels)

        p, r, f1, support = precision_recall_fscore_support(
            y_true,
            y_pred,
            labels=labels,
            zero_division=0,
        )

        metrics = {
            "accuracy": float(accuracy_score(y_true, y_pred)),
            "precision_per_class": {
                str(label): float(value)
                for label, value in zip(labels, p)
            },
            "recall_per_class": {
                str(label): float(value)
                for label, value in zip(labels, r)
            },
            "f1_per_class": {
                str(label): float(value)
                for label, value in zip(labels, f1)
            },
            "support_per_class": {
                str(label): int(value)
                for label, value in zip(labels, support)
            },
            "test_sample_count": int(len(y_true)),
        }

        for average in ("macro", "weighted"):
            avg_p, avg_r, avg_f1, _ = precision_recall_fscore_support(
                y_true,
                y_pred,
                labels=labels,
                average=average,
                zero_division=0,
            )
            metrics[f"{average}_average"] = {
                "precision": float(avg_p),
                "recall": float(avg_r),
                "f1_score": float(avg_f1),
            }

        # Metrics have been calculated, but no acceptance policy
        # has been approved yet. Therefore this is NOT a pass.
        return {
            "evaluation_status": "pending_policy",
            "evaluation_metrics": metrics,
            "confusion_matrix": cm.tolist(),
            "evaluation_class_labels": labels,
            "accuracy": metrics["accuracy"],
            "precision": metrics["precision_per_class"],
            "recall": metrics["recall_per_class"],
            "f1_score": metrics["f1_per_class"],
            "evaluation_report": {
                "status": "pending_policy",
                "candidate_model_path": str(model_path),
                "evaluation_dataset_path": str(x_path),
                "evaluation_label_path": str(y_path),
                "class_labels": labels,
                "confusion_matrix": cm.tolist(),
                "metrics": metrics,
                "note": (
                    "Metrics calculated; acceptance thresholds and "
                    "candidate training provenance remain unverified."
                ),
            },
            "audit_events": _audit(
                state,
                "candidate_metrics_calculated",
                test_sample_count=len(y_true),
                class_labels=labels,
            ),
        }

    except Exception as exc:
        reason = f"{type(exc).__name__}: {exc}"
        return {
            "evaluation_status": "error",
            "evaluation_metrics": {},
            "evaluation_report": {
                "status": "error",
                "reason": reason,
            },
            "audit_events": _audit(
                state, "evaluation_failed", reason=reason
            ),
        }




def evaluation_report_node(state):
    """Persist the evaluator's results without recalculating metrics."""
    import json
    from datetime import datetime, timezone

    REPORT_DIR.mkdir(parents=True, exist_ok=True)

    evaluation_status = state.get("evaluation_status", "not_run")
    metrics = state.get("evaluation_metrics", {})
    confusion = state.get("confusion_matrix", [])
    class_labels = state.get("evaluation_class_labels", [])

    report = {
        "created_at": datetime.now(timezone.utc).isoformat(),
        "candidate_model_version": state.get("candidate_model_version"),
        "training_run_id": state.get("training_run_id"),
        "evaluation_status": evaluation_status,
        "class_labels": class_labels,
        "confusion_matrix": confusion,
        "metrics": metrics,
        "note": (
            "This report records evaluation results only. "
            "It does not authorize model deployment."
        ),
    }

    report_path = (
        REPORT_DIR
        / f"evaluation_{state.get('candidate_model_version') or 'candidate'}.json"
    )
    report_path.write_text(
        json.dumps(report, indent=2),
        encoding="utf-8",
    )

    return {
        "evaluation_report": report,
        "evaluation_report_path": str(report_path),
        "audit_events": _audit(
            state,
            "evaluation_report_created",
            report_path=str(report_path),
            evaluation_status=evaluation_status,
        ),
    }



def lifecycle_reporting_node(state):
    return {
        "audit_events": _audit(state, "lifecycle_report_requested"),
    }


def deployment_approval_node(state):
    decision = interrupt({
        "request_type": "model_deployment",
        "candidate_model_version": state["candidate_model_version"],
        "evaluation_status": state["evaluation_status"],
        "message": "Approve or reject this candidate model deployment?",
    })

    if decision.get("decision") == "approved":
        return {"deployment_approval_status": "approved"}

    if decision.get("decision") == "rejected":
        return {"deployment_approval_status": "rejected"}

    raise ValueError("Invalid deployment decision")



def retain_current_model_node(state):
    return {
        "deployment_approval_status": "not_deployed",
        "audit_events": _audit(state, "current_model_retained"),
    }


def deployment_node(state):
    # Safe deployment/rollback mechanics will be implemented and tested later.
    return {
        "audit_events": _audit(state, "deployment_placeholder"),
    }


def record_deployment_outcome_node(state):
    return {
        "audit_events": _audit(state, "deployment_outcome_recorded"),
    }
