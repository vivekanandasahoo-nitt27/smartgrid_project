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

    # Persist before the graph interrupts, but only when PostgreSQL is the
    # configured review repository. Local JSON-mode unit tests stay isolated.
    repository = get_sample_repository()
    persistence_result = None
    if hasattr(repository, "register_pending_review"):
        persistence_result = repository.register_pending_review(candidate)

    return {
        "candidate_sample": candidate,
        "repository_inserted": (
            persistence_result["inserted"] if persistence_result else False
        ),
        "repository_status": (
            persistence_result["reason"] if persistence_result else "local_only"
        ),
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
    """Pause for human review and persist the officer's decision."""

    decision = interrupt({
        "request_type": "human_attack_review",
        "event_id": state["event_id"],
        "attack_probability": state["attack_probability"],
        "predicted_class": state["predicted_class"],
        "message": (
            "Review this event: confirm attack, reject, unresolved, "
            "or leave pending."
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
    officer = decision.get("officer_username")
    thread_id = (
        decision.get("thread_id")
        or state.get("workflow_thread_id")
        or state["event_id"]
    )

    allowed = {
        "confirmed_attack",
        "not_attack",
        "unresolved",
        "pending_review",
    }
    if outcome not in allowed:
        raise ValueError(f"Invalid human-review decision: {outcome!r}")

    # Only persist decisions in the PostgreSQL workflow.
    repository = get_sample_repository()
    if isinstance(repository, PostgresSampleRepository):
        if not officer or not str(officer).strip():
            raise ValueError("officer_username is required for an audited decision")

        stored = repository.record_officer_decision(
            state["event_id"],
            stage="attack_review",
            decision=outcome,
            officer_username=str(officer).strip(),
            thread_id=str(thread_id),
        )
        persisted_status = stored["status"]
    else:
        persisted_status = (
            "awaiting_data_admission"
            if outcome == "confirmed_attack"
            else "review_rejected"
            if outcome == "not_attack"
            else "review_unresolved"
        )

    return {
        "human_review_status": outcome,
        "human_verified_attack": outcome == "confirmed_attack",
        "repository_status": persisted_status,
        "audit_events": _audit(
            state,
            "human_review_completed",
            outcome=outcome,
            officer_username=officer,
            repository_status=persisted_status,
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
    """Request separate admission approval and persist the decision."""

    candidate = state.get("candidate_sample")
    if not isinstance(candidate, dict):
        raise ValueError("Data admission requires a candidate sample")

    if state.get("human_review_status") != "confirmed_attack":
        raise ValueError("Human confirmation is required")

    if state.get("human_verified_attack") is not True:
        raise ValueError("Human verification is required")

    if candidate.get("event_id") != state.get("event_id"):
        raise ValueError("Candidate event ID mismatch")

    decision = interrupt({
        "request_type": "data_admission",
        "event_id": state["event_id"],
        "attack_probability": state["attack_probability"],
        "message": (
            "Approve or reject this confirmed incident for dataset admission?"
        ),
        "allowed_decisions": ["approved", "rejected"],
    })

    if not isinstance(decision, dict):
        raise ValueError("Data-admission response must be a dictionary")

    outcome = decision.get("decision")
    if outcome not in {"approved", "rejected"}:
        raise ValueError(f"Invalid data-admission decision: {outcome!r}")

    officer = decision.get("officer_username")
    thread_id = (
        decision.get("thread_id")
        or state.get("workflow_thread_id")
        or state["event_id"]
    )

    repository = get_sample_repository()
    if isinstance(repository, PostgresSampleRepository):
        if not officer or not str(officer).strip():
            raise ValueError("officer_username is required for an audited decision")

        stored = repository.record_officer_decision(
            state["event_id"],
            stage="data_admission",
            decision=outcome,
            officer_username=str(officer).strip(),
            thread_id=str(thread_id),
        )
        persisted_status = stored["status"]
    else:
        persisted_status = (
            "awaiting_dataset_validation"
            if outcome == "approved"
            else "admission_rejected"
        )

    return {
        "data_admission_status": outcome,
        "sample_eligible": False,
        "repository_status": persisted_status,
        "audit_events": _audit(
            state,
            "data_admission_decided",
            event_id=state["event_id"],
            outcome=outcome,
            officer_username=officer,
            repository_status=persisted_status,
        ),
    }





import math
from numbers import Real





def dataset_management_node(state):
    """Validate and persist a candidate while keeping it ineligible."""

    import math
    from numbers import Real

    candidate = state.get("candidate_sample")
    if not isinstance(candidate, dict):
        raise ValueError("Candidate sample is missing")

    event_id = state.get("event_id")
    if not event_id or candidate.get("event_id") != event_id:
        raise ValueError("Candidate event ID mismatch")

    if (
        state.get("human_review_status") != "confirmed_attack"
        or state.get("human_verified_attack") is not True
        or state.get("data_admission_status") != "approved"
    ):
        raise ValueError("Required human approvals are missing")

    measurements = candidate.get("measurements")
    if not isinstance(measurements, dict) or not measurements:
        raise ValueError("Measurements must be a non-empty dictionary")

    validated = {}
    for name, value in measurements.items():
        if (
            not isinstance(name, str)
            or not isinstance(value, Real)
            or isinstance(value, bool)
            or not math.isfinite(float(value))
        ):
            raise ValueError(f"Invalid numeric feature: {name!r}")
        validated[name] = float(value)

    probability = candidate.get("attack_probability", state.get("attack_probability"))
    if (
        not isinstance(probability, Real)
        or isinstance(probability, bool)
        or not math.isfinite(float(probability))
        or not 0.0 <= float(probability) <= 1.0
    ):
        raise ValueError("Candidate requires a valid attack probability")

    repository = get_sample_repository()

    # PostgreSQL is the production path and must match the active model schema.
    if isinstance(repository, PostgresSampleRepository):
        import pickle
        from pathlib import Path

        root = Path(__file__).resolve().parents[1]
        schema_path = root / "artifacts" / "feature_columns3.pkl"

        with schema_path.open("rb") as file:
            feature_columns = list(pickle.load(file))

        if len(feature_columns) != 61 or len(set(feature_columns)) != 61:
            raise ValueError("Expected exactly 61 unique model features")

        missing = [name for name in feature_columns if name not in validated]
        extra = [name for name in validated if name not in feature_columns]
        if missing or extra:
            raise ValueError(
                f"Feature schema mismatch. Missing={missing}; extra={extra}"
            )

        validated = {name: validated[name] for name in feature_columns}

    validated_candidate = {
        **candidate,
        "event_id": event_id,
        "measurements": validated,
        "attack_probability": float(probability),
        "status": "validated_pending_persistence",
        "human_review_status": "confirmed_attack",
        "human_verified_attack": True,
        "data_admission_status": "approved",
        "eligible_for_training": False,
    }

    result = repository.admit(validated_candidate)
    stored = result.get("sample")

    if not stored:
        raise RuntimeError("Repository did not return a persisted sample")

    if stored.get("eligible_for_training") is not False:
        raise RuntimeError("Newly persisted sample must remain ineligible")

    return {
        "candidate_sample": stored,
        "repository_inserted": result["inserted"],
        "repository_status": result["reason"],
        "dataset_validation_status": "passed",
        "sample_eligible": False,
        "audit_events": _audit(
            state,
            "dataset_sample_validated_and_persisted",
            event_id=event_id,
            inserted=result["inserted"],
            repository_status=result["reason"],
        ),
    }



def eligibility_management_node(state):
    """Promote a sample only after explicit dataset validation passes."""

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

    # Require an explicit validation result.
    if state.get("dataset_validation_status") != "passed":
        return {
            "candidate_sample": persisted_sample,
            "sample_eligible": False,
            "eligibility_status": "awaiting_explicit_validation",
            "audit_events": _audit(
                state,
                "sample_eligibility_deferred",
                event_id=event_id,
                reason="explicit_dataset_validation_required",
            ),
        }

    # Do not silently re-promote an already eligible sample.
        # An already-eligible sample must still have explicit validation
    # and consistent persisted eligibility fields.
    if persisted_sample.get("status") == "eligible_for_training":
        if persisted_sample.get("eligible_for_training") is not True:
            raise ValueError(
                "Persisted eligibility status and flag are inconsistent"
            )

        return {
            "candidate_sample": persisted_sample,
            "sample_eligible": True,
            "eligibility_status": "already_eligible",
            "audit_events": _audit(
                state,
                "sample_eligibility_already_granted",
                event_id=event_id,
            ),
        }
        

    if (
        persisted_sample.get("status") != "stored_pending_eligibility"
        or persisted_sample.get("eligible_for_training") is not False
    ):
        raise ValueError("Persisted sample is not awaiting eligibility")

    result = repository.promote_to_eligible(
        event_id,
        human_review_status=state["human_review_status"],
        human_verified_attack=state["human_verified_attack"],
        data_admission_status=state["data_admission_status"],
        validation_passed=True,
    )

    promoted_sample = result["sample"]
    is_eligible = (
        promoted_sample.get("status") == "eligible_for_training"
        and promoted_sample.get("eligible_for_training") is True
    )

    return {
        "candidate_sample": promoted_sample,
        "sample_eligible": is_eligible,
        "eligibility_status": (
            "approved" if is_eligible else result["reason"]
        ),
        "audit_events": _audit(
            state,
            "sample_eligibility_result",
            event_id=event_id,
            eligible=is_eligible,
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
    """Train an isolated candidate using at least 100 eligible attack samples."""

    import joblib
    import pandas as pd
    from datetime import datetime, timezone
    from sklearn.ensemble import RandomForestClassifier

    repository = get_sample_repository()
    eligible_count = repository.count_eligible()

    # Gate 1: Never retrain below the required threshold.
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

    # Gate 2: Require trusted baseline feature and label files.
    x_path = state.get("training_dataset_path")
    y_path = state.get("training_label_path")

    if not x_path or not y_path:
        return {
            "training_run_id": None,
            "retraining_status": "blocked_missing_training_paths",
            "eligible_attack_sample_count": eligible_count,
            "training_error": (
                "Trusted baseline feature and label paths are required."
            ),
            "audit_events": _audit(
                state,
                "retraining_blocked",
                eligible_count=eligible_count,
                required_count=100,
                reason="missing_training_paths",
            ),
        }

    try:
        base_dir = Path(__file__).resolve().parents[1]

        # Load the active feature schema.
        feature_path = base_dir / "artifacts" / "feature_columns3.pkl"

        if not feature_path.exists():
            raise FileNotFoundError(
                f"Feature schema not found: {feature_path}"
            )

        feature_columns = list(joblib.load(feature_path))

        if len(feature_columns) != 61 or len(set(feature_columns)) != 61:
            raise ValueError(
                "Expected exactly 61 unique active model features."
            )

        # Load the trusted baseline dataset.
        X_base = pd.read_csv(x_path)
        y_frame = pd.read_csv(y_path)

        if X_base.empty:
            raise ValueError("Baseline training features are empty.")

        if len(X_base) != len(y_frame):
            raise ValueError(
                "Baseline feature and label row counts do not match."
            )

        if list(X_base.columns) != feature_columns:
            raise ValueError(
                "Baseline feature names or ordering do not match the model."
            )

        if len(y_frame.columns) != 1:
            raise ValueError(
                "The baseline label file must contain exactly one column."
            )

        if X_base.isna().any().any() or y_frame.isna().any().any():
            raise ValueError("Baseline training data contains missing values.")

        # Reject non-numeric and non-finite feature values.
        try:
            X_base_numeric = X_base.to_numpy(dtype=float)
        except (TypeError, ValueError) as exc:
            raise ValueError(
                "Baseline features must all be numeric."
            ) from exc

        if not np.isfinite(X_base_numeric).all():
            raise ValueError(
                "Baseline features contain non-finite values."
            )

        X_base = pd.DataFrame(
            X_base_numeric,
            columns=feature_columns,
        )

        # Validate labels without silently truncating decimals.
        try:
            y_numeric = pd.to_numeric(
                y_frame.iloc[:, 0],
                errors="raise",
            ).to_numpy(dtype=float)
        except (TypeError, ValueError) as exc:
            raise ValueError(
                "Baseline labels must be numeric."
            ) from exc

        if not np.isfinite(y_numeric).all():
            raise ValueError("Baseline labels contain non-finite values.")

        if not np.equal(y_numeric, np.floor(y_numeric)).all():
            raise ValueError("Baseline labels must be integers.")

        y_base = pd.Series(
            y_numeric.astype(int),
            name=y_frame.columns[0],
        )

        required_classes = {0, 1, 2}

        if set(y_base.unique()) != required_classes:
            raise ValueError(
                "Baseline must contain classes 0, 1, and 2."
            )

        # Load only samples eligible in both PostgreSQL tables.
        eligible_samples = repository.list_eligible()

        if len(eligible_samples) < 100:
            raise ValueError(
                "Fewer than 100 eligible samples were retrieved."
            )

        attack_rows = []

        for sample in eligible_samples:
            if sample.get("verified_label") != 1:
                raise ValueError(
                    f"Invalid verified label for event {sample.get('event_id')}."
                )

            measurements = sample.get("measurements")

            if not isinstance(measurements, dict):
                raise ValueError(
                    f"Invalid measurements for event {sample.get('event_id')}."
                )

            missing = [
                name for name in feature_columns
                if name not in measurements
            ]
            extra = [
                name for name in measurements
                if name not in feature_columns
            ]

            if missing or extra:
                raise ValueError(
                    f"Feature schema mismatch for {sample.get('event_id')}. "
                    f"Missing={missing}; extra={extra}"
                )

            attack_rows.append([
                measurements[name] for name in feature_columns
            ])

        # Validate all incoming attack feature values.
        try:
            X_attack_numeric = np.asarray(attack_rows, dtype=float)
        except (TypeError, ValueError) as exc:
            raise ValueError(
                "Eligible attack features must all be numeric."
            ) from exc

        if X_attack_numeric.shape != (
            len(attack_rows), len(feature_columns)
        ):
            raise ValueError("Eligible attack feature dimensions are invalid.")

        if not np.isfinite(X_attack_numeric).all():
            raise ValueError(
                "Eligible attack samples contain non-finite values."
            )

        X_attack = pd.DataFrame(
            X_attack_numeric,
            columns=feature_columns,
        )

        y_attack = pd.Series(
            [1] * len(X_attack),
            name=y_base.name,
            dtype=int,
        )

        # Combine baseline data with newly eligible attack samples.
        X_train = pd.concat(
            [X_base, X_attack],
            ignore_index=True,
        )
        y_train = pd.concat(
            [y_base, y_attack],
            ignore_index=True,
        )

        if set(y_train.unique()) != required_classes:
            raise ValueError(
                "Combined training data must contain classes 0, 1, and 2."
            )

        # Train an isolated candidate; do not replace the active model.
        model = RandomForestClassifier(
            n_estimators=300,
            min_samples_split=20,
            min_samples_leaf=8,
            max_features=None,
            max_depth=50,
            criterion="log_loss",
            bootstrap=False,
            random_state=42,
            n_jobs=-1,
        )

        model.fit(X_train, y_train)

        run_id = datetime.now(timezone.utc).strftime(
            "%Y%m%dT%H%M%S%fZ"
        )

        candidate_dir = base_dir / "artifacts" / "candidates"
        candidate_dir.mkdir(parents=True, exist_ok=True)

        candidate_model_path = (
            candidate_dir / f"gridshield_candidate_{run_id}.pkl"
        )
        candidate_features_path = (
            candidate_dir / f"feature_columns_{run_id}.pkl"
        )

        joblib.dump(model, candidate_model_path)
        joblib.dump(feature_columns, candidate_features_path)

        return {
            "training_run_id": run_id,
            "candidate_model_version": run_id,
            "retraining_status": "candidate_trained_pending_evaluation",
            "eligible_attack_sample_count": len(X_attack),
            "candidate_model_path": str(candidate_model_path),
            "candidate_feature_columns_path": str(candidate_features_path),
            "audit_events": _audit(
                state,
                "candidate_model_trained",
                training_run_id=run_id,
                eligible_attack_sample_count=len(X_attack),
                training_sample_count=len(X_train),
                candidate_model_path=str(candidate_model_path),
            ),
        }

    except Exception as exc:
        reason = f"{type(exc).__name__}: {exc}"

        return {
            "training_run_id": None,
            "retraining_status": "candidate_training_failed",
            "eligible_attack_sample_count": eligible_count,
            "training_error": reason,
            "audit_events": _audit(
                state,
                "candidate_training_failed",
                reason=reason,
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
    """Apply acceptance thresholds and save a candidate evaluation report."""
    import json
    import math
    from dotenv import load_dotenv

    project_root = Path(__file__).resolve().parents[1]
    load_dotenv(project_root / ".env")

    REPORT_DIR.mkdir(parents=True, exist_ok=True)

    metrics = state.get("evaluation_metrics") or {}
    labels = state.get("evaluation_class_labels") or []
    original_status = state.get("evaluation_status", "not_run")

    # Invalid configuration must fail closed; never approve on bad settings.
    try:
        min_accuracy = float(os.getenv("GRIDSHIELD_MIN_ACCURACY", "0.90"))
        min_macro_f1 = float(os.getenv("GRIDSHIELD_MIN_MACRO_F1", "0.85"))
        min_class_recall = float(
            os.getenv("GRIDSHIELD_MIN_CLASS_RECALL", "0.80")
        )
    except (TypeError, ValueError) as exc:
        raise ValueError("Evaluation thresholds must be numeric.") from exc

    thresholds = (min_accuracy, min_macro_f1, min_class_recall)
    if not all(math.isfinite(x) and 0.0 <= x <= 1.0 for x in thresholds):
        raise ValueError("Evaluation thresholds must be finite values from 0 to 1.")

    reasons = []

    # The metrics node is expected to return pending_policy when it has
    # successfully calculated metrics. This function applies the policy.
    if original_status == "error":
        reasons.append("Candidate evaluation failed.")
    elif original_status != "pending_policy":
        reasons.append(
            f"Unexpected evaluation status: {original_status}"
        )

    if set(labels) != {0, 1, 2}:
        reasons.append("Evaluation must cover classes 0, 1, and 2.")

    accuracy = metrics.get("accuracy")
    macro_metrics = metrics.get("macro_average") or {}
    macro_f1 = macro_metrics.get("f1_score")
    recalls = metrics.get("recall_per_class") or {}
    supports = metrics.get("support_per_class") or {}

    if (
        not isinstance(accuracy, (int, float))
        or not math.isfinite(float(accuracy))
        or not 0.0 <= accuracy <= 1.0
    ):
        reasons.append("Valid accuracy metric is missing.")
    elif accuracy < min_accuracy:
        reasons.append(f"Accuracy is below {min_accuracy:.0%}.")

    if (
        not isinstance(macro_f1, (int, float))
        or not math.isfinite(float(macro_f1))
        or not 0.0 <= macro_f1 <= 1.0
    ):
        reasons.append("Valid macro F1 metric is missing.")
    elif macro_f1 < min_macro_f1:
        reasons.append(f"Macro F1 is below {min_macro_f1:.0%}.")

    for label in (0, 1, 2):
        recall = recalls.get(str(label))
        support = supports.get(str(label), 0)

        if not isinstance(support, (int, float)) or support <= 0:
            reasons.append(f"Class {label} has no evaluation examples.")

        if (
            not isinstance(recall, (int, float))
            or not math.isfinite(float(recall))
            or not 0.0 <= recall <= 1.0
        ):
            reasons.append(f"Valid recall for class {label} is missing.")
        elif recall < min_class_recall:
            reasons.append(
                f"Recall for class {label} is below "
                f"{min_class_recall:.0%}."
            )

    # This is the key fix: apply the thresholds and produce a final result.
    evaluation_status = "failed" if reasons else "passed"

    report = {
        "created_at": datetime.now(timezone.utc).isoformat(),
        "candidate_model_version": (
            state.get("candidate_model_version")
            or state.get("training_run_id")
        ),
        "training_run_id": state.get("training_run_id"),
        "event_id": state.get("event_id"),
        "candidate_model_path": state.get("candidate_model_path"),
        "candidate_feature_columns_path": state.get("candidate_feature_columns_path"),
        "evaluation_status": evaluation_status,
        "class_labels": labels,
        "confusion_matrix": state.get("confusion_matrix", []),
        "metrics": metrics,
        "acceptance_policy": {
            "minimum_accuracy": min_accuracy,
            "minimum_macro_f1": min_macro_f1,
            "minimum_class_recall": min_class_recall,
        },
        "reasons": reasons,
        "note": (
            "Passing evaluation does not authorize deployment. "
            "Separate human deployment approval remains required."
        ),
    }

    version = (
        state.get("candidate_model_version")
        or state.get("training_run_id")
        or "candidate"
    )
    report_path = REPORT_DIR / f"evaluation_{version}.json"
    report_path.write_text(
        json.dumps(report, indent=2),
        encoding="utf-8",
    )

    return {
        "evaluation_status": evaluation_status,
        "evaluation_report": report,
        "evaluation_report_path": str(report_path),
        "audit_events": _audit(
            state,
            "evaluation_report_created",
            evaluation_status=evaluation_status,
            reasons=reasons,
            report_path=str(report_path),
        ),
    }


def lifecycle_reporting_node(state):
    return {
        "audit_events": _audit(state, "lifecycle_report_requested"),
    }


def deployment_approval_node(state):
    """Pause for human review only after the candidate passes policy."""
    if state.get("evaluation_status") != "passed":
        return {
            "deployment_approval_status": "blocked_evaluation_not_passed",
            "audit_events": _audit(
                state,
                "deployment_approval_blocked",
                reason="candidate_evaluation_not_passed",
            ),
        }

    version = state.get("candidate_model_version") or state.get("training_run_id")
    event_id = state.get("event_id")
    if not version or not event_id:
        return {
            "deployment_approval_status": "blocked_missing_candidate_identity",
            "audit_events": _audit(
                state,
                "deployment_approval_blocked",
                reason="missing_candidate_version_or_event_id",
            ),
        }

    decision = interrupt({
        "request_type": "model_deployment",
        "event_id": event_id,
        "thread_id": event_id,
        "candidate_model_version": version,
        "evaluation_status": state.get("evaluation_status"),
        "evaluation_report_path": state.get("evaluation_report_path"),
        "candidate_model_path": state.get("candidate_model_path"),
        "message": "Candidate passed evaluation. Human approval is required; approval does not activate the model.",
    })

    if not isinstance(decision, dict):
        raise ValueError("Invalid deployment decision payload")
    if decision.get("decision") == "approved":
        return {
            "deployment_approval_status": "approved",
            "deployment_approval_officer": decision.get("officer_username"),
            "audit_events": _audit(
                state, "candidate_deployment_approved",
                candidate_model_version=version,
                officer_username=decision.get("officer_username"),
                deployment_performed=False,
            ),
        }
    if decision.get("decision") == "rejected":
        return {
            "deployment_approval_status": "rejected",
            "deployment_approval_officer": decision.get("officer_username"),
            "audit_events": _audit(
                state, "candidate_deployment_rejected",
                candidate_model_version=version,
                officer_username=decision.get("officer_username"),
            ),
        }
    raise ValueError("Invalid deployment decision")



def retain_current_model_node(state):
    return {
        "deployment_approval_status": "not_deployed",
        "audit_events": _audit(state, "current_model_retained"),
    }



def deployment_node(state):
    """Fail safely until real deployment and rollback are implemented."""

    return {
        "deployment_status": "not_implemented",
        "deployment_approval_status": "approved_but_not_deployed",
        "deployed_model_version": None,
        "audit_events": _audit(
            state,
            "deployment_blocked_not_implemented",
            candidate_model_version=(
                state.get("candidate_model_version")
                or state.get("training_run_id")
            ),
            reason="safe_deployment_and_rollback_not_implemented",
        ),
    }



def record_deployment_outcome_node(state):
    return {
        "audit_events": _audit(state, "deployment_outcome_recorded"),
    }
