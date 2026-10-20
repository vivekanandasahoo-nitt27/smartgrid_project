
import os
from datetime import datetime, timezone
from gridshield.email_service import send_gridshield_email



def communication_agent(event_type: str, subject: str, details: dict) -> dict:
    """Build and send a GridShield email notification."""

    body_lines = [
        "GridShield Agentic AI Notification",
        "",
        f"Event type: {event_type}",
        "",
        "Details:",
    ]

    for key, value in details.items():
        body_lines.append(f"- {key}: {value}")

    body = "\n".join(body_lines)

    try:
        status_code = send_gridshield_email(
            subject=subject,
            body=body,
        )

        return {
            "notification_status": (
                "sent" if 200 <= status_code < 300 else "failed"
            ),
            "notification_event_type": event_type,
            "notification_status_code": status_code,
        }

    except Exception as exc:
        return {
            "notification_status": "failed",
            "notification_event_type": event_type,
            "notification_error": str(exc),
        }


def _notification_node(state, event_type, subject, details):
    """Workflow adapter: notify the officer and audit the outcome."""

    if os.getenv(
        "GRIDSHIELD_EMAIL_NOTIFICATIONS_ENABLED", "false"
    ).strip().lower() != "true":
        result = {
            "notification_status": "skipped",
            "notification_event_type": event_type,
        }
    else:
        result = communication_agent(
            event_type=event_type,
            subject=subject,
            details=details,
        )

    audit_events = list(state.get("audit_events") or [])
    audit_events.append({
        "timestamp": datetime.now(timezone.utc).isoformat(),
        "event_type": "communication_notification",
        "details": {
            "notification_type": event_type,
            "event_id": state.get("event_id"),
            "status": result["notification_status"],
        },
    })

    return {
        **result,
        "audit_events": audit_events,
    }


def attack_review_notification_node(state):
    """Notify the officer that a candidate attack needs review."""

    return _notification_node(
        state=state,
        event_type="attack_review_required",
        subject="GridShield: Attack review required",
        details={
            "event_id": state.get("event_id"),
            "confidence_route": state.get("confidence_route"),
            "attack_probability": state.get("attack_probability"),
            "root_cause_report": state.get("root_cause_report"),
            "status": "awaiting_human_review",
        },
    )


def data_admission_notification_node(state):
    """Notify the officer that a confirmed attack needs admission approval."""

    return _notification_node(
        state=state,
        event_type="data_admission_required",
        subject="GridShield: Data admission approval required",
        details={
            "event_id": state.get("event_id"),
            "human_review_status": state.get("human_review_status"),
            "status": "awaiting_data_admission_approval",
        },
    )



def model_review_notification_node(state):
    """Notify the officer about a trained and evaluated candidate."""

    report = state.get("evaluation_report") or {}
    version = (
        state.get("candidate_model_version")
        or state.get("training_run_id")
        or "unknown"
    )
    status = state.get("evaluation_status", "unknown")

    if status != "passed":
        return _notification_node(
            state=state,
            event_type="candidate_evaluation_failed",
            subject="GridShield: Candidate evaluation failed",
            details={
                "candidate_version": version,
                "evaluation_status": status,
                "evaluation_report_path": state.get(
                    "evaluation_report_path"
                ),
                "message": (
                    "The candidate is not eligible for deployment approval. "
                    "The current model remains active."
                ),
            },
        )

    return _notification_node(
        state=state,
        event_type="model_review_required",
        subject="GridShield: New model awaits your review",
        details={
            "candidate_version": version,
            "evaluation_status": status,
            "accuracy": (report.get("metrics") or {}).get("accuracy"),
            "macro_f1": (
                (report.get("metrics") or {})
                .get("macro_average", {})
                .get("f1_score")
            ),
            "model_artifact": state.get("candidate_model_path"),
            "feature_artifact": state.get(
                "candidate_feature_columns_path"
            ),
            "evaluation_report": state.get("evaluation_report_path"),
            "message": (
                "Log in to the GridShield officer portal to inspect "
                "the candidate and approve or reject it. "
                "The active model has not been changed."
            ),
        },
    )

