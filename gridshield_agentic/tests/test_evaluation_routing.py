
from gridshield.workflow import (
    choose_evaluation_outcome,
    choose_deployment_approval,
)


def test_pending_policy_cannot_proceed_to_deployment_approval():
    assert choose_evaluation_outcome({
        "evaluation_status": "pending_policy",
    }) == "failed"


def test_evaluation_error_cannot_proceed_to_deployment_approval():
    assert choose_evaluation_outcome({
        "evaluation_status": "error",
    }) == "failed"


def test_failed_evaluation_cannot_proceed_to_deployment_approval():
    assert choose_evaluation_outcome({
        "evaluation_status": "failed",
    }) == "failed"


def test_only_passed_evaluation_reaches_approval_route():
    assert choose_evaluation_outcome({
        "evaluation_status": "passed",
    }) == "passed"


def test_rejected_deployment_does_not_take_approved_route():
    assert choose_deployment_approval({
        "deployment_approval_status": "rejected",
    }) == "not_approved"
