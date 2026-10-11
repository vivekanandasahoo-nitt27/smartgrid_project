
from langgraph.types import Command

from gridshield import agents
from gridshield.workflow import (
    build_graph,
    choose_evaluation_outcome,
    choose_deployment_approval,
)


def test_failed_evaluation_routes_to_failure():
    assert choose_evaluation_outcome({
        "evaluation_status": "failed",
    }) == "failed"


def test_passed_evaluation_routes_to_approval():
    assert choose_evaluation_outcome({
        "evaluation_status": "passed",
    }) == "passed"


def test_unapproved_deployment_is_not_approved():
    assert choose_deployment_approval({
        "deployment_approval_status": "rejected",
    }) == "not_approved"


def test_approved_deployment_routes_to_deployment():
    assert choose_deployment_approval({
        "deployment_approval_status": "approved",
    }) == "approved"


def test_deployment_approval_interrupt_pauses_and_resumes():
    from langgraph.checkpoint.memory import InMemorySaver
    from langgraph.graph import StateGraph, START, END
    from gridshield.state import GridShieldState

    builder = StateGraph(GridShieldState)
    builder.add_node(
        "deployment_approval",
        agents.deployment_approval_node,
    )
    builder.add_edge(START, "deployment_approval")
    builder.add_edge("deployment_approval", END)

    graph = builder.compile(checkpointer=InMemorySaver())
    config = {"configurable": {"thread_id": "deployment-approval-test-001"}}

    initial_state = {
        "candidate_model_version": "candidate-test-001",
        "evaluation_status": "passed",
    }

    graph.invoke(initial_state, config=config)

    snapshot = graph.get_state(config)
    assert snapshot.interrupts, "Expected deployment approval interrupt"

    result = graph.invoke(
        Command(resume={"decision": "rejected"}),
        config=config,
    )

    assert result["deployment_approval_status"] == "rejected"
