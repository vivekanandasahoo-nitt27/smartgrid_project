
from langgraph.graph import StateGraph, START, END

from gridshield.state import GridShieldState
from gridshield import agents
from langgraph.checkpoint.memory import InMemorySaver
from gridshield import communication_agent as communication
# ---------------------------------------------------------
# Conditional routing functions
# ---------------------------------------------------------

def choose_confidence_route(state: GridShieldState) -> str:
    return state["confidence_route"]


def choose_after_event_report(state: GridShieldState) -> str:
    """Route reviewable attack events into candidate collection."""
    if state.get("confidence_route") in {
        "potential_new_attack",
        "human_review",
    }:
        return "collect_candidate"
    return "finish"


def choose_human_review_outcome(state: GridShieldState) -> str:
    status = state.get("human_review_status", "pending")

    if status == "confirmed_attack":
        return "confirmed_attack"

    if status == "not_attack":
        return "not_attack"

    if status == "unresolved":
        return "unresolved"

    return "pending_review"



def choose_data_admission_outcome(state: GridShieldState) -> str:
    status = state.get("data_admission_status")

    if status == "approved":
        return "approved"

    if status == "rejected":
        return "rejected"

    return "pending"



def choose_sample_count(state: GridShieldState) -> str:
    count = int(state.get("eligible_attack_sample_count", 0))
    return "retrain" if count >= 100 else "collect"


def choose_evaluation_outcome(state: GridShieldState) -> str:
    if state.get("evaluation_status") == "passed":
        return "passed"
    return "failed"


def choose_deployment_approval(state: GridShieldState) -> str:
    if state.get("deployment_approval_status") == "approved":
        return "approved"
    return "not_approved"


# ---------------------------------------------------------
# Build GridShield LangGraph
# ---------------------------------------------------------

def build_graph(checkpointer=None):
    graph = StateGraph(GridShieldState)

    # 1-3: Monitoring, classification, confidence routing
    graph.add_node("grid_monitoring", agents.grid_monitoring_node)
    graph.add_node("classification", agents.classification_node)
    graph.add_node("confidence_monitor", agents.confidence_monitor_node)

    # Live incident investigation and reporting
    graph.add_node("high_confidence_attack", agents.high_confidence_node)
    graph.add_node("root_cause_analysis", agents.root_cause_analysis_node)
    graph.add_node("event_reporting", agents.event_reporting_node)
    graph.add_node("candidate_collection", agents.candidate_collection_node)
    graph.add_node("below_threshold", agents.below_threshold_node)

    # Human review and data admission
    graph.add_node("human_review", agents.human_review_node)
    graph.add_node("record_excluded_sample", agents.below_threshold_node)
    graph.add_node("keep_pending_review", agents.below_threshold_node)
    graph.add_node("data_admission", agents.data_admission_node)
    graph.add_node("record_rejection", agents.below_threshold_node)
    
    graph.add_node("dataset_management", agents.dataset_management_node)
    graph.add_node(
        "eligibility_management",
        agents.eligibility_management_node,
    )
    graph.add_node("sample_threshold", agents.sample_threshold_node)


    # Model lifecycle
    graph.add_node("retraining", agents.retraining_node)
    graph.add_node("evaluation", agents.evaluate_candidate_metrics_node)
    graph.add_node("evaluation_reporting", agents.evaluation_report_node)
    graph.add_node("deployment_approval", agents.deployment_approval_node)
    graph.add_node("retain_current_model", agents.retain_current_model_node)
    graph.add_node("deployment", agents.deployment_node)
    graph.add_node(
        "record_deployment_outcome",
        agents.record_deployment_outcome_node,
    )
    graph.add_node(
        "deployment_reporting",
        agents.lifecycle_reporting_node,
    )
    
    graph.add_node(
    "notify_attack_review",
    communication.attack_review_notification_node,
    )
    graph.add_node(
        "notify_data_admission",
        communication.data_admission_notification_node,
    )

    # -----------------------------------------------------
    # Initial measurement flow
    # -----------------------------------------------------

    graph.add_edge(START, "grid_monitoring")
    graph.add_edge("grid_monitoring", "classification")
    graph.add_edge("classification", "confidence_monitor")

    graph.add_conditional_edges(
        "confidence_monitor",
        choose_confidence_route,
        {
            "high_confidence_attack": "high_confidence_attack",
            "potential_new_attack": "root_cause_analysis",
            "human_review": "root_cause_analysis",
            "below_attack_collection_threshold": "below_threshold",
        },
    )

    # -----------------------------------------------------
    # High-confidence and potential-new-attack reporting
    # -----------------------------------------------------

    graph.add_edge("high_confidence_attack", "event_reporting")
    graph.add_edge("root_cause_analysis", "event_reporting")

    graph.add_conditional_edges(
        "event_reporting",
        choose_after_event_report,
        {
            "collect_candidate": "candidate_collection",
            "finish": END,
        },
    )

    graph.add_edge("candidate_collection", "notify_attack_review")
    graph.add_edge("notify_attack_review", "human_review")

    # -----------------------------------------------------
    # Human verification: three explicit outcomes
    # -----------------------------------------------------

    graph.add_conditional_edges(
        "human_review",
        choose_human_review_outcome,
        {
            "confirmed_attack": "notify_data_admission",
            "not_attack": "record_excluded_sample",
            "unresolved": "keep_pending_review",
            "pending_review": END,
        },
    )
    graph.add_edge("notify_data_admission", "data_admission")
    graph.add_edge("record_excluded_sample", END)
    graph.add_edge("keep_pending_review", END)
    graph.add_edge("below_threshold", END)

    # -----------------------------------------------------
    # Human data-admission permission
    # -----------------------------------------------------

    
    graph.add_conditional_edges(
        "data_admission",
        choose_data_admission_outcome,
        {
            "approved": "dataset_management",
            "rejected": "record_rejection",
            "pending": END,
        },
    )


    graph.add_edge("record_rejection", END)
    
    graph.add_edge("dataset_management", "eligibility_management")
    graph.add_edge("eligibility_management", "sample_threshold")


    # -----------------------------------------------------
    # Retraining trigger: 100 approved eligible samples
    # -----------------------------------------------------

    graph.add_conditional_edges(
        "sample_threshold",
        choose_sample_count,
        {
            "collect": END,
            "retrain": "retraining",
        },
    )

    graph.add_edge("retraining", "evaluation")
    graph.add_edge("evaluation", "evaluation_reporting")

    # -----------------------------------------------------
    # Evaluation determines whether deployment can proceed
    # -----------------------------------------------------

    graph.add_conditional_edges(
        "evaluation_reporting",
        choose_evaluation_outcome,
        {
            "passed": "deployment_approval",
            "failed": "retain_current_model",
        },
    )

    # -----------------------------------------------------
    # Separate human model-deployment approval
    # -----------------------------------------------------

    graph.add_conditional_edges(
        "deployment_approval",
        choose_deployment_approval,
        {
            "approved": "deployment",
            "not_approved": "retain_current_model",
        },
    )

    graph.add_edge("deployment", "record_deployment_outcome")
    graph.add_edge("retain_current_model", "record_deployment_outcome")
    graph.add_edge("record_deployment_outcome", "deployment_reporting")
    graph.add_edge("deployment_reporting", END)

    if checkpointer is None:
        checkpointer = InMemorySaver()
    return graph.compile(checkpointer=checkpointer)


gridshield_graph = build_graph()
