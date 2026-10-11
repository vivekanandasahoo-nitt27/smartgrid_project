
from langgraph.checkpoint.memory import InMemorySaver
from langgraph.types import Command
from langgraph.graph import StateGraph, START, END
from gridshield.state import GridShieldState
from gridshield.agents import human_review_node


def test_human_review_pause_and_resume():
    builder = StateGraph(GridShieldState)
    builder.add_node("human_review", human_review_node)
    builder.add_edge(START, "human_review")
    builder.add_edge("human_review", END)

    graph = builder.compile(checkpointer=InMemorySaver())

    config = {"configurable": {"thread_id": "review-test-001"}}

    initial_state = {
        "event_id": "event-test-001",
        "predicted_class": 1,
        "attack_probability": 0.78,
    }

    paused = graph.invoke(initial_state, config=config)

    # The graph should pause at the human-review interrupt.
    snapshot = graph.get_state(config)
    assert snapshot.interrupts, "Graph did not pause for human review"

    resumed = graph.invoke(
        Command(resume={"decision": "confirmed_attack"}),
        config=config,
    )

    assert resumed["human_review_status"] == "confirmed_attack"
    assert resumed["human_verified_attack"] is True
