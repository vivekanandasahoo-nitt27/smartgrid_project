
from langgraph.checkpoint.memory import InMemorySaver
from langgraph.graph import StateGraph, START, END
from langgraph.types import Command

from gridshield.state import GridShieldState
from gridshield.agents import human_review_node
from gridshield import agents
from gridshield.repository import JsonSampleRepository


def test_human_review_pause_and_resume(monkeypatch, tmp_path):
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

    # Isolate the test from the real PostgreSQL database.
    repository = JsonSampleRepository(tmp_path / "test_samples.json")
    monkeypatch.setattr(
        agents,
        "get_sample_repository",
        lambda: repository,
    )

    paused = graph.invoke(initial_state, config=config)

    snapshot = graph.get_state(config)
    assert snapshot.interrupts, "Graph did not pause for human review"

    resumed = graph.invoke(
        Command(
            resume={
                "decision": "confirmed_attack",
                "officer_username": "test-officer",
                "thread_id": "review-test-001",
            }
        ),
        config=config,
    )

    assert resumed["human_review_status"] == "confirmed_attack"
    assert resumed["human_verified_attack"] is True
