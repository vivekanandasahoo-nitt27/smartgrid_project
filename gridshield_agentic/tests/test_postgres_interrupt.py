
import os
from uuid import uuid4

import pytest
from langgraph.graph import StateGraph, START, END
from langgraph.types import Command

from gridshield.state import GridShieldState
from gridshield.agents import human_review_node
from gridshield.postgres_checkpointer import postgres_checkpointer


pytestmark = pytest.mark.skipif(
    os.getenv("GRIDSHIELD_RUN_POSTGRES_TESTS") != "1",
    reason="Set GRIDSHIELD_RUN_POSTGRES_TESTS=1 to run PostgreSQL tests",
)


def test_postgres_human_review_pause_and_resume_across_connections():
    builder = StateGraph(GridShieldState)
    builder.add_node("human_review", human_review_node)
    builder.add_edge(START, "human_review")
    builder.add_edge("human_review", END)

    config = {
        "configurable": {
            "thread_id": f"gridshield-review-{uuid4()}",
        }
    }

    initial_state = {
        "event_id": f"event-{uuid4()}",
        "predicted_class": 1,
        "attack_probability": 0.78,
    }

    # First connection: start the graph and verify it pauses.
    with postgres_checkpointer() as checkpointer:
        graph = builder.compile(checkpointer=checkpointer)
        graph.invoke(initial_state, config=config)

        snapshot = graph.get_state(config)
        assert snapshot.interrupts, "Graph did not pause for human review"

    # Second connection: reload the checkpoint and resume.
    with postgres_checkpointer() as checkpointer:
        graph = builder.compile(checkpointer=checkpointer)

        snapshot = graph.get_state(config)
        assert snapshot.interrupts, (
            "Human-review interrupt was not persisted in PostgreSQL"
        )

        result = graph.invoke(
            Command(resume={"decision": "confirmed_attack"}),
            config=config,
        )

        assert result["human_review_status"] == "confirmed_attack"
        assert result["human_verified_attack"] is True

        final_snapshot = graph.get_state(config)
        assert not final_snapshot.interrupts
