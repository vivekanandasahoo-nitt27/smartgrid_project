
from langgraph.graph import StateGraph, START, END

from gridshield import agents
from gridshield.state import GridShieldState
from gridshield.repository import JsonSampleRepository
from gridshield.workflow import choose_sample_count


def make_eligible_samples(repository, count):
    """Create test samples and explicitly promote each one."""
    for index in range(count):
        event_id = f"threshold-event-{index:03d}"

        repository.admit({
            "event_id": event_id,
            "measurements": {"voltage": 0.85},
            "status": "validated_pending_persistence",
            "eligible_for_training": False,
        })

        repository.promote_to_eligible(
            event_id,
            human_review_status="confirmed_attack",
            human_verified_attack=True,
            data_admission_status="approved",
            validation_passed=True,
        )


def build_threshold_test_graph():
    """Test the real repository count without running model training."""
    graph = StateGraph(GridShieldState)

    graph.add_node("sample_threshold", agents.sample_threshold_node)

    def fake_retraining_node(state):
        return {
            "training_run_id": "test-retraining-triggered"
        }

    graph.add_node("retraining", fake_retraining_node)
    graph.add_edge(START, "sample_threshold")

    graph.add_conditional_edges(
        "sample_threshold",
        choose_sample_count,
        {
            "collect": END,
            "retrain": "retraining",
        },
    )

    graph.add_edge("retraining", END)

    return graph.compile()


def test_99_eligible_samples_do_not_trigger_retraining(
    tmp_path, monkeypatch
):
    repository = JsonSampleRepository(tmp_path / "samples.json")
    make_eligible_samples(repository, 99)

    monkeypatch.setattr(
        agents,
        "get_sample_repository",
        lambda: repository,
    )

    graph = build_threshold_test_graph()
    result = graph.invoke({})

    assert repository.count_eligible() == 99
    assert result["eligible_attack_sample_count"] == 99
    assert "training_run_id" not in result


def test_100_eligible_samples_trigger_retraining_branch(
    tmp_path, monkeypatch
):
    repository = JsonSampleRepository(tmp_path / "samples.json")
    make_eligible_samples(repository, 100)

    monkeypatch.setattr(
        agents,
        "get_sample_repository",
        lambda: repository,
    )

    graph = build_threshold_test_graph()
    result = graph.invoke({})

    assert repository.count_eligible() == 100
    assert result["eligible_attack_sample_count"] == 100
    assert result["training_run_id"] == "test-retraining-triggered"
