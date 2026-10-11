
from gridshield.workflow import build_graph


def test_graph_contains_eligibility_management_node():
    graph = build_graph()

    node_names = graph.get_graph().nodes

    assert "dataset_management" in node_names
    assert "eligibility_management" in node_names
    assert "sample_threshold" in node_names


def test_eligibility_node_is_between_dataset_and_threshold():
    graph = build_graph()

    edges = graph.get_graph().edges
    edge_pairs = {
        (edge.source, edge.target)
        for edge in edges
    }

    assert ("dataset_management", "eligibility_management") in edge_pairs
    assert ("eligibility_management", "sample_threshold") in edge_pairs
