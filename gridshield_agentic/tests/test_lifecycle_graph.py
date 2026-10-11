
from gridshield.workflow import build_graph


def test_lifecycle_graph_has_expected_connections():
    graph = build_graph()
    edges = {
        (edge.source, edge.target)
        for edge in graph.get_graph().edges
    }

    assert ("evaluation_reporting", "deployment_approval") in edges
    assert ("evaluation_reporting", "retain_current_model") in edges
    assert ("deployment_approval", "deployment") in edges
    assert ("deployment_approval", "retain_current_model") in edges
    assert ("retain_current_model", "record_deployment_outcome") in edges
    assert ("deployment", "record_deployment_outcome") in edges
