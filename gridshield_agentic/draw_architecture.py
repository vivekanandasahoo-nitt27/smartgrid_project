
from pathlib import Path

from gridshield.workflow import gridshield_graph

# Generate a diagram from the actual compiled LangGraph.
mermaid = gridshield_graph.get_graph().draw_mermaid()

output_path = Path(__file__).parent / "architecture.mmd"
output_path.write_text(mermaid, encoding="utf-8")

print("LangGraph architecture exported successfully!")
print(f"Saved to: {output_path}")
print("\nMermaid architecture:\n")
print(mermaid)
