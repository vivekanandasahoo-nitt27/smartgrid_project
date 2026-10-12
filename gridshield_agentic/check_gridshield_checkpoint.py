
from gridshield.postgres_checkpointer import postgres_checkpointer
from gridshield.workflow import build_graph

event_id = "smoke-review-53f7368198a4"
config = {"configurable": {"thread_id": event_id}}

with postgres_checkpointer() as checkpointer:
    graph = build_graph(checkpointer=checkpointer)
    state = graph.get_state(config)

    print("NEXT NODES:", state.next)
    print("TASK COUNT:", len(state.tasks))

    for task in state.tasks:
        print("\nTASK:", task.name)
        print("TASK ID:", task.id)

        for interrupt in task.interrupts:
            print("INTERRUPT ID:", interrupt.id)
            print("INTERRUPT VALUE:", interrupt.value)
