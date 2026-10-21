"""todo: a visible task list the agent keeps up to date on multi-step work."""

from typing import List, Optional

from strands import tool
from strands.types.tools import ToolContext

STATE_KEY = "coding:todos"
_STATUSES = {"pending": "[ ]", "in_progress": "[~]", "completed": "[x]"}


def render(items: List[dict]) -> str:
    if not items:
        return "No tasks."
    return "\n".join(f"{_STATUSES[i['status']]} {i['task']}" for i in items)


@tool(context="tool_context")
def todo(tool_context: ToolContext, todos: Optional[List[dict]] = None) -> str:
    """Track a plan for multi-step work. Call with no arguments to view the current list.

    Use it at the start of any task with 3+ steps, keep exactly one item in_progress, and mark
    items completed as soon as they are done. Passing todos replaces the whole list.

    Args:
        tool_context: Injected by the framework. Not user-facing.
        todos: The full task list. Each item is {"task": "what to do", "status": "pending|in_progress|completed"}.
    """
    state = tool_context.agent.state
    if todos is None:
        return render(state.get(STATE_KEY) or [])
    cleaned = []
    for item in todos:
        if not isinstance(item, dict) or not str(item.get("task", "")).strip():
            raise ValueError('Each todo needs a non-empty "task".')
        status = str(item.get("status", "pending")).strip().lower()
        if status not in _STATUSES:
            raise ValueError('status must be "pending", "in_progress" or "completed".')
        cleaned.append({"task": str(item["task"]).strip()[:300], "status": status})
    if sum(1 for i in cleaned if i["status"] == "in_progress") > 1:
        raise ValueError("Only one task can be in_progress at a time.")
    state.set(STATE_KEY, cleaned)
    return render(cleaned)
