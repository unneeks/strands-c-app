"""Strands-harness coding agent on Amazon Bedrock AgentCore.

The LLM is Bedrock. Under `agentcore dev` this process runs on your desktop, so the harness's shell /
read / write / edit tools act on your files: the working directory is WORKSPACE_ROOT (default: the
directory `agentcore dev` was started from). Once deployed, the same tools would run inside the cloud
container instead.

Payloads (same protocol as app/codingagent/cli_client.py):
  {"prompt": "..."}                                          start / continue a conversation
  {"interrupt_responses": [{"id": "...", "response": "y"}]}  answer an approval ("y", "n", "t"=trust tool)
Streamed events: raw model events, {"type": "interrupt", "interrupts": [...]}, {"type": "tool_result"}, {"type": "error"}.
"""

import os
from pathlib import Path
from typing import Any

from bedrock_agentcore.runtime import BedrockAgentCoreApp
from strands.models.bedrock import BedrockModel
from strands.vended_interventions.hitl import HumanInTheLoop
from strands_harness import create_harness

MODEL_ID = os.getenv("CODING_AGENT_MODEL", "apac.amazon.nova-pro-v1:0")
APPROVAL = os.getenv("APPROVAL_MODE", "ask")  # ask | smart | off
READ_ONLY_TOOLS = ["read", "todo_write", "search_memory", "retrieve_context"]

INSTRUCTIONS = """\
You are a senior software engineer pair-programming in the user's local checkout.
- Explore before changing: read the relevant files and AGENTS.md/README before editing.
- Make small, focused edits; prefer `edit` over rewriting whole files.
- After changing code, run the project's tests/linters and fix what you broke.
- Use `python3`, not `python`. Use the todo list for multi-step work.
- File tools need ABSOLUTE paths. Your working directory is {cwd}; build every path under it
  (never /home/..., never relative paths). If a file operation fails, fix the path and retry
  instead of giving up or pasting code for the user to save by hand.
- Never touch files outside the working directory, and never print secrets.
- Summarise what you changed and anything left undone at the end.
"""

workspace = Path(os.getenv("WORKSPACE_ROOT") or Path.cwd()).expanduser().resolve()
if not workspace.is_dir():
    raise SystemExit(f"WORKSPACE_ROOT={workspace} does not exist - point it at a real project folder")
os.chdir(workspace)  # the harness (shell, file tools, AGENTS.md, ./.agent state) is rooted at the cwd

app = BedrockAgentCoreApp()
log = app.logger
_agents: dict[str, Any] = {}
_pending: dict[str, list[str]] = {}  # session -> ids of unanswered approvals


def get_agent(session_id: str):
    if session_id not in _agents:
        # No `ask` callback: approvals pause the run as an interrupt that the client answers over HTTP.
        gate = None if APPROVAL == "off" else HumanInTheLoop(
            allowed_tools=READ_ONLY_TOOLS, classifier=(APPROVAL == "smart"), enable_trust=True
        )
        _agents[session_id] = create_harness(
            model=BedrockModel(
                model_id=MODEL_ID,
                region_name=os.getenv("AWS_REGION", "ap-southeast-2"),
                temperature=0.2,
                max_tokens=8000,
            ),
            instructions=INSTRUCTIONS.format(cwd=workspace),
            builtin_tools={"web_fetch": {"transport": "direct"}},
            interventions=gate,
            session={"id": session_id},
            callback_handler=None,  # events are streamed to the caller
        )
    return _agents[session_id]


def _answer(text: str) -> str:
    text = text.strip().lower()
    if text in {"y", "yes", "ok", "approve"}:
        return "y"
    if text in {"t", "trust", "a", "always"}:
        return "t"
    return "n"


def _extract_prompt(payload: dict, pending: list[str]):
    if not isinstance(payload, dict):
        raise ValueError("payload must be a JSON object")
    if pending and "interrupt_responses" not in payload:
        # Clients without the interrupt protocol (the dev web UI) answer in plain chat text.
        reply = _answer(str(payload.get("prompt", "")))
        return [{"interruptResponse": {"interruptId": i, "response": reply}} for i in pending]
    if "interrupt_responses" in payload:
        responses = payload["interrupt_responses"]
        if not isinstance(responses, list) or not responses or not all(
            isinstance(r, dict) and isinstance(r.get("id"), str) for r in responses
        ):
            raise ValueError("interrupt_responses must be a non-empty list of {id, response} objects")
        # The shared client answers "a" for "always"; the harness calls that "t" (trust this tool).
        return [
            {"interruptResponse": {"interruptId": r["id"], "response": "t" if r.get("response") == "a" else r.get("response")}}
            for r in responses
        ]
    prompt = payload.get("prompt", "")
    if not isinstance(prompt, str):
        raise ValueError("prompt must be a string")
    return prompt


def _plain(value: Any) -> Any:
    return value if isinstance(value, (str, int, float, bool, dict, list)) or value is None else str(value)


def _interrupt_event(result: Any) -> dict:
    return {
        "type": "interrupt",
        "interrupts": [
            {
                "id": item.id,
                "kind": "approval" if item.name == HumanInTheLoop.name else "question",
                "reason": _plain(item.reason),
            }
            for item in result.interrupts
        ],
    }


def _text_event(text: str) -> dict:
    return {"event": {"contentBlockDelta": {"contentBlockIndex": 0, "delta": {"text": text}}}}


def _approval_text(result: Any) -> str:
    lines = ["\n\n**Approval needed**"]
    lines += [f"- {_plain(item.reason)}" for item in result.interrupts]
    lines.append("Reply `y` to allow, `t` to always allow this tool, or `n` to deny.")
    return "\n".join(lines)


def _tool_result_events(message: dict):
    for block in message.get("content", []):
        if isinstance(block, dict) and "toolResult" in block:
            tr = block["toolResult"]
            text = " ".join(str(p.get("text", p.get("json", ""))) for p in tr.get("content", []) if isinstance(p, dict))
            yield {"type": "tool_result", "toolUseId": tr.get("toolUseId"), "status": tr.get("status", "success"), "preview": text[:400]}


@app.entrypoint
async def invoke(payload, context):
    session_id = getattr(context, "session_id", None) or "default-session"
    agent = get_agent(session_id)
    try:
        prompt = _extract_prompt(payload, _pending.pop(session_id, []))
        async for event in agent.stream_async(prompt):
            if not isinstance(event, dict):
                continue
            result = event.get("result")
            if result is not None:
                if getattr(result, "stop_reason", None) == "interrupt" and getattr(result, "interrupts", None):
                    _pending[session_id] = [item.id for item in result.interrupts]
                    yield _interrupt_event(result)
                    yield _text_event(_approval_text(result))
                continue
            message = event.get("message")
            if isinstance(message, dict) and message.get("role") == "user":
                for tool_result in _tool_result_events(message):
                    yield tool_result
                continue
            if "event" not in event:
                continue
            start = event["event"].get("contentBlockStart")
            if start is not None and not start.get("start"):
                continue
            yield event
    except Exception as exc:
        log.exception("Agent invocation failed")
        yield {"type": "error", "message": f"{type(exc).__name__}: {exc}"}


if __name__ == "__main__":
    app.run(port=int(os.getenv("PORT", "8080")))
