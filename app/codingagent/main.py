"""Coding agent on Amazon Bedrock AgentCore (Strands Agents).

Invocation payloads:
  {"prompt": "..."}                                    start / continue a conversation
  {"interrupt_responses": [{"id": "...", "response": "y"}]}   answer a pending approval/question
Optional on either: {"approval_mode": "plan" | "ask" | "auto-edit" | "auto"}

Besides the raw model stream events, the agent emits:
  {"type": "interrupt", "interrupts": [{"id", "kind": "approval"|"question", "reason"}], ...}
  {"type": "tool_result", "toolUseId", "status", "preview"}
  {"type": "error", "message"}
"""

from typing import Any

from bedrock_agentcore.runtime import BedrockAgentCoreApp
from strands import Agent
from strands.agent.conversation_manager import SlidingWindowConversationManager

from coding import POLICY_NAME, CodingPolicy, build_system_prompt, get_settings, get_tools
from mcp_client.client import get_streamable_http_mcp_client
from memory.session import get_memory_session_manager
from model.load import load_model

app = BedrockAgentCoreApp()
log = app.logger
settings = get_settings()

# Web/code search over MCP (Exa). Read-only, so the approval policy lets these through.
mcp_clients = [get_streamable_http_mcp_client()]

tools = list(get_tools())
for mcp_client in mcp_clients:
    if mcp_client:
        tools.append(mcp_client)


def agent_factory():
    cache = {}

    def get_or_create_agent(session_id, user_id):
        key = f"{session_id}/{user_id}"
        if key not in cache:
            policy = CodingPolicy()
            agent = Agent(
                model=load_model(),
                session_manager=get_memory_session_manager(session_id, user_id),
                # A sliding window keeps long coding sessions inside the model's context.
                conversation_manager=SlidingWindowConversationManager(window_size=80, should_truncate_results=True),
                system_prompt=build_system_prompt(settings.workspace),
                tools=tools,
                interventions=[policy],
                callback_handler=None,  # events are streamed to the caller; no console printing
            )
            cache[key] = (agent, policy)
        return cache[key]

    return get_or_create_agent


get_or_create_agent = agent_factory()


def strip_trailing_tool_use(messages: Any) -> list[dict]:
    """Strip toolUse blocks from the tail until the last message has none."""
    if not isinstance(messages, list):
        raise ValueError("messages must be a list")
    messages = list(messages)
    while messages:
        last = messages[-1]
        if not isinstance(last, dict):
            raise ValueError("each message must be an object")
        original_content = last.get("content", [])
        if not isinstance(original_content, list) or not all(isinstance(block, dict) for block in original_content):
            raise ValueError("each message content value must be a list of content blocks")
        content = [block for block in original_content if "toolUse" not in block]
        if len(content) == len(original_content):
            break
        if content:
            messages[-1] = {**last, "content": content}
            break
        messages.pop()
    return messages


def _extract_prompt(payload: dict):
    """Accept interrupt responses, validated harness messages, tool results, or a plain prompt."""
    if not isinstance(payload, dict):
        raise ValueError("payload must be a JSON object")
    if "interrupt_responses" in payload:
        responses = payload["interrupt_responses"]
        if not isinstance(responses, list) or not responses or not all(
            isinstance(r, dict) and isinstance(r.get("id"), str) for r in responses
        ):
            raise ValueError("interrupt_responses must be a non-empty list of {id, response} objects")
        return [{"interruptResponse": {"interruptId": r["id"], "response": r.get("response")}} for r in responses]
    if "messages" in payload:
        return strip_trailing_tool_use(payload["messages"])
    if "tool_results" in payload:
        tool_results = payload["tool_results"]
        if not isinstance(tool_results, list) or not all(
            isinstance(tool_result, dict) and isinstance(tool_result.get("toolUseId"), str)
            for tool_result in tool_results
        ):
            raise ValueError("tool_results must contain objects with a toolUseId string")
        return [
            {
                "role": "user",
                "content": [
                    {
                        "toolResult": {
                            "toolUseId": tr["toolUseId"],
                            "status": tr.get("status", "success"),
                            "content": tr.get("content", []),
                        }
                    }
                    for tr in tool_results
                ],
            }
        ]
    prompt = payload.get("prompt", "")
    if not isinstance(prompt, str):
        raise ValueError("prompt must be a string")
    return prompt


def _plain(value: Any) -> Any:
    return value if isinstance(value, (str, int, float, bool, dict, list)) or value is None else str(value)


def _interrupt_event(result: Any, mode: str) -> dict:
    return {
        "type": "interrupt",
        "approval_mode": mode,
        "interrupts": [
            {
                "id": item.id,
                "kind": "approval" if item.name == POLICY_NAME else "question",
                "reason": _plain(item.reason),
            }
            for item in result.interrupts
        ],
    }


def _tool_result_events(message: dict):
    for block in message.get("content", []):
        if not isinstance(block, dict) or "toolResult" not in block:
            continue
        tr = block["toolResult"]
        text = " ".join(str(part.get("text", part.get("json", ""))) for part in tr.get("content", []) if isinstance(part, dict))
        yield {"type": "tool_result", "toolUseId": tr.get("toolUseId"), "status": tr.get("status", "success"), "preview": text[:400]}


@app.entrypoint
async def invoke(payload, context):
    log.info("Invoking Agent.....")
    session_id = getattr(context, "session_id", None) or "default-session"
    user_id = getattr(context, "user_id", None) or "default-user"
    agent, policy = get_or_create_agent(session_id, user_id)
    try:
        prompt = _extract_prompt(payload)
        policy.set_mode(payload.get("approval_mode"))
        async for event in agent.stream_async(prompt):
            if not isinstance(event, dict):
                continue
            result = event.get("result")
            if result is not None:
                if getattr(result, "stop_reason", None) == "interrupt" and getattr(result, "interrupts", None):
                    yield _interrupt_event(result, policy.mode)
                continue
            message = event.get("message")
            if isinstance(message, dict) and message.get("role") == "user":
                for tool_result in _tool_result_events(message):
                    yield tool_result
                continue
            if "event" not in event:
                continue
            cbs = event["event"].get("contentBlockStart")
            if cbs is not None and not cbs.get("start"):
                continue
            yield event
    except Exception as exc:  # surface problems to the caller instead of a bare 500
        log.exception("Agent invocation failed")
        yield {"type": "error", "message": f"{type(exc).__name__}: {exc}"}


if __name__ == "__main__":
    app.run()
