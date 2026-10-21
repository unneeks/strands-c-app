#!/usr/bin/env python3
"""Interactive terminal client for the coding agent (answers approval prompts).

  1. In one terminal:   cd <project>/ && WORKSPACE_ROOT=~/my-repo agentcore dev
  2. In another:        python3 app/codingagent/cli_client.py [--mode ask|auto-edit|auto|plan]

Commands:  /mode <plan|ask|auto-edit|auto>   /quit   /help
Approval prompts accept:  y = yes   a = always allow this kind of action   n = no (default)
"""

import argparse
import json
import sys
import urllib.error
import urllib.request
import uuid

MODES = ("plan", "ask", "auto-edit", "auto")


def stream(url: str, session: str, payload: dict):
    request = urllib.request.Request(
        url,
        data=json.dumps(payload).encode(),
        headers={
            "Content-Type": "application/json",
            "X-Amzn-Bedrock-AgentCore-Runtime-Session-Id": session,
        },
    )
    with urllib.request.urlopen(request, timeout=600) as response:
        for raw in response:
            line = raw.decode("utf-8", "replace").strip()
            if not line.startswith("data:"):
                continue
            body = line[5:].strip()
            try:
                event = json.loads(body)
                if isinstance(event, str):  # some servers double-encode
                    event = json.loads(event)
            except ValueError:
                continue
            if isinstance(event, dict):
                yield event


class ThinkingFilter:
    """Hide <thinking>...</thinking> blocks that some models stream, even when split across chunks."""

    OPEN, CLOSE = "<thinking>", "</thinking>"

    def __init__(self):
        self.buffer, self.hidden = "", False

    def feed(self, text: str) -> str:
        self.buffer += text
        out = []
        while self.buffer:
            tag = self.CLOSE if self.hidden else self.OPEN
            index = self.buffer.find(tag)
            if index >= 0:
                if not self.hidden:
                    out.append(self.buffer[:index])
                self.buffer = self.buffer[index + len(tag):]
                self.hidden = not self.hidden
                continue
            keep = max((k for k in range(1, len(tag)) if self.buffer.endswith(tag[:k])), default=0)
            if not self.hidden:
                out.append(self.buffer[: len(self.buffer) - keep])
            self.buffer = self.buffer[len(self.buffer) - keep:]
            break
        return "".join(out)

    def flush(self) -> str:
        rest, self.buffer = ("" if self.hidden else self.buffer), ""
        return rest


def run_turn(url: str, session: str, payload: dict):
    """Print one streamed turn. Returns the list of pending interrupts (empty when finished)."""
    tool_inputs, tool_names, interrupts = {}, {}, []
    thinking = ThinkingFilter()
    for event in stream(url, session, payload):
        kind = event.get("type")
        if kind == "interrupt":
            interrupts = event.get("interrupts", [])
            continue
        if kind == "tool_result":
            mark = "x" if event.get("status") == "error" else "ok"
            preview = " ".join(str(event.get("preview", "")).split())[:160]
            print(f"    [{mark}] {preview}")
            continue
        if kind == "error":
            print(f"\n[error] {event.get('message')}")
            continue
        raw = event.get("event", {})
        start = raw.get("contentBlockStart", {}).get("start", {})
        if "toolUse" in start:
            index = raw["contentBlockStart"].get("contentBlockIndex", 0)
            tool_names[index], tool_inputs[index] = start["toolUse"].get("name", "?"), ""
        delta = raw.get("contentBlockDelta", {}).get("delta", {})
        if "text" in delta:
            print(thinking.feed(delta["text"]), end="", flush=True)
        elif "toolUse" in delta:
            index = raw["contentBlockDelta"].get("contentBlockIndex", 0)
            tool_inputs[index] = tool_inputs.get(index, "") + delta["toolUse"].get("input", "")
        stop = raw.get("contentBlockStop")
        if stop is not None and stop.get("contentBlockIndex") in tool_names:
            index = stop["contentBlockIndex"]
            args = " ".join(tool_inputs.get(index, "").split())
            print(f"\n  > {tool_names.pop(index)} {args[:140]}")
    print(thinking.flush())
    return interrupts


def ask_human(interrupts: list) -> list:
    answers = []
    for item in interrupts:
        print("\n" + "-" * 60)
        print(item.get("reason", ""))
        try:
            if item.get("kind") == "approval":
                reply = input("  approve? [y/a/N] > ").strip() or "n"
            else:
                reply = input("  your answer > ").strip()
        except EOFError:
            reply = "n"
        answers.append({"id": item["id"], "response": reply})
    return answers


def main() -> int:
    parser = argparse.ArgumentParser(description="Coding agent terminal client")
    parser.add_argument("--url", default="http://localhost:8080/invocations")
    parser.add_argument("--mode", choices=MODES, default="ask", help="approval mode (default: ask)")
    parser.add_argument("--session", default=str(uuid.uuid4()) + "-coding-session")
    args = parser.parse_args()
    mode = args.mode
    print(f"Coding agent  |  mode: {mode}  |  /help for commands  |  server: {args.url}")
    while True:
        try:
            text = input("\nyou> ").strip()
        except (EOFError, KeyboardInterrupt):
            print()
            return 0
        if not text:
            continue
        if text in ("/quit", "/exit"):
            return 0
        if text == "/help":
            print(__doc__)
            continue
        if text.startswith("/mode"):
            choice = text.split(maxsplit=1)[1].strip() if " " in text else ""
            if choice in MODES:
                mode = choice
                print(f"approval mode -> {mode}")
            else:
                print(f"usage: /mode {'|'.join(MODES)}")
            continue
        payload = {"prompt": text, "approval_mode": mode}
        try:
            while True:
                pending = run_turn(args.url, args.session, payload)
                if not pending:
                    break
                payload = {"interrupt_responses": ask_human(pending), "approval_mode": mode}
        except urllib.error.URLError as exc:
            print(f"Cannot reach the agent at {args.url}: {exc}. Is `agentcore dev` running?")
        except KeyboardInterrupt:
            print("\n(interrupted)")


if __name__ == "__main__":
    sys.exit(main())
