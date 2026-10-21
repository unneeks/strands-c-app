#!/usr/bin/env python3
"""Full-fledged coding agent built on the Strands harness.

* The LLM is the same Bedrock model the AgentCore project uses (app/codingagent/model/load.py).
* Every tool (shell, read, write, edit, todo, subagents ...) executes on THIS machine, in the
  directory you launch it from: the harness's default sandbox is the local host.

Usage:
    uv run coding_agent.py                       # interactive, you approve every tool call
    uv run coding_agent.py -p "fix the failing tests"      # one-shot
    uv run coding_agent.py --approve smart       # an LLM risk classifier asks only for risky calls
    uv run coding_agent.py --resume <session-id> # continue a previous conversation
    uv run coding_agent.py --approve off         # no approval gate (use only in a throwaway checkout)
"""

import argparse
import os
import sys
from pathlib import Path

from strands.models.bedrock import BedrockModel
from strands.vended_interventions.hitl import HumanInTheLoop
from strands_harness import create_harness

DEFAULT_MODEL = "apac.amazon.nova-pro-v1:0"  # keep in sync with app/codingagent/model/load.py
DEFAULT_REGION = "ap-southeast-2"

READ_ONLY_TOOLS = ["read", "todo_write", "search_memory", "retrieve_context"]

INSTRUCTIONS = """\
You are a senior software engineer pair-programming in the user's local checkout.
- Explore before changing: read the relevant files and AGENTS.md/README before editing.
- Make small, focused edits; prefer `edit` over rewriting whole files.
- After changing code, run the project's tests/linters and fix what you broke.
- Use the todo list for multi-step work. Ask the user only when genuinely blocked.
- File tools need ABSOLUTE paths. Your working directory is {cwd}; build every path under it
  (never /home/..., never relative paths). If a file operation fails, fix the path and retry
  instead of giving up or pasting code for the user to save by hand.
- Never touch files outside the working directory, and never print secrets.
- Summarise what you changed and anything left undone at the end.
"""


def _gate(approve: str):
    """Approval gate that prompts inline on the terminal (no interrupt/resume round trip)."""
    if approve == "off":
        return None
    return HumanInTheLoop(
        allowed_tools=READ_ONLY_TOOLS,  # no prompt for tools that cannot change anything
        classifier=(approve == "smart"),
        enable_trust=True,  # answer "t" to stop being asked about that tool this session
        ask="stdio",
    )


def build_agent(model_id: str, region: str, approve: str, session_id: str | None, effort: str):
    # Model calls go to Bedrock with your AWS credentials; nothing else leaves the machine.
    model = BedrockModel(model_id=model_id, region_name=region, temperature=0.2, max_tokens=8000)
    mcp_config = Path(".agent/mcp.json")
    return create_harness(
        model=model,
        effort=effort,
        instructions=INSTRUCTIONS.format(cwd=os.getcwd()),
        # Shell/read/write/edit run locally. web_fetch fetches from this process, not via curl.
        builtin_tools={"web_fetch": {"transport": "direct"}},
        interventions=_gate(approve),
        session={"id": session_id} if session_id else True,
        mcp_servers=str(mcp_config) if mcp_config.exists() else None,
    )


def repl(agent) -> None:
    print(f"coding agent | cwd={os.getcwd()} | session={agent.session_id} | /exit to quit")
    while True:
        try:
            prompt = input("\n> ").strip()
        except (EOFError, KeyboardInterrupt):
            print()
            return
        if prompt in {"/exit", "/quit"}:
            return
        if prompt:
            try:
                agent(prompt)
            except KeyboardInterrupt:
                print("\n[interrupted]")


def main() -> int:
    p = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    p.add_argument("-p", "--prompt", help="run one prompt and exit")
    p.add_argument("--model", default=os.getenv("CODING_AGENT_MODEL", DEFAULT_MODEL))
    p.add_argument("--region", default=os.getenv("AWS_REGION", DEFAULT_REGION))
    p.add_argument("--approve", choices=["ask", "smart", "off"], default="ask")
    p.add_argument("--effort", default="auto", help="reasoning effort (auto|off|low|medium|high ...)")
    p.add_argument("--resume", metavar="SESSION_ID")
    a = p.parse_args()

    agent = build_agent(a.model, a.region, a.approve, a.resume, a.effort)
    try:
        if a.prompt:
            agent(a.prompt)
        else:
            repl(agent)
    finally:
        agent.shutdown()  # flush long-term memory extraction
    return 0


if __name__ == "__main__":
    sys.exit(main())
