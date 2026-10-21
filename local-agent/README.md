# Local coding agent (Strands harness)

`create_harness()` from [strands-harness](https://strandsagents.com/docs/user-guide/harness/) gives the agent
shell, read/write/edit, web fetch, a todo list, subagents, context offloading, sessions and memory.
Here the **LLM is Bedrock** (the project's AgentCore model) and **all tools run on your desktop**
in the directory you start it from.

```bash
cd ~/path/to/your/project
export AWS_PROFILE=unneeks-dev AWS_REGION=ap-southeast-2
uv run --project ~/aws-playground/ide/local-agent ~/aws-playground/ide/local-agent/coding_agent.py
```

Flags: `-p "prompt"` one-shot, `--approve ask|smart|off`, `--model <bedrock id>`, `--resume <session-id>`.
`ask` (default) prompts before every tool call; `smart` only for calls an LLM classifier flags as risky;
`off` disables the gate, so use it only in a throwaway checkout.
State lives in `./.agent/` (sessions, memory, optional `skills/`, optional `mcp.json`).
Set `CODING_AGENT_MODEL` to use another Bedrock model (e.g. a Claude inference profile).
