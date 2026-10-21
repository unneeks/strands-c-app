# Coding agent

A Strands agent on Amazon Bedrock AgentCore (model: Amazon Nova Pro) that can explore, edit,
run, test and commit code in a workspace folder, with human approval built in.

## Quick start (local)

```bash
# terminal 1 - point the agent at the project it should work on
cd ~/aws-playground/ide
export AWS_PROFILE=unneeks-dev AWS_REGION=ap-southeast-2
export WORKSPACE_ROOT=~/path/to/your/project      # default: ./workspace (created for you)
agentcore dev                                      # serves http://localhost:8080

# terminal 2 - interactive client that can answer approval prompts
python3 app/codingagent/cli_client.py --mode ask
```

`agentcore invoke --dev "..."` also works, but it cannot answer approval prompts, so use it
with `--mode auto`-style payloads only. Use `cli_client.py` for everyday work.

Client commands: `/mode plan|ask|auto-edit|auto`, `/help`, `/quit`.
At an approval prompt: `y` = yes, `a` = always allow this kind of action, `n` = no (default).

## Approval modes

|                         | plan  | ask   | auto-edit | auto    |
|-------------------------|-------|-------|-----------|---------|
| read, search, git read  | allow | allow | allow     | allow   |
| read-only shell (ls...) | allow | allow | allow     | allow   |
| write / edit / patch    | deny  | ask   | allow     | allow   |
| delete                  | deny  | ask   | ask       | allow   |
| tests / linters / build | deny  | ask   | allow     | allow   |
| other shell commands    | deny  | ask   | ask       | allow   |
| dangerous shell (rm, docker, aws, curl -X POST, git reset --hard ...) | deny | ask | ask | **ask** |
| git commit / branch     | deny  | ask   | allow     | allow   |
| git push                | deny  | ask   | ask       | ask*    |
| web_fetch               | allow | ask   | allow     | allow   |

\* `ALLOW_AUTO_PUSH=1` lets `auto` push without asking.

Always, in every mode: credential-style files (`.env`, `*.pem`, `id_rsa`, ...) need approval to
touch, and commands such as `sudo`, pipe-to-shell (`curl ... | bash`), cloud-metadata endpoints
and reading `~/.ssh` / `~/.aws` are blocked outright.

## Tools (25 + Exa web search)

- **Explore:** `project_overview`, `list_directory`, `glob_files`, `grep_search`, `read_file`
- **Change:** `edit_file`, `write_file`, `apply_patch`, `move_path`, `delete_path`, `make_directory`, `undo_change`
- **Run & verify:** `run_command`, `run_tests` (auto-detects pytest / npm / go / cargo / mvn / gradle / make), `background_process` (dev servers)
- **Git:** `git_status`, `git_diff`, `git_log`, `git_branch`, `git_init`, `git_commit`, `git_push`
- **Research & coordination:** `web_fetch`, `todo`, `ask_user`, plus `web_search_exa` / `web_fetch_exa` via MCP

Every write, edit, move and delete saves a checkpoint (outside the repo); `undo_change` restores it.

## Configuration (environment variables)

| Variable | Default | Meaning |
|---|---|---|
| `WORKSPACE_ROOT` | `./workspace` (or `/tmp/workspace`) | Folder the agent may read and write. Everything outside is refused. |
| `APPROVAL_MODE` | `ask` | Starting mode; clients can change it per request. |
| `APPROVAL_MODE_LOCKED` | off | `1` stops clients from changing the mode. Set this on shared deployments. |
| `ALLOW_AUTO_PUSH` | off | Let `auto` mode push without asking. |
| `EXTRA_READ_TOOLS` | - | Comma-separated extra MCP tool names to treat as read-only. |

Put project rules in `AGENTS.md` (or `CLAUDE.md`) at the workspace root; they are added to the prompt.

## API

Request: `{"prompt": "...", "approval_mode": "ask"}`, or to answer a pause:
`{"interrupt_responses": [{"id": "<id from the interrupt>", "response": "y"}]}`.

Streamed events: the raw model events, plus `{"type": "interrupt", "interrupts": [{"id", "kind":
"approval"|"question", "reason"}]}`, `{"type": "tool_result", ...}` and `{"type": "error", ...}`.

## Tests

```bash
cd app/codingagent && .venv/bin/python -m pytest tests -q     # 85 tests, ~3 s
```

## Security notes

- File tools are confined to the workspace (symlinks included). The **shell is not a sandbox**:
  commands are classified and approved, and children get a scrubbed environment (no AWS or API
  credentials), but a determined command can still reach anything the process can. Prefer
  `ask` / `auto-edit` locally, and use the deployed AgentCore runtime (isolated microVM,
  least-privilege role) or a container for `auto`.
- Command and secret detection is heuristic; treat approvals as the real control.
