"""Approval policy: allow / ask / deny for every tool call, by risk category and mode.

                    plan   ask    auto-edit   auto
  read / search     allow  allow  allow       allow
  write / edit      deny   ask    allow       allow
  delete            deny   ask    ask         allow
  read-only shell   allow  allow  allow       allow
  test/lint/build   deny   ask    allow       allow
  other shell       deny   ask    ask         allow
  dangerous shell   deny   ask    ask         ask
  git commit/branch deny   ask    allow       allow
  git push          deny   ask    ask         ask*   (* allow with ALLOW_AUTO_PUSH=1)
  web fetch         allow  ask    allow       allow
  unknown tools     deny   ask    ask         allow

Credential-style files (.env, *.pem, ...) always ask, in every mode. Commands that are never
acceptable (sudo, pipe-to-shell, metadata endpoints, ...) are denied in every mode.
"""

from __future__ import annotations

import json
import os
from dataclasses import dataclass
from typing import Any, Optional, Tuple

from strands.interventions import Confirm, Deny, InterventionHandler, Proceed

from .commands import CommandInfo, analyze
from .config import MODES, get_settings
from .fs_tools import patch_paths
from .safety import is_sensitive

POLICY_NAME = "coding-policy"
TRUST_KEY = "coding:trusted"

READ_TOOLS = frozenset(
    {"read_file", "list_directory", "glob_files", "grep_search", "project_overview", "git_status", "git_diff", "git_log", "todo"}
)
WRITE_TOOLS = frozenset({"write_file", "edit_file", "apply_patch", "move_path", "make_directory"})
VCS_WRITE_TOOLS = frozenset({"git_commit", "git_init"})
INTERACT_TOOLS = frozenset({"ask_user"})
NETWORK_TOOLS = frozenset({"web_fetch"})

# order: plan, ask, auto-edit, auto
_MATRIX = {
    "read": ("allow", "allow", "allow", "allow"),
    "interact": ("allow", "allow", "allow", "allow"),
    "write": ("deny", "ask", "allow", "allow"),
    "delete": ("deny", "ask", "ask", "allow"),
    "exec_readonly": ("allow", "allow", "allow", "allow"),
    "exec_check": ("deny", "ask", "allow", "allow"),
    "exec_other": ("deny", "ask", "ask", "allow"),
    "exec_dangerous": ("deny", "ask", "ask", "ask"),
    "vcs_write": ("deny", "ask", "allow", "allow"),
    "vcs_remote": ("deny", "ask", "ask", "ask"),
    "network": ("allow", "ask", "allow", "allow"),
    "unknown": ("deny", "ask", "ask", "allow"),
}
_LABELS = {
    "write": "changes files in the workspace",
    "delete": "deletes files",
    "exec_check": "runs tests / linters / a build",
    "exec_other": "runs a shell command",
    "exec_dangerous": "dangerous or outward-facing command",
    "vcs_write": "changes git history or branches",
    "vcs_remote": "publishes to a remote repository",
    "network": "fetches content from the internet",
    "unknown": "tool not covered by the policy",
}
_UNTRUSTABLE_SIGNATURES = {"complex", "unparsed", "empty", "env-assign", "command"}


@dataclass
class Decision:
    action: str  # allow | ask | deny
    category: str
    reason: str = ""
    trust_key: Optional[str] = None
    sensitive: bool = False


# Read-only external tools (the Exa web/code search MCP server). Add more with EXTRA_READ_TOOLS=a,b.
DEFAULT_EXTRA_READ = frozenset({"web_search_exa", "web_fetch_exa", "get_code_context_exa", "crawling_exa"})


def _extra_read_tools() -> frozenset:
    raw = os.getenv("EXTRA_READ_TOOLS", "")
    return DEFAULT_EXTRA_READ | frozenset(t.strip() for t in raw.split(",") if t.strip())


def _exec_category(command: str) -> Tuple[str, CommandInfo]:
    info = analyze(command or "")
    return {
        "readonly": "exec_readonly",
        "check": "exec_check",
        "other": "exec_other",
        "dangerous": "exec_dangerous",
        "denied": "denied",
    }[info.kind], info


def categorize(name: str, inp: dict, extra_read: frozenset = frozenset()) -> Tuple[str, Optional[CommandInfo]]:
    if name in READ_TOOLS or name in extra_read:
        return "read", None
    if name in WRITE_TOOLS:
        return "write", None
    if name == "delete_path":
        return "delete", None
    if name == "undo_change":
        return ("write" if inp.get("checkpoint_id") else "read"), None
    if name in INTERACT_TOOLS:
        return "interact", None
    if name in NETWORK_TOOLS:
        return "network", None
    if name == "git_branch":
        return ("read" if str(inp.get("action") or "list").lower() == "list" else "vcs_write"), None
    if name in VCS_WRITE_TOOLS:
        return "vcs_write", None
    if name == "git_push":
        return "vcs_remote", None
    if name == "run_command":
        return _exec_category(str(inp.get("command") or ""))
    if name == "run_tests":
        command = inp.get("command")
        return ("exec_check", None) if not command else _exec_category(str(command))
    if name == "background_process":
        if str(inp.get("action") or "").lower() == "start":
            return _exec_category(str(inp.get("command") or ""))
        return "read", None
    return "unknown", None


def _touches_sensitive(name: str, inp: dict, info: Optional[CommandInfo]) -> bool:
    if info is not None and info.sensitive:
        return True
    file_tools = READ_TOOLS | WRITE_TOOLS | {"delete_path"}
    if name in file_tools or name == "undo_change":
        for key in ("path", "source", "destination"):
            value = inp.get(key)
            if isinstance(value, str) and value and is_sensitive(value):
                return True
    if name == "move_path":
        return any(isinstance(inp.get(k), str) and is_sensitive(inp[k]) for k in ("source", "destination"))
    if name == "git_commit" and isinstance(inp.get("paths"), list):
        return any(isinstance(p, str) and is_sensitive(p) for p in inp["paths"])
    if name == "apply_patch" and isinstance(inp.get("patch"), str):
        return any(is_sensitive(p) for p in patch_paths(inp["patch"]))
    return False


def decide(
    name: str,
    inp: dict,
    mode: str,
    *,
    allow_auto_push: bool = False,
    extra_read: frozenset = frozenset(),
) -> Decision:
    mode = mode if mode in MODES else "ask"
    category, info = categorize(name, inp, extra_read)
    if category == "denied":
        return Decision("deny", category, f"{info.reason} (blocked in every mode)")
    action = _MATRIX.get(category, _MATRIX["unknown"])[MODES.index(mode)]
    if category == "vcs_remote" and mode == "auto" and allow_auto_push:
        action = "allow"
    sensitive = _touches_sensitive(name, inp, info)
    if sensitive:
        action = "deny" if mode == "plan" else "ask"

    if action == "deny":
        why = "plan mode is read-only. Ask the user to switch to ask, auto-edit or auto mode." if mode == "plan" else "not permitted"
        return Decision("deny", category, why, sensitive=sensitive)

    reason = ""
    if action == "ask":
        reason = "touches a credentials-style file" if sensitive else _LABELS.get(category, "needs approval")
        if info is not None and info.reason and not sensitive:
            reason = f"{reason}: {info.reason}"
    trust_key = None
    if action == "ask" and not sensitive and category not in {"exec_dangerous", "vcs_remote"}:
        if info is not None:
            if info.signature not in _UNTRUSTABLE_SIGNATURES:
                trust_key = f"cmd:{info.signature}"
        else:
            trust_key = f"tool:{name}"
    return Decision(action, category, reason, trust_key, sensitive)


# --------------------------------------------------------------------- prompts
def _preview(text: str, lines: int = 6, width: int = 140) -> str:
    rows = [row[:width] for row in str(text).splitlines()[:lines]]
    more = len(str(text).splitlines()) - lines
    return "\n".join("    " + r for r in rows) + (f"\n    ... (+{more} more lines)" if more > 0 else "")


def describe(name: str, inp: dict) -> str:
    g = inp.get
    if name == "run_command":
        cwd = f"   (in {g('cwd')})" if g("cwd") not in (None, "", ".") else ""
        return f"Run command:\n    $ {g('command')}{cwd}"
    if name == "background_process":
        return f"Start background process:\n    $ {g('command')}"
    if name == "run_tests":
        return f"Run tests: {g('command') or '(auto-detected test command)'}"
    if name == "write_file":
        verb = "Append to" if g("append") else "Write"
        content = str(g("content") or "")
        return f"{verb} {g('path')} ({len(content)} chars)\n" + _preview(content)
    if name == "edit_file":
        old = "\n".join("-" + ln for ln in str(g("old_str") or "").splitlines()[:8])
        new = "\n".join("+" + ln for ln in str(g("new_str") or "").splitlines()[:8])
        return f"Edit {g('path')}\n" + _preview(old + "\n" + new, lines=16)
    if name == "apply_patch":
        files = ", ".join(patch_paths(str(g("patch") or ""))) or "?"
        return f"Apply patch to: {files}\n" + _preview(str(g("patch") or ""), lines=14)
    if name == "delete_path":
        return f"Delete {g('path')}{' (recursive)' if g('recursive') else ''}"
    if name == "move_path":
        return f"Move {g('source')} -> {g('destination')}"
    if name == "undo_change":
        return f"Restore checkpoint {g('checkpoint_id')}"
    if name == "git_commit":
        scope = ", ".join(g("paths") or []) or "all changes"
        return f"Commit ({scope}):\n" + _preview(g("message") or "", lines=4)
    if name == "git_push":
        return f"Push to {g('remote') or 'origin'} {g('branch') or '(current branch)'}"
    if name == "git_branch":
        return f"Git branch {g('action')} {g('name') or ''}"
    if name == "web_fetch":
        return f"Fetch {g('url')}"
    return f"{name} {json.dumps(inp, default=str)[:300]}"


def build_prompt(name: str, inp: dict, decision: Decision) -> str:
    options = "y = yes, n = no" if not decision.trust_key else "y = yes, a = always allow this kind, n = no"
    return f"{describe(name, inp)}\n[{decision.reason}]  Approve? ({options})"


def _answer(response: Any) -> str:
    if isinstance(response, dict):
        response = response.get("response", response.get("decision", ""))
    if response is True:
        return "y"
    return str(response if response is not None else "").strip().lower()


class CodingPolicy(InterventionHandler):
    """Applies the approval matrix and pauses the agent (via interrupt) to ask the human."""

    name = POLICY_NAME

    def __init__(self, mode: Optional[str] = None):
        settings = get_settings()
        self.mode = mode if mode in MODES else settings.approval_mode
        self.locked = settings.mode_locked
        self.allow_auto_push = settings.allow_auto_push
        self.extra_read = _extra_read_tools()

    def set_mode(self, mode: Optional[str]) -> str:
        """Change the mode unless it is locked or invalid. Returns the effective mode."""
        if mode in MODES and not self.locked:
            self.mode = mode
        return self.mode

    def before_tool_call(self, event, **kwargs):
        name = event.tool_use["name"]
        inp = event.tool_use.get("input") or {}
        if not isinstance(inp, dict):
            inp = {}
        decision = decide(name, inp, self.mode, allow_auto_push=self.allow_auto_push, extra_read=self.extra_read)
        if decision.action == "allow":
            return Proceed()
        if decision.action == "deny":
            return Deny(reason=decision.reason)

        trusted = event.agent.state.get(TRUST_KEY) or []
        if decision.trust_key and decision.trust_key in trusted:
            return Proceed()

        def evaluate(response: Any) -> bool:
            answer = _answer(response)
            if answer in {"a", "always", "t", "trust"} and decision.trust_key:
                current = event.agent.state.get(TRUST_KEY) or []
                if decision.trust_key not in current:
                    event.agent.state.set(TRUST_KEY, [*current, decision.trust_key])
                return True
            return answer in {"y", "yes", "true", "approve", "approved", "ok"}

        return Confirm(prompt=build_prompt(name, inp, decision), evaluate=evaluate)
