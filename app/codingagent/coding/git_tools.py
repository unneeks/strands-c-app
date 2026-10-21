"""Git tools. No force-push, no history rewriting: those go through run_command + approval."""

import re
from typing import Optional

from strands import tool

from .safety import PolicyError, clip, is_sensitive, redact, rel, resolve, run_capture, workspace_root

_REF = re.compile(r"^[\w./~^@{}:+-]+(\.\.\.?[\w./~^@{}:+-]+)?$")
_BRANCH = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._/-]*$")


def _git(args: list, timeout: int = 60):
    return run_capture(["git", "-c", "core.quotepath=false", *args], cwd=workspace_root(), timeout=timeout)


def _require_repo() -> None:
    code, out = _git(["rev-parse", "--is-inside-work-tree"], timeout=15)
    if code != 0:
        raise ValueError("This workspace is not a git repository. Call git_init first.")


def _check_ref(ref: str) -> str:
    if not ref or ref.startswith("-") or not _REF.match(ref):
        raise ValueError(f"Invalid revision '{ref}'.")
    return ref


@tool
def git_status() -> str:
    """Show the current branch and which files are modified, staged or untracked."""
    code, out = _git(["status", "--short", "--branch"], timeout=30)
    if code != 0:
        return "Not a git repository. Call git_init to create one."
    return clip(out.strip()) or "Clean working tree."


@tool
def git_diff(path: Optional[str] = None, staged: bool = False, base: Optional[str] = None) -> str:
    """Show changes as a unified diff (working tree vs index by default).

    Args:
        path: Limit the diff to one file or folder, relative to the workspace.
        staged: Show staged changes (what the next commit would contain).
        base: Compare against a revision instead, e.g. "HEAD~1" or "main".
    """
    _require_repo()
    args = ["diff", "--no-color"]
    if staged:
        args.append("--cached")
    if base:
        args.append(_check_ref(base))
    if path:
        args += ["--", rel(resolve(path))]
    code, out = _git(args, timeout=60)
    if code != 0:
        raise ValueError(clip(out, 2000))
    return redact(clip(out)) if out.strip() else "No differences."


@tool
def git_log(max_count: int = 10, path: Optional[str] = None, rev: Optional[str] = None, show_patch: bool = False) -> str:
    """Show recent commit history, or a specific commit when rev is given with show_patch.

    Args:
        max_count: Number of commits to list (1-50).
        path: Only commits touching this file or folder.
        rev: A commit, branch or range such as "HEAD~3..HEAD".
        show_patch: Include the diff of each commit (large; use with small max_count).
    """
    _require_repo()
    count = max(1, min(int(max_count), 50))
    args = ["log", f"-{count}", "--no-color", "--date=short"]
    args += ["-p"] if show_patch else ["--pretty=format:%h %ad %an  %s"]
    if rev:
        args.append(_check_ref(rev))
    if path:
        args += ["--", rel(resolve(path))]
    code, out = _git(args, timeout=60)
    if code != 0:
        raise ValueError(clip(out, 2000))
    return redact(clip(out)) if out.strip() else "No commits."


@tool
def git_branch(action: str = "list", name: Optional[str] = None) -> str:
    """List branches, create a new branch and switch to it, or switch to an existing one.

    Args:
        action: "list", "create" (creates and switches), or "switch".
        name: Branch name (required for create and switch).
    """
    action = (action or "list").strip().lower()
    _require_repo()
    if action == "list":
        code, out = _git(["branch", "--all", "--no-color", "-vv"], timeout=30)
        return clip(out.strip()) if out.strip() else "No branches yet (make a first commit)."
    if action not in {"create", "switch"}:
        raise ValueError('action must be "list", "create" or "switch".')
    if not name or not _BRANCH.match(name):
        raise ValueError("A valid branch name is required (letters, digits, . _ / -).")
    args = ["switch", "-c", name] if action == "create" else ["switch", name]
    code, out = _git(args, timeout=30)
    if code != 0:
        raise ValueError(clip(out, 1500))
    return out.strip() or f"On branch {name}."


@tool
def git_init() -> str:
    """Create a git repository in the workspace (does nothing if one already exists)."""
    code, _ = _git(["rev-parse", "--is-inside-work-tree"], timeout=15)
    if code == 0:
        return "Already a git repository."
    code, out = _git(["init", "-b", "main"], timeout=30)
    if code != 0:
        code, out = _git(["init"], timeout=30)
    if code != 0:
        raise ValueError(clip(out, 1500))
    return out.strip()


@tool
def git_commit(message: str, paths: Optional[list] = None, all_changes: bool = True) -> str:
    """Stage changes and create a commit. Commit only when the user asks you to.

    Refuses to commit files that look like credentials (.env, keys, ...). Use a clear message:
    a short summary line, optionally followed by a blank line and details.

    Args:
        message: The commit message.
        paths: Specific files to stage. When omitted, all changes are staged (if all_changes).
        all_changes: Stage every change (git add -A) when no paths are given.
    """
    _require_repo()
    message = (message or "").strip()
    if not message:
        raise ValueError("A commit message is required.")
    if len(message) > 5000:
        raise ValueError("Commit message is too long.")
    if paths:
        targets = [rel(resolve(p, must_exist=True)) for p in paths]
        code, out = _git(["add", "--", *targets], timeout=60)
    elif all_changes:
        code, out = _git(["add", "-A"], timeout=60)
    else:
        code, out = 0, ""
    if code != 0:
        raise ValueError(clip(out, 1500))

    code, staged = _git(["diff", "--cached", "--name-only"], timeout=30)
    names = [n for n in staged.splitlines() if n.strip()]
    if not names:
        return "Nothing to commit (no staged changes)."
    secrets = [n for n in names if is_sensitive(n)]
    if secrets:
        _git(["reset", "-q", "--", *secrets], timeout=30)
        raise PolicyError(
            "Refusing to commit credential-like files: " + ", ".join(secrets)
            + ". They were unstaged. Add them to .gitignore or remove them."
        )

    identity = []
    for key, fallback in (("user.name", "Coding Agent"), ("user.email", "coding-agent@localhost")):
        have, value = _git(["config", "--get", key], timeout=15)
        if have != 0 or not value.strip():
            identity += ["-c", f"{key}={fallback}"]
    code, out = _git([*identity, "commit", "-m", message], timeout=120)
    if code != 0:
        raise ValueError(clip(out, 3000))
    return clip(out.strip(), 2000)


@tool
def git_push(remote: str = "origin", branch: Optional[str] = None, set_upstream: bool = False) -> str:
    """Push commits to a remote. Never forces. Always needs the user's approval.

    Args:
        remote: Remote name.
        branch: Branch to push (defaults to the current branch's upstream).
        set_upstream: Set the upstream tracking branch (-u).
    """
    _require_repo()
    if not _BRANCH.match(remote or ""):
        raise ValueError("Invalid remote name.")
    args = ["push"]
    if set_upstream:
        args.append("-u")
    args.append(remote)
    if branch:
        if not _BRANCH.match(branch):
            raise ValueError("Invalid branch name.")
        args.append(branch)
    code, out = _git(args, timeout=120)
    if code != 0:
        raise ValueError(clip(redact(out), 2000))
    return clip(redact(out.strip()), 2000) or "Pushed."
