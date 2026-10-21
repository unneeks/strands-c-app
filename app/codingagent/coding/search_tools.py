"""Search tools: glob_files, grep_search, project_overview."""

import fnmatch
import glob as globmod
import os
import re
import shutil
from pathlib import Path
from typing import List, Optional, Tuple

from strands import tool

from .safety import IGNORED_DIRS, clip, redact, rel, resolve, run_capture, workspace_root
from .shell_tools import detect_test_command


def _walk_files(base: Path):
    for dirpath, dirnames, filenames in os.walk(base):
        dirnames[:] = sorted(d for d in dirnames if d not in IGNORED_DIRS)
        for name in sorted(filenames):
            yield Path(dirpath) / name


@tool
def glob_files(pattern: str, path: str = ".", max_results: int = 200) -> str:
    """Find files by name pattern, newest first. Patterns without a slash search all subfolders.

    Examples: "*.py", "**/test_*.py", "src/**/*.ts", "Dockerfile".

    Args:
        pattern: Glob pattern. "*.py" is treated as "**/*.py".
        path: Folder to search in, relative to the workspace.
        max_results: Maximum number of files to return.
    """
    base = resolve(path, must_exist=True)
    if "/" not in pattern:
        pattern = "**/" + pattern
    found = []
    for match in globmod.glob(pattern, root_dir=str(base), recursive=True):
        if any(part in IGNORED_DIRS for part in Path(match).parts):
            continue
        full = base / match
        if full.is_file():
            try:
                found.append((full.stat().st_mtime, full))
            except OSError:
                continue
    found.sort(key=lambda item: item[0], reverse=True)
    limit = max(1, min(int(max_results), 1000))
    if not found:
        return f"No files match '{pattern}' under {rel(base)}."
    lines = [rel(p) for _, p in found[:limit]]
    note = f"\n[showing {limit} of {len(found)} matches]" if len(found) > limit else ""
    return "\n".join(lines) + note


def _py_grep(regex, base: Path, glob_pat: Optional[str], context: int, limit: int) -> Tuple[List[str], bool]:
    out: List[str] = []
    matches = 0
    files = [base] if base.is_file() else _walk_files(base)
    for file_path in files:
        if glob_pat and not (fnmatch.fnmatch(file_path.name, glob_pat) or fnmatch.fnmatch(rel(file_path), glob_pat)):
            continue
        try:
            if file_path.stat().st_size > 1_000_000:
                continue
            data = file_path.read_bytes()
        except OSError:
            continue
        if b"\x00" in data[:4096]:
            continue
        lines = data.decode("utf-8", "replace").splitlines()
        for index, line in enumerate(lines):
            if not regex.search(line):
                continue
            low, high = max(0, index - context), min(len(lines), index + context + 1)
            for j in range(low, high):
                sep = ":" if j == index else "-"
                out.append(f"{rel(file_path)}{sep}{j + 1}{sep} {lines[j][:300]}")
            if context:
                out.append("--")
            matches += 1
            if matches >= limit:
                return out, True
    return out, False


@tool
def grep_search(
    pattern: str,
    path: str = ".",
    glob: Optional[str] = None,
    ignore_case: bool = False,
    literal: bool = False,
    context_lines: int = 0,
    max_results: int = 100,
) -> str:
    """Search file contents with a regular expression. Returns file:line: text.

    Use this to find definitions, usages, TODOs and error strings before editing.

    Args:
        pattern: Regex to search for (or plain text when literal=True).
        path: File or folder to search, relative to the workspace.
        glob: Only search files whose name matches this pattern, e.g. "*.py".
        ignore_case: Case-insensitive matching.
        literal: Treat the pattern as plain text instead of a regex.
        context_lines: Lines of context to show around each match (0-5).
        max_results: Maximum number of matches to return.
    """
    if not pattern:
        raise ValueError("pattern must not be empty.")
    base = resolve(path, must_exist=True)
    context = max(0, min(int(context_lines), 5))
    limit = max(1, min(int(max_results), 500))
    try:
        regex = re.compile(re.escape(pattern) if literal else pattern, re.I if ignore_case else 0)
    except re.error as exc:
        raise ValueError(f"Invalid regex: {exc}") from None

    truncated = False
    ripgrep = shutil.which("rg")
    if ripgrep:
        cmd = [ripgrep, "-n", "--no-heading", "--color", "never", "--max-columns", "300", "--hidden",
               "-g", "!.git", "--max-count", "50"]
        if ignore_case:
            cmd.append("-i")
        if literal:
            cmd.append("-F")
        if context:
            cmd += ["-C", str(context)]
        if glob:
            cmd += ["-g", glob]
        cmd += ["-e", pattern, "--", str(base)]
        code, text = run_capture(cmd, cwd=workspace_root(), timeout=30)
        if code not in (0, 1):
            raise ValueError(f"Search failed: {clip(text, 500)}")
        prefix = str(workspace_root()) + os.sep
        lines = [ln.replace(prefix, "") for ln in text.splitlines()]
        if len(lines) > limit * (1 + 2 * context):
            lines, truncated = lines[: limit * (1 + 2 * context)], True
    else:
        lines, truncated = _py_grep(regex, base, glob, context, limit)

    if not lines:
        return f"No matches for '{pattern}' under {rel(base)}."
    note = f"\n[results truncated at {limit} matches; narrow the search]" if truncated else ""
    return redact(clip("\n".join(lines))) + note


_MARKERS = [
    ("pyproject.toml", "Python"), ("requirements.txt", "Python"), ("package.json", "Node.js"),
    ("tsconfig.json", "TypeScript"), ("go.mod", "Go"), ("Cargo.toml", "Rust"), ("pom.xml", "Java (Maven)"),
    ("build.gradle", "Java/Kotlin (Gradle)"), ("Gemfile", "Ruby"), ("Makefile", "Make"),
    ("Dockerfile", "Docker"), ("docker-compose.yml", "Docker Compose"),
]
_INSTRUCTION_FILES = ("AGENTS.md", "CLAUDE.md", "README.md")


@tool
def project_overview() -> str:
    """Summarize the workspace: stack, git state, test command, top-level layout, instructions.

    Call this first when starting work on a project or when you are unsure what is here.
    """
    root = workspace_root()
    parts = [f"Workspace: {root}"]
    stack = sorted({label for marker, label in _MARKERS if (root / marker).exists()})
    parts.append("Detected: " + (", ".join(stack) if stack else "no known project files (empty or unknown stack)"))
    detected = detect_test_command(root)
    parts.append("Test command: " + (f"{detected[0]}  ({detected[1]})" if detected else "none detected"))
    try:
        code, out = run_capture(["git", "status", "--short", "--branch"], cwd=root, timeout=15)
        parts.append("Git: " + (clip(out.strip(), 1500) if code == 0 else "not a git repository"))
    except ValueError:
        parts.append("Git: not installed")
    entries = sorted(root.iterdir(), key=lambda e: (not e.is_dir(), e.name.lower())) if root.exists() else []
    shown = [f"  {e.name}{'/' if e.is_dir() else ''}" for e in entries if e.name not in {".git"}][:60]
    parts.append("Top level:\n" + ("\n".join(shown) if shown else "  (empty)"))
    for name in _INSTRUCTION_FILES:
        candidate = root / name
        if candidate.is_file():
            text = candidate.read_text(errors="replace").splitlines()[:40]
            parts.append(f"--- {name} (first {len(text)} lines) ---\n" + redact("\n".join(text)))
            break
    return "\n".join(parts)
