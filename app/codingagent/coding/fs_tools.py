"""File tools: read, write, edit, patch, list, delete, move, mkdir, undo."""

import difflib
import os
import re
import shutil
import tempfile
from pathlib import Path
from typing import Optional

from strands import tool

from . import checkpoints
from .safety import (
    IGNORED_DIRS,
    PolicyError,
    atomic_write,
    check_writable,
    clip,
    human_size,
    redact,
    rel,
    resolve,
    run_capture,
    workspace_root,
)

MAX_WRITE_CHARS = 2_000_000


def _read_text(path: Path) -> str:
    if path.is_dir():
        raise ValueError(f"'{rel(path)}' is a directory. Use list_directory.")
    size = path.stat().st_size
    if size > 10 * 1024 * 1024:
        raise ValueError(f"'{rel(path)}' is {human_size(size)}; too large to edit. Use grep_search or run_command (head/tail).")
    data = path.read_bytes()
    if b"\x00" in data[:8192]:
        raise ValueError(f"'{rel(path)}' looks like a binary file.")
    try:
        return data.decode("utf-8")
    except UnicodeDecodeError:
        raise ValueError(f"'{rel(path)}' is not valid UTF-8 text.") from None


def make_diff(old: str, new: str, name: str, max_lines: int = 80) -> str:
    diff = list(
        difflib.unified_diff(
            old.splitlines(), new.splitlines(), f"a/{name}", f"b/{name}", lineterm="", n=2
        )
    )
    if len(diff) > max_lines:
        extra = len(diff) - max_lines
        diff = diff[:max_lines] + [f"... diff truncated ({extra} more lines)"]
    return "\n".join(diff)


def _closest_hint(text: str, old: str) -> str:
    first = next((ln.strip() for ln in old.splitlines() if ln.strip()), "")
    if not first:
        return ""
    lines = text.splitlines()
    candidates = difflib.get_close_matches(first, [ln.strip() for ln in lines], n=1, cutoff=0.6)
    if not candidates:
        return ""
    for number, line in enumerate(lines, 1):
        if line.strip() == candidates[0]:
            snippet = "\n".join(lines[number - 1 : number + 2])
            return f"\nClosest match is near line {number}:\n{snippet}"
    return ""


@tool
def read_file(path: str, start_line: int = 1, end_line: Optional[int] = None) -> str:
    """Read a text file and return it with line numbers.

    Always read a file before editing it. Long files are returned in pages of 400 lines;
    pass start_line/end_line to page through them.

    Args:
        path: File path, relative to the workspace (or absolute inside it).
        start_line: First line to return (1-based).
        end_line: Last line to return (inclusive). Defaults to start_line + 399.
    """
    file_path = resolve(path, must_exist=True)
    text = _read_text(file_path)
    lines = text.splitlines()
    total = len(lines)
    start = max(1, int(start_line))
    end = int(end_line) if end_line else start + 399
    end = min(max(end, start), total, start + 1999)
    if total == 0:
        return f"{rel(file_path)} is empty."
    if start > total:
        raise ValueError(f"start_line {start} is past the end of the file ({total} lines).")
    body = "\n".join(f"{n:>6}\t{lines[n - 1][:2000]}" for n in range(start, end + 1))
    header = f"{rel(file_path)} (lines {start}-{end} of {total})"
    footer = f"\n[more lines available: call read_file with start_line={end + 1}]" if end < total else ""
    return redact(clip(f"{header}\n{body}{footer}"))


@tool
def write_file(path: str, content: str, append: bool = False) -> str:
    """Create a file, overwrite it, or append to it. Parent folders are created automatically.

    Prefer edit_file for changing existing files. For large files, write the first part
    and then call again with append=True so no single call gets too long.

    Args:
        path: File path, relative to the workspace.
        content: The full text to write.
        append: If True, add the content to the end of an existing file instead of overwriting.
    """
    if len(content) > MAX_WRITE_CHARS:
        raise ValueError("Content is too large for one call; split it and use append=True.")
    file_path = resolve(path)
    check_writable(file_path)
    if file_path.is_dir():
        raise ValueError(f"'{rel(file_path)}' is a directory.")
    existed = file_path.exists()
    previous = _read_text(file_path) if existed else ""
    new_text = previous + content if append else content
    checkpoint = checkpoints.snapshot([file_path], f"write_file {rel(file_path)}")
    atomic_write(file_path, new_text)
    verb = "Appended to" if append and existed else ("Overwrote" if existed else "Created")
    return (
        f"{verb} {rel(file_path)} ({len(new_text.splitlines())} lines, {human_size(len(new_text.encode()))}). "
        f"Checkpoint: {checkpoint}"
    )


@tool
def edit_file(path: str, old_str: str, new_str: str, replace_all: bool = False) -> str:
    """Replace exact text in a file. The safest way to modify existing code.

    old_str must match the file exactly (whitespace and indentation included) and must be
    unique, unless replace_all is True. Include a few surrounding lines to make it unique.

    Args:
        path: File path, relative to the workspace.
        old_str: The exact existing text to replace. Must not be empty.
        new_str: The replacement text (use an empty string to delete).
        replace_all: Replace every occurrence instead of requiring a unique match.
    """
    file_path = resolve(path, must_exist=True)
    check_writable(file_path)
    text = _read_text(file_path)
    if old_str == "":
        raise ValueError("old_str must not be empty. Use write_file to create or fully replace a file.")
    if old_str == new_str:
        raise ValueError("old_str and new_str are identical; nothing to change.")
    if "\r\n" in text and "\r\n" not in old_str:
        old_str = old_str.replace("\n", "\r\n")
        new_str = new_str.replace("\n", "\r\n")
    count = text.count(old_str)
    if count == 0:
        raise ValueError(
            f"old_str was not found in {rel(file_path)}. Re-read the file and copy the text exactly."
            + _closest_hint(text, old_str)
        )
    if count > 1 and not replace_all:
        positions = [text.count("\n", 0, m.start()) + 1 for m in re.finditer(re.escape(old_str), text)]
        raise ValueError(
            f"old_str matches {count} places (lines {positions[:10]}). Add more surrounding context "
            "to make it unique, or set replace_all=True."
        )
    updated = text.replace(old_str, new_str) if replace_all else text.replace(old_str, new_str, 1)
    checkpoint = checkpoints.snapshot([file_path], f"edit_file {rel(file_path)}")
    atomic_write(file_path, updated)
    diff = make_diff(text, updated, rel(file_path))
    return f"Edited {rel(file_path)} ({count if replace_all else 1} replacement). Checkpoint: {checkpoint}\n{diff}"


_PATCH_PATH = re.compile(r"^(?:---|\+\+\+) (?:[ab]/)?(\S+)")


def patch_paths(patch: str) -> list:
    paths = []
    for line in patch.splitlines():
        match = _PATCH_PATH.match(line)
        if match and match.group(1) != "/dev/null":
            name = match.group(1)
            if name not in paths:
                paths.append(name)
    return paths


@tool
def apply_patch(patch: str) -> str:
    """Apply a unified diff (as produced by `git diff`) to the workspace.

    Good for multi-file or multi-hunk changes. Paths must be relative to the workspace root
    (a/ and b/ prefixes are fine). The patch is validated first and applied all-or-nothing.

    Args:
        patch: The unified diff text.
    """
    if not patch.strip():
        raise ValueError("The patch is empty.")
    names = patch_paths(patch)
    if not names:
        raise ValueError("No file paths found. Use the unified diff format with ---/+++ headers.")
    targets = []
    for name in names:
        if name.startswith("/") or ".." in Path(name).parts:
            raise PolicyError(f"Patch path '{name}' must be relative and inside the workspace.")
        target = resolve(name)
        check_writable(target)
        targets.append(target)
    root = workspace_root()
    with tempfile.NamedTemporaryFile("w", suffix=".patch", delete=False) as handle:
        handle.write(patch if patch.endswith("\n") else patch + "\n")
        patch_file = handle.name
    try:
        base = ["git", "apply", "-p1", "--whitespace=nowarn"]
        code, out = run_capture(base + ["--check", patch_file], cwd=root)
        if code != 0:
            raise ValueError(f"Patch does not apply cleanly:\n{clip(out, 3000)}")
        checkpoint = checkpoints.snapshot(targets, "apply_patch")
        code, out = run_capture(base + [patch_file], cwd=root)
        if code != 0:
            raise ValueError(f"Patch failed:\n{clip(out, 3000)}")
    finally:
        try:
            os.unlink(patch_file)
        except OSError:
            pass
    return f"Applied patch to {len(names)} file(s): {', '.join(names)}. Checkpoint: {checkpoint}"


def _human_entry(entry: Path) -> str:
    try:
        return human_size(entry.stat().st_size)
    except OSError:
        return "?"


@tool
def list_directory(path: str = ".", depth: int = 1, max_entries: int = 200) -> str:
    """List files and folders (folders first). Build/vendor folders are shown but not expanded.

    Args:
        path: Directory to list, relative to the workspace.
        depth: How many levels to show (1-5).
        max_entries: Maximum number of entries to return.
    """
    base = resolve(path, must_exist=True)
    if not base.is_dir():
        raise ValueError(f"'{rel(base)}' is not a directory.")
    depth = max(1, min(int(depth), 5))
    limit = max(1, min(int(max_entries), 1000))
    lines = []

    def walk(directory: Path, level: int) -> None:
        try:
            entries = sorted(directory.iterdir(), key=lambda e: (not e.is_dir(), e.name.lower()))
        except PermissionError:
            return
        for entry in entries:
            if len(lines) >= limit:
                return
            indent = "  " * level
            if entry.is_dir() and not entry.is_symlink():
                lines.append(f"{indent}{entry.name}/")
                if level + 1 < depth and entry.name not in IGNORED_DIRS:
                    walk(entry, level + 1)
            else:
                lines.append(f"{indent}{entry.name}  ({_human_entry(entry)})")

    walk(base, 0)
    if not lines:
        return f"{rel(base)}/ is empty."
    note = f"\n[truncated at {limit} entries]" if len(lines) >= limit else ""
    return f"{rel(base)}/\n" + "\n".join(lines) + note


@tool
def delete_path(path: str, recursive: bool = False) -> str:
    """Delete a file, or a folder when recursive=True. A checkpoint is saved so it can be undone.

    Args:
        path: File or folder to delete, relative to the workspace.
        recursive: Required to delete a non-empty folder.
    """
    target = resolve(path, must_exist=True)
    check_writable(target)
    if target.is_dir() and not target.is_symlink():
        if any(target.iterdir()) and not recursive:
            raise ValueError(f"'{rel(target)}' is a non-empty folder. Pass recursive=True to delete it.")
        checkpoint = checkpoints.snapshot([target], f"delete_path {rel(target)}")
        shutil.rmtree(target)
    else:
        checkpoint = checkpoints.snapshot([target], f"delete_path {rel(target)}")
        target.unlink()
    return f"Deleted {rel(target)}. Checkpoint: {checkpoint} (undo_change restores it)"


@tool
def move_path(source: str, destination: str) -> str:
    """Move or rename a file or folder. Refuses to overwrite an existing destination.

    Args:
        source: Existing path, relative to the workspace.
        destination: New path, relative to the workspace.
    """
    src = resolve(source, must_exist=True)
    dst = resolve(destination)
    check_writable(src)
    check_writable(dst)
    if dst.exists():
        raise ValueError(f"'{rel(dst)}' already exists. Choose another destination or delete it first.")
    checkpoint = checkpoints.snapshot([src, dst], f"move_path {rel(src)} -> {rel(dst)}")
    dst.parent.mkdir(parents=True, exist_ok=True)
    shutil.move(str(src), str(dst))
    return f"Moved {rel(src)} -> {rel(dst)}. Checkpoint: {checkpoint}"


@tool
def make_directory(path: str) -> str:
    """Create a folder (and any missing parents). Succeeds if it already exists.

    Args:
        path: Folder to create, relative to the workspace.
    """
    target = resolve(path)
    check_writable(target)
    target.mkdir(parents=True, exist_ok=True)
    return f"Directory ready: {rel(target)}/"


@tool
def undo_change(checkpoint_id: Optional[str] = None) -> str:
    """Undo earlier changes. Without an id, lists recent checkpoints (newest first).

    Every write, edit, patch, move and delete saves a checkpoint. Restoring one also saves a
    new checkpoint, so an undo can itself be undone.

    Args:
        checkpoint_id: The checkpoint to restore. Omit to list available checkpoints.
    """
    if not checkpoint_id:
        items = checkpoints.list_checkpoints(15)
        if not items:
            return "No checkpoints yet."
        rows = [f"{i['id']}  {i['label']}  [{', '.join(e['path'] for e in i['entries'])[:120]}]" for i in items]
        return "Recent checkpoints (newest first):\n" + "\n".join(rows)
    return "\n".join(checkpoints.restore(checkpoint_id.strip()))
