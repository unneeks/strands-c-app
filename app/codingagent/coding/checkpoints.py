"""Pre-edit snapshots so every change the agent makes can be undone.

Snapshots live outside the workspace (in the system temp dir) so they never pollute the
repository or end up in a commit.
"""

from __future__ import annotations

import hashlib
import json
import shutil
import tempfile
import time
from pathlib import Path
from typing import Iterable, List

from .safety import PolicyError, rel, workspace_root

MAX_CHECKPOINTS = 50
MAX_DIR_BYTES = 20 * 1024 * 1024


def _store() -> Path:
    key = hashlib.sha1(str(workspace_root()).encode()).hexdigest()[:12]
    directory = Path(tempfile.gettempdir()) / "coding-agent-checkpoints" / key
    directory.mkdir(parents=True, exist_ok=True)
    return directory


def _tree_size(path: Path) -> int:
    return sum(p.stat().st_size for p in path.rglob("*") if p.is_file() and not p.is_symlink())


def _next_id() -> str:
    """Short sequential ids (cp00001, cp00002, ...) so 'newest' is always well defined."""
    numbers = [int(p.name[2:]) for p in _store().iterdir() if p.is_dir() and p.name[2:].isdigit()]
    return f"cp{(max(numbers) + 1 if numbers else 1):05d}"


def snapshot(paths: Iterable[Path], label: str) -> str:
    """Save the current state of ``paths`` (missing paths are recorded as 'did not exist')."""
    checkpoint_id = _next_id()
    base = _store() / checkpoint_id
    files_dir = base / "files"
    files_dir.mkdir(parents=True)
    entries = []
    for path in paths:
        name = rel(path)
        existed = path.exists() or path.is_symlink()
        is_dir = path.is_dir() and not path.is_symlink()
        if existed:
            destination = files_dir / name
            destination.parent.mkdir(parents=True, exist_ok=True)
            if is_dir:
                if _tree_size(path) > MAX_DIR_BYTES:
                    shutil.rmtree(base, ignore_errors=True)
                    raise PolicyError(f"'{name}' is too large to checkpoint safely (> 20 MB).")
                shutil.copytree(path, destination, symlinks=True)
            else:
                shutil.copy2(path, destination, follow_symlinks=False)
        entries.append({"path": name, "existed": existed, "kind": "dir" if is_dir else "file"})
    (base / "manifest.json").write_text(
        json.dumps({"id": checkpoint_id, "label": label, "time": time.time(), "entries": entries})
    )
    _prune()
    return checkpoint_id


def _prune() -> None:
    ids = sorted(p.name for p in _store().iterdir() if p.is_dir())
    for old in ids[:-MAX_CHECKPOINTS]:
        shutil.rmtree(_store() / old, ignore_errors=True)


def list_checkpoints(limit: int = 10) -> List[dict]:
    items = []
    for directory in sorted((p for p in _store().iterdir() if p.is_dir()), reverse=True)[:limit]:
        manifest = directory / "manifest.json"
        if manifest.exists():
            try:
                items.append(json.loads(manifest.read_text()))
            except ValueError:
                continue
    return items


def restore(checkpoint_id: str) -> List[str]:
    """Put every path in the checkpoint back as it was. A new checkpoint is taken first (redo)."""
    base = _store() / checkpoint_id
    manifest = base / "manifest.json"
    if not manifest.exists():
        raise ValueError(f"Unknown checkpoint '{checkpoint_id}'. Call undo_change without an id to list them.")
    data = json.loads(manifest.read_text())
    root = workspace_root()
    targets = [root / entry["path"] for entry in data["entries"]]
    redo_id = snapshot(targets, f"before undo of {checkpoint_id}")
    results = []
    for entry, target in zip(data["entries"], targets, strict=True):
        if entry["existed"]:
            source = base / "files" / entry["path"]
            if target.is_dir() and not target.is_symlink():
                shutil.rmtree(target)
            elif target.exists() or target.is_symlink():
                target.unlink()
            target.parent.mkdir(parents=True, exist_ok=True)
            if entry["kind"] == "dir":
                shutil.copytree(source, target, symlinks=True)
            else:
                shutil.copy2(source, target)
            results.append(f"restored {entry['path']}")
        else:
            if target.is_dir() and not target.is_symlink():
                shutil.rmtree(target)
                results.append(f"removed {entry['path']}")
            elif target.exists() or target.is_symlink():
                target.unlink()
                results.append(f"removed {entry['path']}")
    results.append(f"(redo available as checkpoint {redo_id})")
    return results
