"""Runtime settings for the coding agent (all overridable through environment variables)."""

from __future__ import annotations

import os
import tempfile
from dataclasses import dataclass
from pathlib import Path
from typing import Optional

# plan       - read-only: explore and propose, never change anything
# ask        - reads run freely; every edit / command / commit asks first (default)
# auto-edit  - workspace edits, commits, tests and linters run freely; other commands ask
# auto       - everything runs without asking except dangerous actions (see policy.py)
MODES = ("plan", "ask", "auto-edit", "auto")
DEFAULT_MODE = "ask"


def _truthy(value: Optional[str]) -> bool:
    return str(value or "").strip().lower() in {"1", "true", "yes", "on"}


def _default_workspace() -> Path:
    """WORKSPACE_ROOT if set, else ./workspace, else a temp directory (read-only deployments)."""
    env = os.getenv("WORKSPACE_ROOT")
    if env:
        return Path(env).expanduser().resolve()
    candidate = Path.cwd() / "workspace"
    try:
        candidate.mkdir(parents=True, exist_ok=True)
        if os.access(candidate, os.W_OK):
            return candidate.resolve()
    except OSError:
        pass
    fallback = Path(tempfile.gettempdir()) / "workspace"
    fallback.mkdir(parents=True, exist_ok=True)
    return fallback.resolve()


@dataclass
class Settings:
    workspace: Path
    approval_mode: str = DEFAULT_MODE
    mode_locked: bool = False  # when True callers cannot change the mode per request
    allow_auto_push: bool = False  # let `auto` mode push without asking
    max_file_bytes: int = 1_000_000
    max_output_chars: int = 30_000
    default_timeout: int = 120
    max_timeout: int = 900

    @classmethod
    def from_env(cls) -> "Settings":
        mode = os.getenv("APPROVAL_MODE", DEFAULT_MODE).strip().lower()
        if mode not in MODES:
            mode = DEFAULT_MODE
        workspace = _default_workspace()
        workspace.mkdir(parents=True, exist_ok=True)
        return cls(
            workspace=workspace,
            approval_mode=mode,
            mode_locked=_truthy(os.getenv("APPROVAL_MODE_LOCKED")),
            allow_auto_push=_truthy(os.getenv("ALLOW_AUTO_PUSH")),
        )


_settings: Optional[Settings] = None


def configure(settings: Settings) -> Settings:
    global _settings
    _settings = settings
    return settings


def get_settings() -> Settings:
    global _settings
    if _settings is None:
        _settings = Settings.from_env()
    return _settings
