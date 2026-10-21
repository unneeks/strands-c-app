"""Workspace confinement, secret redaction, atomic writes and output clipping.

Everything in here is a *hard* guarantee enforced inside the tools themselves, so it holds
no matter which approval mode is active.
"""

from __future__ import annotations

import fnmatch
import os
import re
import subprocess
from pathlib import Path
from typing import Optional, Union

from .config import get_settings


class PolicyError(Exception):
    """A hard safety rule was violated. These are never user-approvable."""


IGNORED_DIRS = frozenset(
    {
        ".git", "node_modules", "__pycache__", ".venv", "venv", ".mypy_cache", ".pytest_cache",
        ".ruff_cache", ".tox", ".idea", ".gradle", "dist", "build", "target", ".next", ".cache",
        ".terraform",
    }
)


# --------------------------------------------------------------------------- paths
def workspace_root() -> Path:
    return Path(os.path.realpath(get_settings().workspace))


def resolve(path: Optional[Union[str, os.PathLike]] = None, *, must_exist: bool = False) -> Path:
    """Resolve ``path`` (relative to the workspace) and refuse anything that escapes it.

    Symlinks are resolved first, so a link pointing outside the workspace is rejected too.
    """
    root = workspace_root()
    raw = str(path).strip() if path not in (None, "") else "."
    candidate = Path(raw).expanduser()
    if not candidate.is_absolute():
        candidate = root / candidate
    real = Path(os.path.realpath(candidate))
    if real != root and root not in real.parents:
        raise PolicyError(
            f"'{raw}' is outside the workspace ({root}). Only paths inside the workspace are allowed."
        )
    if must_exist and not real.exists():
        raise FileNotFoundError(f"'{raw}' does not exist. Use list_directory or glob_files to find the right path.")
    return real


def rel(path: Path) -> str:
    try:
        value = os.path.relpath(path, workspace_root())
    except ValueError:
        return str(path)
    return "." if value == "." else value


def in_git_dir(path: Path) -> bool:
    return ".git" in Path(rel(path)).parts


def check_writable(path: Path) -> None:
    if in_git_dir(path):
        raise PolicyError("Files inside .git/ cannot be modified directly. Use the git_* tools instead.")
    if path == workspace_root():
        raise PolicyError("Refusing to modify the workspace root itself.")


# ------------------------------------------------------------------- sensitive files
_SENSITIVE_NAMES = (
    ".env", ".env.*", "*.pem", "*.key", "*.p12", "*.pfx", "*.keystore", "id_rsa*", "id_ed25519*",
    "id_ecdsa*", ".netrc", ".npmrc", ".pypirc", ".git-credentials", "credentials", "credentials.*",
    "secrets.*", "*.tfstate", "*.tfstate.*",
)
_SENSITIVE_OK = {".env.example", ".env.sample", ".env.template", ".env.dist"}
_SENSITIVE_DIRS = {".ssh", ".aws", ".gnupg", ".kube"}


def is_sensitive(path: Union[str, os.PathLike]) -> bool:
    """True for files that commonly hold credentials (reads need explicit approval)."""
    parts = Path(str(path)).parts
    if not parts:
        return False
    name = parts[-1].lower()
    if name in _SENSITIVE_OK:
        return False
    if any(part in _SENSITIVE_DIRS for part in parts[:-1]):
        return True
    return any(fnmatch.fnmatch(name, pattern) for pattern in _SENSITIVE_NAMES)


# ------------------------------------------------------------------------ redaction
_REDACTIONS = [
    (re.compile(r"-----BEGIN [A-Z ]*PRIVATE KEY-----.*?-----END [A-Z ]*PRIVATE KEY-----", re.S), "[REDACTED PRIVATE KEY]"),
    (re.compile(r"\b(?:AKIA|ASIA)[0-9A-Z]{16}\b"), "[REDACTED AWS KEY ID]"),
    (re.compile(r"\bgh[pousr]_[A-Za-z0-9]{30,}\b"), "[REDACTED GITHUB TOKEN]"),
    (re.compile(r"\bxox[abprs]-[A-Za-z0-9-]{10,}\b"), "[REDACTED SLACK TOKEN]"),
    (re.compile(r"\bsk-[A-Za-z0-9_-]{20,}\b"), "[REDACTED API KEY]"),
    (
        re.compile(
            r"(?i)(aws_secret_access_key|aws_session_token|secret[_-]?key|api[_-]?key|access[_-]?token|"
            r"auth[_-]?token|client[_-]?secret|password|passwd)(\s*[=:]\s*)(['\"]?)([^\s'\"]{8,})(\3)"
        ),
        r"\1\2\3[REDACTED]\5",
    ),
]


def redact(text: str) -> str:
    """Mask obvious credentials so they never reach the model or the logs."""
    for pattern, replacement in _REDACTIONS:
        text = pattern.sub(replacement, text)
    return text


# ------------------------------------------------------------------------- helpers
def clip(text: str, limit: Optional[int] = None, *, tail_share: float = 0.4) -> str:
    """Keep the head and the tail of long output (errors usually live at the end)."""
    limit = limit or get_settings().max_output_chars
    if len(text) <= limit:
        return text
    tail = int(limit * tail_share)
    head = limit - tail
    return f"{text[:head]}\n\n... [{len(text) - limit} characters omitted] ...\n\n{text[-tail:]}"


def human_size(num: int) -> str:
    size = float(num)
    for unit in ("B", "KB", "MB", "GB"):
        if size < 1024 or unit == "GB":
            return f"{int(size)} {unit}" if unit == "B" else f"{size:.1f} {unit}"
        size /= 1024
    return f"{num} B"


def atomic_write(path: Path, text: str) -> None:
    """Write text without translating newlines, replacing the target atomically."""
    path.parent.mkdir(parents=True, exist_ok=True)
    tmp = path.with_name(f".{path.name}.agent-{os.getpid()}.tmp")
    try:
        tmp.write_bytes(text.encode("utf-8"))
        if path.exists():
            try:
                os.chmod(tmp, path.stat().st_mode & 0o7777)
            except OSError:
                pass
        os.replace(tmp, path)
    finally:
        if tmp.exists():
            try:
                tmp.unlink()
            except OSError:
                pass


_SECRET_ENV = re.compile(r"(?i)(secret|token|password|passwd|credential|api[_-]?key|private[_-]?key|session)")


def scrubbed_env(extra: Optional[dict] = None) -> dict:
    """Environment for child processes: no cloud/API credentials, non-interactive defaults."""
    env = {}
    for key, value in os.environ.items():
        if key.startswith(("AWS_", "BEDROCK_", "ANTHROPIC_", "OPENAI_", "GOOGLE_", "AZURE_")):
            continue
        if _SECRET_ENV.search(key):
            continue
        env[key] = value
    env.update(
        {
            "CI": "1",
            "GIT_TERMINAL_PROMPT": "0",
            "GIT_PAGER": "cat",
            "PAGER": "cat",
            "NO_COLOR": "1",
            "PYTHONUNBUFFERED": "1",
            "DEBIAN_FRONTEND": "noninteractive",
        }
    )
    if extra:
        env.update(extra)
    return env


def run_capture(args: list, *, cwd: Optional[Path] = None, timeout: int = 60, input_text: Optional[str] = None):
    """Run a command without a shell; returns (returncode, combined output)."""
    try:
        proc = subprocess.run(
            args,
            cwd=str(cwd or workspace_root()),
            input=input_text,
            capture_output=True,
            text=True,
            errors="replace",
            timeout=timeout,
            env=scrubbed_env(),
        )
    except FileNotFoundError:
        raise ValueError(f"'{args[0]}' is not installed in this environment.") from None
    except subprocess.TimeoutExpired:
        raise ValueError(f"'{' '.join(map(str, args[:3]))}' timed out after {timeout}s.") from None
    out = (proc.stdout or "") + (proc.stderr or "")
    return proc.returncode, out
