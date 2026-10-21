"""Shell tools: run_command, run_tests, background_process."""

import asyncio
import atexit
import json
import os
import shutil
import signal
import subprocess
import tempfile
import time
from pathlib import Path
from typing import Dict, Optional, Tuple

from strands import tool

from .commands import guard_command
from .config import get_settings
from .safety import clip, redact, rel, resolve, scrubbed_env, workspace_root


def _shell() -> str:
    return shutil.which("bash") or "/bin/sh"


def _kill_group(proc: subprocess.Popen, grace: float = 2.0) -> None:
    """Terminate the whole process group (children included), escalating to SIGKILL."""
    try:
        pgid = os.getpgid(proc.pid)
    except (ProcessLookupError, OSError):
        return
    for sig in (signal.SIGTERM, signal.SIGKILL):
        try:
            os.killpg(pgid, sig)
        except (ProcessLookupError, PermissionError):
            return
        deadline = time.time() + grace
        while time.time() < deadline:
            if proc.poll() is not None:
                return
            time.sleep(0.05)


def run_sync(command: str, cwd: Path, timeout: int) -> Tuple[int, str, bool]:
    """Run ``command`` in its own process group. Returns (exit_code, output, timed_out)."""
    proc = subprocess.Popen(
        [_shell(), "-c", command],
        cwd=str(cwd),
        stdin=subprocess.DEVNULL,
        stdout=subprocess.PIPE,
        stderr=subprocess.STDOUT,
        env=scrubbed_env(),
        start_new_session=True,
    )
    timed_out = False
    try:
        output, _ = proc.communicate(timeout=timeout)
    except subprocess.TimeoutExpired:
        timed_out = True
        _kill_group(proc)
        try:
            output, _ = proc.communicate(timeout=5)
        except subprocess.TimeoutExpired:
            output = b""
    code = proc.returncode if proc.returncode is not None else -9
    return code, output.decode("utf-8", "replace"), timed_out


def format_result(code: int, output: str, timed_out: bool, seconds: float, timeout: int) -> str:
    status = f"exit_code: {code} ({seconds:.1f}s)"
    if timed_out:
        status += f"\n[TIMED OUT after {timeout}s - the process was killed]"
    body = clip(redact(output.strip())) if output.strip() else "(no output)"
    return f"{status}\n--- output ---\n{body}"


def _clamp_timeout(timeout: int) -> int:
    settings = get_settings()
    return max(1, min(int(timeout or settings.default_timeout), settings.max_timeout))


@tool
async def run_command(command: str, cwd: str = ".", timeout: int = 120) -> str:
    """Run a shell command in the workspace and return its exit code and combined output.

    Each call is a fresh shell (no state carried over) with no stdin, so commands must be
    non-interactive. Use it for builds, installs, scripts, formatters and anything the
    dedicated tools do not cover. Prefer read_file/grep_search/edit_file for file work.
    Long-running servers belong in background_process.

    Args:
        command: The shell command line to run.
        cwd: Working directory, relative to the workspace.
        timeout: Seconds before the command is killed (default 120, max 900).
    """
    guard_command(command)
    work = resolve(cwd, must_exist=True)
    if not work.is_dir():
        raise ValueError(f"cwd '{rel(work)}' is not a directory.")
    limit = _clamp_timeout(timeout)
    started = time.time()
    code, output, timed_out = await asyncio.to_thread(run_sync, command, work, limit)
    return format_result(code, output, timed_out, time.time() - started, limit)


# ----------------------------------------------------------------------- tests
def detect_test_command(root: Path) -> Optional[Tuple[str, str]]:
    """Best-effort guess of how to run the project's tests: (command, why)."""
    package_json = root / "package.json"
    if package_json.exists():
        try:
            scripts = json.loads(package_json.read_text()).get("scripts", {})
        except ValueError:
            scripts = {}
        if "test" in scripts:
            return "npm test --silent", "package.json has a test script"
    python_markers = [root / n for n in ("pytest.ini", "tox.ini", "conftest.py")]
    pyproject = root / "pyproject.toml"
    has_pytest_cfg = pyproject.exists() and "pytest" in pyproject.read_text(errors="replace")
    has_tests = (root / "tests").is_dir() or any(root.glob("test_*.py")) or any(root.glob("*/test_*.py"))
    if any(p.exists() for p in python_markers) or has_pytest_cfg or has_tests:
        venv_python = root / ".venv" / "bin" / "python"
        python = str(venv_python) if venv_python.exists() else "python3"
        return f"{python} -m pytest -q -x", "Python project with pytest tests"
    if (root / "go.mod").exists():
        return "go test ./...", "go.mod found"
    if (root / "Cargo.toml").exists():
        return "cargo test", "Cargo.toml found"
    if (root / "pom.xml").exists():
        return "mvn -q test", "pom.xml found"
    if (root / "gradlew").exists():
        return "./gradlew test", "gradlew found"
    makefile = root / "Makefile"
    if makefile.exists() and "\ntest:" in "\n" + makefile.read_text(errors="replace"):
        return "make test", "Makefile has a test target"
    return None


@tool
async def run_tests(command: Optional[str] = None, timeout: int = 300) -> str:
    """Run the project's test suite and report PASSED or FAILED with the output tail.

    With no command, the test runner is detected automatically (pytest, npm test, go test,
    cargo test, mvn test, gradle test or make test). Run this after every code change.

    Args:
        command: Optional explicit test command, e.g. "python3 -m pytest tests/test_api.py -x".
        timeout: Seconds before the run is killed (default 300, max 900).
    """
    root = workspace_root()
    if command:
        chosen, why = command, "explicit command"
    else:
        detected = detect_test_command(root)
        if not detected:
            return (
                "No test runner detected. Tell me how to run the tests, or create tests first "
                "(for Python: tests/test_*.py, then run_tests)."
            )
        chosen, why = detected
    guard_command(chosen)
    limit = _clamp_timeout(timeout)
    started = time.time()
    code, output, timed_out = await asyncio.to_thread(run_sync, chosen, root, limit)
    verdict = "TIMED OUT" if timed_out else ("PASSED" if code == 0 else "FAILED")
    text = clip(redact(output.strip()), 12_000, tail_share=0.7) if output.strip() else "(no output)"
    return f"{verdict} (exit {code}, {time.time() - started:.1f}s) via `{chosen}` [{why}]\n--- output ---\n{text}"


# ------------------------------------------------------------ background processes
class _Background:
    def __init__(self, bg_id: str, name: str, command: str, proc: subprocess.Popen, log_path: str):
        self.id, self.name, self.command = bg_id, name, command
        self.proc, self.log_path, self.started = proc, log_path, time.time()


_BG: Dict[str, _Background] = {}
_BG_COUNTER = 0
MAX_BACKGROUND = 5


def _cleanup_background() -> None:
    for bg in list(_BG.values()):
        if bg.proc.poll() is None:
            _kill_group(bg.proc, grace=1.0)


atexit.register(_cleanup_background)


def _tail(path: str, lines: int) -> str:
    try:
        with open(path, "rb") as handle:
            handle.seek(0, os.SEEK_END)
            size = handle.tell()
            handle.seek(max(0, size - 65536))
            data = handle.read().decode("utf-8", "replace")
    except OSError:
        return ""
    return redact("\n".join(data.splitlines()[-lines:]))


def _status(bg: _Background) -> str:
    code = bg.proc.poll()
    state = "running" if code is None else f"exited with code {code}"
    return f"{bg.id} [{bg.name}] {state}, up {time.time() - bg.started:.0f}s: {bg.command}"


@tool
def background_process(
    action: str,
    command: Optional[str] = None,
    name: Optional[str] = None,
    process_id: Optional[str] = None,
    tail_lines: int = 60,
    cwd: str = ".",
) -> str:
    """Manage long-running processes such as dev servers or watchers.

    Actions: "start" (needs command), "read" (needs process_id; returns status and recent
    output), "stop" (needs process_id), "list". Use this instead of run_command for anything
    that does not exit on its own. Always stop processes you started when you are done.

    Args:
        action: One of start, read, stop, list.
        command: Shell command to launch (start only).
        name: Short label for the process (start only).
        process_id: Id returned by start, like "bg-1" (read and stop).
        tail_lines: How many recent output lines to return when reading.
        cwd: Working directory for start, relative to the workspace.
    """
    global _BG_COUNTER
    action = (action or "").strip().lower()
    if action == "list":
        return "\n".join(_status(bg) for bg in _BG.values()) or "No background processes."
    if action == "start":
        if not command:
            raise ValueError("start requires a command.")
        guard_command(command)
        if sum(1 for bg in _BG.values() if bg.proc.poll() is None) >= MAX_BACKGROUND:
            raise ValueError(f"At most {MAX_BACKGROUND} background processes can run at once. Stop one first.")
        work = resolve(cwd, must_exist=True)
        _BG_COUNTER += 1
        bg_id = f"bg-{_BG_COUNTER}"
        log = tempfile.NamedTemporaryFile(prefix=f"{bg_id}-", suffix=".log", delete=False)
        proc = subprocess.Popen(
            [_shell(), "-c", command],
            cwd=str(work),
            stdin=subprocess.DEVNULL,
            stdout=log,
            stderr=subprocess.STDOUT,
            env=scrubbed_env(),
            start_new_session=True,
        )
        log.close()
        _BG[bg_id] = _Background(bg_id, name or command.split()[0], command, proc, log.name)
        time.sleep(1.0)  # let it fail fast if it is going to
        return f"Started {_status(_BG[bg_id])}\n--- first output ---\n{_tail(log.name, 20) or '(none yet)'}"
    if action in {"read", "stop"}:
        bg = _BG.get(process_id or "")
        if bg is None:
            raise ValueError(f"Unknown process_id '{process_id}'. Use action=list to see running processes.")
        if action == "stop":
            if bg.proc.poll() is None:
                _kill_group(bg.proc)
            return f"Stopped. {_status(bg)}\n--- last output ---\n{_tail(bg.log_path, 20) or '(none)'}"
        lines = max(1, min(int(tail_lines), 300))
        return f"{_status(bg)}\n--- last {lines} lines ---\n{_tail(bg.log_path, lines) or '(no output yet)'}"
    raise ValueError("action must be one of: start, read, stop, list.")
