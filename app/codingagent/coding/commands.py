"""Shell command analysis: hard-deny rules and risk classification.

`analyze()` returns one of:
  denied     - never allowed in any mode (sudo, pipe-to-shell, credential paths, ...)
  dangerous  - destructive or outward-facing; asks for approval even in `auto` mode
  other      - ordinary command; approval depends on the mode
  check      - tests / linters / builds; allowed without asking in `auto-edit`
  readonly   - cannot change anything; always allowed (outside plan mode restrictions)

This is a *guardrail*, not a sandbox: a shell can always be tricked. Use the deployed
AgentCore runtime (isolated microVM) or a container when running in `auto` mode.
"""

from __future__ import annotations

import os
import re
import shlex
from dataclasses import dataclass
from pathlib import Path
from typing import List, Optional, Tuple

from .safety import PolicyError, is_sensitive, resolve


@dataclass(frozen=True)
class CommandInfo:
    kind: str  # denied | dangerous | other | check | readonly
    reason: str = ""
    signature: str = ""  # stable key for "always allow this kind of command"
    sensitive: bool = False  # touches a credentials-style file


# ------------------------------------------------------------------ hard-deny rules
_HARD_DENY = [
    (r"(^|[\s;&|(`])(sudo|su|doas)(\s|$)", "privilege escalation (sudo/su/doas) is not allowed"),
    (r"\bmkfs(\.\w+)?\b", "formatting filesystems is not allowed"),
    (r"\bdd\b[^;&|]*\bof=/dev/", "writing to raw devices is not allowed"),
    (r":\(\)\s*\{", "fork bombs are not allowed"),
    (r">\s*/dev/(sd|nvme|disk|hd)", "writing to raw devices is not allowed"),
    (r"(^|[\s;&|(`])(shutdown|reboot|poweroff|halt)(\s|$)", "shutting down the machine is not allowed"),
    (
        r"\b(curl|wget|fetch)\b[^;&]*\|\s*(sudo\s+)?(sh|bash|zsh|dash|ksh|python3?|perl|ruby|node)\b",
        "piping downloaded content into an interpreter is not allowed. Download, inspect, then run.",
    ),
    (r"\bbase64\s+(-d|--decode)\b[^;&]*\|\s*(sh|bash|zsh)\b", "decoding payloads into a shell is not allowed"),
    (r"\b(sh|bash|zsh)\s+<\(\s*(curl|wget)", "running remote scripts via process substitution is not allowed"),
    (r"\beval\s+[\"']?\$\(\s*(curl|wget)", "eval of remote content is not allowed"),
    (
        r"169\.254\.169\.254|169\.254\.170\.2|metadata\.google\.internal|fd00:ec2::254",
        "access to cloud metadata / credential endpoints is not allowed",
    ),
    (
        r"(~|\$HOME|\$\{HOME\}|/Users/[^/\s]+|/home/[^/\s]+|/root)/\.(ssh|aws|gnupg|kube|config/gcloud|azure)\b",
        "reading credential folders (~/.ssh, ~/.aws, ...) is not allowed",
    ),
    (r"/etc/(shadow|sudoers)", "reading system credential files is not allowed"),
    (r"/proc/[^\s/]*/environ", "reading process environments is not allowed"),
    (
        r"(>|>>|\btee\b[^|;&]*)\s*/(etc|usr|bin|sbin|boot|sys|proc|lib|var/lib)\b",
        "writing to system directories is not allowed",
    ),
    (r"\bchmod\b[^;&|]*\s-R\b[^;&|]*\s/(\s|$)", "recursive permission changes on / are not allowed"),
]
_HARD_DENY_RE = [(re.compile(pattern), message) for pattern, message in _HARD_DENY]
_RM_BAD_TARGETS = {"/", "/*", "~", "~/", "$HOME", "${HOME}", "/.", "..", "../"}


def hard_deny(command: str) -> Optional[str]:
    for pattern, message in _HARD_DENY_RE:
        if pattern.search(command):
            return message
    return None


def guard_command(command: str) -> None:
    """Raise PolicyError for commands that must never run, whatever the mode."""
    if not command or not command.strip():
        raise ValueError("The command is empty.")
    if len(command) > 20_000:
        raise ValueError("The command is too long. Put long scripts in a file and run that.")
    reason = hard_deny(command)
    if reason:
        raise PolicyError(f"Command blocked: {reason}.")
    info = analyze(command)
    if info.kind == "denied":
        raise PolicyError(f"Command blocked: {info.reason}.")


# ------------------------------------------------------------------ tokenising
_OPERATORS = {";", "&&", "||", "|", "&", "|&", ";;"}
_REDIRECTS = {">", ">>", ">&", ">|", "&>", "<", "<<", "<&", "<<<"}
_ASSIGNMENT = re.compile(r"^[A-Za-z_][A-Za-z0-9_]*=")


def _tokenize(command: str) -> Optional[List[str]]:
    try:
        lexer = shlex.shlex(command, posix=True, punctuation_chars=True)
        lexer.whitespace_split = True
        return list(lexer)
    except ValueError:
        return None


def _split_segments(tokens: List[str]) -> Tuple[List[List[str]], bool, bool]:
    """Split on operators; returns (segments, writes_via_redirect, is_complex)."""
    segments: List[List[str]] = [[]]
    writes = False
    complex_ = False
    i = 0
    while i < len(tokens):
        tok = tokens[i]
        if tok in _OPERATORS:
            segments.append([])
        elif tok in ("(", ")", "{", "}"):
            complex_ = True
        elif tok in _REDIRECTS:
            target = tokens[i + 1] if i + 1 < len(tokens) else ""
            if tok in ("<<", "<<<"):
                complex_ = True
            elif tok.startswith(">") or tok == "&>":
                harmless = target == "/dev/null" or (tok == ">&" and (target.isdigit() or target == "-"))
                if not harmless:
                    writes = True
            i += 1  # skip the redirect target
        else:
            segments[-1].append(tok)
        i += 1
    return [s for s in segments if s], writes, complex_


# ------------------------------------------------------------------ program tables
_READONLY = {
    "ls", "cat", "head", "tail", "wc", "pwd", "echo", "printf", "which", "whoami", "date", "uname",
    "id", "hostname", "tree", "stat", "file", "du", "df", "sort", "uniq", "diff", "cmp", "cut", "tr",
    "nl", "basename", "dirname", "realpath", "readlink", "true", "false", "test", "[", "grep",
    "egrep", "fgrep", "rg", "jq", "cd", "sleep", "seq", "expr", "column", "fold", "tac", "rev",
    "md5sum", "sha1sum", "sha256sum", "shasum", "cksum", "type", "nproc", "uptime", "ps", "free",
}
_FIND_WRITERS = {"-exec", "-execdir", "-ok", "-okdir", "-delete", "-fprint", "-fprint0", "-fprintf", "-fls"}
_VERSION_FLAGS = {"--version", "-V", "-v", "--help", "-h", "version"}

_DANGEROUS_PROGS = {
    "chmod", "chown", "chgrp", "kill", "pkill", "killall", "ssh", "scp", "sftp", "rsync", "nc", "ncat",
    "telnet", "docker", "podman", "kubectl", "helm", "terraform", "tofu", "aws", "gcloud", "az", "dd",
    "mount", "umount", "systemctl", "service", "crontab", "launchctl", "eval", "unlink", "rmdir",
    "shred", "truncate",
}
_NET_WRITE_FLAGS = {
    "-X", "--request", "-d", "--data", "--data-raw", "--data-binary", "--data-urlencode", "-F",
    "--form", "-T", "--upload-file", "--json", "-u", "--user",
}

_CHECK_PROGS = {
    "pytest", "py.test", "ruff", "flake8", "pylint", "mypy", "pyright", "black", "isort", "pyflakes",
    "bandit", "prettier", "eslint", "tsc", "jest", "vitest", "mocha", "rubocop", "shellcheck", "hadolint",
}
_CHECK_PY_MODULES = {
    "pytest", "unittest", "mypy", "ruff", "black", "flake8", "pyflakes", "isort", "compileall",
    "py_compile", "pylint", "doctest", "pyright",
}
_CHECK_SCRIPTS = {
    "test", "tests", "lint", "build", "typecheck", "type-check", "check", "format", "fmt", "tsc", "unit",
}
_GO_CHECK = {"test", "vet", "build", "fmt", "list", "version"}
_CARGO_CHECK = {"test", "check", "build", "clippy", "fmt", "doc"}
_MAVEN_GOALS = {"test", "verify", "compile", "package", "clean"}
_GRADLE_TASKS = {"test", "build", "check", "assemble", "clean"}
_MAKE_TARGETS = {"test", "tests", "check", "lint", "build", "all", "format", "fmt", "typecheck"}
_RUNNER_PREFIXES = {"uv", "poetry", "pdm", "hatch", "pipenv"}

_GIT_READONLY = {
    "status", "diff", "log", "show", "rev-parse", "ls-files", "blame", "describe", "shortlog", "ls-tree",
    "cat-file", "diff-tree", "merge-base", "name-rev", "for-each-ref", "rev-list", "grep",
    "check-ignore", "count-objects", "whatchanged", "reflog",
}
_GIT_BRANCH_READ_FLAGS = {"-a", "-r", "-v", "-vv", "--list", "--show-current", "--merged", "--no-merged", "-l", "--all"}


def _flags(args: List[str]) -> List[str]:
    return [a for a in args if a.startswith("-")]


def _classify_git(args: List[str]) -> Tuple[str, str, str]:
    rest = list(args)
    while rest and rest[0].startswith("-"):
        rest = rest[2:] if rest[0] in {"-C", "-c", "--git-dir", "--work-tree", "--namespace"} else rest[1:]
    if not rest:
        return "readonly", "", "git"
    sub, tail = rest[0], rest[1:]
    sig = f"git {sub}"
    if sub in _GIT_READONLY:
        if any(a.startswith("--output") for a in tail):
            return "other", "", sig
        return "readonly", "", sig
    if sub == "branch":
        if all(a in _GIT_BRANCH_READ_FLAGS for a in tail):
            return "readonly", "", sig
        if any(a in {"-d", "-D", "--delete"} for a in tail):
            return "dangerous", "deletes a branch", sig
        return "other", "", sig
    if sub == "remote":
        return ("readonly", "", sig) if tail in ([], ["-v"]) else ("other", "", sig)
    if sub == "tag":
        return ("readonly", "", sig) if all(a in {"-l", "--list"} for a in tail) else ("other", "", sig)
    if sub == "stash":
        action = tail[0] if tail else "push"
        if action in {"list", "show"}:
            return "readonly", "", sig
        if action in {"drop", "clear"}:
            return "dangerous", "discards stashed work", sig
        return "other", "", sig
    if sub == "config":
        if any(a in {"--get", "--get-all", "--list", "-l"} for a in tail):
            return "readonly", "", sig
        return "other", "", sig
    if sub == "push":
        return "dangerous", "publishes commits to a remote", sig
    if sub in {"clean", "rebase", "filter-branch", "filter-repo"}:
        return "dangerous", f"git {sub} rewrites or deletes work", sig
    if sub == "reset" and any(a in {"--hard", "--merge", "--keep"} for a in tail):
        return "dangerous", "git reset --hard discards work", sig
    if sub == "restore" and "--staged" not in tail:
        return "dangerous", "git restore discards uncommitted changes", sig
    if sub == "checkout" and ("--" in tail or "." in tail):
        return "dangerous", "git checkout -- discards uncommitted changes", sig
    return "other", "", sig


def _classify_segment(words: List[str]) -> Tuple[str, str, str]:
    """Return (kind, reason, signature) for one simple command."""
    if _ASSIGNMENT.match(words[0]):
        return "other", "sets environment variables", "env-assign"
    prog = os.path.basename(words[0])
    args = words[1:]

    # peel simple wrappers and package-runner prefixes (uv run pytest ...)
    while prog in {"time", "nohup", "command", "exec"} and args and not args[0].startswith("-"):
        prog, args = os.path.basename(args[0]), args[1:]
    if prog in _RUNNER_PREFIXES and args and args[0] == "run":
        rest = [a for a in args[1:]]
        while rest and rest[0].startswith("-"):
            rest = rest[1:]
        if rest:
            prog, args = os.path.basename(rest[0]), rest[1:]

    sig = f"{prog} {args[0]}" if args and not args[0].startswith("-") else prog

    if prog == "cd":
        return "readonly", "", "cd"
    if prog == "rm":
        if "--no-preserve-root" in args or any(a in _RM_BAD_TARGETS for a in args):
            return "denied", "deleting the filesystem root, home or parent directories is not allowed", "rm"
        return "dangerous", "deletes files (prefer delete_path, which can be undone)", "rm"
    if prog in _DANGEROUS_PROGS:
        return "dangerous", f"'{prog}' can change systems outside the workspace", prog
    if prog in {"curl", "wget", "http", "https"}:
        if any(a in _NET_WRITE_FLAGS or a.startswith("--data") for a in args):
            return "dangerous", "sends data to a remote server", prog
        return "other", "network request", prog
    if prog == "git":
        return _classify_git(args)
    if prog == "find":
        if any(a in _FIND_WRITERS for a in args):
            return "other", "find with -exec/-delete", "find-exec"
        return "readonly", "", "find"
    if prog == "sed":
        if any(a.startswith("-i") or a == "--in-place" for a in args):
            return "other", "sed -i edits files", "sed -i"
        return "readonly", "", "sed"
    if prog == "sort" and any(a == "-o" or a.startswith("--output") for a in args):
        return "other", "sort -o writes a file", "sort -o"
    if prog in _READONLY:
        return "readonly", "", prog
    if args and all(a in _VERSION_FLAGS for a in args):
        return "readonly", "", f"{prog} --version"

    if prog in {"python", "python3", "py"} and len(args) >= 2 and args[0] == "-m":
        module = args[1].split(".")[0]
        if module in _CHECK_PY_MODULES:
            return "check", "", f"python -m {module}"
        return "other", "", f"python -m {module}"
    if prog in _CHECK_PROGS:
        return "check", "", prog
    sub = args[0] if args else ""
    if prog == "go" and sub in _GO_CHECK:
        return "check", "", f"go {sub}"
    if prog == "cargo" and sub in _CARGO_CHECK:
        return "check", "", f"cargo {sub}"
    if prog in {"npm", "pnpm", "yarn", "bun"}:
        script = args[1] if sub in {"run", "run-script"} and len(args) > 1 else sub
        if script in _CHECK_SCRIPTS:
            return "check", "", f"{prog} {script}"
        return "other", "", f"{prog} {sub}".strip()
    if prog in {"mvn", "mvnw"}:
        goals = [a for a in args if not a.startswith("-")]
        if goals and all(g in _MAVEN_GOALS for g in goals):
            return "check", "", f"{prog} {' '.join(goals)}"
        return "other", "", prog
    if prog in {"gradle", "gradlew"}:
        tasks = [a for a in args if not a.startswith("-")]
        if tasks and all(t in _GRADLE_TASKS for t in tasks):
            return "check", "", f"{prog} {' '.join(tasks)}"
        return "other", "", prog
    if prog in {"make", "just", "task"}:
        targets = [a for a in args if not a.startswith("-")]
        if targets and all(t in _MAKE_TARGETS for t in targets):
            return "check", "", f"{prog} {' '.join(targets)}"
        return "other", "", prog
    return "other", "", sig


def _path_args_outside(words: List[str]) -> Optional[str]:
    """For read-only programs: any path argument that points outside the workspace."""
    for arg in words[1:]:
        if arg.startswith("-") or arg == "/dev/null":
            continue
        if arg.startswith(("/", "~")) or ".." in Path(arg).parts:
            try:
                resolve(arg)
            except PolicyError:
                return arg
    return None


_RANK = {"readonly": 0, "check": 1, "other": 2, "dangerous": 3, "denied": 4}


def analyze(command: str) -> CommandInfo:
    reason = hard_deny(command)
    if reason:
        return CommandInfo("denied", reason)
    if "\n" in command or "$(" in command or "`" in command or "<(" in command:
        # command substitution / multi-line scripts cannot be reasoned about safely
        return CommandInfo("other", "uses command substitution or multiple lines", "complex", False)
    tokens = _tokenize(command)
    if tokens is None:
        return CommandInfo("other", "could not be parsed", "unparsed")
    segments, writes, complex_ = _split_segments(tokens)
    if not segments:
        return CommandInfo("other", "empty command", "empty")

    worst = "readonly"
    worst_reason = ""
    signature = ""
    sensitive = False
    for words in segments:
        kind, why, sig = _classify_segment(words)
        if kind == "readonly":
            outside = _path_args_outside(words)
            if outside:
                kind, why = "other", f"reads '{outside}' outside the workspace"
        if kind == "readonly" and any(is_sensitive(a) for a in words[1:] if not a.startswith("-")):
            sensitive = True
        if _RANK[kind] > _RANK[worst]:
            worst, worst_reason, signature = kind, why, sig
        elif not signature:
            signature = sig
    if (writes or complex_) and _RANK[worst] < _RANK["other"]:
        worst = "other"
        worst_reason = "redirects output to a file" if writes else "uses a subshell or heredoc"
    return CommandInfo(worst, worst_reason, signature or "command", sensitive)
