"""Filesystem guardrails: path containment and safe file opening."""

import os
import stat
from pathlib import Path

import re
import subprocess

# Directories that must never be written to, even inside the root.
PROTECTED_DIRS = {".git", ".venv", "node_modules", ".mypy_cache", ".pytest_cache"}


class SecurityError(Exception):
    """Raised when an operation would escape the project root."""


_root_cache = None


def project_root():
    """Return the absolute, symlink-resolved working directory at launch.

    Cached after the first call. All file operations must stay inside this.
    """
    global _root_cache
    if _root_cache is None:
        _root_cache = Path(os.path.realpath(os.getcwd()))
    return _root_cache


def tool_install_dir():
    """Directory containing the lc package itself.

    This is where the guardrails live. Writes here are always refused,
    so a runaway model cannot disable its own security by rewriting
    guard.py, config.toml, or pyproject.toml.
    """
    return Path(__file__).resolve().parent.parent


def _reject_bad_input(path_str):
    """Reject empty paths and NUL bytes before any filesystem call."""
    if not path_str or not path_str.strip():
        raise SecurityError("Empty path not allowed")
    if "\x00" in path_str:
        raise SecurityError("NUL byte in path not allowed")
    if len(path_str) > 4096:
        raise SecurityError("Path too long")


def ensure_inside(path):
    """Resolve path and verify it stays inside the project root.

    Returns the resolved absolute Path. Raises SecurityError otherwise.
    Anchors relative paths to the root before resolving, so symlinks
    and .. traversal are both caught.
    """
    if isinstance(path, Path):
        path_str = str(path)
    else:
        path_str = path
    _reject_bad_input(path_str)

    root = project_root()
    candidate = Path(path_str)

    # Anchor first: only join if the path is relative.
    if candidate.is_absolute():
        anchored = candidate
    else:
        anchored = root / candidate

    # realpath follows symlinks; this is the single source of truth.
    try:
        resolved = Path(os.path.realpath(anchored))
    except OSError as e:
        raise SecurityError(f"Cannot resolve path {path_str!r}: {e}") from e

    # commonpath does lexical-safe comparison (no /home/user vs /home/user2 bug).
    try:
        common = os.path.commonpath([str(root), str(resolved)])
    except ValueError as e:
        raise SecurityError(f"Path {path_str!r} is not inside project root") from e

    if common != str(root):
        raise SecurityError(
            f"Path {resolved} escapes project root {root}"
        )

    return resolved


def ensure_writable(path):
    """Like ensure_inside, plus checks the path is not in a protected dir.

    Two layers of protection:
    1. Never write inside the tool's own installation directory.
       This is unconditional: no environment variable can disable it.
    2. Never write inside PROTECTED_DIRS anywhere in the project.
    """
    resolved = ensure_inside(path)
    root = project_root()

    # Layer 1: tool install dir is off-limits, always.
    tool_dir = tool_install_dir()
    if resolved == tool_dir or tool_dir in resolved.parents:
        raise SecurityError(
            f"Refusing to write inside the tool's installation directory "
            f"({tool_dir}). Use your editor to change the tool's own code."
        )

    # Layer 2: protected dirs anywhere inside the project.
    rel = resolved.relative_to(root)
    for part in rel.parts:
        if part in PROTECTED_DIRS:
            raise SecurityError(
                f"Refusing to write inside protected directory {part!r}"
            )
    return resolved


def safe_write(path, data, encoding="utf-8"):
    """Write bytes or text to path with O_NOFOLLOW and post-open verification.

    Creates parent directories if missing, but only inside the root.
    Returns the resolved Path that was written.
    """
    resolved = ensure_writable(path)
    resolved.parent.mkdir(parents=True, exist_ok=True)

    if isinstance(data, str):
        payload = data.encode(encoding)
    else:
        payload = data

    flags = os.O_WRONLY | os.O_CREAT | os.O_TRUNC
    if hasattr(os, "O_NOFOLLOW"):
        flags |= os.O_NOFOLLOW

    try:
        fd = os.open(str(resolved), flags, 0o644)
    except OSError as e:
        raise SecurityError(f"Cannot open {resolved} for writing: {e}") from e

    try:
        # Post-open verification: is the fd pointing at the file we resolved?
        st_fd = os.fstat(fd)
        st_path = os.lstat(str(resolved))
        if (st_fd.st_dev, st_fd.st_ino) != (st_path.st_dev, st_path.st_ino):
            raise SecurityError(
                f"File swapped between check and open: {resolved}"
            )
        os.write(fd, payload)
    finally:
        os.close(fd)

    return resolved


# Commands that must never run, regardless of context.
BLOCKED_PATTERNS = [
    (r'\brm\s+-rf\b', "rm -rf"),
    (r'\bmkfs\b', "mkfs"),
    (r'\bdd\s+if=', "dd"),
    (r'\bshred\b', "shred"),
    (r'\breboot\b', "reboot"),
    (r'\bshutdown\b', "shutdown"),
    (r'\binit\s+[06]\b', "init 0/6"),
    (r'\biptables\s+-F\b', "iptables flush"),
    (r'\bsystemctl\s+(stop|disable)\s', "systemctl stop/disable"),
    (r':\(\)\s*\{\s*:\|:\s*&\s*\}\s*;', "fork bomb"),
    (r'\bchmod\s+-R\s+777\s+/', "chmod 777 /"),
    (r'\b>\s*/dev/sd[a-z]', "write to block device"),
    (r'\bwget\b.*\|\s*sh', "pipe wget to shell"),
    (r'\bcurl\b.*\|\s*sh', "pipe curl to shell"),
    (r'\bgit\s+reset\s+--hard\b', "git reset --hard"),
    (r'\bgit\s+push\s+--force\b', "git push --force"),
    (r'\bgit\s+clean\s+-fd\b', "git clean -fd"),
    (r'\bgit\s+checkout\s+--\s+\.', "git checkout -- ."),
]


def require_git_repo():
    """Raise SecurityError if cwd is not inside a git repository."""
    result = subprocess.run(
        ["git", "rev-parse", "--git-dir"],
        cwd=str(project_root()),
        capture_output=True, text=True,
    )
    if result.returncode != 0:
        raise SecurityError(
            f"Not a git repository: {project_root()}. "
            "Git is required for rollback safety."
        )


def require_clean_git():
    """Raise SecurityError if the working tree has uncommitted changes.

    This ensures that if the model makes a mess, git checkout can restore
    the previous state. Call this before any command that writes files.
    """
    require_git_repo()
    result = subprocess.run(
        ["git", "status", "--porcelain"],
        cwd=str(project_root()),
        capture_output=True, text=True,
    )
    if result.returncode != 0:
        raise SecurityError(f"git status failed: {result.stderr.strip()}")
    if result.stdout.strip():
        dirty = result.stdout.strip().splitlines()
        raise SecurityError(
            f"Working tree is dirty ({len(dirty)} file(s)). "
            "Commit or stash your changes before running this command.\n"
            + "\n".join(dirty[:10])
        )


def check_command(cmd):
    """Check a shell command string against destructive patterns.

    Returns (ok, reason). Does not execute anything.
    """
    for pattern, name in BLOCKED_PATTERNS:
        if re.search(pattern, cmd, re.IGNORECASE):
            return False, f"BLOCKED: destructive command ({name})"
    return True, "OK"


def verify_only_allowed_changed(allowed_paths):
    """After an edit, verify that only the allowed files were modified.

    Uses git status --porcelain to list changed files, then compares
    against the allowed set. Raises SecurityError if anything else changed.
    Returns the list of changed files on success.
    """
    require_git_repo()
    result = subprocess.run(
        ["git", "status", "--porcelain", "-z"],
        cwd=str(project_root()),
        capture_output=True, text=True,
    )
    if result.returncode != 0:
        raise SecurityError(f"git status failed: {result.stderr.strip()}")

    # With -z, entries are NUL-separated and paths are never quoted.
    # Format: "XY <path>\0" or for renames "XY <new>\0<old>\0".
    changed = []
    entries = result.stdout.split("\x00")
    i = 0
    while i < len(entries):
        entry = entries[i]
        if not entry:
            i += 1
            continue
        status = entry[:2]
        path = entry[3:]
        # Renames have the new path in this entry and the old path next.
        if status[0] in ("R", "C"):
            i += 1  # skip the old path entry
        changed.append(path)
        i += 1

    root = project_root()
    allowed_resolved = {str(ensure_inside(p)) for p in allowed_paths}
    unexpected = []
    for c in changed:
        # git reports paths relative to the repo root.
        try:
            resolved = str(ensure_inside(root / c))
        except SecurityError:
            unexpected.append(c)
            continue
        if resolved not in allowed_resolved:
            unexpected.append(c)

    if unexpected:
        raise SecurityError(
            "Unexpected files changed outside the allowed set:\n"
            + "\n".join(unexpected)
        )
    return changed


# Approximate token estimation: 1 token ≈ 4 characters for English/code.
CHARS_PER_TOKEN = 4
DEFAULT_TOKEN_LIMIT = 6000
DEFAULT_FILE_LIMIT = 10


def estimate_tokens(text):
    """Rough estimate of token count from character count."""
    if not text:
        return 0
    return len(text) // CHARS_PER_TOKEN


def cap_tokens(text, limit=DEFAULT_TOKEN_LIMIT, label="input"):
    """Raise SecurityError if estimated tokens exceed the limit.

    Returns the estimated token count on success.
    """
    n = estimate_tokens(text)
    if n > limit:
        raise SecurityError(
            f"{label} is too large: ~{n} tokens (limit: {limit}). "
            f"Reduce the input and try again."
        )
    return n


def cap_files(files, limit=DEFAULT_FILE_LIMIT):
    """Raise SecurityError if too many files are passed at once."""
    if len(files) > limit:
        raise SecurityError(
            f"Too many files: {len(files)} (limit: {limit}). "
            f"Split into smaller batches."
        )
    return files