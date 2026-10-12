"""Filesystem guardrails: path containment and safe file opening."""

import os
import stat
from pathlib import Path

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