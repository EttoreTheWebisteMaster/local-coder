"""Tests for path containment guardrails."""

import os
import tempfile
from pathlib import Path

import pytest

from lc import guard


@pytest.fixture(autouse=True)
def in_tmp_root(monkeypatch):
    """Run each test inside a fresh temp directory as project root."""
    with tempfile.TemporaryDirectory() as td:
        monkeypatch.chdir(td)
        guard._root_cache = None
        yield Path(td)


def test_relative_path_inside():
    p = guard.ensure_inside("src/app.py")
    assert str(p).startswith(str(guard.project_root()))


def test_dotdot_escape_blocked():
    with pytest.raises(guard.SecurityError):
        guard.ensure_inside("../outside.txt")


def test_absolute_outside_blocked():
    with pytest.raises(guard.SecurityError):
        guard.ensure_inside("/etc/passwd")


def test_nul_byte_blocked():
    with pytest.raises(guard.SecurityError):
        guard.ensure_inside("file\x00.txt")


def test_empty_blocked():
    with pytest.raises(guard.SecurityError):
        guard.ensure_inside("")


def test_symlink_escape_blocked(tmp_path, in_tmp_root):
    outside = tmp_path.parent / "secret.txt"
    outside.write_text("secret")
    link = in_tmp_root / "link.txt"
    os.symlink(outside, link)
    with pytest.raises(guard.SecurityError):
        guard.ensure_inside("link.txt")


def test_protected_dir_blocked():
    with pytest.raises(guard.SecurityError):
        guard.ensure_writable(".git/config")
    with pytest.raises(guard.SecurityError):
        guard.ensure_writable(".venv/pyvenv.cfg")


def test_safe_write_creates_file(in_tmp_root):
    p = guard.safe_write("notes.txt", "hello")
    assert p.read_text() == "hello"
    assert p.parent == in_tmp_root.resolve()


def test_safe_write_refuses_symlink(tmp_path, in_tmp_root):
    outside = tmp_path.parent / "target.txt"
    outside.write_text("original")
    link = in_tmp_root / "sneaky.txt"
    os.symlink(outside, link)
    with pytest.raises(guard.SecurityError):
        guard.safe_write("sneaky.txt", "pwned")
    assert outside.read_text() == "original"


def test_tool_dir_write_blocked(monkeypatch):
    """Writes inside the tool's install dir are refused by layer 1."""
    monkeypatch.chdir(guard.tool_install_dir())
    guard._root_cache = None
    with pytest.raises(guard.SecurityError, match="installation directory"):
        guard.ensure_writable("lc/guard.py")


def test_tool_config_write_blocked(monkeypatch):
    """Writes to config.toml are refused by layer 1."""
    monkeypatch.chdir(guard.tool_install_dir())
    guard._root_cache = None
    with pytest.raises(guard.SecurityError, match="installation directory"):
        guard.ensure_writable("config.toml")


def test_tool_pyproject_write_blocked(monkeypatch):
    """Writes to pyproject.toml are refused by layer 1."""
    monkeypatch.chdir(guard.tool_install_dir())
    guard._root_cache = None
    with pytest.raises(guard.SecurityError, match="installation directory"):
        guard.ensure_writable("pyproject.toml")


def test_tool_dir_outside_root_also_blocked(in_tmp_root):
    """When cwd is elsewhere, the tool dir is blocked by ensure_inside."""
    tool_file = guard.tool_install_dir() / "lc" / "guard.py"
    with pytest.raises(guard.SecurityError):
        guard.ensure_writable(tool_file)