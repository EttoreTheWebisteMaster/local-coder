"""Tests for path containment guardrails."""

import os
import tempfile
from pathlib import Path

import pytest

import subprocess

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


def test_require_git_repo_raises_outside_repo(tmp_path, monkeypatch):
    """Outside a git repo, require_git_repo raises."""
    monkeypatch.chdir(tmp_path)
    guard._root_cache = None
    with pytest.raises(guard.SecurityError, match="Not a git repository"):
        guard.require_git_repo()


def test_require_clean_git_raises_on_dirty(in_tmp_root):
    """Dirty working tree is rejected."""
    subprocess.run(["git", "init"], cwd=str(in_tmp_root), capture_output=True)
    subprocess.run(["git", "config", "user.email", "t@t"], cwd=str(in_tmp_root), capture_output=True)
    subprocess.run(["git", "config", "user.name", "t"], cwd=str(in_tmp_root), capture_output=True)
    (in_tmp_root / "a.txt").write_text("hi")
    subprocess.run(["git", "add", "."], cwd=str(in_tmp_root), capture_output=True)
    subprocess.run(["git", "commit", "-m", "init"], cwd=str(in_tmp_root), capture_output=True)
    (in_tmp_root / "a.txt").write_text("modified")
    with pytest.raises(guard.SecurityError, match="dirty"):
        guard.require_clean_git()


def test_check_command_blocks_rm_rf():
    ok, reason = guard.check_command("rm -rf /tmp/foo")
    assert not ok
    assert "rm -rf" in reason


def test_check_command_blocks_git_reset_hard():
    ok, reason = guard.check_command("git reset --hard HEAD~1")
    assert not ok
    assert "git reset --hard" in reason


def test_check_command_allows_safe():
    ok, reason = guard.check_command("ls -la")
    assert ok
    assert reason == "OK"


def test_verify_only_allowed_changed_ok(in_tmp_root):
    subprocess.run(["git", "init"], cwd=str(in_tmp_root), capture_output=True)
    subprocess.run(["git", "config", "user.email", "t@t"], cwd=str(in_tmp_root), capture_output=True)
    subprocess.run(["git", "config", "user.name", "t"], cwd=str(in_tmp_root), capture_output=True)
    (in_tmp_root / "a.txt").write_text("hi")
    subprocess.run(["git", "add", "."], cwd=str(in_tmp_root), capture_output=True)
    subprocess.run(["git", "commit", "-m", "init"], cwd=str(in_tmp_root), capture_output=True)
    (in_tmp_root / "a.txt").write_text("modified")
    changed = guard.verify_only_allowed_changed([in_tmp_root / "a.txt"])
    assert "a.txt" in changed


def test_verify_only_allowed_changed_rejects_extra(in_tmp_root):
    subprocess.run(["git", "init"], cwd=str(in_tmp_root), capture_output=True)
    subprocess.run(["git", "config", "user.email", "t@t"], cwd=str(in_tmp_root), capture_output=True)
    subprocess.run(["git", "config", "user.name", "t"], cwd=str(in_tmp_root), capture_output=True)
    (in_tmp_root / "a.txt").write_text("hi")
    (in_tmp_root / "b.txt").write_text("hi")
    subprocess.run(["git", "add", "."], cwd=str(in_tmp_root), capture_output=True)
    subprocess.run(["git", "commit", "-m", "init"], cwd=str(in_tmp_root), capture_output=True)
    (in_tmp_root / "a.txt").write_text("modified")
    (in_tmp_root / "b.txt").write_text("modified too")
    with pytest.raises(guard.SecurityError, match="Unexpected files"):
        guard.verify_only_allowed_changed([in_tmp_root / "a.txt"])


def test_estimate_tokens():
    assert guard.estimate_tokens("") == 0
    assert guard.estimate_tokens("a" * 400) == 100


def test_cap_tokens_allows_small():
    assert guard.cap_tokens("hello world") == 2


def test_cap_tokens_blocks_large():
    big = "a" * (7000 * 4)
    with pytest.raises(guard.SecurityError, match="too large"):
        guard.cap_tokens(big)


def test_cap_files_allows_small():
    assert guard.cap_files(["a", "b", "c"]) == ["a", "b", "c"]


def test_cap_files_blocks_many():
    with pytest.raises(guard.SecurityError, match="Too many files"):
        guard.cap_files([str(i) for i in range(20)])