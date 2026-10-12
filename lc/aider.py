"""Safe invocation of Aider as a subprocess."""

import subprocess
import time
from pathlib import Path

from . import guard

AIDER_MODEL = "lm_studio/qwen2.5-coder-3b-instruct-mlx"


def build_aider_command(files, message):
    """Build the Aider command line with safety flags.

    Disables all features that could execute shell commands or make
    commits without user review.
    """
    cmd = [
        "python", "-m", "aider",
        "--model", AIDER_MODEL,
        "--no-auto-commits",
        "--no-dirty-commits",
        "--no-auto-lint",
        "--no-auto-test",
        "--no-gitignore",
        "--yes",
        "--message", message,
    ]
    cmd.extend(str(f) for f in files)
    return cmd


def run_aider(files, message):
    """Run Aider on the given files with a message.

    Pre-conditions (checked before running):
      - must be a git repo
      - working tree must be clean

    Post-conditions (checked after running):
      - only the listed files may have been modified

    Returns (stdout, stderr, elapsed_s).
    """
    guard.require_git_repo()
    guard.require_clean_git()

    # Verify all target files are inside the project root.
    resolved = [guard.ensure_writable(f) for f in files]

    cmd = build_aider_command(resolved, message)
    start = time.monotonic()
    result = subprocess.run(
        cmd,
        cwd=str(guard.project_root()),
        capture_output=True, text=True,
    )
    elapsed = time.monotonic() - start

    # Post-condition: only allowed files changed.
    guard.verify_only_allowed_changed(resolved)

    if result.returncode != 0:
        raise RuntimeError(
            f"Aider exited with code {result.returncode}.\n"
            f"stderr: {result.stderr[-500:]}"
        )

    return result.stdout, result.stderr, elapsed