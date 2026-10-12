"""Append-only JSONL logging for every model call."""

import json
from datetime import datetime, timezone
from pathlib import Path

LOG_FILE = Path(__file__).resolve().parent.parent / "logs" / "calls.jsonl"

HEAD_LEN = 120


def _head(text, n=HEAD_LEN):
    """Return a single-line preview of text, capped at n chars."""
    if not text:
        return ""
    flat = " ".join(text.split())
    return flat if len(flat) <= n else flat[: n - 1] + "…"


def log_call(role, model, prompt_tokens, completion_tokens,
             latency_s, tok_per_s, prompt_text=None, reply_text=None,
             error=None):
    """Append one JSON line describing a model call."""
    LOG_FILE.parent.mkdir(parents=True, exist_ok=True)

    entry = {
        "ts": datetime.now(timezone.utc).isoformat(timespec="seconds"),
        "role": role,
        "model": model,
        "prompt_tokens": prompt_tokens,
        "completion_tokens": completion_tokens,
        "latency_s": round(latency_s, 3),
        "tok_per_s": round(tok_per_s, 2),
        "prompt_head": _head(prompt_text),
        "reply_head": _head(reply_text),
    }
    if error:
        entry["error"] = error

    with LOG_FILE.open("a", encoding="utf-8") as f:
        f.write(json.dumps(entry, ensure_ascii=False) + "\n")