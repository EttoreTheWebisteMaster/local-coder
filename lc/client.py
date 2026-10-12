"""Minimal HTTP client for the LM Studio local API."""

import time
from dataclasses import dataclass

import httpx

from . import config
from . import logging as lc_logging


@dataclass
class Response:
    text: str
    prompt_tokens: int
    completion_tokens: int
    latency_s: float

    @property
    def tok_per_s(self) -> float:
        if self.latency_s <= 0:
            return 0.0
        return self.completion_tokens / self.latency_s


def chat(messages, max_tokens=None, role="unknown"):
    """Send a chat completion request and return a Response.

    Every call is logged to logs/calls.jsonl with the given role.
    """
    cfg = config.load()
    server = cfg["server"]
    model = cfg["model"]

    if max_tokens is None:
        max_tokens = model.get("max_tokens", 1024)

    url = server["base_url"].rstrip("/") + "/chat/completions"
    headers = {
        "Authorization": f"Bearer {server['api_key']}",
        "Content-Type": "application/json",
    }
    payload = {
        "model": model["name"],
        "messages": messages,
        "max_tokens": max_tokens,
        "temperature": 0.2,
    }

    start = time.monotonic()
    try:
        r = httpx.post(url, json=payload, headers=headers,
                       timeout=server.get("timeout", 120))
        r.raise_for_status()
    except httpx.HTTPError as e:
        latency = time.monotonic() - start
        lc_logging.log_call(
            role=role,
            model=model["name"],
            prompt_tokens=0,
            completion_tokens=0,
            latency_s=latency,
            tok_per_s=0.0,
            prompt_text=messages[-1].get("content", "") if messages else "",
            error=str(e),
        )
        raise RuntimeError(f"LM Studio request failed: {e}") from e
    latency = time.monotonic() - start

    data = r.json()
    choice = data["choices"][0]["message"]
    usage = data.get("usage", {})

    resp = Response(
        text=choice.get("content", ""),
        prompt_tokens=usage.get("prompt_tokens", 0),
        completion_tokens=usage.get("completion_tokens", 0),
        latency_s=latency,
    )

    lc_logging.log_call(
        role=role,
        model=model["name"],
        prompt_tokens=resp.prompt_tokens,
        completion_tokens=resp.completion_tokens,
        latency_s=resp.latency_s,
        tok_per_s=resp.tok_per_s,
        prompt_text=messages[-1].get("content", "") if messages else "",
        reply_text=resp.text,
    )

    return resp