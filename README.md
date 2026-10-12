# Local AI Coding Assistant on 8 GB Mac

A minimal local AI coding setup for an 8 GB Apple Silicon Mac. One small model, one editor, one router. No cloud, no swap thrashing.

## Hardware constraint

8 GB unified memory. Running two models side by side (or swapping between them) causes memory pressure to go red and swap to spike to 3.5 GB. Only one model may be loaded at a time. The project is built around this limit.

## Stack

| Component | Choice | Notes |
|---|---|---|
| Runtime | LM Studio Bionic | Local API server on port 1235 |
| Model | qwen2.5-coder-3b-instruct-mlx | MLX 4-bit, ~20 tok/s, ~2.1 GB |
| Editor | Aider | Drives file edits through git |
| Router | Python CLI (to be built) | Wraps Aider + LM Studio API |

## Setup

### 1. LM Studio Bionic

1. Install LM Studio Bionic.
2. Download lmstudio-community/Qwen2.5-Coder-3B-Instruct-MLX-4bit from Hugging Face inside the app.
3. Settings -> Local Model API -> enable Enable Local API Server (and Enable CORS).
4. Server listens on http://localhost:1235.

### 2. Environment variables

Add to ~/.zshrc:

    export LM_STUDIO_API_BASE=http://localhost:1235/v1
    export LM_STUDIO_API_KEY=dummy-api-key

Then run: source ~/.zshrc

### 3. Aider

    python3 -m pip install -U aider-chat

Run from a git project directory:

    cd ~/your-project
    python -m aider --model lm_studio/qwen2.5-coder-3b-instruct-mlx

## Key facts

- Model IDs are lowercase and case-sensitive: qwen2.5-coder-3b-instruct-mlx.
- Aider provider prefix uses an underscore: lm_studio/, not lm-studio/.
- LM_STUDIO_API_KEY must be set to any non-empty string; LM Studio rejects empty Bearer tokens.
- aider is not added to PATH by pip. Use python -m aider.
- Context length is auto-fitted by Bionic and may be lower than requested. Accept it.

## Model roster

| Role | Model |
|---|---|
| Planner / editor / tiny tasks | qwen2.5-coder-3b-instruct-mlx |

A single model covers all roles. Multi-model routing was ruled out by the 8 GB limit.

## Roadmap

v1.0 — Python CLI router with commands:

- plan — write a plan to PLAN.md
- explain — explain a file or function
- edit — run Aider on selected files
- fix — diagnose a traceback, then edit
- commit — generate a commit message from the staged diff
- bench — rerun the three-task benchmark
- status — check the server is reachable

Includes config.toml and JSONL logging of every call (role, model, tokens, latency, tok/s).

Out of scope: LLM-based classifier, reviewer agents, autocomplete, Xcode integration.
