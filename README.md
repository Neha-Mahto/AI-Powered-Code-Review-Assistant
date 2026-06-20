# 🤖 CodeReview AI

**FAANG-level automated code review combining AST static analysis with a free LLM (Llama 3.3 70B via Groq).**

CodeReview AI catches security vulnerabilities, performance issues, and style problems in your code — then layers an LLM-powered review on top for deeper architectural and logic feedback. Use it as a web app, a CLI tool, or a GitHub Actions bot that comments on your PRs automatically. **No paid API required** — runs entirely on Groq's free tier.

![Python](https://img.shields.io/badge/python-3.10%2B-blue)
![FastAPI](https://img.shields.io/badge/FastAPI-009688)
![License](https://img.shields.io/badge/license-MIT-green)
![Tests](https://github.com/YOUR_USERNAME/ai-code-reviewer/actions/workflows/tests.yml/badge.svg)

---

## ✨ Features

- 🔍 **Two-stage analysis**: a custom Python AST static analyzer catches 16+ issue types instantly (no API call needed), then an LLM reviews the code for deeper logic, architecture, and naming issues
- 🆓 **Completely free to run** — uses Groq's free tier (Llama 3.3 70B), no credit card required anywhere
- 🛡️ **Security-first**: detects hardcoded secrets, SQL injection, shell injection, and unsafe `eval()`/`exec()` usage
- 📊 **Scored reports**: 0–100 overall score + letter grade, broken down across 5 categories (Security, Performance, Maintainability, Best Practices, Code Style)
- 💻 **3 ways to use it**: web UI, CLI (for local use or CI), and a GitHub Action that comments directly on pull requests
- 🐳 **Dockerized** — one command to run anywhere
- ✅ **26 unit tests** covering every static analysis rule, with false-positive checks

## 📸 Demo

Paste code in the web UI → get an instant scored breakdown with line-level fixes:

```
Score: 32/100   Grade: D

Summary: Multiple critical security vulnerabilities including a hardcoded
password and shell injection risk. Several maintainability issues compound
the risk of regressions.

⚡ Top priority: Remove the hardcoded PASSWORD and API_KEY — move them to
environment variables before this code touches version control.

Issues (24):
  [CRITICAL]  Hardcoded password detected (Line 9)
  [CRITICAL]  Hardcoded API key detected (Line 10)
  [CRITICAL]  Shell injection risk: subprocess.run(shell=True) (Line 22)
  [WARNING]   Mutable default argument (list) in 'add_log' (Line 25)
  [WARNING]   Bare except clause (Line 59)
  ...
```

## 🏗️ Architecture

```
┌─────────────┐      ┌──────────────────┐      ┌─────────────────┐
│  Web UI /   │─────▶│   FastAPI         │─────▶│  AST Analyzer    │
│  CLI /      │      │   Backend         │      │  (instant,       │
│  GitHub PR  │      │                   │      │   no API call)   │
└─────────────┘      │                   │      └─────────────────┘
                      │                   │               │
                      │                   │               ▼
                      │                   │      ┌─────────────────┐
                      │                   │─────▶│  Llama 3.3 70B   │
                      │                   │      │  via Groq (free, │
                      │                   │      │   grounded by    │
                      └──────────────────┘      │   AST findings)  │
                                                  └─────────────────┘
```

The AST analyzer runs first and is **free and instant** — it finds concrete, deterministic issues (hardcoded secrets, bare excepts, missing type hints, etc.) using Python's built-in `ast` module. Its findings are then passed as context to the LLM, which validates them, finds deeper issues regex/AST can't catch (logic bugs, poor naming, architectural smells), and produces the final scored report.

## 🚀 Quick Start

### 1. Get a free Groq API key (no credit card needed)

1. Go to [console.groq.com/keys](https://console.groq.com/keys)
2. Sign up / log in
3. Create an API key (starts with `gsk_...`)

### Option A: Docker (recommended)

```bash
git clone https://github.com/YOUR_USERNAME/ai-code-reviewer.git
cd ai-code-reviewer
cp .env.example .env
# Edit .env and paste your GROQ_API_KEY
docker-compose up --build
```

Visit `http://localhost:8000`.

### Option B: Local Python

```bash
git clone https://github.com/YOUR_USERNAME/ai-code-reviewer.git
cd ai-code-reviewer
pip install -r requirements.txt
export GROQ_API_KEY=gsk_your-key-here
uvicorn backend.main:app --reload
```

Visit `http://localhost:8000`.

### Option C: CLI

```bash
pip install -r requirements.txt
export GROQ_API_KEY=gsk_your-key-here

python cli/review.py examples/vulnerable_app.py
python cli/review.py path/to/file.py --json             # machine-readable output
python cli/review.py path/to/file.py --fail-on critical  # exit 1 if criticals found (for CI)
```

## 🔧 GitHub Action Setup

This repo includes a ready-to-use GitHub Action that automatically reviews every PR and posts the results as a comment.

1. Add your Groq API key as a repo secret: **Settings → Secrets and variables → Actions → New repository secret** → name it `GROQ_API_KEY`
2. The workflow at [`.github/workflows/ai-review.yml`](.github/workflows/ai-review.yml) runs automatically on every PR that touches `.py` files
3. It fails the check if any **critical** severity issue is found — configurable via `--fail-on`

## 📡 API Reference

### `POST /api/review`

```bash
curl -X POST http://localhost:8000/api/review \
  -H "Content-Type: application/json" \
  -d '{"code": "PASSWORD = \"admin123\"", "language": "Python"}'
```

```json
{
  "overall_score": 35,
  "grade": "D",
  "summary": "...",
  "categories": { "security": 10, "performance": 80, "maintainability": 60, "best_practices": 55, "code_style": 70 },
  "issues": [ { "severity": "critical", "category": "security", "title": "...", "description": "...", "fix": "..." } ],
  "top_recommendation": "...",
  "ast_issue_count": 1
}
```

### `POST /api/review/file`
Upload a file directly (multipart form) instead of pasting code.

### `POST /api/review/github-pr`
Pass a GitHub PR URL — reviews all changed Python/JS/TS files in that PR.

## 🧪 What the AST Analyzer Catches

| Category | Checks |
|---|---|
| **Security** | Hardcoded passwords/API keys/secrets/tokens, SQL injection via string concat/f-strings, `eval`/`exec`/`compile` usage, `shell=True` in subprocess calls |
| **Best Practices** | Bare `except:` clauses, mutable default arguments, `global` statement usage, files opened without context managers, `assert` used for validation |
| **Performance** | `range(len(x))` instead of `enumerate()`, list membership tests that should use sets |
| **Maintainability** | Missing docstrings, functions >50 lines, functions with >5 parameters |
| **Code Style** | Missing type hints, unexplained magic numbers |

Run the test suite to see all 26 tests covering these rules, including false-positive checks:

```bash
pytest tests/ -v
```

## 🔄 Swapping the LLM provider

`backend/ai_reviewer.py` calls Groq's OpenAI-compatible endpoint (`https://api.groq.com/openai/v1/chat/completions`). Because it's OpenAI-compatible, swapping providers is just two changes:

```python
# Gemini (also free tier) — OpenAI-compatible endpoint
GROQ_API_URL = "https://generativelanguage.googleapis.com/v1beta/openai/chat/completions"
DEFAULT_MODEL = "gemini-2.0-flash"
```

Or set `GROQ_MODEL` env var to use a different Groq-hosted model (e.g. `llama3-70b-8192`, `mixtral-8x7b-32768`) without touching code.

## ⚠️ Free tier limits

Groq's free tier has rate limits (requests/min and requests/day, varies by model — check [console.groq.com](https://console.groq.com) for current limits on your account). For personal projects and demos this is more than enough; if you hit a 429, the API returns a clear "rate limit" message and you just wait a bit.

## 🛣️ Roadmap

- [ ] Multi-language AST support (currently Python-only for static analysis; AI review works for all languages)
- [ ] VS Code extension
- [ ] Configurable rule severity / custom rule plugins
- [ ] Diff-aware review (only review changed lines, not whole file)

## 📄 License

MIT — see [LICENSE](LICENSE)

## 🙋 Why I built this

Most "AI code review" projects are a thin wrapper around an LLM prompt. I wanted to build something closer to what real review tooling looks like at scale: a fast, deterministic static analysis layer (so you're not paying API costs or waiting on latency for issues that pure pattern-matching catches instantly) combined with an LLM layer for the things only an LLM can do — understanding intent, architecture, and naming. The GitHub Action turns it from a toy into something that could plausibly sit in a real CI pipeline — and it's free to run end to end.
