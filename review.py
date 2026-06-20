#!/usr/bin/env python3
"""
AI Code Review CLI

Usage:
    python cli/review.py path/to/file.py
    python cli/review.py path/to/file.py --language python
    python cli/review.py path/to/file.py --json
    python cli/review.py path/to/file.py --fail-on critical

Exit codes:
    0 - no blocking issues
    1 - blocking issues found (for use in CI/CD, see --fail-on)
    2 - error (file not found, API error, etc.)
"""

import argparse
import asyncio
import json
import os
import sys

sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))

from backend.ast_analyzer import ASTAnalyzer
from backend.ai_reviewer import AIReviewer

EXT_TO_LANG = {
    ".py": "Python", ".js": "JavaScript", ".ts": "TypeScript",
    ".java": "Java", ".go": "Go", ".rs": "Rust", ".cpp": "C++",
    ".rb": "Ruby", ".php": "PHP", ".cs": "C#", ".swift": "Swift", ".kt": "Kotlin",
}

SEVERITY_RANK = {"critical": 3, "warning": 2, "suggestion": 1, "good": 0}

COLORS = {
    "critical": "\033[91m", "warning": "\033[93m",
    "suggestion": "\033[94m", "good": "\033[92m",
    "reset": "\033[0m", "bold": "\033[1m", "dim": "\033[2m",
}


def colorize(text: str, color: str) -> str:
    if not sys.stdout.isatty():
        return text
    return f"{COLORS.get(color, '')}{text}{COLORS['reset']}"


def print_report(result, filename: str, ast_count: int):
    print()
    print(colorize(f"━━━ AI Code Review: {filename} ━━━", "bold"))
    print()

    grade_color = "good" if result.overall_score >= 80 else "warning" if result.overall_score >= 60 else "critical"
    print(f"  Score: {colorize(str(result.overall_score) + '/100', grade_color)}  "
          f"Grade: {colorize(result.grade, grade_color)}")
    print()

    print("  Category breakdown:")
    for name, value in result.categories.model_dump().items():
        bar_len = 20
        filled = int(bar_len * value / 100)
        bar = "█" * filled + "░" * (bar_len - filled)
        print(f"    {name:18s} {bar} {value}/100")
    print()

    print(colorize(f"  Summary: ", "bold") + result.summary)
    print()
    print(colorize("  ⚡ Top priority: ", "bold") + result.top_recommendation)
    print()

    if ast_count:
        print(colorize(f"  (includes {ast_count} static-analysis findings)", "dim"))
        print()

    print(colorize(f"  Issues ({len(result.issues)}):", "bold"))
    print()

    sorted_issues = sorted(result.issues, key=lambda i: -SEVERITY_RANK.get(i.severity, 0))
    for issue in sorted_issues:
        sev_label = f"[{issue.severity.upper()}]"
        line_info = f" ({issue.line_hint})" if issue.line_hint else ""
        print(f"  {colorize(sev_label, issue.severity)} {issue.title}{line_info}")
        print(f"    {issue.description}")
        if issue.fix:
            print(colorize(f"    → Fix: {issue.fix.splitlines()[0]}", "dim"))
            if len(issue.fix.splitlines()) > 1:
                print(colorize(f"      ...({len(issue.fix.splitlines())-1} more lines)", "dim"))
        print()


async def main():
    parser = argparse.ArgumentParser(description="AI-powered code review CLI")
    parser.add_argument("file", help="Path to the file to review")
    parser.add_argument("--language", "-l", help="Override detected language")
    parser.add_argument("--json", action="store_true", help="Output raw JSON instead of formatted report")
    parser.add_argument("--fail-on", choices=["critical", "warning", "any"], default=None,
                         help="Exit with code 1 if issues of this severity or higher are found (for CI)")
    parser.add_argument("--api-key", help="Groq API key (defaults to GROQ_API_KEY env var)")
    args = parser.parse_args()

    if not os.path.isfile(args.file):
        print(f"Error: file not found: {args.file}", file=sys.stderr)
        sys.exit(2)

    with open(args.file, "r", encoding="utf-8") as f:
        code = f.read()

    ext = os.path.splitext(args.file)[1].lower()
    language = args.language or EXT_TO_LANG.get(ext, "Unknown")

    ast_issues = []
    if language == "Python":
        ast_issues = ASTAnalyzer().analyze(code, filename=args.file)

    api_key = args.api_key or os.environ.get("GROQ_API_KEY")
    if not api_key:
        print("Error: set GROQ_API_KEY environment variable or pass --api-key", file=sys.stderr)
        sys.exit(2)

    reviewer = AIReviewer(api_key=api_key)
    try:
        result = await reviewer.review(code=code, language=language, filename=args.file, ast_issues=ast_issues)
    except Exception as e:
        print(f"Error during review: {e}", file=sys.stderr)
        sys.exit(2)

    if args.json:
        print(result.model_dump_json(indent=2))
    else:
        print_report(result, args.file, len(ast_issues))

    if args.fail_on:
        threshold = {"critical": 3, "warning": 2, "any": 1}[args.fail_on]
        blocking = [i for i in result.issues if SEVERITY_RANK.get(i.severity, 0) >= threshold]
        if blocking:
            print(colorize(f"\n✗ {len(blocking)} issue(s) at or above '{args.fail_on}' severity. Failing.", "critical"))
            sys.exit(1)

    sys.exit(0)


if __name__ == "__main__":
    asyncio.run(main())
