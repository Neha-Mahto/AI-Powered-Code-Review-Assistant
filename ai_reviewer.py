"""
AI Reviewer
Calls Groq's OpenAI-compatible chat completions API with a carefully engineered
system prompt to produce a structured, senior-engineer-level code review.
Merges in findings from the AST static analyzer for grounded, accurate results.

Groq is used because it offers a genuinely free tier (no credit card required)
with fast inference on open models like Llama 3.3 70B. Swap GROQ_MODEL or the
base URL below if you want to point this at a different OpenAI-compatible
provider later (e.g. Gemini's OpenAI-compatible endpoint).
"""

import os
import json
import re
from typing import List, Optional
import httpx

from backend.models import ReviewResponse, Issue, Categories
from backend.ast_analyzer import ASTIssue

SYSTEM_PROMPT = """You are a senior staff engineer at a top tech company conducting a rigorous code review.

You will be given source code and, optionally, a list of issues already found by static analysis (AST-based).
Your job:
1. Validate and incorporate the static analysis findings (don't repeat them verbatim — synthesize).
2. Find ADDITIONAL issues static analysis can't catch: logic errors, race conditions, poor naming,
   architectural concerns, missing edge case handling, test coverage gaps, API design issues.
3. Score the code honestly across 5 categories.

Respond with ONLY a single valid JSON object — no markdown fences, no preamble, nothing else:
{
  "overall_score": <integer 0-100>,
  "grade": <"A+"|"A"|"A-"|"B+"|"B"|"B-"|"C+"|"C"|"D"|"F">,
  "summary": "<2-3 sentence honest assessment, referencing severity of findings>",
  "categories": {
    "security": <integer 0-100>,
    "performance": <integer 0-100>,
    "maintainability": <integer 0-100>,
    "best_practices": <integer 0-100>,
    "code_style": <integer 0-100>
  },
  "issues": [
    {
      "severity": <"critical"|"warning"|"suggestion"|"good">,
      "category": <"security"|"performance"|"maintainability"|"best_practices"|"code_style">,
      "title": "<short specific title>",
      "description": "<detailed technical explanation of WHY this matters>",
      "line_hint": "<'Line N' or 'Lines N-M' or null>",
      "fix": "<concrete fix with a short code snippet>"
    }
  ],
  "top_recommendation": "<single most critical thing to fix first, and why>"
}

Rules:
- Find 5-10 issues total, combining static analysis context with your own deeper review.
- Always include at least 1 "good" issue if anything is done well — be fair, not just harsh.
- Scores should be brutally honest. A file with a hardcoded secret or SQL injection cannot score above 40 overall.
- Be specific: cite line numbers when given, reference actual variable/function names from the code.
- Output JSON only. Do not wrap it in ```json fences. Do not add any text before or after it.
"""

GROQ_API_URL = "https://api.groq.com/openai/v1/chat/completions"
DEFAULT_MODEL = "llama-3.3-70b-versatile"


class AIReviewer:
    def __init__(self, api_key: str = "", model: Optional[str] = None):
        self.api_key = api_key or os.environ.get("GROQ_API_KEY", "")
        self.model = model or os.environ.get("GROQ_MODEL", DEFAULT_MODEL)
        self.api_url = GROQ_API_URL

    async def review(
        self,
        code: str,
        language: str = "Python",
        filename: Optional[str] = None,
        ast_issues: Optional[List[ASTIssue]] = None,
    ) -> ReviewResponse:
        ast_issues = ast_issues or []
        ast_context = self._format_ast_context(ast_issues)

        user_message = (
            f"Language: {language}\n"
            f"Filename: {filename or 'unnamed'}\n\n"
            f"{ast_context}\n\n"
            f"Source code:\n```{language.lower()}\n{code}\n```"
        )

        headers = {
            "Authorization": f"Bearer {self.api_key}",
            "Content-Type": "application/json",
        }
        payload = {
            "model": self.model,
            "messages": [
                {"role": "system", "content": SYSTEM_PROMPT},
                {"role": "user", "content": user_message},
            ],
            "temperature": 0.3,
            "max_tokens": 3000,
            "response_format": {"type": "json_object"},
        }

        async with httpx.AsyncClient(timeout=60.0) as client:
            resp = await client.post(self.api_url, headers=headers, json=payload)
            resp.raise_for_status()
            data = resp.json()

        text = data["choices"][0]["message"]["content"]
        text = re.sub(r"^```json\s*|\s*```$", "", text.strip())
        parsed = json.loads(text)

        issues = [
            Issue(
                id=i,
                severity=item["severity"],
                category=item["category"],
                title=item["title"],
                description=item["description"],
                line_hint=item.get("line_hint"),
                fix=item.get("fix"),
                source="ai",
            )
            for i, item in enumerate(parsed["issues"])
        ]

        return ReviewResponse(
            overall_score=parsed["overall_score"],
            grade=parsed["grade"],
            summary=parsed["summary"],
            categories=Categories(**parsed["categories"]),
            issues=issues,
            top_recommendation=parsed["top_recommendation"],
            ast_issue_count=len(ast_issues),
        )

    @staticmethod
    def _format_ast_context(ast_issues: List[ASTIssue]) -> str:
        if not ast_issues:
            return "Static analysis: no issues detected (or not applicable for this language)."

        lines = [f"Static analysis (AST) found {len(ast_issues)} issue(s) already — incorporate these:"]
        for issue in ast_issues[:15]:
            lines.append(f"  - Line {issue.line} [{issue.severity}/{issue.category}]: {issue.title}")
        return "\n".join(lines)
