"""
AI Code Review API
FastAPI backend combining AST static analysis + Llama 3.3 (via Groq) AI review
"""

import os
import json
import httpx
from fastapi import FastAPI, HTTPException, UploadFile, File
from fastapi.middleware.cors import CORSMiddleware
from fastapi.staticfiles import StaticFiles
from fastapi.responses import FileResponse
from pydantic import BaseModel
from typing import Optional

from backend.ast_analyzer import ASTAnalyzer
from backend.ai_reviewer import AIReviewer
from backend.models import ReviewRequest, ReviewResponse

app = FastAPI(
    title="AI Code Review API",
    description="Automated code review combining AST static analysis and Llama 3.3 (via Groq)",
    version="1.0.0"
)

app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_methods=["*"],
    allow_headers=["*"],
)

ast_analyzer = ASTAnalyzer()
ai_reviewer  = AIReviewer(api_key=os.environ.get("GROQ_API_KEY", ""))

app.mount("/static", StaticFiles(directory="frontend"), name="static")


@app.get("/")
async def root():
    return FileResponse("frontend/index.html")


@app.get("/health")
async def health():
    return {"status": "ok", "version": "1.0.0"}


@app.post("/api/review", response_model=ReviewResponse)
async def review_code(req: ReviewRequest):
    """
    Full review: runs AST static analysis first, then Llama 3.3 (via Groq) AI review.
    AST issues are injected into the AI prompt for richer context.
    """
    if not req.code.strip():
        raise HTTPException(status_code=400, detail="Code cannot be empty.")

    ast_issues = []
    if req.language.lower() == "python":
        ast_issues = ast_analyzer.analyze(req.code, filename=req.filename or "code.py")

    try:
        result = await ai_reviewer.review(
            code=req.code,
            language=req.language,
            filename=req.filename,
            ast_issues=ast_issues,
        )
    except httpx.HTTPStatusError as e:
        if e.response.status_code == 401:
            raise HTTPException(status_code=502, detail="Invalid or missing GROQ_API_KEY on the server.")
        if e.response.status_code == 429:
            raise HTTPException(status_code=502, detail="Groq rate limit hit — wait a moment and retry (free tier).")
        raise HTTPException(status_code=502, detail=f"AI provider error: {e.response.status_code}")
    except (json.JSONDecodeError, KeyError):
        raise HTTPException(status_code=502, detail="AI returned an unparseable response. Please retry.")

    return result


@app.post("/api/review/file")
async def review_file(file: UploadFile = File(...), language: Optional[str] = None):
    """Upload a file and get a review."""
    content = await file.read()
    try:
        code = content.decode("utf-8")
    except UnicodeDecodeError:
        raise HTTPException(status_code=400, detail="File must be valid UTF-8 text.")

    ext_to_lang = {
        ".py": "Python", ".js": "JavaScript", ".ts": "TypeScript",
        ".java": "Java", ".go": "Go", ".rs": "Rust", ".cpp": "C++",
        ".rb": "Ruby", ".php": "PHP", ".cs": "C#",
    }
    detected_lang = language
    if not detected_lang:
        ext = os.path.splitext(file.filename or "")[1].lower()
        detected_lang = ext_to_lang.get(ext, "Unknown")

    ast_issues = []
    if detected_lang == "Python":
        ast_issues = ast_analyzer.analyze(code, filename=file.filename or "code.py")

    result = await ai_reviewer.review(
        code=code,
        language=detected_lang,
        filename=file.filename,
        ast_issues=ast_issues,
    )
    return result


@app.post("/api/review/github-pr")
async def review_github_pr(pr_url: str, github_token: Optional[str] = None):
    """
    Fetch and review all changed Python files in a GitHub PR.
    Provide a GitHub token for private repos.
    """
    # Parse URL: https://github.com/owner/repo/pull/123
    try:
        parts = pr_url.rstrip("/").split("/")
        owner, repo, pr_number = parts[-4], parts[-3], parts[-1]
    except Exception:
        raise HTTPException(status_code=400, detail="Invalid GitHub PR URL.")

    headers = {"Accept": "application/vnd.github.v3+json"}
    if github_token:
        headers["Authorization"] = f"Bearer {github_token}"

    async with httpx.AsyncClient() as client:
        files_resp = await client.get(
            f"https://api.github.com/repos/{owner}/{repo}/pulls/{pr_number}/files",
            headers=headers,
        )
        if files_resp.status_code != 200:
            raise HTTPException(status_code=400, detail="Could not fetch PR files. Check URL and token.")

        pr_files = files_resp.json()

    results = []
    for f in pr_files[:5]:  # limit to 5 files per PR
        if f.get("status") == "removed":
            continue
        raw_url = f.get("raw_url", "")
        filename = f.get("filename", "")
        ext = os.path.splitext(filename)[1].lower()
        ext_to_lang = {".py": "Python", ".js": "JavaScript", ".ts": "TypeScript"}
        lang = ext_to_lang.get(ext)
        if not lang:
            continue

        async with httpx.AsyncClient() as client:
            code_resp = await client.get(raw_url, headers=headers)
            code = code_resp.text

        ast_issues = []
        if lang == "Python":
            ast_issues = ast_analyzer.analyze(code, filename=filename)

        review = await ai_reviewer.review(code=code, language=lang, filename=filename, ast_issues=ast_issues)
        results.append({"filename": filename, "review": review})

    return {"pr_url": pr_url, "files_reviewed": len(results), "results": results}
