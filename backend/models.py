"""
Pydantic models for the AI Code Review API.
"""

from typing import List, Optional

from pydantic import BaseModel, Field


class ReviewRequest(BaseModel):
    code: str = Field(..., description="Source code to review")
    language: str = Field(default="Python", description="Programming language")
    filename: Optional[str] = Field(default=None, description="Original filename, if any")


class Issue(BaseModel):
    id: int
    severity: str          # critical | warning | suggestion | good
    category: str          # security | performance | maintainability | best_practices | code_style
    title: str
    description: str
    line_hint: Optional[str] = None
    fix: Optional[str] = None
    source: str = "ai"      # "ai" or "ast" — lets the frontend show provenance


class Categories(BaseModel):
    security: int
    performance: int
    maintainability: int
    best_practices: int
    code_style: int


class ReviewResponse(BaseModel):
    overall_score: int
    grade: str
    summary: str
    categories: Categories
    issues: List[Issue]
    top_recommendation: str
    ast_issue_count: int = 0
