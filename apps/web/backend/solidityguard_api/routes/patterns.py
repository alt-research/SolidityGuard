"""Routes for /api/patterns."""

from fastapi import APIRouter, HTTPException

from solidityguard_api.models.schemas import PatternInfo
from solidityguard_api.services.scanner import PATTERNS, PATTERNS_BY_ID

router = APIRouter()


@router.get("/api/patterns", response_model=list[PatternInfo])
async def list_patterns(
    category: str | None = None,
    severity: str | None = None,
):
    results = PATTERNS
    if category:
        results = [p for p in results if p.category == category]
    if severity:
        results = [p for p in results if p.severity == severity.upper()]
    return results


@router.get("/api/patterns/{pattern_id}", response_model=PatternInfo)
async def get_pattern(pattern_id: str):
    pattern = PATTERNS_BY_ID.get(pattern_id.upper())
    if not pattern:
        raise HTTPException(status_code=404, detail=f"Pattern {pattern_id} not found")
    return pattern
