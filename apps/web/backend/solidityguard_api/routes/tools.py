"""Routes for /api/tools and /api/health."""

from datetime import datetime, timezone

from fastapi import APIRouter

from solidityguard_api.models.schemas import HealthResponse, ToolStatus
from solidityguard_api.services.scanner import ALL_TOOLS, check_tool

router = APIRouter()


@router.get("/api/health", response_model=HealthResponse)
async def health_check():
    return HealthResponse(timestamp=datetime.now(timezone.utc))


@router.get("/api/tools", response_model=list[ToolStatus])
async def list_tools():
    return [check_tool(name) for name in ALL_TOOLS]
