"""Routes for /api/fuzz-tests — fuzz test generation from findings."""

import sys
from pathlib import Path

from fastapi import APIRouter, HTTPException

from solidityguard_api.models.schemas import FuzzTestRequest, FuzzTestResponse

router = APIRouter()


def _get_fuzz_generator():
    """Lazily import the fuzz generator from the scripts directory."""
    # Resolve path relative to the repo root
    here = Path(__file__).resolve()
    # Walk up to find repo root (contains CLAUDE.md)
    repo_root = here
    for parent in here.parents:
        if (parent / "CLAUDE.md").exists():
            repo_root = parent
            break
    scripts_dir = str(repo_root / ".claude" / "skills" / "solidity-guard" / "scripts")
    if scripts_dir not in sys.path:
        sys.path.insert(0, scripts_dir)
    from fuzz_generator import generate_from_json
    return generate_from_json


@router.post("/api/fuzz-tests", response_model=FuzzTestResponse)
async def generate_fuzz_tests(request: FuzzTestRequest):
    """Generate Foundry invariant tests and Echidna property tests from findings."""
    if not request.findings:
        raise HTTPException(status_code=400, detail="No findings provided")

    generate_from_json = _get_fuzz_generator()
    result = generate_from_json(request.findings, request.contracts_path)

    return FuzzTestResponse(
        foundry_test=result["foundry_test"],
        echidna_test=result["echidna_test"],
        echidna_config=result["echidna_config"],
        summary=result["summary"],
    )
