"""SolidityGuard API — FastAPI application entry point."""

import asyncio
from contextlib import asynccontextmanager
from pathlib import Path

from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware

from solidityguard_api.routes import audit, auth, fuzz, patterns, tools
from solidityguard_api.websocket import ws_manager


@asynccontextmanager
async def lifespan(app: FastAPI):
    # Store the event loop so background threads can schedule coroutines
    ws_manager.set_loop(asyncio.get_running_loop())
    yield


app = FastAPI(
    title="SolidityGuard API",
    description="Solidity smart contract security audit API",
    version="1.2.0",
    lifespan=lifespan,
)

# CORS — allow frontend origins (credentials + wildcard is invalid per spec
# and causes Starlette to reject WebSocket connections with 403)
app.add_middleware(
    CORSMiddleware,
    allow_origins=[
        "https://solidityguard.org",
        "http://localhost:5173",
        "http://localhost:8000",
        "http://localhost:3000",
    ],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

# Register routers
app.include_router(auth.router)
app.include_router(audit.router)
app.include_router(fuzz.router)
app.include_router(patterns.router)
app.include_router(tools.router)

# Serve static frontend in production (Docker / Railway)
_static_dir = Path("/app/static")
if _static_dir.is_dir():
    from fastapi.responses import FileResponse

    _index_html = _static_dir / "index.html"

    # Catch-all for SPA client-side routes (e.g. /new, /audit/xxx, /report/xxx)
    @app.get("/{full_path:path}")
    async def spa_fallback(full_path: str):
        # Serve actual static files if they exist
        static_file = _static_dir / full_path
        if static_file.is_file():
            return FileResponse(static_file)
        # Otherwise return index.html for client-side routing
        return FileResponse(_index_html)
else:
    # Dev mode: no static files, frontend runs on separate dev server
    pass
