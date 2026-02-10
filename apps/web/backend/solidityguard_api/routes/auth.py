"""Google OAuth authentication routes."""

import os
import time
import hashlib
import hmac
import json
import base64
from urllib.parse import urlencode

from fastapi import APIRouter, Request, HTTPException, Depends
from fastapi.responses import RedirectResponse

router = APIRouter(prefix="/auth", tags=["auth"])

# Google OAuth config — set via environment variables
GOOGLE_CLIENT_ID = os.getenv("GOOGLE_CLIENT_ID", "")
GOOGLE_CLIENT_SECRET = os.getenv("GOOGLE_CLIENT_SECRET", "")
JWT_SECRET = os.getenv("JWT_SECRET", "")
FRONTEND_URL = os.getenv("FRONTEND_URL", "")


def _get_base_url(request: Request) -> str:
    """Get base URL, respecting X-Forwarded-Proto behind reverse proxies."""
    base = str(request.base_url).rstrip("/")
    proto = request.headers.get("x-forwarded-proto")
    if proto == "https" and base.startswith("http://"):
        base = "https://" + base[7:]
    return base

# Token expiry: 7 days
TOKEN_EXPIRY = 7 * 24 * 3600


def _b64url_encode(data: bytes) -> str:
    return base64.urlsafe_b64encode(data).rstrip(b"=").decode()


def _b64url_decode(s: str) -> bytes:
    padding = 4 - len(s) % 4
    if padding != 4:
        s += "=" * padding
    return base64.urlsafe_b64decode(s)


def create_jwt(payload: dict) -> str:
    """Create a simple JWT (HS256)."""
    header = _b64url_encode(json.dumps({"alg": "HS256", "typ": "JWT"}).encode())
    payload_b64 = _b64url_encode(json.dumps(payload).encode())
    signing_input = f"{header}.{payload_b64}"
    signature = hmac.new(JWT_SECRET.encode(), signing_input.encode(), hashlib.sha256).digest()
    sig_b64 = _b64url_encode(signature)
    return f"{signing_input}.{sig_b64}"


def decode_jwt(token: str) -> dict | None:
    """Decode and verify a JWT. Returns payload or None if invalid."""
    try:
        parts = token.split(".")
        if len(parts) != 3:
            return None
        signing_input = f"{parts[0]}.{parts[1]}"
        expected_sig = hmac.new(JWT_SECRET.encode(), signing_input.encode(), hashlib.sha256).digest()
        actual_sig = _b64url_decode(parts[2])
        if not hmac.compare_digest(expected_sig, actual_sig):
            return None
        payload = json.loads(_b64url_decode(parts[1]))
        if payload.get("exp", 0) < time.time():
            return None
        return payload
    except Exception:
        return None


def get_current_user(request: Request) -> dict | None:
    """Extract user from Authorization header. Returns None if not authenticated."""
    auth = request.headers.get("Authorization", "")
    if not auth.startswith("Bearer "):
        return None
    return decode_jwt(auth[7:])


def require_auth(request: Request) -> dict:
    """Dependency that requires authentication."""
    user = get_current_user(request)
    if not user:
        raise HTTPException(status_code=401, detail="Authentication required")
    return user


@router.get("/google/login")
async def google_login(request: Request):
    """Redirect to Google OAuth consent screen."""
    if not GOOGLE_CLIENT_ID:
        raise HTTPException(status_code=500, detail="Google OAuth not configured")

    # Determine callback URL from request (respect reverse proxy)
    callback_url = _get_base_url(request) + "/auth/google/callback"

    params = urlencode({
        "client_id": GOOGLE_CLIENT_ID,
        "redirect_uri": callback_url,
        "response_type": "code",
        "scope": "openid email profile",
        "access_type": "offline",
        "prompt": "consent",
    })
    return RedirectResponse(f"https://accounts.google.com/o/oauth2/v2/auth?{params}")


@router.get("/google/callback")
async def google_callback(request: Request, code: str | None = None, error: str | None = None):
    """Handle Google OAuth callback."""
    if error:
        frontend = FRONTEND_URL or _get_base_url(request)
        return RedirectResponse(f"{frontend}/login?error={error}")

    if not code:
        raise HTTPException(status_code=400, detail="Missing authorization code")

    # Must match the redirect_uri used in /google/login exactly
    callback_url = _get_base_url(request) + "/auth/google/callback"

    # Exchange code for tokens
    import httpx
    async with httpx.AsyncClient() as client:
        token_resp = await client.post("https://oauth2.googleapis.com/token", data={
            "client_id": GOOGLE_CLIENT_ID,
            "client_secret": GOOGLE_CLIENT_SECRET,
            "code": code,
            "grant_type": "authorization_code",
            "redirect_uri": callback_url,
        })

        if token_resp.status_code != 200:
            detail = token_resp.text
            raise HTTPException(status_code=400, detail=f"Google token exchange failed: {detail}")

        tokens = token_resp.json()
        access_token = tokens.get("access_token")

        # Get user info
        userinfo_resp = await client.get(
            "https://www.googleapis.com/oauth2/v2/userinfo",
            headers={"Authorization": f"Bearer {access_token}"},
        )

        if userinfo_resp.status_code != 200:
            raise HTTPException(status_code=400, detail="Failed to get user info")

        userinfo = userinfo_resp.json()

    # Create JWT
    jwt_payload = {
        "sub": userinfo.get("id"),
        "email": userinfo.get("email"),
        "name": userinfo.get("name", ""),
        "picture": userinfo.get("picture", ""),
        "iat": int(time.time()),
        "exp": int(time.time()) + TOKEN_EXPIRY,
    }
    token = create_jwt(jwt_payload)

    # Redirect to frontend with token
    frontend = FRONTEND_URL or _get_base_url(request)
    return RedirectResponse(f"{frontend}/?token={token}")


@router.get("/me")
async def get_me(user: dict = Depends(require_auth)):
    """Get current user info."""
    return {
        "id": user.get("sub"),
        "email": user.get("email"),
        "name": user.get("name"),
        "picture": user.get("picture"),
    }


@router.post("/logout")
async def logout():
    """Logout — client-side token removal. Server-side is stateless."""
    return {"ok": True}
