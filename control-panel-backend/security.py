import secrets
import os
from pathlib import Path
from fastapi import Header, HTTPException, Security
from fastapi.security import APIKeyHeader

BASE_DIR = Path(__file__).resolve().parent.parent
TOKEN_FILE = Path(__file__).resolve().parent / ".token"

def get_or_create_token() -> str:
    """Generates a random token on boot or reuses existing .token file for local UI discovery."""
    if TOKEN_FILE.exists():
        existing = TOKEN_FILE.read_text(encoding="utf-8").strip()
        if existing:
            return existing
    token = secrets.token_hex(24)
    TOKEN_FILE.write_text(token, encoding="utf-8")
    return token

def read_token() -> str:
    if TOKEN_FILE.exists():
        return TOKEN_FILE.read_text(encoding="utf-8").strip()
    return ""

async def verify_token(x_detectforge_token: str = Header(None, alias="X-DetectForge-Token")):
    expected = read_token()
    if not expected:
        raise HTTPException(status_code=500, detail="Backend token not initialized")
    if not x_detectforge_token or x_detectforge_token != expected:
        raise HTTPException(status_code=403, detail="Invalid or missing X-DetectForge-Token header")
