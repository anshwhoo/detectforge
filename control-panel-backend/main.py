import uvicorn
from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware
from security import get_or_create_token, read_token
from routers import status, rules, git_ops

app = FastAPI(
    title="DetectForge Control Panel API",
    description="Local-only administrative backend for DetectForge",
    version="1.0.0"
)

# Lock CORS strictly to http://localhost:5173 only
app.add_middleware(
    CORSMiddleware,
    allow_origins=["http://localhost:5173"],
    allow_credentials=True,
    allow_methods=["GET", "POST", "OPTIONS"],
    allow_headers=["*"],
)

# Token discovery endpoint for local dev UI
@app.get("/api/auth/token")
def get_token():
    """Returns local security token for initial frontend initialization."""
    return {"token": read_token()}

# Include Routers
app.include_router(status.router)
app.include_router(rules.router)
app.include_router(git_ops.router)

@app.on_event("startup")
def startup_event():
    token = get_or_create_token()
    print("=" * 60)
    print(" [DetectForge Local Control Panel Backend] STARTED")
    print(f" Bound to: http://127.0.0.1:8001")
    print(f" Session Token: {token}")
    print(" CORS Origin Allowed: http://localhost:5173")
    print("=" * 60)

if __name__ == "__main__":
    uvicorn.run("main:app", host="127.0.0.1", port=8001, reload=True)
