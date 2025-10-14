"""
REST API for the encrypted notes manager

This module provides an interface that uses
the business logic from core.py. Suitable for web/mobile apps.

Security Notes:
- In production: There is a consideration to add JWT + HTTP/TLs
for now there is X-Master-Password for dev purpose.
"""

import json
from contextlib import asynccontextmanager
from pathlib import Path

from fastapi import (
    FastAPI,
)
from fastapi.middleware.cors import CORSMiddleware

from .storage import FileStorage

CONFIG_DIR = Path.home() / ".config" / "encrypted-notes"
CONFIG_FILE = CONFIG_DIR / "config.json"
STORAGE_DIR = CONFIG_DIR / "storage"

app_state = {
    "storage": None,
    "salt_hex": None,
    "iterations": 100_000,
}


def load_config():
    """
    Load application configuration.
    """

    if not CONFIG_FILE.exists():
        raise RuntimeError(
            "Application not initialized! Run 'python3 -m encrypted_notes.cli init' first."
        )

    with open(CONFIG_FILE, "r") as f:
        config = json.load(f)

    app_state["salt_hex"] = config.get("salt_hex")
    app_state["iterations"] = config.get("iterations", 100_000)

    storage_path = Path(config.get("storage_dir", STORAGE_DIR))
    app_state["storage"] = FileStorage(storage_path)


@asynccontextmanager
async def lifespan(app: FastAPI):
    """
    Application lifespan manager.
    """
    try:
        load_config()
        print("✓ Configuration loaded")
        print(f"✓ Storage initialized at: {STORAGE_DIR}")
    except Exception as e:
        print(f"✗ Failed to initialize: {e}")
        raise

    yield

    print("Shutting down...")


app = FastAPI(
    title="Encrypted Notes Manager API",
    description="""
    Secure encrypted notes manager with password-based encryption.
    
    ## Authentication
    
    All endpoints require the `X-Master-Password` header with your master password.
    
    ## Security Warning
    
    This API uses a simple password header for demo purposes.
    In production, use:
    - HTTPS/TLS for all connections
    - Proper authentication (JWT tokens, OAuth2)
    - Rate limiting on authentication
    - Session management
    
    ## Features
    
    * Create, read, update, delete encrypted notes
    * Search and filter notes
    * Tags and favorites
    * Import/export functionality
    * Statistics and analytics
    """,
    version="1.0.0",
    lifespan=lifespan,
    docs_url="/docs",
)

app.add_middleware(
    CORSMiddleware,
    allow_origins=[
        "http://localhost:5173",  # Vite dev server
    ],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)
