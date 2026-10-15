"""WireGuard Manager API application."""
import logging
from contextlib import asynccontextmanager
from fastapi import FastAPI, Request
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import JSONResponse
from . import models  # ensure model metadata is registered
from .auth import router as auth_router
from .config import get_settings
from .db import Base, engine
from .routers import router as routers_router
from .peers import router as peers_router
from .admin import router as admin_router

logging.basicConfig(level=logging.INFO, format="%(asctime)s %(levelname)s %(name)s %(message)s")
logger = logging.getLogger("wireguard_manager")

@asynccontextmanager
async def lifespan(app: FastAPI):
    # Local MVP convenience only. Production schema changes must use Alembic.
    Base.metadata.create_all(bind=engine)
    yield

app = FastAPI(title="WireGuard Manager API", description="Backend API for controlled RouterOS WireGuard inventory and management.", version="0.2.0", docs_url="/docs", redoc_url=None, lifespan=lifespan)
settings = get_settings()
origins = [origin.strip() for origin in settings.allowed_origins.split(",") if origin.strip()]
app.add_middleware(CORSMiddleware, allow_origins=origins, allow_credentials=False, allow_methods=["GET", "POST", "PATCH", "DELETE"], allow_headers=["Authorization", "Content-Type"])
app.include_router(auth_router)
app.include_router(routers_router)
app.include_router(peers_router)
app.include_router(admin_router)

@app.get("/healthz", tags=["health"])
def liveness() -> dict[str, str]:
    return {"status": "ok"}

@app.get("/api/v1/health", tags=["health"])
def readiness() -> dict[str, str]:
    return {"status": "ready", "service": "wireguard-manager-api", "router_connectivity": "configured-per-router"}

@app.exception_handler(Exception)
async def unexpected_error_handler(request: Request, exc: Exception) -> JSONResponse:
    logger.exception("Unhandled request failure path=%s", request.url.path)
    return JSONResponse(status_code=500, content={"detail": "Internal server error"})
