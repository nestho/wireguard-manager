"""WireGuard Manager API application."""
import logging
from contextlib import asynccontextmanager
from fastapi import FastAPI, Request
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import JSONResponse
from . import models
from .auth import router as auth_router
from .config import get_settings
from .routers import router as routers_router
from .peers import router as peers_router
from .admin import router as admin_router
from .linux_servers import router as linux_servers_router
from .linux_peers import router as linux_peers_router
from .linux_optimizer import router as linux_optimizer_router
from .schemas import HealthResponse

logging.basicConfig(level=logging.INFO, format="%(asctime)s %(levelname)s %(name)s %(message)s")
logger = logging.getLogger("wireguard_manager")

@asynccontextmanager
async def lifespan(app: FastAPI):
    # Schema changes are applied only through reviewed Alembic migrations.
    # This avoids silently mutating production schemas at application startup.
    yield

app = FastAPI(title="WireGuard Manager API", description="Multi-platform WireGuard management API for RouterOS and Linux servers.", version="0.3.0", docs_url="/docs", redoc_url=None, lifespan=lifespan)
settings = get_settings()
origins = [origin.strip() for origin in settings.allowed_origins.split(",") if origin.strip()]
app.add_middleware(CORSMiddleware, allow_origins=origins, allow_credentials=False, allow_methods=["GET", "POST", "PATCH", "DELETE"], allow_headers=["Authorization", "Content-Type"])
app.include_router(auth_router)
app.include_router(routers_router)
app.include_router(peers_router)
app.include_router(admin_router)
app.include_router(linux_servers_router)
app.include_router(linux_peers_router)
app.include_router(linux_optimizer_router)

@app.get("/healthz", tags=["health"])
def liveness() -> dict[str, str]:
    return {"status": "ok"}

@app.get("/api/v1/health", tags=["health"], response_model=HealthResponse)
def readiness() -> HealthResponse:
    return HealthResponse(status="ready", service="wireguard-manager-api", providers=["mikrotik-routeros", "linux-ssh"], router_connectivity="configured-per-router", linux_connectivity="configured-per-server")

@app.exception_handler(Exception)
async def unexpected_error_handler(request: Request, exc: Exception) -> JSONResponse:
    logger.exception("Unhandled request failure path=%s", request.url.path)
    return JSONResponse(status_code=500, content={"detail": "Internal server error"})
