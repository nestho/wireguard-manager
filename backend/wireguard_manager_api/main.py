"""Initial FastAPI scaffold for the WireGuard Manager backend."""

from fastapi import FastAPI, Request
from fastapi.responses import JSONResponse

app = FastAPI(
    title="WireGuard Manager API",
    description=(
        "Development API foundation. Router connectivity and peer mutations "
        "are intentionally not implemented in this milestone."
    ),
    version="0.1.0",
    docs_url="/docs",
    redoc_url=None,
)


@app.get("/healthz", tags=["health"])
def liveness() -> dict[str, str]:
    """Report that the process is running; do not depend on external services."""
    return {"status": "ok"}


@app.get("/api/v1/health", tags=["health"])
def readiness() -> dict[str, str]:
    """Report readiness of the scaffold itself."""
    return {
        "status": "ready",
        "service": "wireguard-manager-api",
        "router_connectivity": "not_configured",
    }


@app.exception_handler(Exception)
async def unexpected_error_handler(
    request: Request, exc: Exception
) -> JSONResponse:
    """Return a generic response without leaking exception details to clients."""
    # Keep details out of the HTTP response. Structured server-side logging will
    # be introduced with the authentication and audit-log milestone.
    return JSONResponse(
        status_code=500,
        content={"detail": "Internal server error"},
    )
