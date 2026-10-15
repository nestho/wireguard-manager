from fastapi.testclient import TestClient

from wireguard_manager_api.main import app

client = TestClient(app)


def test_liveness() -> None:
    response = client.get("/healthz")
    assert response.status_code == 200
    assert response.json() == {"status": "ok"}


def test_versioned_readiness_is_explicit_about_router_connectivity() -> None:
    response = client.get("/api/v1/health")
    assert response.status_code == 200
    body = response.json()
    assert body["status"] == "ready"
    assert body["service"] == "wireguard-manager-api"
    assert body["router_connectivity"] == "not_configured"


def test_openapi_document_is_available_for_local_development() -> None:
    response = client.get("/openapi.json")
    assert response.status_code == 200
    assert response.json()["info"]["title"] == "WireGuard Manager API"
