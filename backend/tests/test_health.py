from fastapi.testclient import TestClient
from wireguard_manager_api.main import app

client = TestClient(app)

def test_liveness() -> None:
    response = client.get("/healthz")
    assert response.status_code == 200
    assert response.json() == {"status": "ok"}

def test_versioned_readiness() -> None:
    response = client.get("/api/v1/health")
    assert response.status_code == 200
    assert response.json()["service"] == "wireguard-manager-api"

def test_openapi_document_is_available() -> None:
    response = client.get("/openapi.json")
    assert response.status_code == 200
    assert response.json()["info"]["title"] == "WireGuard Manager API"
