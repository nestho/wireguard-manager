from fastapi.testclient import TestClient
from wireguard_manager_api.main import app
client = TestClient(app)
def test_liveness():
    response = client.get("/healthz")
    assert response.status_code == 200
    assert response.json() == {"status": "ok"}
def test_versioned_readiness():
    response = client.get("/api/v1/health")
    assert response.status_code == 200
    body = response.json()
    assert body["service"] == "wireguard-manager-api"
    assert body["providers"] == ["mikrotik-routeros", "linux-ssh"]
    assert body["status"] == "ready"
    assert body["router_connectivity"] == "configured-per-router"
    assert body["linux_connectivity"] == "configured-per-server"
def test_openapi_available():
    response = client.get("/openapi.json")
    assert response.status_code == 200
    assert response.json()["info"]["title"] == "WireGuard Manager API"
