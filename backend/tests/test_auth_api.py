from fastapi.testclient import TestClient
from sqlalchemy import create_engine
from sqlalchemy.orm import sessionmaker
from sqlalchemy.pool import StaticPool
from wireguard_manager_api.db import Base, get_db
from wireguard_manager_api.main import app
from wireguard_manager_api.models import User
from wireguard_manager_api.security import hash_password
engine = create_engine("sqlite://", connect_args={"check_same_thread": False}, poolclass=StaticPool)
TestingSession = sessionmaker(bind=engine, autoflush=False, expire_on_commit=False)
Base.metadata.create_all(bind=engine)
def override_db():
    db = TestingSession()
    try: yield db
    finally: db.close()
app.dependency_overrides[get_db] = override_db
with TestingSession() as db:
    if not db.query(User).filter_by(username="testadmin").first():
        db.add(User(username="testadmin", password_hash=hash_password("testing-password-123"), role="admin")); db.commit()
client = TestClient(app)
def test_login_rejects_invalid_password():
    response = client.post("/api/v1/auth/login", json={"username": "testadmin", "password": "wrong-password"})
    assert response.status_code == 401
def test_login_and_me():
    response = client.post("/api/v1/auth/login", json={"username": "testadmin", "password": "testing-password-123"})
    assert response.status_code == 200
    token = response.json()["access_token"]
    me = client.get("/api/v1/auth/me", headers={"Authorization": f"Bearer {token}"})
    assert me.status_code == 200 and me.json()["role"] == "admin"
def test_router_list_requires_authentication():
    assert client.get("/api/v1/routers").status_code == 401
