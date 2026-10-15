import pytest
from fastapi import HTTPException
from wireguard_manager_api.security import hash_password, verify_password
from wireguard_manager_api.peers import validate_address, _overlaps, generate_keypair
def test_password_policy_and_hashing():
    with pytest.raises(ValueError): hash_password("short")
    encoded = hash_password("a-long-development-password")
    assert encoded != "a-long-development-password"
    assert verify_password("a-long-development-password", encoded)
    assert not verify_password("wrong-password", encoded)
def test_peer_address_rejects_broad_ipv4_route():
    with pytest.raises(HTTPException): validate_address("10.0.0.0/8")
def test_peer_address_accepts_single_host():
    assert validate_address("10.20.0.2/32") == "10.20.0.2/32"

def test_peer_network_overlap_detection():
    assert _overlaps("10.20.0.2/32", "10.20.0.0/24")
    assert not _overlaps("10.20.1.2/32", "10.20.0.0/24")
    assert not _overlaps("2001:db8::1/128", "10.20.0.0/24")

def test_generated_wireguard_keypair_is_valid_base64_and_distinct():
    import base64
    private, public = generate_keypair()
    assert len(base64.b64decode(private, validate=True)) == 32
    assert len(base64.b64decode(public, validate=True)) == 32
    assert private != public

def test_client_config_inputs_validate_server_key_and_endpoint():
    import base64
    from pydantic import ValidationError
    from wireguard_manager_api.schemas import ClientConfigRequest
    key = base64.b64encode(b"x" * 32).decode()
    request = ClientConfigRequest(server_public_key=key, endpoint="vpn.example.com:51820")
    assert request.endpoint == "vpn.example.com:51820"
    with pytest.raises(ValidationError):
        ClientConfigRequest(server_public_key="not-a-wireguard-key", endpoint="vpn.example.com:51820")
    with pytest.raises(ValidationError):
        ClientConfigRequest(server_public_key=key, endpoint="vpn.example.com:99999")

def test_linux_host_validation_accepts_private_ip_and_rejects_hostname():
    from wireguard_manager_api.linux_servers import validate_linux_host
    assert validate_linux_host("10.20.30.40") == "10.20.30.40"
    with pytest.raises(ValueError):
        validate_linux_host("vpn.example.com")
    with pytest.raises(ValueError):
        validate_linux_host("127.0.0.1")

def test_linux_install_plan_is_distribution_specific():
    from wireguard_manager_api.linux_servers import _install_plan
    assert "apt-get update" in _install_plan("ubuntu", "apt-get")[0]["command"]
    assert "dnf install" in _install_plan("rocky", "dnf")[0]["command"]
    assert "zypper" in _install_plan("opensuse-leap", "zypper")[0]["command"]
    assert "apk add" in _install_plan("alpine", "apk")[0]["command"]
    assert _install_plan("unknown", "unknown") == []

def test_linux_peer_address_validation_rejects_broad_and_loopback_routes():
    from fastapi import HTTPException
    from wireguard_manager_api.linux_peers import _address
    assert _address("10.10.10.2/32") == "10.10.10.2/32"
    with pytest.raises(HTTPException):
        _address("10.0.0.0/8")
    with pytest.raises(HTTPException):
        _address("127.0.0.1/32")
