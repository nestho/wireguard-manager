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
