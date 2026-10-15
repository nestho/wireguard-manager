import pytest
from wireguard_manager_api.routeros import validate_router_host

def test_private_router_ip_is_accepted():
    assert validate_router_host("192.168.88.1") == "192.168.88.1"

@pytest.mark.parametrize("host", ["127.0.0.1", "169.254.1.1", "224.0.0.1", "not-a-hostname", "https://192.168.1.1"])
def test_unsafe_router_hosts_are_rejected(host):
    with pytest.raises(ValueError):
        validate_router_host(host)

def test_public_router_ip_is_disabled_by_default():
    with pytest.raises(ValueError):
        validate_router_host("8.8.8.8")
