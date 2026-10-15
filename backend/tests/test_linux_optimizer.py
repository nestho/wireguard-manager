from fastapi.testclient import TestClient
from wireguard_manager_api.main import app
from wireguard_manager_api.linux_optimizer import TUNING, _int_sysctl, _section

client = TestClient(app)

def test_optimizer_tuning_allowlist_is_conservative():
    assert set(TUNING) == {"socket_receive_buffer", "socket_send_buffer", "network_backlog"}
    assert TUNING["socket_receive_buffer"]["key"] == "net.core.rmem_max"
    assert TUNING["network_backlog"]["value"] == 4096

def test_optimizer_parsing_helpers():
    assert _int_sysctl("4194304\n") == 4194304
    assert _int_sysctl("unavailable") is None
    assert _section("prefix__WGM_KERNEL__Linux host__WGM_CPU__cpu data", "KERNEL") == "Linux host"

def test_optimizer_apply_schema_rejects_empty_list():
    from pydantic import ValidationError
    from wireguard_manager_api.linux_optimizer import OptimizerApplyRequest
    import pytest
    with pytest.raises(ValidationError):
        OptimizerApplyRequest(recommendation_ids=[], confirm=True)
    request = OptimizerApplyRequest(recommendation_ids=["network_backlog"], confirm=True)
    assert request.confirm is True
