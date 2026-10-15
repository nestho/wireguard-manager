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


def test_sysctl_parser_rejects_partial_or_malformed_values():
    assert _int_sysctl("4194304\n") == 4194304
    assert _int_sysctl("not-a-number 4194304") is None
    assert _int_sysctl("4194304 trailing-text") is None


def test_apply_script_has_atomic_create_and_failure_compensation():
    from wireguard_manager_api.linux_optimizer import DROPIN, _build_apply_script

    script = _build_apply_script(
        ["socket_receive_buffer", "network_backlog"],
        {"net.core.rmem_max": 212992, "net.core.netdev_max_backlog": 1000},
    )
    assert "ln \"$tmp\" \"$dropin\"" in script
    assert "trap rollback EXIT" in script
    assert 'if [ "$created" -eq 1 ]; then rm -f -- "$dropin" || true; fi' in script
    assert "sysctl -w net.core.rmem_max=212992" in script
    assert "sysctl -w net.core.netdev_max_backlog=1000" in script
    assert DROPIN in script
    assert "mv " not in script


def test_apply_script_rejects_duplicate_unknown_ids_and_missing_previous_values():
    import pytest
    from wireguard_manager_api.linux_optimizer import _build_apply_script

    with pytest.raises(ValueError):
        _build_apply_script(["network_backlog", "network_backlog"], {"net.core.netdev_max_backlog": 1000})
    with pytest.raises(ValueError):
        _build_apply_script(["arbitrary_shell"], {})
    with pytest.raises(ValueError):
        _build_apply_script(["network_backlog"], {})
