import importlib.util
from importlib.machinery import SourceFileLoader
from pathlib import Path

import pytest

SCRIPT = Path(__file__).parents[1] / "scripts" / "wgm-acl-helper"
LOADER = SourceFileLoader("wgm_acl_helper", str(SCRIPT))
SPEC = importlib.util.spec_from_loader("wgm_acl_helper", LOADER)
HELPER = importlib.util.module_from_spec(SPEC)
assert SPEC.loader is not None
SPEC.loader.exec_module(HELPER)


def test_helper_renders_deny_all_for_empty_acl():
    table, full, update = HELPER.render(12, "10.9.0.12/32", [])
    assert table == "wgm_acl_12"
    assert "ip saddr 10.9.0.12 drop" in full
    assert "ip daddr" not in full
    assert "flush chain inet wgm_acl_12 forward_guard" in update


def test_helper_renders_allow_then_drop():
    _, full, update = HELPER.render(5, "10.9.0.5/32", ["172.16.16.0/24"])
    assert full.index("172.16.16.0/24 accept") < full.index("ip saddr 10.9.0.5 drop")
    assert "172.16.16.0/24 accept" in update


def test_helper_rejects_mixed_family_and_default_route():
    with pytest.raises(ValueError):
        HELPER.checked_networks(["2001:db8::/32"], 4)
    with pytest.raises(ValueError):
        HELPER.checked_networks(["0.0.0.0/0"], 4)


def test_helper_limits_network_count():
    with pytest.raises(ValueError):
        HELPER.checked_networks([f"10.{i}.0.0/16" for i in range(129)], 4)


def test_helper_atomic_write(tmp_path):
    target = tmp_path / "policy.nft"
    HELPER.atomic_write(target, "first\n")
    HELPER.atomic_write(target, "second\n")
    assert target.read_text() == "second\n"
