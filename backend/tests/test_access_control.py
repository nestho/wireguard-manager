import pytest

from wireguard_manager_api.access_control import normalize_networks, nft_rules, routeros_rule_plan


@pytest.mark.parametrize(("raw", "expected"), [
    (["172.16.16.0/24", "172.16.16.0/24"], ["172.16.16.0/24"]),
    (["10.1.2.3/24"], ["10.1.2.0/24"]),
    (["2001:db8:1::/64"], ["2001:db8:1::/64"]),
    ([], []),
])
def test_normalize_networks(raw, expected):
    assert normalize_networks(raw) == expected


@pytest.mark.parametrize("raw", [
    "not-a-network", "", "127.0.0.1/8", "169.254.0.0/16",
    "224.0.0.0/4", "0.0.0.0/0", "::/0", None,
])
def test_reject_invalid_or_special_networks(raw):
    with pytest.raises(ValueError):
        normalize_networks([raw])


def test_empty_acl_generates_deny_all_for_peer():
    script = nft_rules(7, "10.9.0.10/32", [])
    assert "ip saddr 10.9.0.10 drop" in script
    assert "ip daddr" not in script


def test_nft_rules_allow_declared_destinations_then_drop():
    script = nft_rules(2, "10.9.0.2/32", ["172.16.16.0/24"])
    assert "ip saddr 10.9.0.2 ip daddr 172.16.16.0/24 accept" in script
    assert script.index(" accept") < script.index(" drop")


def test_nft_rules_support_ipv6_peer_and_destinations():
    script = nft_rules(3, "fd00::3/128", ["2001:db8:1::/64"])
    assert "ip6 saddr fd00::3 ip6 daddr 2001:db8:1::/64 accept" in script


def test_nft_rules_reject_mixed_address_families():
    with pytest.raises(ValueError):
        nft_rules(2, "10.9.0.2/32", ["2001:db8:1::/64"])


def test_routeros_rule_plan_has_allow_before_deny_and_is_peer_scoped():
    rules = routeros_rule_plan(9, "10.9.0.9/32", ["172.16.16.0/24", "10.20.30.15/32"])
    assert rules[-1]["action"] == "drop"
    assert all(rule["src-address"] == "10.9.0.9" for rule in rules)
    assert [rule["action"] for rule in rules] == ["accept", "accept", "drop"]
    assert all(rule["comment"].startswith("wgm-acl-peer-9") for rule in rules)


def test_acl_network_limit_is_enforced():
    with pytest.raises(ValueError):
        normalize_networks([f"10.{i}.0.0/16" for i in range(129)])
