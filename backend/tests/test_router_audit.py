from wireguard_manager_api.router_audit import analyze_inventory


def test_unrestricted_telnet_and_api_are_high_risk():
    findings = analyze_inventory({
        "management_services": [
            {"name": "telnet", "disabled": "false", "port": 23, "address": ""},
            {"name": "api", "disabled": "false", "port": 8728},
        ],
        "firewall_input": [{"chain": "input", "action": "accept", "disabled": "false"}],
        "wireguard_interfaces": [{"name": "wg0", "disabled": "false"}],
        "wireguard_peers": [],
        "system_resource": [{"version": "7.x"}],
        "firewall_nat": [],
    })
    ids = {f["id"] for f in findings}
    assert "ROS_MGMT_SERVICE_UNRESTRICTED_TELNET" in ids
    assert "ROS_MGMT_SERVICE_UNRESTRICTED_API" in ids
    assert "ROS_INPUT_NO_DROP_REJECT" in ids


def test_disabled_management_services_are_not_flagged_as_enabled():
    findings = analyze_inventory({
        "management_services": [{"name": "telnet", "disabled": "true", "port": 23}],
        "firewall_input": [{"chain": "input", "action": "drop", "disabled": "false"}],
        "wireguard_interfaces": [{"name": "wg0", "disabled": "false"}],
        "wireguard_peers": [],
        "system_resource": [{"version": "7.16.2"}],
        "firewall_nat": [],
    })
    assert not any(f["id"] == "ROS_MGMT_SERVICE_UNRESTRICTED_TELNET" for f in findings)
    assert any(f["id"] == "ROS_INPUT_TERMINAL_RULE_PRESENT" for f in findings)


def test_no_wireguard_inventory_is_review_finding():
    findings = analyze_inventory({
        "management_services": [],
        "firewall_input": [],
        "wireguard_interfaces": [],
        "wireguard_peers": [],
        "system_resource": [],
        "firewall_nat": [],
    })
    assert any(f["id"] == "ROS_WG_INTERFACES_EMPTY" for f in findings)
    assert any(f["id"] == "ROS_INPUT_FIREWALL_UNAVAILABLE" for f in findings)


def test_report_does_not_claim_version_is_vulnerable():
    findings = analyze_inventory({
        "system_resource": [{"version": "7.16.2"}],
        "management_services": [],
        "firewall_input": [{"chain": "input", "action": "drop"}],
        "wireguard_interfaces": [{"name": "wg0"}],
        "wireguard_peers": [],
        "firewall_nat": [],
    })
    version_finding = next(f for f in findings if f["id"] == "ROS_VERSION_SUPPORT_REVIEW")
    assert version_finding["severity"] == "review"
    assert "cannot assert whether it is currently vulnerable" in version_finding["description"]
