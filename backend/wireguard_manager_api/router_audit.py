"""Read-only RouterOS security/configuration audit. This module never calls a write method."""
from datetime import datetime, timezone
from typing import Any

from fastapi import APIRouter, Depends, HTTPException
from sqlalchemy.orm import Session

from .audit import record_event
from .db import get_db
from .dependencies import current_user, require_roles
from .models import Router, User
from .routeros import RouterConnectionError
from .routers import client_for

router = APIRouter(prefix="/api/v1/routers", tags=["router-audit"])

# Only GET requests are issued. These checks are intentionally bounded and do not
# attempt exploit validation, brute force, configuration changes, or reboot actions.
AUDIT_RESOURCES = {
    "system_resource": "/system/resource",
    "system_identity": "/system/identity",
    "system_packages": "/system/package",
    "management_services": "/ip/service",
    "firewall_input": "/ip/firewall/filter",
    "firewall_nat": "/ip/firewall/nat",
    "ip_addresses": "/ip/address",
    "routes": "/ip/route",
    "wireguard_interfaces": "/interface/wireguard",
    "wireguard_peers": "/interface/wireguard/peers",
}


def as_rows(value: Any) -> list[dict]:
    if isinstance(value, list):
        return [row for row in value if isinstance(row, dict)]
    if isinstance(value, dict):
        return [value]
    return []


def enabled(row: dict) -> bool:
    return str(row.get("disabled", "false")).lower() not in {"true", "yes", "1"}


def finding(findings: list[dict], severity: str, code: str, title: str,
            description: str, recommendation: str, evidence: dict | None = None) -> None:
    findings.append({
        "id": code,
        "severity": severity,
        "title": title,
        "description": description,
        "recommendation": recommendation,
        "evidence": evidence or {},
    })


def analyze_inventory(inventory: dict[str, Any]) -> list[dict]:
    """Pure analysis function, separated for deterministic unit testing."""
    findings: list[dict] = []

    resources = as_rows(inventory.get("system_resource"))
    if resources:
        resource = resources[0]
        version = str(resource.get("version", "")).strip()
        if version:
            finding(
                findings, "review", "ROS_VERSION_SUPPORT_REVIEW",
                "RouterOS version support requires verification",
                "The running RouterOS version was collected, but this audit does not use a live vendor security-advisory feed and cannot assert whether it is currently vulnerable.",
                "Compare the exact version and device model with MikroTik's official security advisories and supported release channel before making changes.",
                {"version": version, "architecture": resource.get("architecture-name"), "board": resource.get("board-name")},
            )
        else:
            finding(findings, "info", "ROS_VERSION_UNAVAILABLE", "RouterOS version not reported",
                    "The API account did not return a version field.", "Verify RouterOS version visibility and manually review vendor advisories.")

    services = as_rows(inventory.get("management_services"))
    risky_services = {"ftp", "telnet", "www", "api"}
    observed = []
    for service in services:
        if not enabled(service):
            continue
        name = str(service.get("name", "")).lower()
        if name not in risky_services:
            continue
        address = str(service.get("address", "")).strip()
        observed.append({"name": name, "port": service.get("port"), "address_restriction_configured": bool(address)})
        if not address:
            severity = "high" if name in {"telnet", "ftp", "api"} else "medium"
            finding(
                findings, severity, "ROS_MGMT_SERVICE_UNRESTRICTED_" + name.upper(),
                f"Management service '{name}' is enabled without an address restriction",
                "RouterOS reports this management service as enabled and its service-level address allowlist is empty. This does not by itself prove internet exposure; firewall and network placement still matter.",
                "Disable the service if unused, or restrict allowed management source networks and verify the input firewall from a trusted management host.",
                {"service": name, "port": service.get("port")},
            )
        else:
            finding(
                findings, "info", "ROS_MGMT_SERVICE_RESTRICTED_" + name.upper(),
                f"Management service '{name}' has an address restriction",
                "A service-level address restriction is configured; this audit cannot verify that the listed networks are appropriate for your environment.",
                "Confirm the allowlist contains only approved management networks and review the input firewall.",
                {"service": name, "port": service.get("port"), "address_restriction_configured": True},
            )

    rules = [r for r in as_rows(inventory.get("firewall_input")) if enabled(r) and str(r.get("chain", "")).lower() == "input"]
    terminal_rules = [r for r in rules if str(r.get("action", "")).lower() in {"drop", "reject"}]
    if not rules:
        finding(findings, "review", "ROS_INPUT_FIREWALL_UNAVAILABLE",
                "Input firewall rules could not be confirmed",
                "No enabled input-chain rules were returned. This can mean no such rules exist or the API account cannot read them.",
                "Verify API permissions and inspect the complete input chain and interface lists in WinBox/RouterOS.")
    elif not terminal_rules:
        finding(findings, "high", "ROS_INPUT_NO_DROP_REJECT",
                "No enabled input-chain drop/reject rule was found",
                "The returned enabled input rules contain no drop/reject action. This is a review signal, not proof that the router is exposed: interface lists, raw rules, dynamic rules, and other controls can affect reachability.",
                "Review input-chain rule order and ensure management access is explicitly allowed only from trusted networks before a final drop rule.")
    else:
        finding(findings, "info", "ROS_INPUT_TERMINAL_RULE_PRESENT",
                "Input-chain drop/reject rule detected",
                "At least one enabled drop/reject rule was returned; ordering and actual packet behavior were not tested.",
                "Manually verify rule order, interface-list membership, established/related handling, and management access from an authorized source.",
                {"enabled_input_rules": len(rules), "drop_reject_rules": len(terminal_rules)})

    peers = as_rows(inventory.get("wireguard_peers"))
    interfaces = as_rows(inventory.get("wireguard_interfaces"))
    if not interfaces:
        finding(findings, "review", "ROS_WG_INTERFACES_EMPTY",
                "No WireGuard interfaces were returned",
                "No WireGuard interfaces were visible to this API account.",
                "Confirm WireGuard is expected on this router and that the API account can read WireGuard resources.")
    else:
        disabled_interfaces = [str(x.get("name", x.get(".id", "unknown"))) for x in interfaces if not enabled(x)]
        if disabled_interfaces:
            finding(findings, "review", "ROS_WG_INTERFACE_DISABLED",
                    "Disabled WireGuard interface(s) detected",
                    "One or more returned WireGuard interfaces are disabled.",
                    "Confirm each disabled interface is intentional before proceeding.",
                    {"interfaces": disabled_interfaces})
        finding(findings, "info", "ROS_WG_INVENTORY",
                "WireGuard inventory collected",
                "WireGuard interfaces and peer records were read successfully; peer connectivity and key correctness were not actively tested.",
                "Review peer ownership, allowed-address overlap, stale peers, endpoint reachability, and handshake freshness in the next configuration step.",
                {"interface_count": len(interfaces), "peer_count": len(peers)})

    if "firewall_nat" in inventory:
        nat_rules = as_rows(inventory.get("firewall_nat"))
        finding(findings, "info", "ROS_NAT_RULES_COLLECTED",
                "NAT rules collected",
                "NAT rules were read for context; this audit does not infer whether every NAT rule is correct for your intended topology.",
                "Compare NAT behavior with the intended VPN routing design and confirm no existing rules conflict with the planned configuration.",
                {"rule_count": len(nat_rules)})

    # Missing resources are reported by the caller as unassessed checks. We do not
    # convert missing visibility into a clean bill of health.
    return findings


@router.get("/{router_id}/audit")
async def read_only_router_audit(
    router_id: int,
    db: Session = Depends(get_db),
    user: User = Depends(require_roles("admin", "operator")),
):
    """Collect a read-only RouterOS configuration/security review report."""
    item = db.get(Router, router_id)
    if item is None:
        raise HTTPException(404, "Router not found")

    client = client_for(item)
    inventory: dict[str, Any] = {}
    checks: list[dict] = []
    for name, path in AUDIT_RESOURCES.items():
        started = datetime.now(timezone.utc)
        try:
            result = await client.get(path)  # Intentionally GET-only; never use post/patch/delete here.
            inventory[name] = result
            checks.append({
                "name": name,
                "status": "collected",
                "item_count": len(result) if isinstance(result, list) else (1 if result else 0),
                "duration_ms": int((datetime.now(timezone.utc) - started).total_seconds() * 1000),
            })
        except (RouterConnectionError, ValueError):
            checks.append({
                "name": name,
                "status": "unassessed",
                "item_count": None,
                "duration_ms": int((datetime.now(timezone.utc) - started).total_seconds() * 1000),
                "note": "Request failed or permission was insufficient; this area is not considered clean.",
            })

    findings = analyze_inventory(inventory)
    unassessed = [c["name"] for c in checks if c["status"] == "unassessed"]
    for name in unassessed:
        finding(findings, "review", "ROS_CHECK_UNASSESSED_" + name.upper(),
                f"Could not assess: {name.replace('_', ' ')}",
                "The required read-only resource could not be collected. This is not evidence that the configuration is safe.",
                "Check RouterOS API permissions, device compatibility, and reachability; then run the audit again.",
                {"check": name})

    counts = {level: sum(1 for f in findings if f["severity"] == level)
              for level in ("critical", "high", "medium", "low", "review", "info")}
    status = "attention_required" if counts["critical"] or counts["high"] or counts["medium"] or counts["review"] else "no_findings_detected"
    report = {
        "report_type": "read_only_routeros_audit",
        "report_version": 1,
        "router": {"id": item.id, "name": item.name, "host": item.host, "port": item.port},
        "generated_at": datetime.now(timezone.utc).isoformat(),
        "status": status,
        "read_only": True,
        "configuration_changed": False,
        "limitations": [
            "This is a configuration review, not a penetration test or a guarantee of security.",
            "No live CVE/vendor advisory feed is queried; firmware vulnerability status requires manual verification.",
            "Network exposure, rule ordering, and actual packet behavior cannot be fully established from read-only API inventory alone.",
            "Unassessed checks must be resolved before treating the report as complete.",
        ],
        "summary": {"checks_total": len(checks), "checks_collected": len(checks) - len(unassessed),
                    "checks_unassessed": len(unassessed), "findings_by_severity": counts},
        "checks": checks,
        "findings": findings,
        "next_actions": [
            {"id": "continue", "label": "Continue to configuration", "enabled": True,
             "note": "If high-risk findings or unassessed checks exist, review them carefully. Continuing does not apply changes automatically; every future write action must have its own explicit confirmation."},
            {"id": "export", "label": "Export report", "enabled": True},
            {"id": "close", "label": "Close", "enabled": True},
        ],
    }
    record_event(db, user.username, "router.read_only_audit", "router", str(item.id),
                 outcome="warning" if status == "attention_required" else "success",
                 details={"status": status, "checks_total": len(checks), "checks_unassessed": len(unassessed),
                          "findings_by_severity": counts})
    db.commit()
    return report
