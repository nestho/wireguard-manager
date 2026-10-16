"""Validated per-peer destination ACLs and platform rule generation."""
from __future__ import annotations

import ipaddress
import re
import shlex
from typing import Iterable

MAX_NETWORKS = 128
MANAGED_COMMENT_PREFIX = "wgm-acl-peer-"


def normalize_networks(values: Iterable[str]) -> list[str]:
    """Canonicalize a bounded list of destination CIDRs; empty means deny all."""
    if isinstance(values, (str, bytes)):
        raise ValueError("access_networks must be a list of CIDR strings")
    result: list[str] = []
    seen: set[str] = set()
    for raw in values:
        if not isinstance(raw, str) or not raw.strip():
            raise ValueError("Each access network must be a non-empty CIDR string")
        try:
            network = ipaddress.ip_network(raw.strip(), strict=False)
        except ValueError as exc:
            raise ValueError(f"Invalid access network: {raw!r}") from exc
        if network.is_loopback or network.is_link_local or network.is_multicast or network.is_unspecified:
            raise ValueError(f"Special-purpose destination network is not allowed: {network}")
        canonical = str(network)
        if canonical not in seen:
            result.append(canonical)
            seen.add(canonical)
        if len(result) > MAX_NETWORKS:
            raise ValueError(f"At most {MAX_NETWORKS} destination networks may be assigned")
    return result


def _peer_ip(peer_address: str) -> str:
    try:
        return str(ipaddress.ip_interface(peer_address).ip)
    except ValueError as exc:
        raise ValueError("Peer address must be a valid IP interface") from exc


def nft_rules(peer_id: int, peer_address: str, networks: list[str]) -> str:
    """Return a deterministic nftables fragment for one peer; no shell syntax."""
    if peer_id < 1:
        raise ValueError("peer_id must be positive")
    source = _peer_ip(peer_address)
    if any(ipaddress.ip_network(network, strict=False).version != ipaddress.ip_address(source).version for network in networks):
        raise ValueError("Destination network IP family must match the peer address")
    table = f"wgm_acl_{peer_id}"
    lines = [f"table inet {table} {{", "  chain forward_guard {", "    type filter hook forward priority -10; policy accept;"]
    for network in networks:
        parsed = ipaddress.ip_network(network, strict=False)
        if parsed.version == 4:
            lines.append(f"    ip saddr {source} ip daddr {parsed} accept")
        else:
            lines.append(f"    ip6 saddr {source} ip6 daddr {parsed} accept")
    lines.append(f"    { 'ip' if ipaddress.ip_address(source).version == 4 else 'ip6' } saddr {source} drop")
    lines.extend(["  }", "}"])
    return "\n".join(lines) + "\n"


def routeros_rule_plan(peer_id: int, peer_address: str, networks: list[str]) -> list[dict[str, str]]:
    """Rules are intended to be installed at the top of forward filter in safe order."""
    if peer_id < 1:
        raise ValueError("peer_id must be positive")
    source = _peer_ip(peer_address)
    comment = f"{MANAGED_COMMENT_PREFIX}{peer_id}"
    rules = [{
        "chain": "forward", "action": "drop", "src-address": source,
        "comment": f"{comment}-deny",
    }]
    for index, network in reversed(list(enumerate(networks))):
        rules.insert(0, {
            "chain": "forward", "action": "accept", "src-address": source,
            "dst-address": network, "comment": f"{comment}-allow-{index}",
        })
    return rules
