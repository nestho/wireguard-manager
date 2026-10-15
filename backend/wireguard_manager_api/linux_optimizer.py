"""Evidence-based, opt-in Linux WireGuard host assessment and conservative sysctl tuning.

The assessment is read-only. Applying changes is admin-only, disabled by default,
and limited to a small allowlist of reversible network-buffer/backlog sysctls.
It deliberately does not change CPU governor, IRQ affinity, NIC offloads, MTU,
firewall, routing, congestion control, or kernel packages automatically.
"""
import re
import shlex
from datetime import datetime, timezone

from fastapi import APIRouter, Depends, HTTPException
from pydantic import BaseModel, Field
from sqlalchemy.orm import Session

from .audit import record_event
from .config import get_settings
from .db import get_db
from .dependencies import require_roles
from .linux_servers import _connect, _run, _server
from .models import User

router = APIRouter(prefix="/api/v1/linux-servers", tags=["linux-optimizer"])

# Fixed values only: never accept arbitrary sysctl names/values or shell commands.
TUNING = {
    "socket_receive_buffer": {
        "key": "net.core.rmem_max", "value": 4194304,
        "title": "Maximum socket receive buffer",
        "reason": "Can prevent receive-buffer ceilings from constraining high-throughput or high-RTT UDP flows.",
        "risk": "Allows larger per-socket buffers; memory use can increase under load.",
    },
    "socket_send_buffer": {
        "key": "net.core.wmem_max", "value": 4194304,
        "title": "Maximum socket send buffer",
        "reason": "Raises the ceiling available to applications that request larger UDP send buffers.",
        "risk": "Allows larger per-socket buffers; memory use can increase under load.",
    },
    "network_backlog": {
        "key": "net.core.netdev_max_backlog", "value": 4096,
        "title": "Network receive backlog",
        "reason": "Provides more queue headroom during short bursts when packets arrive faster than the kernel processes them.",
        "risk": "A larger queue can increase latency during sustained overload instead of fixing a CPU bottleneck.",
    },
}
DROPIN = "/etc/sysctl.d/90-wgm-wireguard-optimizer.conf"


class OptimizerApplyRequest(BaseModel):
    recommendation_ids: list[str] = Field(min_length=1, max_length=3)
    confirm: bool = False


def _section(output: str, name: str) -> str:
    marker = f"__WGM_{name}__"
    if marker not in output:
        return ""
    return output.split(marker, 1)[1].split("__WGM_", 1)[0].strip()


def _int_sysctl(value: str) -> int | None:
    """Parse a complete integer sysctl value; do not accept numeric fragments."""
    match = re.fullmatch(r"\s*(-?\d+)\s*", value)
    return int(match.group(1)) if match else None


def _build_apply_script(recommendation_ids: list[str], previous: dict[str, int]) -> str:
    """Build a fixed-allowlist shell transaction with best-effort compensation."""
    unknown = sorted(set(recommendation_ids) - set(TUNING))
    if unknown or len(set(recommendation_ids)) != len(recommendation_ids):
        raise ValueError("Unsupported or duplicate optimizer recommendation IDs")
    expected_keys = {TUNING[rid]["key"] for rid in recommendation_ids}
    if set(previous) != expected_keys or any(type(value) is not int for value in previous.values()):
        raise ValueError("Previous sysctl values must be integers for every selected setting")

    content = "# Managed by WireGuard Manager; remove this file to revert persistent overrides.\n"
    content += "".join(
        f"{TUNING[rid]['key']} = {TUNING[rid]['value']}\n"
        for rid in recommendation_ids
    )
    lines = [
        "set -eu",
        f"dropin={shlex.quote(DROPIN)}",
        "tmp=$(mktemp /etc/sysctl.d/.wgm-optimizer.XXXXXX)",
        "created=0",
        "rollback() {",
        "  rc=$?",
        "  trap - EXIT",
        '  if [ "$rc" -ne 0 ]; then',
        '    if [ "$created" -eq 1 ]; then rm -f -- "$dropin" || true; fi',
    ]
    for key, value in previous.items():
        lines.append(f"    sysctl -w {key}={value} >/dev/null 2>&1 || true")
    lines.extend([
        "  fi",
        '  rm -f -- "$tmp" 2>/dev/null || true',
        '  exit "$rc"',
        "}",
        "trap rollback EXIT",
        "printf %s " + shlex.quote(content) + ' > "$tmp"',
        'chmod 0644 "$tmp"',
        # ln is atomic and refuses to replace a pre-existing destination.
        'ln "$tmp" "$dropin"',
        "created=1",
        'rm -f -- "$tmp"',
    ])
    lines.extend(
        f"sysctl -w {TUNING[rid]['key']}={TUNING[rid]['value']}"
        for rid in recommendation_ids
    )
    lines.append("trap - EXIT")
    return "\n".join(lines)


@router.post("/{server_id}/optimizer/inspect")
async def inspect_optimizer(server_id: int, db: Session = Depends(get_db), user: User = Depends(require_roles("admin", "operator"))):
    server = _server(db, server_id)
    command = (
        "printf '__WGM_OS__\n'; cat /etc/os-release 2>/dev/null; "
        "printf '__WGM_KERNEL__\n'; uname -a; "
        "printf '__WGM_CPU__\n'; lscpu 2>/dev/null | grep -E '^(Architecture|CPU\\(s\\)|On-line CPU|Thread|Core|Socket|Model name|CPU max MHz|Virtualization):' | head -30; "
        "printf '__WGM_MEMORY__\n'; free -b 2>/dev/null; "
        "printf '__WGM_LINKS__\n'; ip -s -br link 2>/dev/null; "
        "printf '__WGM_SYSCTLS__\n'; for k in net.core.rmem_max net.core.wmem_max net.core.netdev_max_backlog net.ipv4.ip_forward net.ipv4.conf.all.rp_filter net.ipv4.tcp_congestion_control net.core.default_qdisc; do printf '%s=' \"$k\"; sysctl -n \"$k\" 2>/dev/null || true; done; "
        "printf '__WGM_MODULES__\n'; (lsmod 2>/dev/null | grep -E '^(wireguard|sch_fq|tcp_bbr) ' || true); "
        "printf '__WGM_OFFLOADS__\n'; for n in $(ip -o link show 2>/dev/null | awk -F': ' '{print $2}' | cut -d@ -f1 | grep -v '^lo$' | head -8); do printf '%s\n' \"### $n\"; ethtool -k \"$n\" 2>/dev/null | grep -E '^(generic-receive-offload|generic-segmentation-offload|tcp-segmentation-offload|tx-checksumming|rx-checksumming):' || true; done; "
        "printf '__WGM_QDISC__\n'; tc qdisc show 2>/dev/null | head -30; "
        "printf '__WGM_WG__\n'; if command -v wg >/dev/null 2>&1; then wg show interfaces 2>/dev/null; else echo 'wg not installed'; fi; "
    )
    conn = await _connect(server)
    try:
        output = await _run(conn, command, timeout=30)
    finally:
        conn.close()
        await conn.wait_closed()

    sysctls = {}
    for line in _section(output, "SYSCTLS").splitlines():
        if "=" in line:
            key, value = line.split("=", 1)
            sysctls[key.strip()] = value.strip()
    recommendations = []
    for rec_id, item in TUNING.items():
        current = _int_sysctl(sysctls.get(item["key"], ""))
        if current is not None and current < item["value"]:
            recommendations.append({
                "id": rec_id, "title": item["title"], "key": item["key"],
                "current": current, "proposed": item["value"], "unit": "bytes" if rec_id.startswith("socket_") else "packets",
                "reason": item["reason"], "risk": item["risk"],
                "reversible": True, "requires_confirmation": True,
            })

    kernel = _section(output, "KERNEL")
    cpu = _section(output, "CPU")
    memory = _section(output, "MEMORY")
    links = _section(output, "LINKS")
    modules = _section(output, "MODULES")
    offloads = _section(output, "OFFLOADS")
    qdisc = _section(output, "QDISC")
    wg = _section(output, "WG")
    manual_checks = [
        {"id": "mtu-path", "title": "Validate end-to-end MTU / PMTUD", "status": "manual",
         "detail": "Check client-to-server path MTU and fragmentation with real probes before changing MTU; never guess a universal value."},
        {"id": "nic-driver", "title": "Inspect NIC/virtual NIC driver and counters", "status": "manual",
         "detail": "Compare ethtool -S, driver/firmware and hypervisor limits under load; do not toggle offloads blindly."},
        {"id": "cpu-irq", "title": "Measure CPU saturation and IRQ distribution", "status": "manual",
         "detail": "Use mpstat, softnet_stat, /proc/interrupts and per-core load during a representative throughput test before changing affinity/RPS/XPS."},
        {"id": "bbr", "title": "Evaluate congestion control only for routed TCP traffic", "status": "manual",
         "detail": "WireGuard carries UDP. TCP BBR/FQ can affect TCP traffic through the tunnel but does not directly accelerate WireGuard's UDP transport; verify workload and kernel support first."},
    ]
    record_event(db, user.username, "linux_optimizer.inspect", "linux_server", str(server.id),
                 outcome="success", details={"recommendations": [x["id"] for x in recommendations], "read_only": True})
    db.commit()
    return {
        "server_id": server.id, "server_name": server.name, "host": server.host,
        "inspected_at": datetime.now(timezone.utc).isoformat(), "read_only": True,
        "system": {"kernel": kernel, "cpu": cpu, "memory": memory, "links": links,
                   "sysctls": sysctls, "modules": modules, "offloads": offloads, "qdisc": qdisc, "wireguard_interfaces": wg},
        "recommendations": recommendations, "manual_checks": manual_checks,
        "apply_enabled": get_settings().enable_linux_optimizer_mutations,
        "notice": "Findings are host snapshots, not a throughput benchmark. Apply only after reviewing impact and testing a maintenance window.",
    }


@router.post("/{server_id}/optimizer/apply")
async def apply_optimizer(server_id: int, body: OptimizerApplyRequest, db: Session = Depends(get_db), user: User = Depends(require_roles("admin"))):
    settings = get_settings()
    if not settings.enable_linux_optimizer_mutations:
        raise HTTPException(503, "Linux optimizer changes are disabled; set WGM_ENABLE_LINUX_OPTIMIZER_MUTATIONS=true only after reviewing the deployment")
    if body.confirm is not True:
        raise HTTPException(400, "Explicit confirm=true is required to apply system-wide kernel network tuning")
    if len(set(body.recommendation_ids)) != len(body.recommendation_ids):
        raise HTTPException(422, "Duplicate recommendation IDs are not allowed")
    unknown = sorted(set(body.recommendation_ids) - set(TUNING))
    if unknown:
        raise HTTPException(422, "Unsupported recommendation IDs: " + ", ".join(unknown))

    server = _server(db, server_id)
    # Never overwrite an existing file, which may have been created or edited by an operator.
    conn = await _connect(server)
    try:
        probe = await conn.run(f"sudo -n test ! -e {DROPIN}", check=False, timeout=10)
        if probe.exit_status != 0:
            raise HTTPException(409, f"{DROPIN} already exists or cannot be checked; inspect it manually and do not overwrite it")
        previous = {}
        for rec_id in body.recommendation_ids:
            key = TUNING[rec_id]["key"]
            raw_value = (await _run(conn, f"sysctl -n {key}", timeout=10)).strip()
            parsed_value = _int_sysctl(raw_value)
            if parsed_value is None:
                raise HTTPException(502, f"Could not safely parse the current value of {key}; no changes were applied")
            previous[key] = parsed_value
        # The remote script creates the drop-in without overwriting an existing file.
        # If any write fails, its EXIT trap removes the new drop-in and restores prior runtime values.
        script = _build_apply_script(body.recommendation_ids, previous)
        command = "sudo -n sh -c " + shlex.quote(script)
        await _run(conn, command, timeout=30)
    except HTTPException:
        raise
    except Exception as exc:
        raise HTTPException(502, "Optimizer apply failed; inspect sysctl values and " + DROPIN + " before retrying") from exc
    finally:
        conn.close()
        await conn.wait_closed()

    record_event(db, user.username, "linux_optimizer.apply", "linux_server", str(server.id),
                 details={"recommendation_ids": body.recommendation_ids, "previous_values": previous, "dropin": DROPIN})
    db.commit()
    return {
        "status": "applied", "server_id": server.id, "changed": [
            {"id": rid, "key": TUNING[rid]["key"], "previous": previous[TUNING[rid]["key"]], "value": TUNING[rid]["value"]}
            for rid in body.recommendation_ids
        ],
        "persistent_file": DROPIN,
        "rollback": f"Remove {DROPIN} and run 'sudo sysctl --system' on the server; verify the resulting values. Review other sysctl sources first.",
        "note": "No kernel package, NIC offload, IRQ, MTU, firewall, route, or congestion-control changes were made.",
    }
