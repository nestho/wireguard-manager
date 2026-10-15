# Linux VPN server optimizer

The optimizer is a separate, admin-controlled workflow for registered Linux servers.

## Inspect first

Call `POST /api/v1/linux-servers/{id}/optimizer/inspect` as an admin or operator. It collects a read-only snapshot of kernel, CPU, memory, interfaces, selected network sysctls, NIC offload flags (where ethtool is installed), qdisc, loaded modules and WireGuard interfaces. The response separates concrete allowlisted sysctl recommendations from manual investigations.

This is not a throughput benchmark. Run representative iperf3/UDP and real tunnel tests before and after any changes, capture packet loss/latency/CPU, and test under the expected number of peers. Repeat the test on the actual VM/hypervisor and NIC type.

## Apply selected recommendations

Changes are admin-only and require both `confirm=true` and `WGM_ENABLE_LINUX_OPTIMIZER_MUTATIONS=true`. The flag defaults to false. Only these settings are currently allowlisted:

- `net.core.rmem_max = 4194304`
- `net.core.wmem_max = 4194304`
- `net.core.netdev_max_backlog = 4096`

The API refuses to overwrite an existing `/etc/sysctl.d/90-wgm-wireguard-optimizer.conf`. It uses `sudo -n`, so the SSH account must have narrowly scoped non-interactive sudo rights for the required commands. Review the proposed settings, their risks, and the current values before applying. Remove the drop-in and run `sudo sysctl --system` to roll back the persistent override, then verify actual values.

## Deliberately not automated

The optimizer does not automatically update/reboot the kernel, change CPU governor or IRQ/RPS/XPS affinity, toggle NIC offloads, set MTU, alter firewall/routes/forwarding, or switch TCP congestion control. Those actions depend on NIC/driver, hypervisor, traffic pattern, and routing/security requirements; the inspection response returns manual checks instead. In particular, WireGuard transports packets over UDP, so TCP BBR does not directly optimize WireGuard's outer transport.

## Operational safety

Keep the mutation flag off until reviewed and tested. Use a maintenance window, maintain out-of-band console access, and test rollback. A successful sysctl write does not guarantee higher throughput; retain a change only if measurements demonstrate improvement without regressions.
