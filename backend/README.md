# WireGuard Manager API

FastAPI backend for WireGuard inventory and controlled RouterOS/Linux server operations. The default Vite/GitHub Pages build is a demo; the separate production build uses an authenticated API-backed UI served by a PM2-managed static web process that proxies same-origin API requests to FastAPI.

> [!WARNING]
> The PM2 deployment path and API-backed production UI are implemented, and CI covers frontend builds, known demo-fixture checks, migrations, and backend tests. This is not a security certification or proof of compatibility with live infrastructure. The production UI includes peer lifecycle, ACL, config/QR, diagnostics, router audit, user management, and audit browsing workflows, but live peer creation/revocation, Linux package installation, and optimizer apply operations remain gated off by default. Real-device end-to-end/failure-injection tests, rate limiting, timeout/rollback reconciliation, backup/restore drills, and off-host audit retention remain release gates.

## Contents

- [Requirements](#requirements)
- [Local setup](#local-setup)
- [Configuration](#configuration)
- [Implemented features](#implemented-features)
- [API routes](#api-routes)
- [Role model](#role-model)
- [Linux SSH and sudo requirements](#linux-ssh-and-sudo-requirements)
- [Safe mutation workflow](#safe-mutation-workflow)
- [Testing](#testing)
- [Operational limitations](#operational-limitations)

## Production host deployment

See the [production deployment and operations guide](../docs/PRODUCTION_DEPLOYMENT.md). On a prepared host, run `bash scripts/deploy-production.sh` from the repository root after creating `.env` from `.env.production.example` and configuring unique JWT/Fernet secrets, a persistent database URL, the exact external origin, and first-admin credentials. The script does not generate secrets or prompt for the admin password. It builds the isolated production UI, applies Alembic migrations without demo seeding/resetting, starts the API and web frontend under PM2, performs health checks, and removes one-time bootstrap credentials after the first bootstrap attempt. It preserves the existing `.env` and database files, but migrations are not an atomic rollback guarantee. Keep the services loopback-bound and put TLS/restricted ingress in front before remote use.

## Requirements

- Python 3.11+
- A SQLAlchemy-supported database; SQLite is the local default
- For RouterOS: HTTPS reachability and a dedicated account permitted to read the required REST resources
- For Linux: SSH reachability, public-key authentication, an independently verified SHA256 host-key fingerprint, and carefully scoped non-interactive sudo permissions for the specific commands used

## Local setup

Run these commands from the repository root:

~~~bash
python3 -m venv .venv
source .venv/bin/activate
python -m pip install -e ".[dev]"
cp backend/.env.example .env
~~~

Generate independent secrets:

~~~bash
python -c 'import secrets; print(secrets.token_urlsafe(48))'
python -c 'from cryptography.fernet import Fernet; print(Fernet.generate_key().decode())'
~~~

Set the generated values as WGM_JWT_SECRET and WGM_ENCRYPTION_KEY in the protected environment. Never commit them. Configure WGM_BOOTSTRAP_ADMIN_USERNAME and WGM_BOOTSTRAP_ADMIN_PASSWORD only for initial bootstrap; remove the bootstrap password from the environment after creating the admin account.

~~~bash
alembic upgrade head
uvicorn wireguard_manager_api.main:app --reload --app-dir backend
~~~

- API base URL: http://127.0.0.1:8000
- OpenAPI / Swagger UI: http://127.0.0.1:8000/docs
- Liveness: GET /healthz
- Readiness: GET /api/v1/health

The application deliberately does not create or mutate database schemas at startup. Apply reviewed Alembic migrations before deploying a new version.

## Configuration

See [backend/.env.example](.env.example). Main settings:

| Variable | Description | Default |
|---|---|---|
| WGM_DATABASE_URL | SQLAlchemy database URL | sqlite:///./wireguard-manager.db |
| WGM_JWT_SECRET | Access-token signing secret | Empty; configure a strong random secret |
| WGM_ENCRYPTION_KEY | Fernet encryption key for stored credentials/keys | Empty; configure and back up securely |
| WGM_ACCESS_TOKEN_MINUTES | Access-token lifetime | 15 |
| WGM_BOOTSTRAP_ADMIN_USERNAME | One-time bootstrap username | Empty |
| WGM_BOOTSTRAP_ADMIN_PASSWORD | One-time bootstrap password | Empty |
| WGM_ALLOWED_ORIGINS | CORS origin allowlist | http://localhost:5173 |
| WGM_ALLOW_PUBLIC_ROUTER_HOSTS | Permit public RouterOS target IPs | false |
| WGM_ALLOW_PUBLIC_LINUX_HOSTS | Permit public Linux SSH target IPs | false |
| WGM_ENABLE_PEER_MUTATIONS | Permit RouterOS peer create/revoke | false |
| WGM_ENABLE_LINUX_MUTATIONS | Permit Linux install and peer create/revoke | false |

These defaults are restrictive by design. Only change host/mutation settings after reviewing network egress controls, credentials, permissions, and rollback behavior.

## Implemented features

### Identity, authorization, and data protection
- JWT access authentication and refresh-token rotation/revocation.
- Argon2 password hashing.
- Admin, operator, and viewer roles.
- One-time admin bootstrap and admin user provisioning.
- SQLAlchemy models with Alembic migrations.
- Fernet encryption for stored RouterOS credentials, Linux SSH private keys, and peer private keys.
- Hash-linked audit events and admin-only chain verification.

### RouterOS provider
- Register RouterOS targets and test REST connectivity over HTTPS with TLS verification.
- Read WireGuard interfaces/peers and current traffic counters.
- Run bounded read-only diagnostics.
- Validate peer addresses and interface selection, and check local and remote address overlaps before writes.
- Guard peer creation/revocation with WGM_ENABLE_PEER_MUTATIONS=false by default, explicit confirmation, and compensating rollback attempts.
- Generate client config and QR PNG outputs with audit events and no-store response headers.

- Versioned API, health checks, JWT access tokens, Argon2 password hashing, and admin/operator/viewer RBAC.
- Admin-only initial bootstrap and user provisioning.
- SQLAlchemy persistence models and an initial Alembic migration.
- Fernet-encrypted router credentials and an encrypted private-key field.
- RouterOS registration, TLS-verified REST connectivity test, read-only peer discovery, point-in-time traffic counters, and bounded diagnostics.
- Linux SSH onboarding with pinned SHA256 host-key fingerprints, encrypted private-key storage, distro/kernel/package-manager detection, and package plans for Debian/Ubuntu, Fedora/RHEL family, openSUSE/SLES, and Alpine.
- Linux interface/peer discovery, point-in-time counters, and gated peer create/revoke with `wg set`, `wg-quick save`, explicit confirmation, and compensating rollback attempts.
- Admin-controlled Linux VPN optimizer: read-only host inspection, evidence-based sysctl recommendations, and optional allowlisted tuning behind a default-off feature flag.
- Audited Linux client config and QR delivery with no-store response headers.
- IP-literal host validation to reduce DNS rebinding/SSRF risk; public router addresses disabled by default.
- Peer address validation, router-side overlap checks, dry-run preview, and create/revoke endpoints guarded by default-off mutation gates.
- Hash-linked audit records with chain verification.


## Read-only RouterOS pre-configuration audit

Authenticated admins/operators can run `GET /api/v1/routers/{router_id}/audit` before proceeding to configuration. The handler issues only RouterOS REST GET requests for system identity/resource/package metadata, management services, input firewall rules, NAT, IP addresses/routes, and WireGuard interfaces/peers. It never calls the client's POST/PATCH/DELETE methods. A summary event is written to the manager's own audit database; RouterOS configuration is not modified.

The report includes per-resource collection status, severity-labelled findings, recommendations, evidence, limitations, and next-action hints. Missing permissions/connectivity produce `unassessed` checks and review findings rather than a clean bill of health. The desktop client exports JSON/HTML. Treat exported reports as sensitive because they can contain internal addresses and security posture details.

This is a bounded configuration review, not a vulnerability scanner or penetration test. It does not test exploitability, prove actual network exposure, or consult a live CVE feed. The RouterOS version is returned for manual comparison with official MikroTik security advisories. Firewall findings require manual validation against rule ordering and network topology.

## Linux VPN server optimizer

See [linux-vpn-optimizer.md](linux-vpn-optimizer.md). The read-only endpoint `POST /api/v1/linux-servers/{id}/optimizer/inspect` collects kernel/CPU/memory/network-interface/sysctl/qdisc/NIC-offload/module/WireGuard snapshots and separates actionable recommendations from manual checks.

The apply endpoint `POST /api/v1/linux-servers/{id}/optimizer/apply` is admin-only, requires `confirm=true`, and remains disabled unless `WGM_ENABLE_LINUX_OPTIMIZER_MUTATIONS=true` is deliberately configured. Current automatic changes are limited to socket receive/send buffer ceilings and the network receive backlog. Kernel upgrades/reboots, CPU governor, IRQ/RPS/XPS, NIC offloads, MTU, routes/firewall/forwarding, and congestion control are not changed automatically.

## Linux server setup and safety

Linux API routes are documented at `/docs` under `linux-servers`, `linux-peers`, and `linux-optimizer`. Registration requires a private SSH key and an independently verified `SHA256:` host-key fingerprint. Public SSH targets are blocked unless `WGM_ALLOW_PUBLIC_LINUX_HOSTS=true` is deliberately configured after egress review.

Inspect a server before requesting an install plan. Package installation is limited to recognized OS/package-manager combinations and runs via `sudo -n`; it requires explicit confirmation. Linux package installation, peer changes, and optimizer changes are disabled by default. Keep gates off until tests against exact distributions, sudo rules, WireGuard versions, and expected traffic loads are completed.

Remaining production release gates include:
- End-to-end and failure-injection tests against real supported RouterOS/Linux versions, including permission errors, timeouts, partial writes, rollback failure, firewall ordering, and ACL reconciliation.
- Robust reconciliation for ambiguous timeout-after-write and rollback failure scenarios.
- Rate limiting, dependency/security scanning, and an independent security review.
- External secret-manager support and tested key rotation/recovery procedures.
- Tested database + encryption-key backup/restore and PM2 reboot recovery.
- Tamper-resistant off-host audit retention.
- Historical traffic/metrics storage, alerting, and monitoring.
- End-to-end and accessibility tests.

Do not expose this API directly to the public internet. Use a private management network, TLS termination, firewall rules, least-privilege device credentials, protected secrets, database/key backups, and a documented recovery process.


### Per-peer destination access control (ACL)

Peers now store a canonical list of destination CIDRs in `access_networks_json`. Set or replace the list with an authenticated admin/operator request:

- RouterOS: `PUT /api/v1/routers/{router_id}/peers/{peer_id}/access-control`
- Linux: `PUT /api/v1/linux-servers/{server_id}/peers/{peer_id}/access-control`

Example body:

```json
{
  "access_networks": ["172.16.16.0/24", "10.20.30.15/32"]
}
```

Use one destination network per item. Empty `access_networks` means deny all forwarded destinations. CIDRs are normalized, duplicates removed, special-purpose ranges rejected, and at most 128 entries are accepted. A peer address and its destination CIDRs must use the same IP family; IPv4 and IPv6 access require separate peer addresses. Generated client configurations use the assigned ACL as their client-side `AllowedIPs` when the ACL is non-empty; server-side firewall enforcement remains authoritative.

For RouterOS, the API installs managed allow rules followed by a source-specific drop rule at the start of the matching IPv4 or IPv6 forward filter, and tags managed rules with `wgm-acl-peer-{id}-...`. New RouterOS peers are created disabled and only enabled after the ACL operation succeeds.

For Linux, ACL enforcement delegates to a constrained root-owned helper rather than running arbitrary nftables commands through sudo. Install `backend/scripts/wgm-acl-helper` as `/usr/local/sbin/wgm-acl-helper` owned by `root:root`, mode `0755`, and configure the SSH account to invoke only this helper via sudo. The helper validates all arguments, checks that `/etc/nftables.conf` includes `/etc/nftables.d/*.nft`, applies an nftables transaction, and atomically persists `/etc/nftables.d/wgm_acl_{id}.nft`. This controls forwarded traffic; host-local services on the VPN server are not covered by the forward hook.

Example one-time setup, performed by a trusted administrator on each Linux server:

```bash
sudo install -o root -g root -m 0755 backend/scripts/wgm-acl-helper /usr/local/sbin/wgm-acl-helper
sudo visudo -f /etc/sudoers.d/wgm-acl-helper
```

Add a narrowly scoped sudoers entry for the dedicated SSH account (replace `wgm-ssh-user`):

```sudoers
wgm-ssh-user ALL=(root) NOPASSWD: /usr/local/sbin/wgm-acl-helper
```

Do not grant unrestricted `nft`, `sh`, or `install` sudo access for ACL management. Ensure the helper is root-owned and not writable by the SSH account, and validate the nftables include configuration before enabling live mutations.

**Important limitations:** the GitHub Pages/default Vite frontend is demo-only; the separate production UI is API-backed and exposes ACL controls. Existing peers are not automatically reconciled by the migration; apply the ACL endpoint to each existing peer before relying on default-deny policy. Test the exact RouterOS version, nftables version, and existing firewall ordering in a lab before enabling live mutations. These endpoints do not replace a review of pre-existing broad accept rules or routing/NAT policy.
