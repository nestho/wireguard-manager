# Changelog

Notable changes to WireGuard Manager are recorded here. These entries describe merged repository capabilities; they are not a security certification or a claim that every live infrastructure workflow has passed production acceptance testing.

## Unreleased

### Backend and API
- Added a FastAPI service with versioned routes, health/readiness checks, JWT authentication, rotating/revocable refresh tokens, Argon2 password hashing, and admin/operator/viewer authorization.
- Added one-time administrator bootstrap and admin user provisioning.
- Added SQLAlchemy models and Alembic migrations for users, RouterOS routers, Linux servers, peers, refresh sessions, and audit events.
- Added Fernet encryption for stored RouterOS credentials, Linux SSH private keys, and peer private-key material.
- Added RouterOS registration, TLS-verified REST connectivity checks, read-only WireGuard discovery, point-in-time traffic counters, and bounded diagnostics.
- Added guarded RouterOS peer preview/create/revoke flows with IP/interface validation, local and remote overlap checks, explicit confirmation, mutation gates, and compensating rollback attempts.
- Added Linux server onboarding over SSH with pinned SHA256 host-key fingerprints, IP-literal host validation, OS/kernel/package-manager detection, and distribution-family install plans for apt-get, dnf/yum, zypper, and apk.
- Added Linux WireGuard interface/peer discovery, current handshake/RX/TX counters, guarded peer create/revoke, and package installation behind a default-off mutation gate.
- Added audited WireGuard client configuration and QR image delivery with no-store response headers.
- Added hash-linked audit events and an admin-only audit-chain verification endpoint.
- Added backend tests to the CI workflow alongside frontend build and Alembic migration validation.

### Frontend
- Added a responsive React/TypeScript/Vite dashboard prototype with Overview, Routers, Users & devices, Traffic, Diagnostics, Audit log, Settings, and illustrative Linux Servers views.
- Added synthetic seed data, demo-only interactions, local browser persistence, CSV/JSON exports where offered by the UI, SVG preview illustrations, and GitHub Pages deployment workflow.
- Kept the GitHub Pages/default Vite dashboard explicitly demo-only, with synthetic fixtures and browser-local state.
- Added a separate production-only React entry point and typed API client; the production bundle does not import the demo dashboard or seed demo records.
- Added authenticated production workflows for RouterOS and Linux server inventory, connectivity/inspection, peer discovery and lifecycle controls, per-peer destination ACLs, client configuration/QR delivery, diagnostics, router audit, user management, audit browsing, and audit-chain verification.

### Production deployment and operations
- Added a PM2-managed production deployment path with `ecosystem.config.cjs`, a same-origin frontend `/api` proxy, and `bash scripts/deploy-production.sh` for one-command install/upgrade.
- Added `.env.production.example` and a production deployment guide covering secret generation, one-time admin bootstrap, database migrations, health checks, PM2 operations, reverse-proxy/TLS requirements, and operational safeguards.
- Deployment builds only the production entry point, checks known demo fixture markers in the output, applies Alembic migrations without seeding or resetting the database, starts/reloads PM2 services, and performs local health checks.
- CI now builds the production-only frontend, checks fixture markers and deployment scripts, validates migrations, and runs backend tests. The merged production change passed CI on 2026-10-24.

### Security and known limitations
- RouterOS peer mutations are disabled by default with WGM_ENABLE_PEER_MUTATIONS=false; Linux installation and peer mutations are disabled by default with WGM_ENABLE_LINUX_MUTATIONS=false.
- Public RouterOS and Linux host targets are disabled by default. Linux SSH registration requires an independently verified SHA256 host-key fingerprint and uses IP-literal targets.
- Remote mutation rollback is best-effort. Timeouts, database failures, and remote state mismatches can require manual reconciliation.
- Hash-linked audit records are not immutable against an actor able to rewrite the database and recompute the chain.
- The PM2 deployment path is implemented, but target-host upgrade/recovery, backup/restore, reverse-proxy/TLS, reboot recovery, and real-device acceptance must still be validated in the deployment environment.
- Rate limiting, external secret-manager integration, tested key rotation/recovery, off-host tamper-resistant audit retention, historical monitoring, end-to-end/failure-injection tests, and an independent security review remain outstanding.
- The Linux optimizer has guarded backend/UI support; live apply operations must remain disabled until tested against the exact host/kernel/sysctl environment and approved change-control/rollback procedures.

## Version history

No stable production backend release has been published.
