# Changelog

Notable changes to WireGuard Manager are recorded here. The backend has not yet published a stable production release; entries describe repository capabilities and limitations, not a production-readiness claim.

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
- Clarified that the frontend is not yet integrated with the backend and all frontend operational data is illustrative.

### Security and known limitations
- RouterOS peer mutations are disabled by default with WGM_ENABLE_PEER_MUTATIONS=false; Linux installation and peer mutations are disabled by default with WGM_ENABLE_LINUX_MUTATIONS=false.
- Public RouterOS and Linux host targets are disabled by default. Linux SSH registration requires an independently verified SHA256 host-key fingerprint and uses IP-literal targets.
- Remote mutation rollback is best-effort. Timeouts, database failures, and remote state mismatches can require manual reconciliation.
- Hash-linked audit records are not immutable against an actor able to rewrite the database and recompute the chain.
- Rate limiting, external secret-manager integration, off-host tamper-resistant audit retention, historical monitoring, production deployment hardening, real-device integration tests, and frontend/API integration remain outstanding.
- The Linux performance optimizer is not listed as a shipped capability unless its implementation is merged to main and its behavior is validated and documented.

## Version history

No stable production backend release has been published.
