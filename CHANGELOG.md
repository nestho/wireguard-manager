# Changelog

All notable changes to this project are documented here. The project follows Semantic Versioning (SemVer):

- **MAJOR** for incompatible API or configuration changes
- **MINOR** for backward-compatible features
- **PATCH** for backward-compatible bug fixes and security fixes

## [Unreleased]

### Linux server support
- Added a Linux server inventory model and Alembic migrations for Linux servers and their WireGuard peers.
- Added SSH onboarding with encrypted private-key storage and SHA256 host-key pinning, plus OS/kernel/package-manager and WireGuard tool detection.
- Added explicit install preview and confirmation for apt, dnf/yum, zypper and apk package managers.
- Added Linux interface/peer discovery and point-in-time counters, guarded peer create/revoke with `wg-quick save` and rollback attempts, and audited client config/QR delivery.
- Added a Linux Servers frontend demo section describing onboarding and supported distribution families. It is illustrative only; live UI/API integration is still pending.
- Added unit tests for Linux host validation and distribution-specific package plans.


### Added
- Initial FastAPI backend package and versioned API namespace.
- JWT access authentication, Argon2 password hashing, and admin/operator/viewer role checks.
- Environment-based secret configuration and Fernet encryption for router credentials and stored peer private keys.
- Router onboarding, TLS-verified RouterOS REST connection tests, and read-only WireGuard peer discovery endpoints.
- IP/interface validation and a dry-run preview endpoint for proposed peer creation.
- Hash-linked audit events and an administrator audit-chain verification endpoint.
- Backend health, authentication, and address-validation tests in CI.

### Security / limitations
- Peer create/revoke now has an implementation behind `WGM_ENABLE_PEER_MUTATIONS=false` by default: preview checks local/router-side overlaps, creation uses explicit confirmation and compensating deletion, and revocation disables the peer with a re-enable rollback attempt. Keep the flag off until RouterOS-version-specific integration tests pass; timeout-after-write ambiguity and real-device rollback still need verification.
- Refresh-session lifecycle, rate limiting, external secret-manager integration, and immutable off-host audit retention remain required before production use.
- Added a checked-in Alembic environment and versioned schema migrations; application startup no longer silently creates or mutates the database schema.
- Added gated RouterOS peer create/revoke operations with interface selection, remote address-overlap checks, encrypted private-key persistence, and compensating rollback attempts.
- Added audited client `.conf` and QR PNG delivery endpoints with strict input validation and no-store response headers; generated configuration and QR contents are never written to the audit log.
- Added opaque, hashed refresh tokens with rotation, expiration, replay rejection, and logout revocation.
- Current audit hash chain detects edits only while its trust anchor is protected; a database administrator able to rewrite all rows can recompute the chain.
- Automatic schema creation is for development only; production deployment must apply reviewed Alembic migrations.

## Version history

No stable release has been published from this backend branch yet. Do not treat the frontend demo's existing version as a production backend release.
