# Changelog

All notable changes to this project are documented here. The project follows Semantic Versioning (SemVer):

- **MAJOR** for incompatible API or configuration changes
- **MINOR** for backward-compatible features
- **PATCH** for backward-compatible bug fixes and security fixes

## [Unreleased]

### Added
- Initial FastAPI backend package and versioned API namespace.
- JWT access authentication, Argon2 password hashing, and admin/operator/viewer role checks.
- Environment-based secret configuration and Fernet encryption for router credentials and stored peer private keys.
- Router onboarding, TLS-verified RouterOS REST connection tests, and read-only WireGuard peer discovery endpoints.
- IP/interface validation and a dry-run preview endpoint for proposed peer creation.
- Hash-linked audit events and an administrator audit-chain verification endpoint.
- Backend health, authentication, and address-validation tests in CI.

### Security / limitations
- Peer mutation intentionally returns HTTP 501 until router-side rollback, interface selection, address-pool reconciliation, and end-to-end tests are complete.
- Refresh-session lifecycle, rate limiting, external secret-manager integration, and immutable off-host audit retention remain required before production use.
- Added a checked-in Alembic environment and initial schema migration; application startup no longer silently creates or mutates the database schema.
- Current audit hash chain detects edits only while its trust anchor is protected; a database administrator able to rewrite all rows can recompute the chain.
- Automatic schema creation is for development only; production deployment must apply reviewed Alembic migrations.

## Version history

No stable release has been published from this backend branch yet. Do not treat the frontend demo's existing version as a production backend release.
