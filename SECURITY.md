# Security Policy

## Scope

WireGuard Manager is under active development. The React frontend is illustrative and is not connected to the FastAPI backend. The backend has real early-stage RouterOS and Linux integration paths, but it is **not approved for public internet exposure or production management** without a deployment-specific security review and integration testing.

## Reporting a vulnerability

Do not publish credentials, private keys, router addresses, production topology, or exploitable details in a public issue. Contact the repository maintainer privately through a verified channel associated with the repository. Include the affected commit/version, impact, and safe reproduction steps. Allow time for investigation and remediation before public disclosure.

## Deployment guardrails

- Keep the API on a private management network behind TLS termination and firewall rules.
- Use a dedicated RouterOS account with minimum required permissions; do not use the full-privilege administrator account for routine operations.
- Keep RouterOS HTTPS certificate verification enabled.
- Configure WGM_JWT_SECRET and WGM_ENCRYPTION_KEY from a secret manager or protected environment. Never commit real values.
- Back up the encryption key separately and securely from the database. Losing the key can make encrypted credentials/keys unrecoverable; exposing it compromises stored secrets.
- Use private router management IPs by default. Public RouterOS hosts are blocked unless WGM_ALLOW_PUBLIC_ROUTER_HOSTS=true is explicitly configured after egress review.
- Use private Linux management IPs by default. Linux hostnames are rejected, SSH host keys must be independently verified and pinned, and public Linux hosts are blocked unless WGM_ALLOW_PUBLIC_LINUX_HOSTS=true is explicitly configured after egress review.
- Keep WGM_ENABLE_PEER_MUTATIONS=false and WGM_ENABLE_LINUX_MUTATIONS=false until integration, rollback, permissions, and failure-injection tests pass for the exact deployment.
- Review dry-run/preview output before enabling or confirming any remote write.
- Use a restricted Linux SSH account and narrowly scoped non-interactive sudo permissions; do not use root SSH if avoidable.
- Treat downloaded WireGuard config files and QR images as secrets. QR images embed the full client configuration, including the private key. No-store response headers do not prevent a client from saving or capturing the response.
- Protect the audit database and encryption keys. The hash-linked audit chain detects some record edits, but it is not tamper-proof against an administrator able to rewrite all database records and recompute the chain.
- Do not expose interactive API docs, verbose error information, or management endpoints publicly without an explicit risk review.
- Maintain encrypted database backups and test recovery of both database and encryption key.

## Known security gaps

Rate limiting, external secret-manager integration, off-host append-only audit retention, robust reconciliation after timeout-after-write, complete production deployment hardening, and real-device integration/failure testing remain outstanding. Unit tests passing is not a security certification.

## Current security status

See [README.md](README.md), [backend/README.md](backend/README.md), and [CHANGELOG.md](CHANGELOG.md) for the current feature set and limitations. Report vulnerabilities privately; do not attach production configuration exports, credentials, private keys, client configs, QR codes, or secret values to issues or pull requests.
