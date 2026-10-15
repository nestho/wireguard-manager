# Security Policy

## Scope
WireGuard Manager is under active development. The current frontend is illustrative, and the backend is an early API milestone. It is not yet approved for internet exposure or production management of routers.

## Reporting a vulnerability
Do not publish credentials, private keys, router addresses, or exploitable details in a public issue. Contact the repository maintainer privately through a verified channel associated with the repository. Include affected commit/version, impact, and safe reproduction steps. Allow time for investigation and a fix before public disclosure.

## Deployment guardrails
- Keep the API on a private management network behind HTTPS and a firewall.
- Use a dedicated RouterOS account with the minimum permissions needed; do not use the RouterOS full-privilege administrator account.
- Keep RouterOS REST HTTPS certificate verification enabled. Do not disable TLS verification to work around certificates.
- Configure WGM_JWT_SECRET and WGM_ENCRYPTION_KEY from a secret manager or protected environment. Never commit real values.
- Back up the encryption key separately from the database. Losing the key makes encrypted credentials unrecoverable; exposing it compromises stored secrets.
- Use private router management addresses by default. Public router hosts are disabled unless WGM_ALLOW_PUBLIC_ROUTER_HOSTS=true is explicitly configured and outbound network restrictions are in place.
- Do not expose debug traces or OpenAPI docs publicly without an explicit deployment decision.
- Peer mutations are disabled until rollback and router-side consistency checks are implemented and tested.

## Current security status
See the backend README and CHANGELOG for implemented controls and known gaps. Passing unit tests alone is not a production security assessment.
