# WireGuard Manager

A local-first dashboard concept for organizing WireGuard peers across MikroTik routers. The repository currently contains a **frontend demo** with synthetic data; it does not yet connect to RouterOS, generate real peer keys, or apply router changes.

![WireGuard Manager dashboard preview](docs/dashboard-preview.svg)

<p align="center">
  <strong>Dark dashboard · Router health · Peer inventory · Traffic overview</strong>
</p>

> **Safety notice:** The current UI is a visual prototype. Router health and traffic are illustrative, and device creation is intentionally non-operational. Do not treat the dashboard as a live monitoring system.

## Current status

- [x] Responsive dashboard UI with dark theme
- [x] Synthetic router and device examples
- [x] Searchable sample device table
- [x] Dashboard metrics, router-health cards, and illustrative traffic chart
- [x] Demo-mode warning and non-operational “Add device” dialog
- [x] MIT license
- [ ] RouterOS SSH/API integration
- [ ] Setup wizard and connection diagnostics
- [ ] Peer create/revoke workflow with dry-run and explicit confirmation
- [ ] Inventory persistence, backups, and rollback
- [ ] Audit log backed by real operations
- [ ] Automated tests and release packaging

## Run locally

Requirements: Node.js 20+ and npm.

```bash
git clone https://github.com/nestho/wireguard-manager.git
cd wireguard-manager
npm install
npm run dev
```

Vite prints a local URL (usually `http://localhost:5173`). To create and preview a production build:

```bash
npm run build
npm run preview
```

## Demo data

Synthetic example records live in [`demo/seed-data.json`](demo/seed-data.json). They use documentation-only IP ranges where possible and do not contain real router addresses, private keys, client configurations, or QR codes. The initial UI currently renders its own local sample objects; the JSON file is provided as a starter fixture for the next implementation step.

## Safety and design principles

This project is intended to become a **local-first management tool**. Before any live RouterOS integration is implemented, the design should preserve these safeguards:

- Never include router credentials, private keys, client configuration files, or QR codes in logs, screenshots, issues, or demo fixtures.
- Keep real inventory separate from demo data.
- Make read-only inspection the default; clearly preview mutations before applying them.
- Require explicit confirmation for peer creation, revocation, and other changes that affect a live router.
- Back up relevant configuration before writes and provide a clear failure/rollback path.
- Do not rotate existing peer keys or reassign peer addresses as a side effect of setup.
- Treat router output and user-supplied inventory as untrusted input.

The current prototype **does not implement these live-operation safeguards yet**, because it does not perform live operations.

## Planned architecture

The dashboard is built with React, TypeScript, and Vite. A future backend can own RouterOS connectivity and secret handling; browser code should never receive router passwords, SSH private keys, or WireGuard private keys. Prefer a narrow backend API, authenticated local access, and explicit per-router permissions.

## Contributing

Issues and pull requests are welcome. Please do not attach production configuration exports or secrets to bug reports. Use redacted logs and synthetic examples.

## License

Distributed under the MIT License. See [LICENSE](LICENSE).
