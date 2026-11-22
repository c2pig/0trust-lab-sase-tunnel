# Agent & Contributor Instructions (`0trust-lab-sase-tunnel`)

## Two-Way Architecture Diagram Sync (Global <-> Local)

This repository powers **Lab 5 (`Zero-Trust SASE & Browser-to-Origin Tunnel` — `/sase-tunnel`)** on [`0trust.dev`](https://github.com/c2pig/0trust.dev/blob/main/docs/ECOSYSTEM_MAP.md), hosted at `https://lab.0trust.dev/sase-tunnel`.

Whenever you modify code, edge functions, or infrastructure under `src/`, `functions/`, `infra/`, or `.github/workflows/`:
1. **Local Sync**: Update [`docs/ARCHITECTURE.md`](docs/ARCHITECTURE.md) and [`docs/diagrams/sase_tunnel_architecture.svg`](docs/diagrams/sase_tunnel_architecture.svg) in the same Pull Request (enforced by [`.github/workflows/diagram-check.yml`](.github/workflows/diagram-check.yml)).
2. **Global Sync**: If public contracts (`lab.manifest.json`, `seats`, `apiEndpoints`, `kvPrefixes`), Cloudflare Access posture gates, `cloudflared` tunnel invariants, or Gateway DNS egress rules change, also update `docs/diagrams/platform_capability_zoomin.svg` and `src/contracts/labManifest.ts` in [`c2pig/0trust.dev`](https://github.com/c2pig/0trust.dev).
