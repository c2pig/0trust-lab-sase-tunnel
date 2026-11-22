# Architecture: Zero-Trust SASE & Browser-to-Origin Tunnel (`0trust-lab-sase-tunnel`)

> **Standalone Route**: `https://lab.0trust.dev/sase-tunnel`
> **Local Dev Port**: `5180` (`preview`: `4180`)
> **KV Prefix**: `lab5:sase:` (1-hour TTL)

![SASE Tunnel Architecture](diagrams/sase_tunnel_architecture.svg)

## System Overview

Lab 5 models a Cloudflare One Zero-Trust SASE deployment that eliminates legacy VPNs and public origin IP exposure:

1. **Endpoint & Browser (`remote-employee` — Samira Al-Mansoor)**:
   - Simulates 3 device posture profiles (`managed-corp`, `unmanaged-byod`, `stale-os`) with Cloudflare WARP, disk encryption, and OS version signals.
2. **Cloudflare Edge (`Access + Gateway DNS`)**:
   - `POST /api/sase-tunnel/evaluate-access`: Enforces device posture gates (`require_warp`, `require_disk_encryption`, `require_min_os`), fails closed (`403 CF_ACCESS_POSTURE_DENIED`) on posture failure, fails closed (`403 ORIGIN_NO_PUBLIC_INGRESS`) on direct-to-origin probes, and mints synthetic `cf-access-jwt-assertion` claims when compliant.
   - `POST /api/sase-tunnel/dns-resolve`: Evaluates outbound DNS queries against an allowlisted preset catalog (`CORPORATE_INTERNAL`, `APPROVED_SAAS`, `SHADOW_AI_GENAI`, `COMMAND_AND_CONTROL`, `MALWARE`) and sinkholes blocked categories to `NXDOMAIN` (`0.0.0.0`, HTTP `403`).
3. **`cloudflared` Outbound-Only Tunnel & Private Origin**:
   - Connector `tun-cf-sase-sin-01` dials outbound QUIC to Cloudflare Edge (`SIN`), exposing `0` public inbound ports on private origin `10.24.0.14`.
4. **Edge Middleware & Telemetry (`functions/api/_middleware.ts`)**:
   - Propagates W3C `traceparent`, sanitizes `X-Session-Id`, redacts JWT signatures, and injects `_telemetry` into JSON responses for the `XRayTelemetryDrawer`.
   - In `vite dev`, `src/engine/saseTunnelEngine.ts` probes `/api/sase-tunnel/health` once and falls back deterministically client-side (`$0.00/mo`) when Edge Functions are absent.
