# Architecture: Zero-Trust SASE & Browser-to-Origin Tunnel (`0trust-lab-sase-tunnel`)

> **Standalone Route**: `https://lab.0trust.dev/sase-tunnel`
> **Local Dev Port**: `5180` (`preview`: `4180`; local Hono API on `127.0.0.1:8080`)
> **Hosting Split**: Static SPA (`dist/`) on **Cloudflare Pages** + API (`/api/sase-tunnel/*`) on **GCP Cloud Run** (`0trust-lab-sase-tunnel`, `min_instance_count = 0`) fronted by `0trust-lab-router`
> **State Backend**: **Firestore Native** (`kv_state` collection, doc ID `sase-tunnel:<encodeURIComponent(key)>`, `lab5:sase:` prefix, 1-hour TTL with synchronous `expireAt` enforcement; `MemoryKvAdapter` local fallback)

![SASE Tunnel Architecture](diagrams/sase_tunnel_architecture.svg)

## System Overview

Lab 5 models a Cloudflare One Zero-Trust SASE deployment that eliminates legacy VPNs and public origin IP exposure:

1. **AppShell Header, `driver.js` Orientation & Dropdown Role Switcher (`remote-employee` ↔ `net-admin`)**:
   - Compact sticky `56px` AppShell header with `All Labs`, lab title, live status pill, dropdown `RoleSwitcherBar` (with notification dots for pending policy hardening or verification), `Lab Tour` (`driver.js` orientation overlay), and `Reset`.
   - **Remote Staff (`Samira Al-Mansoor`)**: Corporate Browser & Internal App Portal simulating 3 endpoint posture profiles (`managed-corp`, `unmanaged-byod`, `stale-os`), internal app tunnel launches (`Internal ERP`, `Finance Ledger`, `SSH Bastion`), and Gateway DNS lookups with strict role isolation.
   - **Network Security (`Carlos Mendez`)**: Access & Tunnel Policy console managing Cloudflare Access posture rules, Gateway DNS egress sinkholes, active `cloudflared` connector telemetry, and recent DNS query logs.
   - Static SPA (`dist/`) is served from Cloudflare Pages via `0trust-lab-router` at `https://lab.0trust.dev/sase-tunnel`.
2. **Same-Origin Routing & Cloud Run API (`server/app.ts` → synced `server/runtime.ts`, canonical `Dockerfile`)**:
   - `server/app.ts` is a thin lab-specific route wrapper calling `createBaseLabApp` from the canonical synced `server/runtime.ts` (synced from `0trust.dev/templates/lab-runtime/` alongside `server/kvAdapter.ts`, `server/origin.ts`, `server/index.ts`, and the canonical multi-stage `Dockerfile`).
   - `0trust-lab-router` forwards `/api/sase-tunnel/*` and `/sase-tunnel/api/*` to the GCP Cloud Run origin with `X-Forwarded-Host`, `X-Forwarded-Proto`, and `X-Lab-Router-Secret`.
   - Cloud Run enforces fail-closed `LAB_ROUTER_SECRET` validation on all `/api/*` routes (`403 FORBIDDEN_DIRECT_ORIGIN` when unset or mismatched) via SHA-256 digest normalization + `crypto.timingSafeEqual`, restricts localhost origin fallback to dev-only (`server/origin.ts`), uses bounded OTLP flush (`server/runtime.ts`), and calls `closeIdleConnections()` on shutdown (`server/index.ts`), while exposing `GET /healthz` (`200 { ok: true, lab: "sase-tunnel" }`) for Cloud Run probes.
   - `GET /api/sase-tunnel/health`: Returns service health for frontend capability detection.
   - `POST /api/sase-tunnel/evaluate-access`: Enforces device posture gates (`require_warp`, `require_disk_encryption`, `require_min_os`), fails closed (`403 CF_ACCESS_POSTURE_DENIED`) on posture failure, fails closed (`403 ORIGIN_NO_PUBLIC_INGRESS`) on direct-to-origin probes, and mints synthetic `cf-access-jwt-assertion` claims when compliant.
   - `POST /api/sase-tunnel/dns-resolve`: Evaluates outbound DNS queries against an allowlisted preset catalog (`CORPORATE_INTERNAL`, `APPROVED_SAAS`, `SHADOW_AI_GENAI`, `COMMAND_AND_CONTROL`, `MALWARE`) and sinkholes blocked categories to `NXDOMAIN` (`0.0.0.0`, HTTP `403`).
3. **`cloudflared` Outbound-Only Tunnel & Private Origin**:
   - Connector `tun-cf-sase-sin-01` dials outbound QUIC to Cloudflare Edge (`SIN`), exposing `0` public inbound ports on private origin `10.24.0.14`.
4. **State, Observability & Terraform Backend (`server/kvAdapter.ts`, `functions/api/_middleware.ts`, `_telemetry.ts`, `infra/terraform/backend.tf`)**:
   - `FirestoreKvAdapter` stores session state in Firestore Native (`kv_state`) with document IDs scoped to `sase-tunnel:<encodeURIComponent(key)>` and synchronous `expireAt?.toMillis()` guard (`<= Date.now()`) expiry checks; local `npm run dev` uses `MemoryKvAdapter` with zero GCP credentials required.
   - `_middleware.ts` and `_telemetry.ts` propagate W3C `traceparent`, sanitize `X-Session-Id`, apply auth/JWT redaction (never logging `X-Lab-Router-Secret` or `OTLP_AUTH_HEADER`), handle null-body responses, emit error telemetry, strip sensitive internal headers, set `X-Edge-Latency-Ms`, inject `_telemetry` into JSON responses for the `XRayTelemetryDrawer` (including a `Global Live Dashboard ↗` link to `https://0trust.dev/observability`), and export non-blocking OTLP `/v1/traces` + `/v1/logs` with `OTEL_SERVICE_NAME=zerotrust-lab-sase-tunnel` authenticated via GCP Secret Manager `grafana-otlp-auth-header` (`OTLP_AUTH_HEADER`).
   - Provisioned via `infra/terraform/` using immutably pinned modules (`managed-infrastructure//modules/cloudflare-pages-lab?ref=v1.0.0` + `managed-infrastructure//modules/cloud-run-lab?ref=v1.0.0`) with a multi-platform `.terraform.lock.hcl` (`linux_amd64` + `darwin_arm64`), validated on every PR by the `terraform-validate` job in `.github/workflows/ci.yml` (`fmt -check`, `init -backend=false -input=false`, `validate`), and deployed via split GitHub Actions jobs (`deploy-pages` + WIF OIDC `deploy-cloudrun`). Remote GCS state is declared in `infra/terraform/backend.tf` (`bucket = "0trust-dev-tfstate"`, `prefix = "labs/sase-tunnel"`), with `.terraform/` and `*.tfstate*` gitignored. Operators migrating from local state should provision the GCS bucket once (Uniform Bucket-Level Access, versioning enabled, `public_access_prevention = "enforced"`) and run `terraform init -migrate-state`.

---

## Turnstile & 3-Minute Single-Session Lease Gate
- **Frontend Guard (`src/components/LabLeaseGuard.tsx`, re-exported via `src/shell/index.ts`)**: `src/App.tsx` wraps `<SaseTunnelPage>` with `<LabLeaseGuard labSlug="sase-tunnel" labTitle="Zero-Trust SASE & Browser-to-Origin Tunnel">`. Fails closed while `status === null` and on non-localhost network/5xx/non-JSON errors (with a **Retry** button), and uses server-relative `retryAfterSec` countdowns without clock-skew polling loops.
- **Edge Enforcement (`0trust-lab-router` + `LabLeaseDO`)**: Queries `GET /api/lease/sase-tunnel/status`, renders the explicit Cloudflare Turnstile widget (`0x4AAAAAAGVF1oWC5CsFWn-J`) when available, acquires an `HttpOnly; Secure; SameSite=Lax` lease cookie (`lab_lease_sase-tunnel`) via `POST /api/lease/sase-tunnel/acquire` (180s hard cap, 25 calls/lease, 200 calls/UTC day), shows a countdown lock screen when occupied, and exposes a floating `MM:SS + End Lab` pill while active.
- **Zero Engine Changes**: All existing same-origin `/api/sase-tunnel/*` requests carry the `HttpOnly` lease cookie automatically; local development (`localhost` / `127.0.0.1`) and disabled lease configs pass through transparently.
- **Bounded Fallback & CI/CD Gates**: Unit-test / unbound-KV fallback maps in `functions/api/sase-tunnel/{dns-resolve,evaluate-access}.ts` are bounded (`MAX_EPHEMERAL_ENTRIES = 256`) with `1h` TTL eviction and are never written when `STATE_KV` is bound. `.github/workflows/ci.yml` gates PRs (`tsc --noEmit`, `tsc -p tsconfig.server.json --noEmit`, `npm test`, `npm run build`), and `.github/workflows/deploy.yml` gates both `deploy-pages` and `deploy-cloudrun` behind `needs: test-and-build`.

- **X-Ray Telemetry Drawer Theme**: Uses Chrome DevTools Light Mode palette (`#ffffff` / `#f1f3f4` surfaces, `#dadce0` borders, `#202124` / `#5f6368` text, `#1a73e8` active indicators) for high-contrast readability.
