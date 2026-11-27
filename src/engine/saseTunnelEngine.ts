import {
  AccessEvaluationResult,
  DEVICE_PROFILES,
  DNS_PRESETS,
  DnsDomainPreset,
  DnsResolveResult,
  SaseTunnelState,
  TARGET_APPS
} from '../contracts/saseTunnelContract';
import { ObservabilitySpan } from '../types';

function randomHex(byteCount: number): string {
  const bytes = new Uint8Array(byteCount);
  if (typeof crypto !== 'undefined' && typeof crypto.getRandomValues === 'function') {
    crypto.getRandomValues(bytes);
  } else {
    for (let i = 0; i < byteCount; i++) {
      bytes[i] = Math.floor(Math.random() * 256);
    }
  }
  return Array.from(bytes, (b) => b.toString(16).padStart(2, '0')).join('');
}

export function createSaseSessionId(): string {
  return `sase-${randomHex(6)}`;
}

export function createTraceparent(): string {
  return `00-${randomHex(16)}-${randomHex(8)}-01`;
}

export function createSaseSpan(params: {
  sessionId: string;
  traceparent?: string;
  method: string;
  path: string;
  status: number;
  latencyMs: number;
  origin: 'cloudflare-edge' | 'browser-webcrypto-fallback';
  summary: Record<string, unknown>;
}): ObservabilitySpan {
  const traceparent = params.traceparent || createTraceparent();
  const parts = traceparent.split('-');
  return {
    id: `span-${randomHex(4)}`,
    traceparent,
    trace_id: parts[1] || randomHex(16),
    span_id: parts[2] || randomHex(8),
    parent_span_id: '0000000000000000',
    session_id: params.sessionId,
    method: params.method,
    path: params.path,
    status: params.status,
    latency_ms: Math.max(1, params.latencyMs),
    timestamp: new Date().toISOString(),
    otlp_export: 'in-lab-only',
    redacted_auth_header: null,
    redaction_applied: true,
    execution_origin: params.origin,
    response_summary: params.summary
  };
}

export function createInitialSaseState(): SaseTunnelState {
  return {
    stage: 'discovery',
    targetApp: 'internal-erp',
    deviceProfile: 'unmanaged-byod',
    accessPolicy: {
      requireWarp: true,
      requireDiskEncryption: true,
      requireMinOs: false
    },
    dnsPolicy: {
      blockC2: false,
      blockMalware: false,
      blockShadowAi: false
    },
    poePrediction: null,
    poeExplanationUnlocked: false,
    lastAccessResult: null,
    lastDnsResult: null,
    dnsHistory: [],
    traps: {
      trap5aUnmanagedBlocked: false,
      trap5bDirectOriginBlocked: false,
      trap5cShadowAiObserved: false,
      managedAccessGranted: false,
      shadowAiAndC2Sinkholed: false
    },
    tunnelHealthy: true,
    tunnelConnectorId: 'tun-cf-sase-sin-01'
  };
}

let saseEdgeApiAvailable: boolean | null = null;

async function checkEdgeApiAvailable(): Promise<boolean> {
  const win = (
    globalThis as { window?: { location?: { hostname?: string; port?: string } } }
  ).window;
  if (!win) return false;
  if (saseEdgeApiAvailable !== null) return saseEdgeApiAvailable;
  if (
    (win.location?.hostname === 'localhost' || win.location?.hostname === '127.0.0.1') &&
    (win.location?.port === '5180' || win.location?.port === '4180')
  ) {
    saseEdgeApiAvailable = false;
    return false;
  }
  try {
    const res = await fetch('/api/sase-tunnel/health', { method: 'GET' });
    const ct = res.headers.get('Content-Type') || '';
    saseEdgeApiAvailable = res.ok && ct.includes('application/json');
  } catch {
    saseEdgeApiAvailable = false;
  }
  return saseEdgeApiAvailable;
}

function encodeBase64Url(obj: Record<string, unknown>): string {
  const json = JSON.stringify(obj);
  const bytes = new TextEncoder().encode(json);
  let binary = '';
  for (const b of bytes) {
    binary += String.fromCharCode(b);
  }
  return btoa(binary).replace(/\+/g, '-').replace(/\//g, '_').replace(/=+$/, '');
}

function simulateAccessLocally(
  state: SaseTunnelState,
  directOriginProbe: boolean
): AccessEvaluationResult {
  const appMeta = TARGET_APPS[state.targetApp];
  const profile = DEVICE_PROFILES[state.deviceProfile];
  const timestamp = new Date().toISOString();

  if (directOriginProbe) {
    return {
      status: 'BLOCKED_NO_PUBLIC_INGRESS',
      http_status: 403,
      error_code: 'ORIGIN_NO_PUBLIC_INGRESS',
      target_app: state.targetApp,
      target_hostname: appMeta.hostname,
      probed_socket: `203.0.113.10:443 -> ${appMeta.originIp}`,
      public_ports_open: 0,
      outbound_only_tunnel: true,
      storage: 'browser-fallback',
      kv_ttl_seconds: 3600,
      timestamp,
      message:
        'Connection refused: Private origin 10.24.0.14 has zero public IPs and zero inbound ports. Only outbound-only cloudflared tunnel connections are accepted.'
    };
  }

  const failedChecks: string[] = [];
  if (state.accessPolicy.requireWarp && !profile.warpConnected) {
    failedChecks.push('WARP_CLIENT_MISSING');
  }
  if (state.accessPolicy.requireDiskEncryption && !profile.diskEncrypted) {
    failedChecks.push('DISK_UNENCRYPTED');
  }
  if (state.accessPolicy.requireMinOs && !profile.osVersionOk) {
    failedChecks.push('OS_VERSION_STALE');
  }

  if (failedChecks.length > 0) {
    return {
      status: 'ACCESS_DENIED',
      http_status: 403,
      error_code: 'CF_ACCESS_POSTURE_DENIED',
      target_app: state.targetApp,
      target_hostname: appMeta.hostname,
      device_profile: state.deviceProfile,
      failed_checks: failedChecks,
      storage: 'browser-fallback',
      kv_ttl_seconds: 3600,
      timestamp,
      message: `Cloudflare Access denied request (403) before reaching cloudflared tunnel: failed posture checks [${failedChecks.join(', ')}].`
    };
  }

  const nowSec = Math.floor(Date.now() / 1000);
  const jwtHeader = { alg: 'RS256', kid: 'cf-access-sin-edge-key-01', typ: 'JWT' };
  const jwtPayload = {
    aud: ['cf-access-0trust-sase-lab-aud'],
    email: 'samira.al-mansoor@0trust.corp',
    exp: nowSec + 3600,
    iat: nowSec,
    iss: 'https://0trust-lab.cloudflareaccess.com',
    sub: 'usr-samira-al-mansoor',
    country: 'SG',
    device_posture: {
      profile: state.deviceProfile,
      warp_connected: profile.warpConnected,
      disk_encrypted: profile.diskEncrypted,
      os_version_ok: profile.osVersionOk
    },
    target_app: appMeta.hostname
  };

  return {
    status: 'ACCESS_GRANTED',
    http_status: 200,
    target_app: state.targetApp,
    target_hostname: appMeta.hostname,
    device_profile: state.deviceProfile,
    cf_access_jwt_assertion: `${encodeBase64Url(jwtHeader)}.${encodeBase64Url(jwtPayload)}.***REDACTED***`,
    decoded_claims: { header: jwtHeader, payload: jwtPayload },
    tunnel_connector: {
      connector_id: state.tunnelConnectorId,
      edge_colo: 'SIN',
      protocol: 'quic',
      outbound_only: true,
      public_ports_open: 0,
      origin_private_ip: '10.24.0.14'
    },
    storage: 'browser-fallback',
    kv_ttl_seconds: 3600,
    timestamp,
    message: `Cloudflare Access verified device posture and minted cf-access-jwt-assertion; traffic forwarded over outbound-only cloudflared tunnel to ${appMeta.hostname}.`
  };
}

function simulateDnsLocally(
  state: SaseTunnelState,
  domain: DnsDomainPreset
): DnsResolveResult {
  const preset = DNS_PRESETS.find((d) => d.domain === domain) || DNS_PRESETS[0];
  const timestamp = new Date().toISOString();

  const ipMap: Record<DnsDomainPreset, string> = {
    'erp.internal.0trust.corp': '10.24.0.14',
    'api.github.com': '140.82.114.6',
    'shadow-llm-upload.example': '198.51.100.77',
    'c2-beacon.bad': '203.0.113.99',
    'dropper-payload.malicious.example': '198.51.100.212'
  };

  let blockedReason: string | null = null;
  if (preset.category === 'COMMAND_AND_CONTROL' && state.dnsPolicy.blockC2) {
    blockedReason = 'GATEWAY_DNS_BLOCK_C2';
  } else if (preset.category === 'MALWARE' && state.dnsPolicy.blockMalware) {
    blockedReason = 'GATEWAY_DNS_BLOCK_MALWARE';
  } else if (preset.category === 'SHADOW_AI_GENAI' && state.dnsPolicy.blockShadowAi) {
    blockedReason = 'GATEWAY_DNS_BLOCK_SHADOW_AI';
  }

  if (blockedReason) {
    return {
      status: 'BLOCKED_SINKHOLE',
      http_status: 403,
      domain,
      category: preset.category,
      dns_rcode: 'NXDOMAIN',
      resolved_ip: '0.0.0.0',
      matched_policy: blockedReason,
      resolver_colo: 'SIN',
      storage: 'browser-fallback',
      kv_ttl_seconds: 3600,
      timestamp,
      message: `Gateway DNS sinkholed ${domain} (${preset.category}) -> NXDOMAIN 0.0.0.0 via ${blockedReason}.`
    };
  }

  return {
    status: 'ALLOWED',
    http_status: 200,
    domain,
    category: preset.category,
    dns_rcode: 'NOERROR',
    resolved_ip: ipMap[domain],
    matched_policy: 'GATEWAY_DNS_ALLOW_DEFAULT',
    resolver_colo: 'SIN',
    storage: 'browser-fallback',
    kv_ttl_seconds: 3600,
    timestamp,
    message: `Gateway DNS resolved ${domain} -> ${ipMap[domain]} (NOERROR).`
  };
}

function applyAccessResultToState(
  state: SaseTunnelState,
  result: AccessEvaluationResult,
  directOriginProbe: boolean
): SaseTunnelState {
  const nextTraps = { ...state.traps };
  if (directOriginProbe && result.status === 'BLOCKED_NO_PUBLIC_INGRESS') {
    nextTraps.trap5bDirectOriginBlocked = true;
  }
  if (!directOriginProbe && result.status === 'ACCESS_DENIED') {
    nextTraps.trap5aUnmanagedBlocked = true;
  }
  if (!directOriginProbe && result.status === 'ACCESS_GRANTED' && state.deviceProfile === 'managed-corp') {
    nextTraps.managedAccessGranted = true;
  }

  const poeExplanationUnlocked =
    state.poeExplanationUnlocked ||
    (nextTraps.trap5aUnmanagedBlocked && nextTraps.trap5cShadowAiObserved);

  return {
    ...state,
    lastAccessResult: result,
    traps: nextTraps,
    poeExplanationUnlocked
  };
}

function applyDnsResultToState(
  state: SaseTunnelState,
  result: DnsResolveResult
): SaseTunnelState {
  const nextTraps = { ...state.traps };
  if (
    (result.domain === 'shadow-llm-upload.example' || result.domain === 'c2-beacon.bad') &&
    result.status === 'ALLOWED'
  ) {
    nextTraps.trap5cShadowAiObserved = true;
  }
  if (
    (result.domain === 'shadow-llm-upload.example' || result.domain === 'c2-beacon.bad') &&
    result.status === 'BLOCKED_SINKHOLE'
  ) {
    nextTraps.shadowAiAndC2Sinkholed = true;
  }

  const poeExplanationUnlocked =
    state.poeExplanationUnlocked ||
    (nextTraps.trap5aUnmanagedBlocked && nextTraps.trap5cShadowAiObserved);

  return {
    ...state,
    lastDnsResult: result,
    dnsHistory: [result, ...state.dnsHistory].slice(0, 12),
    traps: nextTraps,
    poeExplanationUnlocked
  };
}

export async function evaluateAccessWithEdgeFallback(
  state: SaseTunnelState,
  sessionId: string,
  directOriginProbe = false
): Promise<{ nextState: SaseTunnelState; span: ObservabilitySpan }> {
  const startPerf = performance.now();
  const traceparent = createTraceparent();
  const profile = DEVICE_PROFILES[state.deviceProfile];

  const edgeReady = await checkEdgeApiAvailable();
  if (edgeReady) {
    try {
      const res = await fetch('/api/sase-tunnel/evaluate-access', {
        method: 'POST',
        headers: {
          'Content-Type': 'application/json',
          'X-Session-Id': sessionId,
          traceparent
        },
        body: JSON.stringify({
          sessionId,
          target_app: state.targetApp,
          device_profile: state.deviceProfile,
          warp_connected: profile.warpConnected,
          disk_encrypted: profile.diskEncrypted,
          os_version_ok: profile.osVersionOk,
          require_warp: state.accessPolicy.requireWarp,
          require_disk_encryption: state.accessPolicy.requireDiskEncryption,
          require_min_os: state.accessPolicy.requireMinOs,
          direct_origin_probe: directOriginProbe
        })
      });
      const ct = res.headers.get('Content-Type') || '';
      if (ct.includes('application/json')) {
        const data = (await res.json()) as AccessEvaluationResult & {
          _telemetry?: { traceparent?: string; latency_ms?: number };
        };
        const latencyMs = Math.max(1, Math.round(performance.now() - startPerf));
        const nextState = applyAccessResultToState(state, data, directOriginProbe);
        const summary: Record<string, unknown> = { ...data };
        delete summary._telemetry;

        return {
          nextState,
          span: createSaseSpan({
            sessionId,
            traceparent: data._telemetry?.traceparent || traceparent,
            method: 'POST',
            path: '/api/sase-tunnel/evaluate-access',
            status: res.status,
            latencyMs: data._telemetry?.latency_ms ?? latencyMs,
            origin: 'cloudflare-edge',
            summary
          })
        };
      }
    } catch {
      // Fall through to deterministic browser fallback
    }
  }

  const latencyMs = Math.max(1, Math.round(performance.now() - startPerf));
  const result = simulateAccessLocally(state, directOriginProbe);
  const nextState = applyAccessResultToState(state, result, directOriginProbe);

  return {
    nextState,
    span: createSaseSpan({
      sessionId,
      traceparent,
      method: 'POST',
      path: '/api/sase-tunnel/evaluate-access',
      status: result.http_status,
      latencyMs,
      origin: 'browser-webcrypto-fallback',
      summary: { ...result }
    })
  };
}

export async function resolveDnsWithEdgeFallback(
  state: SaseTunnelState,
  sessionId: string,
  domain: DnsDomainPreset
): Promise<{ nextState: SaseTunnelState; span: ObservabilitySpan }> {
  const startPerf = performance.now();
  const traceparent = createTraceparent();

  const edgeReady = await checkEdgeApiAvailable();
  if (edgeReady) {
    try {
      const res = await fetch('/api/sase-tunnel/dns-resolve', {
        method: 'POST',
        headers: {
          'Content-Type': 'application/json',
          'X-Session-Id': sessionId,
          traceparent
        },
        body: JSON.stringify({
          sessionId,
          domain,
          block_c2: state.dnsPolicy.blockC2,
          block_malware: state.dnsPolicy.blockMalware,
          block_shadow_ai: state.dnsPolicy.blockShadowAi
        })
      });
      const ct = res.headers.get('Content-Type') || '';
      if (ct.includes('application/json')) {
        const data = (await res.json()) as DnsResolveResult & {
          _telemetry?: { traceparent?: string; latency_ms?: number };
        };
        const latencyMs = Math.max(1, Math.round(performance.now() - startPerf));
        const nextState = applyDnsResultToState(state, data);
        const summary: Record<string, unknown> = { ...data };
        delete summary._telemetry;

        return {
          nextState,
          span: createSaseSpan({
            sessionId,
            traceparent: data._telemetry?.traceparent || traceparent,
            method: 'POST',
            path: '/api/sase-tunnel/dns-resolve',
            status: res.status,
            latencyMs: data._telemetry?.latency_ms ?? latencyMs,
            origin: 'cloudflare-edge',
            summary
          })
        };
      }
    } catch {
      // Fall through to deterministic browser fallback
    }
  }

  const latencyMs = Math.max(1, Math.round(performance.now() - startPerf));
  const result = simulateDnsLocally(state, domain);
  const nextState = applyDnsResultToState(state, result);

  return {
    nextState,
    span: createSaseSpan({
      sessionId,
      traceparent,
      method: 'POST',
      path: '/api/sase-tunnel/dns-resolve',
      status: result.http_status,
      latencyMs,
      origin: 'browser-webcrypto-fallback',
      summary: { ...result }
    })
  };
}

export function exportSasePostureReport(state: SaseTunnelState): string {
  return JSON.stringify(
    {
      lab: '0trust-lab-sase-tunnel',
      generated_at: new Date().toISOString(),
      tunnel_connector: {
        id: state.tunnelConnectorId,
        outbound_only: true,
        public_ports_exposed: 0,
        healthy: state.tunnelHealthy
      },
      access_policy: state.accessPolicy,
      gateway_dns_policy: state.dnsPolicy,
      verification_checklist: state.traps
    },
    null,
    2
  );
}
