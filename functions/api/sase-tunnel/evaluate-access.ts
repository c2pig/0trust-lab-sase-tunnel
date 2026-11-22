export interface KVNamespace {
  get(key: string): Promise<string | null>;
  put(key: string, value: string, options?: { expirationTtl?: number }): Promise<void>;
  delete(key: string): Promise<void>;
}

function sanitizeSessionId(raw: string | null | undefined): string {
  if (!raw || typeof raw !== 'string') return 'demo-visitor';
  const cleaned = raw.replace(/[^a-zA-Z0-9_-]/g, '').slice(0, 64);
  return cleaned || 'demo-visitor';
}

export type TargetAppId = 'internal-erp' | 'finance-portal' | 'admin-ssh-bastion';
export type DeviceProfileId = 'managed-corp' | 'unmanaged-byod' | 'stale-os';

export interface EvaluateAccessEnv {
  STATE_KV?: KVNamespace;
  ENVIRONMENT?: string;
}

export interface EvaluateAccessRequest {
  sessionId?: string;
  target_app?: TargetAppId;
  device_profile?: DeviceProfileId;
  warp_connected?: boolean;
  disk_encrypted?: boolean;
  os_version_ok?: boolean;
  require_warp?: boolean;
  require_disk_encryption?: boolean;
  require_min_os?: boolean;
  direct_origin_probe?: boolean;
}

interface SaseSessionKvRecord {
  session_id: string;
  last_access_decision: 'ACCESS_GRANTED' | 'ACCESS_DENIED' | 'BLOCKED_NO_PUBLIC_INGRESS';
  access_checks_run: number;
  dns_queries_run: number;
  dns_queries_blocked: number;
  posture_policy: {
    require_warp: boolean;
    require_disk_encryption: boolean;
    require_min_os: boolean;
  };
  updated_at: string;
}

const MAX_BODY_BYTES = 64 * 1024;
const KV_TTL_SECONDS = 3600;

const VALID_APPS = new Set<TargetAppId>([
  'internal-erp',
  'finance-portal',
  'admin-ssh-bastion'
]);

const VALID_PROFILES = new Set<DeviceProfileId>([
  'managed-corp',
  'unmanaged-byod',
  'stale-os'
]);

const APP_HOSTNAMES: Record<TargetAppId, string> = {
  'internal-erp': 'erp.internal.0trust.corp',
  'finance-portal': 'finance.internal.0trust.corp',
  'admin-ssh-bastion': 'bastion.internal.0trust.corp'
};

const ephemeralSaseStore = new Map<string, SaseSessionKvRecord>();

function jsonResponse(body: unknown, status = 200): Response {
  return new Response(JSON.stringify(body), {
    status,
    headers: {
      'Content-Type': 'application/json',
      'Cache-Control': 'no-store'
    }
  });
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

export async function onRequestPost(context: {
  request: Request;
  env: EvaluateAccessEnv;
}): Promise<Response> {
  const rawText = await context.request.text();
  if (rawText.length > MAX_BODY_BYTES) {
    return jsonResponse(
      {
        error: 'PAYLOAD_TOO_LARGE',
        message: 'Request payload exceeds 64KB limit.'
      },
      413
    );
  }

  let body: EvaluateAccessRequest = {};
  if (rawText.trim().length > 0) {
    try {
      body = JSON.parse(rawText) as EvaluateAccessRequest;
    } catch {
      return jsonResponse(
        {
          error: 'INVALID_JSON',
          message: 'Request body must be valid JSON.'
        },
        400
      );
    }
  }

  const sessionId = sanitizeSessionId(
    context.request.headers.get('X-Session-Id') || body.sessionId
  );
  const kvKey = `lab5:sase:${sessionId}`;

  const targetApp: TargetAppId =
    body.target_app && VALID_APPS.has(body.target_app) ? body.target_app : 'internal-erp';
  const deviceProfile: DeviceProfileId =
    body.device_profile && VALID_PROFILES.has(body.device_profile)
      ? body.device_profile
      : 'managed-corp';

  const warpConnected = Boolean(body.warp_connected);
  const diskEncrypted = Boolean(body.disk_encrypted);
  const osVersionOk = Boolean(body.os_version_ok);

  const requireWarp = body.require_warp !== undefined ? Boolean(body.require_warp) : true;
  const requireDiskEncryption =
    body.require_disk_encryption !== undefined ? Boolean(body.require_disk_encryption) : true;
  const requireMinOs = body.require_min_os !== undefined ? Boolean(body.require_min_os) : true;
  const directOriginProbe = Boolean(body.direct_origin_probe);

  const timestamp = new Date().toISOString();
  const storageMode = context.env.STATE_KV ? 'cloudflare-kv' : 'ephemeral-edge';

  let existing: SaseSessionKvRecord | null = null;
  if (context.env.STATE_KV) {
    try {
      const raw = await context.env.STATE_KV.get(kvKey);
      if (raw) {
        existing = JSON.parse(raw) as SaseSessionKvRecord;
      }
    } catch {
      existing = null;
    }
  } else {
    existing = ephemeralSaseStore.get(kvKey) || null;
  }

  const nextChecksRun = (existing?.access_checks_run ?? 0) + 1;

  const persistRecord = async (
    decision: SaseSessionKvRecord['last_access_decision']
  ): Promise<void> => {
    const record: SaseSessionKvRecord = {
      session_id: sessionId,
      last_access_decision: decision,
      access_checks_run: nextChecksRun,
      dns_queries_run: existing?.dns_queries_run ?? 0,
      dns_queries_blocked: existing?.dns_queries_blocked ?? 0,
      posture_policy: {
        require_warp: requireWarp,
        require_disk_encryption: requireDiskEncryption,
        require_min_os: requireMinOs
      },
      updated_at: timestamp
    };

    if (context.env.STATE_KV) {
      await context.env.STATE_KV.put(kvKey, JSON.stringify(record), {
        expirationTtl: KV_TTL_SECONDS
      });
    } else {
      ephemeralSaseStore.set(kvKey, record);
    }
  };

  if (directOriginProbe) {
    await persistRecord('BLOCKED_NO_PUBLIC_INGRESS');
    return jsonResponse(
      {
        status: 'BLOCKED_NO_PUBLIC_INGRESS',
        http_status: 403,
        error_code: 'ORIGIN_NO_PUBLIC_INGRESS',
        target_app: targetApp,
        target_hostname: APP_HOSTNAMES[targetApp],
        probed_socket: '203.0.113.10:443 -> 10.24.0.14:8443',
        public_ports_open: 0,
        outbound_only_tunnel: true,
        storage: storageMode,
        kv_ttl_seconds: KV_TTL_SECONDS,
        timestamp,
        message:
          'Connection refused: Private origin 10.24.0.14 has zero public IPs and zero inbound ports. Only outbound-only cloudflared tunnel connections are accepted.'
      },
      403
    );
  }

  const failedChecks: string[] = [];
  if (requireWarp && !warpConnected) failedChecks.push('WARP_CLIENT_MISSING');
  if (requireDiskEncryption && !diskEncrypted) failedChecks.push('DISK_UNENCRYPTED');
  if (requireMinOs && !osVersionOk) failedChecks.push('OS_VERSION_STALE');

  if (failedChecks.length > 0) {
    await persistRecord('ACCESS_DENIED');
    return jsonResponse(
      {
        status: 'ACCESS_DENIED',
        http_status: 403,
        error_code: 'CF_ACCESS_POSTURE_DENIED',
        target_app: targetApp,
        target_hostname: APP_HOSTNAMES[targetApp],
        device_profile: deviceProfile,
        failed_checks: failedChecks,
        posture_evaluated: {
          warp_connected: warpConnected,
          disk_encrypted: diskEncrypted,
          os_version_ok: osVersionOk
        },
        policy_required: {
          require_warp: requireWarp,
          require_disk_encryption: requireDiskEncryption,
          require_min_os: requireMinOs
        },
        storage: storageMode,
        kv_ttl_seconds: KV_TTL_SECONDS,
        timestamp,
        message: `Cloudflare Access denied request (403) before reaching cloudflared tunnel: failed posture checks [${failedChecks.join(', ')}].`
      },
      403
    );
  }

  await persistRecord('ACCESS_GRANTED');

  const nowSec = Math.floor(Date.now() / 1000);
  const jwtHeader = {
    alg: 'RS256',
    kid: 'cf-access-sin-edge-key-01',
    typ: 'JWT'
  };
  const jwtPayload = {
    aud: ['cf-access-0trust-sase-lab-aud'],
    email: 'samira.al-mansoor@0trust.corp',
    exp: nowSec + 3600,
    iat: nowSec,
    iss: 'https://0trust-lab.cloudflareaccess.com',
    sub: 'usr-samira-al-mansoor',
    country: 'SG',
    device_posture: {
      profile: deviceProfile,
      warp_connected: warpConnected,
      disk_encrypted: diskEncrypted,
      os_version_ok: osVersionOk
    },
    target_app: APP_HOSTNAMES[targetApp]
  };
  const syntheticJwt = `${encodeBase64Url(jwtHeader)}.${encodeBase64Url(jwtPayload)}.***REDACTED***`;

  return jsonResponse(
    {
      status: 'ACCESS_GRANTED',
      http_status: 200,
      target_app: targetApp,
      target_hostname: APP_HOSTNAMES[targetApp],
      device_profile: deviceProfile,
      cf_access_jwt_assertion: syntheticJwt,
      decoded_claims: {
        header: jwtHeader,
        payload: jwtPayload
      },
      tunnel_connector: {
        connector_id: 'tun-cf-sase-sin-01',
        edge_colo: 'SIN',
        protocol: 'quic',
        outbound_only: true,
        public_ports_open: 0,
        origin_private_ip: '10.24.0.14'
      },
      storage: storageMode,
      kv_ttl_seconds: KV_TTL_SECONDS,
      timestamp,
      message: `Cloudflare Access verified device posture and minted cf-access-jwt-assertion; traffic forwarded over outbound-only cloudflared tunnel to ${APP_HOSTNAMES[targetApp]}.`
    },
    200
  );
}
