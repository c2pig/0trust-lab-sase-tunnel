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

export type DnsDomainPreset =
  | 'erp.internal.0trust.corp'
  | 'api.github.com'
  | 'shadow-llm-upload.example'
  | 'c2-beacon.bad'
  | 'dropper-payload.malicious.example';

export type DnsCategory =
  | 'CORPORATE_INTERNAL'
  | 'APPROVED_SAAS'
  | 'SHADOW_AI_GENAI'
  | 'COMMAND_AND_CONTROL'
  | 'MALWARE';

export interface DnsResolveEnv {
  STATE_KV?: KVNamespace;
  ENVIRONMENT?: string;
}

export interface DnsResolveRequest {
  sessionId?: string;
  domain?: DnsDomainPreset;
  block_c2?: boolean;
  block_malware?: boolean;
  block_shadow_ai?: boolean;
}

interface SaseDnsKvRecord {
  session_id: string;
  last_access_decision?: string;
  access_checks_run?: number;
  dns_queries_run: number;
  dns_queries_blocked: number;
  last_domain?: DnsDomainPreset;
  last_rcode?: 'NOERROR' | 'NXDOMAIN';
  updated_at: string;
}

const MAX_BODY_BYTES = 64 * 1024;
const KV_TTL_SECONDS = 3600;

const DOMAIN_CATALOG: Record<
  DnsDomainPreset,
  { category: DnsCategory; resolvedIp: string; description: string }
> = {
  'erp.internal.0trust.corp': {
    category: 'CORPORATE_INTERNAL',
    resolvedIp: '10.24.0.14',
    description: 'Internal ERP routed via cloudflared private tunnel'
  },
  'api.github.com': {
    category: 'APPROVED_SAAS',
    resolvedIp: '140.82.114.6',
    description: 'Approved engineering SaaS endpoint'
  },
  'shadow-llm-upload.example': {
    category: 'SHADOW_AI_GENAI',
    resolvedIp: '198.51.100.77',
    description: 'Unapproved external GenAI prompt & file upload endpoint'
  },
  'c2-beacon.bad': {
    category: 'COMMAND_AND_CONTROL',
    resolvedIp: '203.0.113.99',
    description: 'Known threat-intel Command & Control beaconing domain'
  },
  'dropper-payload.malicious.example': {
    category: 'MALWARE',
    resolvedIp: '198.51.100.212',
    description: 'Malware staging & payload delivery host'
  }
};

const VALID_DOMAINS = new Set<DnsDomainPreset>(
  Object.keys(DOMAIN_CATALOG) as DnsDomainPreset[]
);

const ephemeralDnsStore = new Map<string, SaseDnsKvRecord>();

function jsonResponse(body: unknown, status = 200): Response {
  return new Response(JSON.stringify(body), {
    status,
    headers: {
      'Content-Type': 'application/json',
      'Cache-Control': 'no-store'
    }
  });
}

export async function onRequestPost(context: {
  request: Request;
  env: DnsResolveEnv;
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

  let body: DnsResolveRequest = {};
  if (rawText.trim().length > 0) {
    try {
      body = JSON.parse(rawText) as DnsResolveRequest;
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

  if (!body.domain || !VALID_DOMAINS.has(body.domain)) {
    return jsonResponse(
      {
        error: 'INVALID_DOMAIN_PRESET',
        message: 'Domain must be one of the approved lab DNS presets.'
      },
      400
    );
  }

  const domain = body.domain;
  const entry = DOMAIN_CATALOG[domain];
  const blockC2 = Boolean(body.block_c2);
  const blockMalware = Boolean(body.block_malware);
  const blockShadowAi = Boolean(body.block_shadow_ai);

  const sessionId = sanitizeSessionId(
    context.request.headers.get('X-Session-Id') || body.sessionId
  );
  const kvKey = `lab5:sase:${sessionId}`;
  const timestamp = new Date().toISOString();
  const storageMode = context.env.STATE_KV ? 'cloudflare-kv' : 'ephemeral-edge';

  let blockedReason: string | null = null;
  if (entry.category === 'COMMAND_AND_CONTROL' && blockC2) {
    blockedReason = 'GATEWAY_DNS_BLOCK_C2';
  } else if (entry.category === 'MALWARE' && blockMalware) {
    blockedReason = 'GATEWAY_DNS_BLOCK_MALWARE';
  } else if (entry.category === 'SHADOW_AI_GENAI' && blockShadowAi) {
    blockedReason = 'GATEWAY_DNS_BLOCK_SHADOW_AI';
  }

  let existing: SaseDnsKvRecord | null = null;
  if (context.env.STATE_KV) {
    try {
      const raw = await context.env.STATE_KV.get(kvKey);
      if (raw) {
        existing = JSON.parse(raw) as SaseDnsKvRecord;
      }
    } catch {
      existing = null;
    }
  } else {
    existing = ephemeralDnsStore.get(kvKey) || null;
  }

  const nextQueriesRun = (existing?.dns_queries_run ?? 0) + 1;
  const nextQueriesBlocked = (existing?.dns_queries_blocked ?? 0) + (blockedReason ? 1 : 0);
  const rcode: 'NOERROR' | 'NXDOMAIN' = blockedReason ? 'NXDOMAIN' : 'NOERROR';

  const record: SaseDnsKvRecord = {
    ...(existing || {}),
    session_id: sessionId,
    dns_queries_run: nextQueriesRun,
    dns_queries_blocked: nextQueriesBlocked,
    last_domain: domain,
    last_rcode: rcode,
    updated_at: timestamp
  };

  if (context.env.STATE_KV) {
    await context.env.STATE_KV.put(kvKey, JSON.stringify(record), {
      expirationTtl: KV_TTL_SECONDS
    });
  } else {
    ephemeralDnsStore.set(kvKey, record);
  }

  if (blockedReason) {
    return jsonResponse(
      {
        status: 'BLOCKED_SINKHOLE',
        http_status: 403,
        domain,
        category: entry.category,
        dns_rcode: 'NXDOMAIN',
        resolved_ip: '0.0.0.0',
        matched_policy: blockedReason,
        resolver_colo: 'SIN',
        storage: storageMode,
        kv_ttl_seconds: KV_TTL_SECONDS,
        timestamp,
        message: `Gateway DNS sinkholed ${domain} (${entry.category}) -> NXDOMAIN 0.0.0.0 via ${blockedReason}.`
      },
      403
    );
  }

  return jsonResponse(
    {
      status: 'ALLOWED',
      http_status: 200,
      domain,
      category: entry.category,
      dns_rcode: 'NOERROR',
      resolved_ip: entry.resolvedIp,
      matched_policy: 'GATEWAY_DNS_ALLOW_DEFAULT',
      resolver_colo: 'SIN',
      storage: storageMode,
      kv_ttl_seconds: KV_TTL_SECONDS,
      timestamp,
      message: `Gateway DNS resolved ${domain} -> ${entry.resolvedIp} (NOERROR).`
    },
    200
  );
}
