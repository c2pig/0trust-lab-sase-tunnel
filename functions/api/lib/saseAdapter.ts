export type SaseIntegrationMode = 'sandbox' | 'live' | 'auto';

export interface SaseAdapterEnv {
  SASE_INTEGRATION_MODE?: string;
  CF_ACCOUNT_ID?: string;
  CF_TUNNEL_ID?: string;
  CF_API_TOKEN?: string;
  CF_ACCESS_TEAM_DOMAIN?: string;
  CF_ACCESS_AUD?: string;
  ORIGIN_DIRECT_PROBE_URL?: string;
}

export type FetchLike = (input: string | URL | Request, init?: RequestInit) => Promise<Response>;

export interface DohLookupResult {
  integration_mode: 'live-doh' | 'sandbox';
  doh_endpoint: string;
  doh_status: number;
  resolved_ip: string | null;
  cf_ray: string | null;
  error?: string;
}

export interface TunnelConnectorSnapshot {
  integration_mode: 'live-cf-one' | 'sandbox';
  connector_id: string;
  edge_colo: string;
  protocol: string;
  outbound_only: boolean;
  public_ports_open: number;
  origin_private_ip: string;
  tunnel_status: string;
  cf_ray: string | null;
}

export interface DirectOriginProbeSnapshot {
  integration_mode: 'live-cf-one' | 'sandbox';
  probed_socket: string;
  upstream_status: number | null;
  blocked: boolean;
  detail: string;
}

export function resolveIntegrationMode(env?: SaseAdapterEnv): SaseIntegrationMode {
  const raw = env?.SASE_INTEGRATION_MODE?.trim().toLowerCase();
  if (raw === 'sandbox' || raw === 'live' || raw === 'auto') {
    return raw;
  }
  return 'auto';
}

export function isCloudflareOneConfigured(env?: SaseAdapterEnv): boolean {
  return Boolean(
    env?.CF_ACCOUNT_ID?.trim() &&
      env?.CF_TUNNEL_ID?.trim() &&
      env?.CF_API_TOKEN?.trim()
  );
}

interface DohJsonResponse {
  Status?: number;
  Answer?: Array<{ name?: string; type?: number; TTL?: number; data?: string }>;
}

export async function resolveDnsViaDoh(params: {
  domain: string;
  useMalwareFilter: boolean;
  env?: SaseAdapterEnv;
  fetchFn?: FetchLike;
}): Promise<DohLookupResult> {
  const mode = resolveIntegrationMode(params.env);
  const endpoint = params.useMalwareFilter
    ? 'https://security.cloudflare-dns.com/dns-query'
    : 'https://cloudflare-dns.com/dns-query';

  if (mode === 'sandbox') {
    return {
      integration_mode: 'sandbox',
      doh_endpoint: endpoint,
      doh_status: 0,
      resolved_ip: null,
      cf_ray: null
    };
  }

  const doFetch = params.fetchFn ?? fetch;
  try {
    const res = await doFetch(
      `${endpoint}?name=${encodeURIComponent(params.domain)}&type=A`,
      {
        method: 'GET',
        headers: { Accept: 'application/dns-json' },
        signal: AbortSignal.timeout(3000)
      }
    );
    const cfRay = res.headers.get('cf-ray');
    if (!res.ok) {
      return {
        integration_mode: 'sandbox',
        doh_endpoint: endpoint,
        doh_status: res.status,
        resolved_ip: null,
        cf_ray: cfRay,
        error: `DoH HTTP ${res.status}`
      };
    }

    const payload = (await res.json()) as DohJsonResponse;
    const aRecord = payload.Answer?.find((ans) => ans.type === 1 && typeof ans.data === 'string');
    return {
      integration_mode: 'live-doh',
      doh_endpoint: endpoint,
      doh_status: typeof payload.Status === 'number' ? payload.Status : 0,
      resolved_ip: aRecord?.data ?? null,
      cf_ray: cfRay
    };
  } catch (err) {
    return {
      integration_mode: 'sandbox',
      doh_endpoint: endpoint,
      doh_status: -1,
      resolved_ip: null,
      cf_ray: null,
      error: err instanceof Error ? err.message : 'DoH lookup failed'
    };
  }
}

interface CfTunnelApiResponse {
  success?: boolean;
  result?: {
    id?: string;
    name?: string;
    status?: string;
    connections?: Array<{
      colo_name?: string;
      client_version?: string;
      is_pending_reconnect?: boolean;
    }>;
  };
}

export async function fetchTunnelConnectorStatus(params: {
  env?: SaseAdapterEnv;
  fetchFn?: FetchLike;
}): Promise<TunnelConnectorSnapshot> {
  const mode = resolveIntegrationMode(params.env);
  const fallback: TunnelConnectorSnapshot = {
    integration_mode: 'sandbox',
    connector_id: 'tun-cf-sase-sin-01',
    edge_colo: 'SIN',
    protocol: 'quic',
    outbound_only: true,
    public_ports_open: 0,
    origin_private_ip: '10.24.0.14',
    tunnel_status: 'healthy (simulated)',
    cf_ray: null
  };

  if (mode === 'sandbox' || !isCloudflareOneConfigured(params.env)) {
    return fallback;
  }

  const accountId = params.env!.CF_ACCOUNT_ID!.trim();
  const tunnelId = params.env!.CF_TUNNEL_ID!.trim();
  const apiToken = params.env!.CF_API_TOKEN!.trim();
  const doFetch = params.fetchFn ?? fetch;

  try {
    const res = await doFetch(
      `https://api.cloudflare.com/client/v4/accounts/${encodeURIComponent(accountId)}/cfd_tunnel/${encodeURIComponent(tunnelId)}`,
      {
        method: 'GET',
        headers: {
          Authorization: `Bearer ${apiToken}`,
          'Content-Type': 'application/json'
        },
        signal: AbortSignal.timeout(3000)
      }
    );
    const cfRay = res.headers.get('cf-ray');
    if (!res.ok) {
      return fallback;
    }
    const body = (await res.json()) as CfTunnelApiResponse;
    if (!body.success || !body.result) {
      return fallback;
    }
    const primaryConn = body.result.connections?.[0];
    return {
      integration_mode: 'live-cf-one',
      connector_id: body.result.name || body.result.id || tunnelId,
      edge_colo: primaryConn?.colo_name || 'SIN',
      protocol: 'quic',
      outbound_only: true,
      public_ports_open: 0,
      origin_private_ip: '10.24.0.14',
      tunnel_status: body.result.status || 'healthy',
      cf_ray: cfRay
    };
  } catch {
    return fallback;
  }
}

export async function probeDirectOrigin(params: {
  env?: SaseAdapterEnv;
  fetchFn?: FetchLike;
}): Promise<DirectOriginProbeSnapshot> {
  const mode = resolveIntegrationMode(params.env);
  const probeUrl = params.env?.ORIGIN_DIRECT_PROBE_URL?.trim();
  const fallback: DirectOriginProbeSnapshot = {
    integration_mode: 'sandbox',
    probed_socket: '203.0.113.10:443 -> 10.24.0.14:8443',
    upstream_status: 403,
    blocked: true,
    detail:
      'Connection refused: Private origin 10.24.0.14 has zero public IPs and zero inbound ports. Only outbound-only cloudflared tunnel connections are accepted.'
  };

  if (mode === 'sandbox' || !probeUrl) {
    return fallback;
  }

  const doFetch = params.fetchFn ?? fetch;
  try {
    const res = await doFetch(probeUrl, {
      method: 'HEAD',
      signal: AbortSignal.timeout(3000)
    });
    const blocked = res.status === 401 || res.status === 403 || res.status === 404;
    return {
      integration_mode: 'live-cf-one',
      probed_socket: probeUrl,
      upstream_status: res.status,
      blocked,
      detail: blocked
        ? `Live origin probe ${probeUrl} returned HTTP ${res.status} (public ingress blocked).`
        : `Live origin probe ${probeUrl} returned HTTP ${res.status}.`
    };
  } catch (err) {
    return {
      integration_mode: 'live-cf-one',
      probed_socket: probeUrl,
      upstream_status: null,
      blocked: true,
      detail: `Live origin probe ${probeUrl} failed closed (${err instanceof Error ? err.message : 'connection refused'}).`
    };
  }
}
