export type SaseSeatId = 'remote-employee' | 'net-admin';

export type SaseStage = 'discovery' | 'poe' | 'practice' | 'reflection';

export type TargetAppId = 'internal-erp' | 'finance-portal' | 'admin-ssh-bastion';

export type DeviceProfileId = 'managed-corp' | 'unmanaged-byod' | 'stale-os';

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

export type PoePredictionId =
  | 'both-succeed'
  | 'access-blocks-dns-leaks'
  | 'origin-drops-both';

export interface DevicePostureState {
  profile: DeviceProfileId;
  label: string;
  osVersion: string;
  warpConnected: boolean;
  diskEncrypted: boolean;
  osVersionOk: boolean;
}

export interface AccessPolicyConfig {
  requireWarp: boolean;
  requireDiskEncryption: boolean;
  requireMinOs: boolean;
}

export interface GatewayDnsPolicyConfig {
  blockC2: boolean;
  blockMalware: boolean;
  blockShadowAi: boolean;
}

export interface AccessEvaluationResult {
  status: 'ACCESS_GRANTED' | 'ACCESS_DENIED' | 'BLOCKED_NO_PUBLIC_INGRESS';
  http_status: number;
  error_code?: string;
  target_app: TargetAppId;
  target_hostname: string;
  device_profile?: DeviceProfileId;
  failed_checks?: string[];
  cf_access_jwt_assertion?: string;
  decoded_claims?: {
    header: Record<string, unknown>;
    payload: Record<string, unknown>;
  };
  tunnel_connector?: {
    connector_id: string;
    edge_colo: string;
    protocol: string;
    outbound_only: boolean;
    public_ports_open: number;
    origin_private_ip: string;
  };
  probed_socket?: string;
  public_ports_open?: number;
  outbound_only_tunnel?: boolean;
  integration_mode?: 'sandbox' | 'live-doh' | 'live-cf-one';
  tunnel_status?: string;
  cf_ray?: string | null;
  storage: string;
  kv_ttl_seconds: number;
  timestamp: string;
  message: string;
}

export interface DnsResolveResult {
  status: 'ALLOWED' | 'BLOCKED_SINKHOLE';
  http_status: number;
  domain: DnsDomainPreset;
  category: DnsCategory;
  dns_rcode: 'NOERROR' | 'NXDOMAIN';
  resolved_ip: string;
  matched_policy: string;
  resolver_colo: string;
  integration_mode?: 'sandbox' | 'live-doh' | 'live-cf-one';
  doh_endpoint?: string;
  cf_ray?: string | null;
  storage: string;
  kv_ttl_seconds: number;
  timestamp: string;
  message: string;
}

export interface SaseTrapsExplored {
  trap5aUnmanagedBlocked: boolean;
  trap5bDirectOriginBlocked: boolean;
  trap5cShadowAiObserved: boolean;
  managedAccessGranted: boolean;
  shadowAiAndC2Sinkholed: boolean;
}

export interface SaseTunnelState {
  stage: SaseStage;
  targetApp: TargetAppId;
  deviceProfile: DeviceProfileId;
  accessPolicy: AccessPolicyConfig;
  dnsPolicy: GatewayDnsPolicyConfig;
  poePrediction: PoePredictionId | null;
  poeExplanationUnlocked: boolean;
  lastAccessResult: AccessEvaluationResult | null;
  lastDnsResult: DnsResolveResult | null;
  dnsHistory: DnsResolveResult[];
  traps: SaseTrapsExplored;
  tunnelHealthy: boolean;
  tunnelConnectorId: string;
}

export const DEVICE_PROFILES: Record<DeviceProfileId, DevicePostureState> = {
  'managed-corp': {
    profile: 'managed-corp',
    label: 'Managed Corporate MacBook Pro',
    osVersion: 'macOS 14.6 (Compliant)',
    warpConnected: true,
    diskEncrypted: true,
    osVersionOk: true
  },
  'unmanaged-byod': {
    profile: 'unmanaged-byod',
    label: 'Unmanaged Personal Laptop (BYOD)',
    osVersion: 'macOS 14.2',
    warpConnected: false,
    diskEncrypted: false,
    osVersionOk: true
  },
  'stale-os': {
    profile: 'stale-os',
    label: 'Corporate Laptop (Stale OS)',
    osVersion: 'macOS 13.2 (Below 14.5 Min)',
    warpConnected: true,
    diskEncrypted: true,
    osVersionOk: false
  }
};

export const TARGET_APPS: Record<
  TargetAppId,
  { label: string; hostname: string; originIp: string }
> = {
  'internal-erp': {
    label: 'Internal ERP',
    hostname: 'erp.internal.0trust.corp',
    originIp: '10.24.0.14:8443'
  },
  'finance-portal': {
    label: 'Finance Ledger',
    hostname: 'finance.internal.0trust.corp',
    originIp: '10.24.0.18:8443'
  },
  'admin-ssh-bastion': {
    label: 'SSH Bastion',
    hostname: 'bastion.internal.0trust.corp',
    originIp: '10.24.0.22:22'
  }
};

export const DNS_PRESETS: Array<{
  domain: DnsDomainPreset;
  category: DnsCategory;
  label: string;
  riskTag: string;
}> = [
  {
    domain: 'erp.internal.0trust.corp',
    category: 'CORPORATE_INTERNAL',
    label: 'Internal ERP (Tunnel)',
    riskTag: 'INTERNAL'
  },
  {
    domain: 'api.github.com',
    category: 'APPROVED_SAAS',
    label: 'GitHub API',
    riskTag: 'APPROVED'
  },
  {
    domain: 'shadow-llm-upload.example',
    category: 'SHADOW_AI_GENAI',
    label: 'Shadow-AI GenAI Upload',
    riskTag: 'SHADOW_AI'
  },
  {
    domain: 'c2-beacon.bad',
    category: 'COMMAND_AND_CONTROL',
    label: 'C2 Beacon Domain',
    riskTag: 'C2'
  },
  {
    domain: 'dropper-payload.malicious.example',
    category: 'MALWARE',
    label: 'Malware Dropper Host',
    riskTag: 'MALWARE'
  }
];
