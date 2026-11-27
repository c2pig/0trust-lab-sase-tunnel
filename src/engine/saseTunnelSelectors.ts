import {
  DnsResolveResult,
  SaseSeatId,
  SaseTunnelState
} from '../contracts/saseTunnelContract';

export interface SaseSeatBadge {
  text: string;
  tone: 'amber' | 'crimson' | 'emerald' | 'blue';
  pulse?: boolean;
}

export interface SaseSeatItem {
  id: SaseSeatId;
  name: string;
  roleLabel: string;
  appLabel: string;
  avatarInitials: string;
  badge?: SaseSeatBadge | null;
}

export function isAllAccessProtected(accessPolicy: SaseTunnelState['accessPolicy']): boolean {
  return (
    accessPolicy.requireWarp &&
    accessPolicy.requireDiskEncryption &&
    accessPolicy.requireMinOs
  );
}

export function isAllDnsProtected(dnsPolicy: SaseTunnelState['dnsPolicy']): boolean {
  return (
    dnsPolicy.blockC2 &&
    dnsPolicy.blockMalware &&
    dnsPolicy.blockShadowAi
  );
}

export function isAllPoliciesHardened(state: Pick<SaseTunnelState, 'accessPolicy' | 'dnsPolicy'>): boolean {
  return isAllAccessProtected(state.accessPolicy) && isAllDnsProtected(state.dnsPolicy);
}

export function hasRiskyDnsAllowed(dnsHistory: DnsResolveResult[]): boolean {
  return dnsHistory.some(
    (d) =>
      d.status === 'ALLOWED' &&
      (d.category === 'SHADOW_AI_GENAI' ||
        d.category === 'COMMAND_AND_CONTROL' ||
        d.category === 'MALWARE')
  );
}

export function doesStaffNeedVerify(
  state: Pick<SaseTunnelState, 'accessPolicy' | 'dnsPolicy' | 'lastAccessResult'>
): boolean {
  return (
    isAllPoliciesHardened(state) &&
    state.lastAccessResult?.status !== 'ACCESS_GRANTED'
  );
}

export function getGlobalStatusLabel(
  state: Pick<SaseTunnelState, 'accessPolicy' | 'dnsPolicy' | 'lastAccessResult'>
): 'Zero-Trust Verified' | 'Policies Hardened' | 'Policy Gaps Open' {
  if (!isAllPoliciesHardened(state)) {
    return 'Policy Gaps Open';
  }
  return state.lastAccessResult?.status === 'ACCESS_GRANTED'
    ? 'Zero-Trust Verified'
    : 'Policies Hardened';
}

export function buildSaseSeats(
  state: Pick<SaseTunnelState, 'accessPolicy' | 'dnsPolicy' | 'dnsHistory' | 'lastAccessResult'>
): SaseSeatItem[] {
  const allPoliciesHardened = isAllPoliciesHardened(state);
  const riskyDnsAllowed = hasRiskyDnsAllowed(state.dnsHistory);
  const staffNeedsVerify = doesStaffNeedVerify(state);

  return [
    {
      id: 'remote-employee',
      name: 'Samira Al-Mansoor',
      roleLabel: 'Remote Staff',
      appLabel: 'Corporate Browser & Internal App Portal',
      avatarInitials: 'SA',
      badge: staffNeedsVerify
        ? { text: 'Verify Access', tone: 'blue', pulse: true }
        : null
    },
    {
      id: 'net-admin',
      name: 'Carlos Mendez',
      roleLabel: 'Network Security',
      appLabel: 'Access & Tunnel Policy Console',
      avatarInitials: 'CM',
      badge: !allPoliciesHardened
        ? {
            text: riskyDnsAllowed ? 'Egress Alert' : 'Policy Gaps',
            tone: riskyDnsAllowed ? 'crimson' : 'amber',
            pulse: true
          }
        : null
    }
  ];
}
