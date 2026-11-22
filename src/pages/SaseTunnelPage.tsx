import React, { useCallback, useEffect, useMemo, useState } from 'react';
import {
  Activity,
  AlertTriangle,
  ArrowLeft,
  ArrowRight,
  CheckCircle2,
  Copy,
  Globe,
  Laptop,
  Lock,
  Network,
  RotateCcw,
  Server,
  Shield,
  ShieldAlert,
  ShieldCheck,
  Terminal
} from 'lucide-react';
import {
  DEVICE_PROFILES,
  DeviceProfileId,
  DNS_PRESETS,
  DnsDomainPreset,
  PoePredictionId,
  SaseSeatId,
  SaseStage,
  SaseTunnelState,
  TARGET_APPS,
  TargetAppId
} from '../contracts/saseTunnelContract';
import {
  createInitialSaseState,
  createSaseSessionId,
  createSaseSpan,
  evaluateAccessWithEdgeFallback,
  exportSasePostureReport,
  resolveDnsWithEdgeFallback
} from '../engine/saseTunnelEngine';
import { RoleSeatItem, RoleSwitcherBar } from '../components/RoleSwitcherBar';
import { XRayDecodedProofSection, XRayTelemetryDrawer } from '../components/XRayTelemetryDrawer';
import { ObservabilitySpan } from '../types';

export interface SaseTunnelPageProps {
  onBack: () => void;
}

const STAGE_LABELS: Array<{ id: SaseStage; label: string; short: string }> = [
  { id: 'discovery', label: '1. Discovery · Topology', short: '1. Discovery' },
  { id: 'poe', label: '2. POE · Predict & Observe', short: '2. POE Gate' },
  { id: 'practice', label: '3. Practice · Patch & Verify', short: '3. Practice' },
  { id: 'reflection', label: '4. Reflection · Posture Diff', short: '4. Reflection' }
];

const POE_OPTIONS: Array<{ id: PoePredictionId; label: string; detail: string }> = [
  {
    id: 'both-succeed',
    label: 'Both succeed because Zero-Trust VPN is not active',
    detail: 'Assumes neither Cloudflare Access nor Gateway DNS inspects traffic.'
  },
  {
    id: 'access-blocks-dns-leaks',
    label: 'Access blocks unmanaged device (403), but Shadow-AI DNS resolves until Gateway is patched',
    detail: 'Access enforces WARP/Disk posture, while Gateway DNS defaults to permissive until categories are blocked.'
  },
  {
    id: 'origin-drops-both',
    label: 'Private origin firewall drops both requests directly',
    detail: 'Assumes the private origin has a public IP receiving the packets.'
  }
];

export function SaseTunnelPage({ onBack }: SaseTunnelPageProps): React.ReactElement {
  const [sessionId, setSessionId] = useState<string>(() => createSaseSessionId());
  const [activeSeat, setActiveSeat] = useState<SaseSeatId>('remote-employee');
  const [state, setState] = useState<SaseTunnelState>(() => createInitialSaseState());
  const [busy, setBusy] = useState<boolean>(false);
  const [copiedReport, setCopiedReport] = useState<boolean>(false);
  const [spans, setSpans] = useState<ObservabilitySpan[]>([]);

  const recordSpan = useCallback((span: ObservabilitySpan) => {
    setSpans((prev) => [span, ...prev].slice(0, 40));
  }, []);

  useEffect(() => {
    recordSpan(
      createSaseSpan({
        sessionId,
        method: 'GET',
        path: '/api/sase-tunnel/session-init',
        status: 200,
        latencyMs: 3,
        origin: 'browser-webcrypto-fallback',
        summary: {
          mode: 'guided-sandbox',
          cost: '$0.00/mo',
          tunnel_connector: 'tun-cf-sase-sin-01',
          public_ports_exposed: 0
        }
      })
    );
  }, [sessionId, recordSpan]);

  const handleReset = () => {
    const freshSession = createSaseSessionId();
    setSessionId(freshSession);
    setActiveSeat('remote-employee');
    setState(createInitialSaseState());
    setCopiedReport(false);
    setSpans([]);
  };

  const handleEvaluateAccess = async (directOriginProbe = false) => {
    setBusy(true);
    try {
      const { nextState, span } = await evaluateAccessWithEdgeFallback(
        state,
        sessionId,
        directOriginProbe
      );
      setState(nextState);
      recordSpan(span);
    } finally {
      setBusy(false);
    }
  };

  const handleResolveDns = async (domain: DnsDomainPreset) => {
    setBusy(true);
    try {
      const { nextState, span } = await resolveDnsWithEdgeFallback(state, sessionId, domain);
      setState(nextState);
      recordSpan(span);
    } finally {
      setBusy(false);
    }
  };

  const handleApplyZeroTrustBaseline = () => {
    setState((prev) => ({
      ...prev,
      accessPolicy: {
        requireWarp: true,
        requireDiskEncryption: true,
        requireMinOs: true
      },
      dnsPolicy: {
        blockC2: true,
        blockMalware: true,
        blockShadowAi: true
      }
    }));
  };

  const handleCopyReport = async () => {
    const report = exportSasePostureReport(state);
    try {
      await navigator.clipboard.writeText(report);
      setCopiedReport(true);
      window.setTimeout(() => setCopiedReport(false), 2000);
    } catch {
      setCopiedReport(false);
    }
  };

  const seats: RoleSeatItem<SaseSeatId>[] = useMemo(() => {
    const accessStatus = state.lastAccessResult?.status;
    const employeeBadge =
      accessStatus === 'ACCESS_GRANTED'
        ? { text: 'TUNNEL GRANTED', tone: 'emerald' as const }
        : accessStatus === 'ACCESS_DENIED' || accessStatus === 'BLOCKED_NO_PUBLIC_INGRESS'
          ? { text: '403 BLOCKED', tone: 'crimson' as const }
          : { text: DEVICE_PROFILES[state.deviceProfile].warpConnected ? 'WARP ON' : 'UNMANAGED', tone: 'amber' as const };

    const allDnsProtected =
      state.dnsPolicy.blockC2 && state.dnsPolicy.blockMalware && state.dnsPolicy.blockShadowAi;
    const adminBadge = allDnsProtected && state.accessPolicy.requireMinOs
      ? { text: 'ZERO-TRUST HARDENED', tone: 'emerald' as const }
      : { text: 'POLICY GAPS', tone: 'amber' as const, pulse: true };

    return [
      {
        id: 'remote-employee',
        name: 'Samira Al-Mansoor',
        roleLabel: 'Remote Staff · Endpoint Client',
        appLabel: 'Browser & WARP Posture Simulator',
        badge: employeeBadge
      },
      {
        id: 'net-admin',
        name: 'Carlos Mendez',
        roleLabel: 'Network Sec · Cloudflare One Admin',
        appLabel: 'Access, Tunnel & Gateway DNS Console',
        badge: adminBadge
      }
    ];
  }, [state]);

  const decodedProofSections: XRayDecodedProofSection[] = useMemo(() => {
    const sections: XRayDecodedProofSection[] = [];
    if (state.lastAccessResult?.decoded_claims) {
      sections.push({
        id: 'cf-access-jwt',
        label: 'Cloudflare Access JWT (cf-access-jwt-assertion)',
        payload: {
          raw_redacted: state.lastAccessResult.cf_access_jwt_assertion,
          ...state.lastAccessResult.decoded_claims
        }
      });
    } else if (state.lastAccessResult) {
      sections.push({
        id: 'cf-access-decision',
        label: 'Cloudflare Access Gate Evaluation',
        payload: state.lastAccessResult
      });
    }

    sections.push({
      id: 'cloudflared-connector',
      label: 'cloudflared Tunnel Connector Metadata',
      payload: state.lastAccessResult?.tunnel_connector || {
        connector_id: state.tunnelConnectorId,
        edge_colo: 'SIN',
        protocol: 'quic',
        outbound_only: true,
        public_ports_open: 0,
        origin_private_ip: '10.24.0.14',
        healthy: state.tunnelHealthy
      }
    });

    if (state.lastDnsResult) {
      sections.push({
        id: 'gateway-dns-trace',
        label: 'Gateway DNS Query & Policy Trace',
        payload: state.lastDnsResult
      });
    }

    return sections;
  }, [state]);

  const activeProfile = DEVICE_PROFILES[state.deviceProfile];
  const trapsDoneCount = [
    state.traps.trap5aUnmanagedBlocked,
    state.traps.trap5bDirectOriginBlocked,
    state.traps.trap5cShadowAiObserved,
    state.traps.managedAccessGranted,
    state.traps.shadowAiAndC2Sinkholed
  ].filter(Boolean).length;

  return (
    <div className="lab-shell">
      <header className="lab-header">
        <div
          style={{
            maxWidth: 980,
            margin: '0 auto',
            display: 'flex',
            alignItems: 'center',
            justifyContent: 'space-between',
            gap: 12,
            flexWrap: 'wrap',
            padding: '10px 20px'
          }}
        >
          <div style={{ display: 'flex', alignItems: 'center', gap: 10, minWidth: 0 }}>
            <button type="button" className="btn-sm" onClick={onBack}>
              <ArrowLeft size={14} /> All Labs
            </button>
            <div style={{ minWidth: 0 }}>
              <div style={{ fontWeight: 700, fontSize: 15, color: 'var(--text-primary)' }}>
                Zero-Trust SASE &amp; Browser-to-Origin Tunnel
              </div>
              <div style={{ fontSize: 12, color: 'var(--text-muted)' }}>
                Lab 5 · Guided Sandbox ($0.00/mo) · 0 Public Ports
              </div>
            </div>
          </div>

          <div style={{ display: 'flex', alignItems: 'center', gap: 8, flexWrap: 'wrap' }}>
            <span className="badge badge-blue">
              Milestones {trapsDoneCount}/5
            </span>
            <button type="button" className="btn-sm" onClick={handleReset}>
              <RotateCcw size={13} /> Reset
            </button>
          </div>
        </div>
      </header>

      <main className="lab-workspace">
        <RoleSwitcherBar
          seats={seats}
          activeSeatId={activeSeat}
          onSelectSeat={(id) => setActiveSeat(id)}
          ariaLabel="SASE Lab Persona Seats"
        />

        {/* 4-Phase Cognitive Arc Stepper */}
        <nav
          aria-label="4-Phase Cognitive Arc"
          style={{
            display: 'grid',
            gridTemplateColumns: 'repeat(auto-fit, minmax(145px, 1fr))',
            gap: 8,
            marginBottom: 16
          }}
        >
          {STAGE_LABELS.map((item) => {
            const isCurrent = state.stage === item.id;
            return (
              <button
                key={item.id}
                type="button"
                onClick={() => setState((prev) => ({ ...prev, stage: item.id }))}
                style={{
                  padding: '9px 12px',
                  borderRadius: 'var(--radius-md)',
                  border: isCurrent
                    ? '1.5px solid var(--accent-primary)'
                    : '1px solid var(--border-subtle)',
                  backgroundColor: isCurrent ? 'var(--accent-primary-dim)' : 'var(--bg-surface)',
                  color: isCurrent ? 'var(--accent-primary)' : 'var(--text-secondary)',
                  fontWeight: isCurrent ? 700 : 500,
                  fontSize: 12,
                  textAlign: 'left',
                  cursor: 'pointer'
                }}
              >
                {item.short}
              </button>
            );
          })}
        </nav>

        {/* PHASE 1: DISCOVERY */}
        {state.stage === 'discovery' && (
          <section
            style={{
              backgroundColor: 'var(--bg-surface)',
              border: '1px solid var(--border-subtle)',
              borderRadius: 'var(--radius-lg)',
              padding: 20,
              marginBottom: 16
            }}
          >
            <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', flexWrap: 'wrap', gap: 10, marginBottom: 14 }}>
              <div>
                <h2 style={{ margin: 0, fontSize: 17, color: 'var(--text-primary)' }}>
                  Phase 1 · Discovery: Zero-Exposed-Port SASE Topology
                </h2>
                <p style={{ margin: '4px 0 0', fontSize: 13, color: 'var(--text-secondary)' }}>
                  Replace legacy VPNs with identity + device posture at the Cloudflare Edge and an outbound-only <code>cloudflared</code> tunnel.
                </p>
              </div>
              <span className="badge badge-emerald">0 Inbound Ports</span>
            </div>

            <div
              style={{
                display: 'grid',
                gridTemplateColumns: 'repeat(auto-fit, minmax(185px, 1fr))',
                gap: 12,
                marginBottom: 18
              }}
            >
              <div style={{ padding: 14, borderRadius: 'var(--radius-md)', border: '1px solid var(--border-subtle)', backgroundColor: 'var(--bg-canvas)' }}>
                <div style={{ display: 'flex', alignItems: 'center', gap: 8, fontWeight: 600, fontSize: 13, marginBottom: 6 }}>
                  <Laptop size={16} color="#2563eb" /> 1. Endpoint &amp; Browser
                </div>
                <p style={{ margin: 0, fontSize: 12, color: 'var(--text-secondary)' }}>
                  Samira&apos;s device runs Cloudflare WARP + device posture telemetry (Disk Encryption, OS version).
                </p>
              </div>

              <div style={{ padding: 14, borderRadius: 'var(--radius-md)', border: '1px solid var(--border-subtle)', backgroundColor: 'var(--bg-canvas)' }}>
                <div style={{ display: 'flex', alignItems: 'center', gap: 8, fontWeight: 600, fontSize: 13, marginBottom: 6 }}>
                  <Shield size={16} color="#059669" /> 2. Cloudflare Edge
                </div>
                <p style={{ margin: 0, fontSize: 12, color: 'var(--text-secondary)' }}>
                  Access evaluates posture &amp; mints <code>cf-access-jwt-assertion</code>; Gateway DNS filters C2, Malware &amp; Shadow-AI.
                </p>
              </div>

              <div style={{ padding: 14, borderRadius: 'var(--radius-md)', border: '1px solid var(--border-subtle)', backgroundColor: 'var(--bg-canvas)' }}>
                <div style={{ display: 'flex', alignItems: 'center', gap: 8, fontWeight: 600, fontSize: 13, marginBottom: 6 }}>
                  <Network size={16} color="#7c3aed" /> 3. cloudflared Tunnel
                </div>
                <p style={{ margin: 0, fontSize: 12, color: 'var(--text-secondary)' }}>
                  Connector <code>{state.tunnelConnectorId}</code> dials outbound QUIC to Edge. Zero public IPs or open ports.
                </p>
              </div>

              <div style={{ padding: 14, borderRadius: 'var(--radius-md)', border: '1px solid var(--border-subtle)', backgroundColor: 'var(--bg-canvas)' }}>
                <div style={{ display: 'flex', alignItems: 'center', gap: 8, fontWeight: 600, fontSize: 13, marginBottom: 6 }}>
                  <Server size={16} color="#0f172a" /> 4. Private Origin
                </div>
                <p style={{ margin: 0, fontSize: 12, color: 'var(--text-secondary)' }}>
                  Internal ERP (<code>10.24.0.14:8443</code>) accepts traffic only from the local <code>cloudflared</code> daemon.
                </p>
              </div>
            </div>

            <div style={{ display: 'flex', justifyContent: 'flex-end' }}>
              <button
                type="button"
                className="btn-primary"
                onClick={() => setState((prev) => ({ ...prev, stage: 'poe' }))}
              >
                Continue to POE Prediction Gate <ArrowRight size={14} />
              </button>
            </div>
          </section>
        )}

        {/* PHASE 2: POE GATE */}
        {state.stage === 'poe' && (
          <section
            style={{
              backgroundColor: 'var(--bg-surface)',
              border: '1px solid var(--border-subtle)',
              borderRadius: 'var(--radius-lg)',
              padding: 20,
              marginBottom: 16
            }}
          >
            <h2 style={{ margin: '0 0 6px', fontSize: 17, color: 'var(--text-primary)' }}>
              Phase 2 · Predict · Observe · Explain (POE Gate)
            </h2>
            <p style={{ margin: '0 0 14px', fontSize: 13, color: 'var(--text-secondary)' }}>
              Predict what happens when an unmanaged BYOD laptop accesses Internal ERP AND resolves <code>shadow-llm-upload.example</code> under the initial Gateway policy.
            </p>

            {/* Step 1: Predict */}
            <div style={{ marginBottom: 16 }}>
              <div style={{ fontWeight: 600, fontSize: 13, marginBottom: 8 }}>
                Step 1 · Predict the Outcome
              </div>
              <div style={{ display: 'flex', flexDirection: 'column', gap: 8 }}>
                {POE_OPTIONS.map((opt) => {
                  const selected = state.poePrediction === opt.id;
                  return (
                    <button
                      key={opt.id}
                      type="button"
                      onClick={() => setState((prev) => ({ ...prev, poePrediction: opt.id }))}
                      style={{
                        padding: '10px 14px',
                        borderRadius: 'var(--radius-md)',
                        border: selected
                          ? '1.5px solid var(--accent-primary)'
                          : '1px solid var(--border-subtle)',
                        backgroundColor: selected ? 'var(--accent-primary-dim)' : 'var(--bg-canvas)',
                        textAlign: 'left',
                        cursor: 'pointer'
                      }}
                    >
                      <div style={{ fontWeight: 600, fontSize: 13, color: 'var(--text-primary)' }}>
                        {opt.label}
                      </div>
                      <div style={{ fontSize: 12, color: 'var(--text-secondary)', marginTop: 2 }}>
                        {opt.detail}
                      </div>
                    </button>
                  );
                })}
              </div>
            </div>

            {/* Step 2: Observe */}
            <div style={{ marginBottom: 16, opacity: state.poePrediction ? 1 : 0.55 }}>
              <div style={{ fontWeight: 600, fontSize: 13, marginBottom: 8 }}>
                Step 2 · Observe Live Edge Traps
              </div>
              <div style={{ display: 'flex', gap: 10, flexWrap: 'wrap' }}>
                <button
                  type="button"
                  className="btn-danger-soft"
                  disabled={!state.poePrediction || busy}
                  onClick={() => {
                    setState((prev) => ({ ...prev, deviceProfile: 'unmanaged-byod' }));
                    void handleEvaluateAccess(false);
                  }}
                >
                  <ShieldAlert size={14} /> Trap 5A: Unmanaged BYOD Access
                </button>
                <button
                  type="button"
                  className="btn-amber-soft"
                  disabled={!state.poePrediction || busy}
                  onClick={() => void handleEvaluateAccess(true)}
                >
                  <Terminal size={14} /> Trap 5B: Direct-to-Origin IP Scan
                </button>
                <button
                  type="button"
                  className="btn-dark"
                  disabled={!state.poePrediction || busy}
                  onClick={() => void handleResolveDns('shadow-llm-upload.example')}
                >
                  <Globe size={14} /> Trap 5C: Shadow-AI DNS Lookup
                </button>
              </div>
            </div>

            {/* Live Observe Output */}
            {(state.lastAccessResult || state.lastDnsResult) && (
              <div
                style={{
                  display: 'grid',
                  gridTemplateColumns: 'repeat(auto-fit, minmax(260px, 1fr))',
                  gap: 12,
                  marginBottom: 16
                }}
              >
                {state.lastAccessResult && (
                  <div style={{ padding: 12, borderRadius: 'var(--radius-md)', border: '1px solid var(--border-subtle)', backgroundColor: 'var(--bg-canvas)' }}>
                    <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', marginBottom: 6 }}>
                      <span style={{ fontWeight: 600, fontSize: 12 }}>Access / Origin Gate</span>
                      <span className={`badge ${state.lastAccessResult.http_status === 200 ? 'badge-emerald' : 'badge-crimson'}`}>
                        HTTP {state.lastAccessResult.http_status}
                      </span>
                    </div>
                    <div style={{ fontSize: 12, color: 'var(--text-secondary)' }}>
                      {state.lastAccessResult.message}
                    </div>
                  </div>
                )}

                {state.lastDnsResult && (
                  <div style={{ padding: 12, borderRadius: 'var(--radius-md)', border: '1px solid var(--border-subtle)', backgroundColor: 'var(--bg-canvas)' }}>
                    <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', marginBottom: 6 }}>
                      <span style={{ fontWeight: 600, fontSize: 12 }}>Gateway DNS Resolver</span>
                      <span className={`badge ${state.lastDnsResult.dns_rcode === 'NXDOMAIN' ? 'badge-emerald' : 'badge-amber'}`}>
                        {state.lastDnsResult.dns_rcode} · {state.lastDnsResult.resolved_ip}
                      </span>
                    </div>
                    <div style={{ fontSize: 12, color: 'var(--text-secondary)' }}>
                      {state.lastDnsResult.message}
                    </div>
                  </div>
                )}
              </div>
            )}

            {/* Step 3: Explain */}
            {state.poeExplanationUnlocked && (
              <div
                style={{
                  padding: 14,
                  borderRadius: 'var(--radius-md)',
                  border: '1px solid #a7f3d0',
                  backgroundColor: '#ecfdf5',
                  marginBottom: 14
                }}
              >
                <div style={{ fontWeight: 700, fontSize: 13, color: '#065f46', marginBottom: 4 }}>
                  Step 3 · Explain: Why Access Blocked Device Posture, While Gateway DNS Leaked Shadow-AI
                </div>
                <p style={{ margin: 0, fontSize: 12, color: '#065f46' }}>
                  Cloudflare Access enforces device posture (WARP + Disk Encryption) before traffic ever touches the <code>cloudflared</code> tunnel, and direct IP scans fail because the origin has 0 public ports. However, outbound DNS queries to <code>shadow-llm-upload.example</code> still resolve (<code>NOERROR</code>) until Carlos Mendez enables Gateway DNS category blocks in Practice mode.
                </p>
              </div>
            )}

            <div style={{ display: 'flex', justifyContent: 'space-between', flexWrap: 'wrap', gap: 10 }}>
              <button
                type="button"
                className="btn-sm"
                onClick={() => setState((prev) => ({ ...prev, stage: 'discovery' }))}
              >
                <ArrowLeft size={14} /> Back
              </button>
              <button
                type="button"
                className="btn-primary"
                disabled={!state.poeExplanationUnlocked}
                onClick={() => {
                  setActiveSeat('net-admin');
                  setState((prev) => ({ ...prev, stage: 'practice' }));
                }}
              >
                Proceed to Practice (Patch Policies) <ArrowRight size={14} />
              </button>
            </div>
          </section>
        )}

        {/* PHASE 3: PRACTICE (2-SEAT WORKBENCH) */}
        {state.stage === 'practice' && (
          <section
            style={{
              display: 'grid',
              gridTemplateColumns: 'repeat(auto-fit, minmax(280px, 1fr))',
              gap: 16,
              marginBottom: 16
            }}
          >
            {/* Seat 1: Remote Employee */}
            <div
              style={{
                backgroundColor: 'var(--bg-surface)',
                border: activeSeat === 'remote-employee' ? '1.5px solid var(--accent-primary)' : '1px solid var(--border-subtle)',
                borderRadius: 'var(--radius-lg)',
                padding: 18,
                minWidth: 0
              }}
            >
              <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', gap: 8, marginBottom: 12 }}>
                <div style={{ fontWeight: 700, fontSize: 15 }}>
                  Remote Staff · Endpoint Simulator
                </div>
                <span className="badge badge-blue">Samira Al-Mansoor</span>
              </div>

              <label style={{ display: 'block', fontSize: 12, fontWeight: 600, marginBottom: 6 }}>
                Endpoint Device Posture Profile
              </label>
              <div style={{ display: 'flex', flexDirection: 'column', gap: 6, marginBottom: 14 }}>
                {(Object.keys(DEVICE_PROFILES) as DeviceProfileId[]).map((pid) => {
                  const prof = DEVICE_PROFILES[pid];
                  const selected = state.deviceProfile === pid;
                  return (
                    <button
                      key={pid}
                      type="button"
                      onClick={() => {
                        setActiveSeat('remote-employee');
                        setState((prev) => ({ ...prev, deviceProfile: pid }));
                      }}
                      style={{
                        padding: '8px 10px',
                        borderRadius: 'var(--radius-md)',
                        border: selected ? '1.5px solid var(--accent-primary)' : '1px solid var(--border-subtle)',
                        backgroundColor: selected ? 'var(--accent-primary-dim)' : 'var(--bg-canvas)',
                        textAlign: 'left',
                        cursor: 'pointer'
                      }}
                    >
                      <div style={{ fontWeight: 600, fontSize: 12 }}>{prof.label}</div>
                      <div style={{ fontSize: 11, color: 'var(--text-muted)' }}>
                        WARP: {prof.warpConnected ? 'ON' : 'OFF'} · Disk Enc: {prof.diskEncrypted ? 'YES' : 'NO'} · {prof.osVersion}
                      </div>
                    </button>
                  );
                })}
              </div>

              <label style={{ display: 'block', fontSize: 12, fontWeight: 600, marginBottom: 6 }}>
                Target Private Application (via cloudflared)
              </label>
              <div style={{ display: 'flex', gap: 6, flexWrap: 'wrap', marginBottom: 12 }}>
                {(Object.keys(TARGET_APPS) as TargetAppId[]).map((appId) => (
                  <button
                    key={appId}
                    type="button"
                    className={state.targetApp === appId ? 'btn-primary btn-sm' : 'btn-sm'}
                    onClick={() => setState((prev) => ({ ...prev, targetApp: appId }))}
                  >
                    {TARGET_APPS[appId].label}
                  </button>
                ))}
              </div>

              <div style={{ display: 'flex', gap: 8, flexWrap: 'wrap', marginBottom: 14 }}>
                <button
                  type="button"
                  className="btn-primary"
                  disabled={busy}
                  onClick={() => {
                    setActiveSeat('remote-employee');
                    void handleEvaluateAccess(false);
                  }}
                >
                  <Lock size={14} /> Connect via Cloudflare Access
                </button>
                <button
                  type="button"
                  className="btn-amber-soft"
                  disabled={busy}
                  onClick={() => {
                    setActiveSeat('remote-employee');
                    void handleEvaluateAccess(true);
                  }}
                >
                  <Terminal size={14} /> Probe Direct Origin IP
                </button>
              </div>

              <div style={{ fontSize: 12, fontWeight: 600, marginBottom: 6 }}>
                Test Outbound DNS Egress Queries
              </div>
              <div style={{ display: 'flex', gap: 6, flexWrap: 'wrap', marginBottom: 12 }}>
                {DNS_PRESETS.map((preset) => (
                  <button
                    key={preset.domain}
                    type="button"
                    className="btn-sm"
                    disabled={busy}
                    onClick={() => {
                      setActiveSeat('remote-employee');
                      void handleResolveDns(preset.domain);
                    }}
                  >
                    {preset.label}
                  </button>
                ))}
              </div>

              {state.lastAccessResult && (
                <div style={{ padding: 10, borderRadius: 'var(--radius-md)', border: '1px solid var(--border-subtle)', backgroundColor: 'var(--bg-canvas)', fontSize: 12, marginBottom: 8 }}>
                  <strong>Access Result ({state.lastAccessResult.http_status}):</strong>{' '}
                  {state.lastAccessResult.message}
                </div>
              )}

              {state.lastDnsResult && (
                <div style={{ padding: 10, borderRadius: 'var(--radius-md)', border: '1px solid var(--border-subtle)', backgroundColor: 'var(--bg-canvas)', fontSize: 12 }}>
                  <strong>DNS ({state.lastDnsResult.dns_rcode}):</strong>{' '}
                  <code>{state.lastDnsResult.domain}</code> → <code>{state.lastDnsResult.resolved_ip}</code> ({state.lastDnsResult.matched_policy})
                </div>
              )}
            </div>

            {/* Seat 2: Network Admin */}
            <div
              style={{
                backgroundColor: 'var(--bg-surface)',
                border: activeSeat === 'net-admin' ? '1.5px solid var(--accent-primary)' : '1px solid var(--border-subtle)',
                borderRadius: 'var(--radius-lg)',
                padding: 18,
                minWidth: 0
              }}
            >
              <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', gap: 8, marginBottom: 12 }}>
                <div style={{ fontWeight: 700, fontSize: 15 }}>
                  Cloudflare One Admin Console
                </div>
                <span className="badge badge-emerald">Carlos Mendez</span>
              </div>

              <div style={{ fontWeight: 600, fontSize: 12, marginBottom: 8 }}>
                Cloudflare Access Device Posture Rules
              </div>
              <div style={{ display: 'flex', flexDirection: 'column', gap: 8, marginBottom: 14 }}>
                <label style={{ display: 'flex', alignItems: 'center', gap: 8, fontSize: 13, cursor: 'pointer' }}>
                  <input
                    type="checkbox"
                    checked={state.accessPolicy.requireWarp}
                    onChange={(e) =>
                      setState((prev) => ({
                        ...prev,
                        accessPolicy: { ...prev.accessPolicy, requireWarp: e.target.checked }
                      }))
                    }
                  />
                  Require WARP Zero-Trust Client
                </label>
                <label style={{ display: 'flex', alignItems: 'center', gap: 8, fontSize: 13, cursor: 'pointer' }}>
                  <input
                    type="checkbox"
                    checked={state.accessPolicy.requireDiskEncryption}
                    onChange={(e) =>
                      setState((prev) => ({
                        ...prev,
                        accessPolicy: { ...prev.accessPolicy, requireDiskEncryption: e.target.checked }
                      }))
                    }
                  />
                  Require Full-Disk Encryption (FileVault / BitLocker)
                </label>
                <label style={{ display: 'flex', alignItems: 'center', gap: 8, fontSize: 13, cursor: 'pointer' }}>
                  <input
                    type="checkbox"
                    checked={state.accessPolicy.requireMinOs}
                    onChange={(e) =>
                      setState((prev) => ({
                        ...prev,
                        accessPolicy: { ...prev.accessPolicy, requireMinOs: e.target.checked }
                      }))
                    }
                  />
                  Require OS &gt;= macOS 14.5 (Blocks Stale OS)
                </label>
              </div>

              <div style={{ fontWeight: 600, fontSize: 12, marginBottom: 8 }}>
                Cloudflare Gateway DNS Egress Filtering
              </div>
              <div style={{ display: 'flex', flexDirection: 'column', gap: 8, marginBottom: 14 }}>
                <label style={{ display: 'flex', alignItems: 'center', gap: 8, fontSize: 13, cursor: 'pointer' }}>
                  <input
                    type="checkbox"
                    checked={state.dnsPolicy.blockC2}
                    onChange={(e) =>
                      setState((prev) => ({
                        ...prev,
                        dnsPolicy: { ...prev.dnsPolicy, blockC2: e.target.checked }
                      }))
                    }
                  />
                  Sinkhole Command &amp; Control (C2) Domains
                </label>
                <label style={{ display: 'flex', alignItems: 'center', gap: 8, fontSize: 13, cursor: 'pointer' }}>
                  <input
                    type="checkbox"
                    checked={state.dnsPolicy.blockMalware}
                    onChange={(e) =>
                      setState((prev) => ({
                        ...prev,
                        dnsPolicy: { ...prev.dnsPolicy, blockMalware: e.target.checked }
                      }))
                    }
                  />
                  Sinkhole Malware Staging Hosts
                </label>
                <label style={{ display: 'flex', alignItems: 'center', gap: 8, fontSize: 13, cursor: 'pointer' }}>
                  <input
                    type="checkbox"
                    checked={state.dnsPolicy.blockShadowAi}
                    onChange={(e) =>
                      setState((prev) => ({
                        ...prev,
                        dnsPolicy: { ...prev.dnsPolicy, blockShadowAi: e.target.checked }
                      }))
                    }
                  />
                  Block Unapproved Shadow-AI GenAI Uploads
                </label>
              </div>

              <div style={{ display: 'flex', gap: 8, flexWrap: 'wrap', marginBottom: 16 }}>
                <button
                  type="button"
                  className="btn-emerald"
                  onClick={handleApplyZeroTrustBaseline}
                >
                  <ShieldCheck size={14} /> Apply Zero-Trust Baseline
                </button>
                <button
                  type="button"
                  className="btn-primary"
                  onClick={() => setState((prev) => ({ ...prev, stage: 'reflection' }))}
                >
                  View Reflection &amp; Diff <ArrowRight size={14} />
                </button>
              </div>

              <div style={{ padding: 10, borderRadius: 'var(--radius-md)', border: '1px solid var(--border-subtle)', backgroundColor: 'var(--bg-canvas)', fontSize: 12 }}>
                <div style={{ fontWeight: 600, marginBottom: 4 }}>
                  <Activity size={13} style={{ verticalAlign: 'middle', marginRight: 4 }} />
                  Active Profile: {activeProfile.label}
                </div>
                <div style={{ color: 'var(--text-muted)' }}>
                  Tunnel: <code>{state.tunnelConnectorId}</code> · QUIC Outbound-Only · 0 Public Ports
                </div>
              </div>
            </div>
          </section>
        )}

        {/* PHASE 4: REFLECTION */}
        {state.stage === 'reflection' && (
          <section
            style={{
              backgroundColor: 'var(--bg-surface)',
              border: '1px solid var(--border-subtle)',
              borderRadius: 'var(--radius-lg)',
              padding: 20,
              marginBottom: 16
            }}
          >
            <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', flexWrap: 'wrap', gap: 10, marginBottom: 14 }}>
              <div>
                <h2 style={{ margin: 0, fontSize: 17, color: 'var(--text-primary)' }}>
                  Phase 4 · Reflection: Zero-Exposed-Port Posture Summary
                </h2>
                <p style={{ margin: '4px 0 0', fontSize: 13, color: 'var(--text-secondary)' }}>
                  Before vs. After edge policy diff and verification milestones.
                </p>
              </div>
              <button type="button" className="btn-sm" onClick={() => void handleCopyReport()}>
                <Copy size={13} /> {copiedReport ? 'Copied JSON!' : 'Copy Posture Report'}
              </button>
            </div>

            <div
              style={{
                display: 'grid',
                gridTemplateColumns: 'repeat(auto-fit, minmax(220px, 1fr))',
                gap: 12,
                marginBottom: 16
              }}
            >
              {[
                { label: 'Trap 5A · Unmanaged Device Blocked (403)', done: state.traps.trap5aUnmanagedBlocked },
                { label: 'Trap 5B · Direct Origin Scan Blocked (0 Ports)', done: state.traps.trap5bDirectOriginBlocked },
                { label: 'Trap 5C · Shadow-AI Leak Observed in POE', done: state.traps.trap5cShadowAiObserved },
                { label: 'Managed Laptop Granted Tunnel Access (200)', done: state.traps.managedAccessGranted },
                { label: 'Shadow-AI / C2 Sinkholed (NXDOMAIN 0.0.0.0)', done: state.traps.shadowAiAndC2Sinkholed }
              ].map((item) => (
                <div
                  key={item.label}
                  style={{
                    padding: 12,
                    borderRadius: 'var(--radius-md)',
                    border: '1px solid var(--border-subtle)',
                    backgroundColor: 'var(--bg-canvas)',
                    display: 'flex',
                    alignItems: 'center',
                    gap: 8,
                    fontSize: 12
                  }}
                >
                  {item.done ? (
                    <CheckCircle2 size={16} color="#059669" />
                  ) : (
                    <AlertTriangle size={16} color="#d97706" />
                  )}
                  <span>{item.label}</span>
                </div>
              ))}
            </div>

            <div style={{ display: 'flex', justifyContent: 'space-between', flexWrap: 'wrap', gap: 10 }}>
              <button
                type="button"
                className="btn-sm"
                onClick={() => setState((prev) => ({ ...prev, stage: 'practice' }))}
              >
                <ArrowLeft size={14} /> Back to Practice
              </button>
              <button type="button" className="btn-primary" onClick={handleReset}>
                <RotateCcw size={14} /> Reset Lab Session
              </button>
            </div>
          </section>
        )}
      </main>

      <XRayTelemetryDrawer
        spans={spans}
        decodedProofSections={decodedProofSections}
        onClear={() => setSpans([])}
      />
    </div>
  );
}
