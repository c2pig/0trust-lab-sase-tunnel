import React, { useCallback, useEffect, useMemo, useRef, useState } from 'react';
import { ArrowLeft, Compass, Download, Globe, Laptop, RotateCcw, ShieldCheck } from 'lucide-react';
import { driver } from 'driver.js';
import 'driver.js/dist/driver.css';
import {
  AccessEvaluationResult,
  DEVICE_PROFILES,
  DeviceProfileId,
  DNS_PRESETS,
  DnsDomainPreset,
  DnsResolveResult,
  SaseSeatId,
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
import {
  buildSaseSeats,
  getGlobalStatusLabel,
  isAllPoliciesHardened
} from '../engine/saseTunnelSelectors';
import { RoleSeatItem, RoleSwitcherBar } from '../components/RoleSwitcherBar';
import { XRayDecodedProofSection, XRayTelemetryDrawer } from '../components/XRayTelemetryDrawer';
import { ObservabilitySpan } from '../types';

export interface SaseTunnelPageProps {
  onBack: () => void;
}

const APP_IDS: TargetAppId[] = ['internal-erp', 'finance-portal', 'admin-ssh-bastion'];
const DEVICE_IDS: DeviceProfileId[] = ['managed-corp', 'unmanaged-byod', 'stale-os'];

export function SaseTunnelPage({ onBack }: SaseTunnelPageProps): React.ReactElement {
  const [sessionId, setSessionId] = useState<string>(() => createSaseSessionId());
  const sessionIdRef = useRef<string>(sessionId);
  sessionIdRef.current = sessionId;

  const [activeSeat, setActiveSeat] = useState<SaseSeatId>('remote-employee');
  const [state, setState] = useState<SaseTunnelState>(() => createInitialSaseState());
  const [appResults, setAppResults] = useState<Partial<Record<TargetAppId, AccessEvaluationResult>>>({});
  const [dnsResults, setDnsResults] = useState<Partial<Record<DnsDomainPreset, DnsResolveResult>>>({});
  const [busyKey, setBusyKey] = useState<string | null>(null);
  const [spans, setSpans] = useState<ObservabilitySpan[]>([]);

  const tourLaunchedRef = useRef<boolean>(false);

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
          tunnel_connector: 'tun-cf-sase-sin-01',
          public_ports_exposed: 0
        }
      })
    );
  }, [sessionId, recordSpan]);

  const startLabTour = useCallback(() => {
    const driverObj = driver({
      showProgress: true,
      animate: true,
      allowClose: true,
      overlayOpacity: 0.5,
      steps: [
        {
          popover: {
            title: 'Lab Orientation: Zero-Trust SASE & Browser-to-Origin Tunnel',
            description:
              'Explore how identity and device posture gate internal application access over an outbound-only cloudflared tunnel while Gateway DNS filters risky egress.'
          }
        },
        {
          element: '#tour-role-switcher',
          popover: {
            title: 'Role Switcher',
            description:
              'Switch between Samira Al-Mansoor (Remote Staff) and Carlos Mendez (Network Security). Notification dots highlight pending policy hardening or verification steps.'
          }
        },
        {
          element: '#tour-workspace',
          popover: {
            title: 'Role Workspace',
            description:
              'Start as Samira Al-Mansoor to launch internal apps under different endpoint posture profiles and test web destinations, then switch to Carlos Mendez to enforce Zero-Trust Access and DNS rules.'
          }
        },
        {
          element: '.xray-drawer',
          popover: {
            title: 'X-Ray Telemetry Drawer',
            description:
              'Expand this bottom drawer anytime to inspect live HTTP spans, Cloudflare Access JWT assertions, tunnel connector metadata, and Gateway DNS traces.'
          }
        },
        {
          element: '#tour-lab-controls',
          popover: {
            title: 'Lab Controls',
            description:
              'Use Lab Tour to replay this orientation, or Reset to restore default endpoint posture and baseline SASE policies.'
          }
        }
      ]
    });
    driverObj.drive();
  }, []);

  useEffect(() => {
    if (tourLaunchedRef.current) return;
    tourLaunchedRef.current = true;
    const timer = window.setTimeout(() => {
      startLabTour();
    }, 300);
    return () => window.clearTimeout(timer);
  }, [startLabTour]);

  const handleReset = () => {
    const freshSession = createSaseSessionId();
    sessionIdRef.current = freshSession;
    setSessionId(freshSession);
    setActiveSeat('remote-employee');
    setState(createInitialSaseState());
    setAppResults({});
    setDnsResults({});
    setBusyKey(null);
    setSpans([]);
  };

  const handleLaunchApp = async (appId: TargetAppId) => {
    const currentSid = sessionIdRef.current;
    setBusyKey(`app:${appId}`);
    try {
      const candidateState: SaseTunnelState = {
        ...state,
        targetApp: appId
      };
      const { nextState, span } = await evaluateAccessWithEdgeFallback(
        candidateState,
        currentSid,
        false
      );
      if (sessionIdRef.current !== currentSid) return;
      setState(nextState);
      if (nextState.lastAccessResult) {
        setAppResults((prev) => ({
          ...prev,
          [appId]: nextState.lastAccessResult!
        }));
      }
      recordSpan(span);
    } finally {
      setBusyKey(null);
    }
  };

  const handleResolveDns = async (domain: DnsDomainPreset) => {
    const currentSid = sessionIdRef.current;
    setBusyKey(`dns:${domain}`);
    try {
      const { nextState, span } = await resolveDnsWithEdgeFallback(state, currentSid, domain);
      if (sessionIdRef.current !== currentSid) return;
      setState(nextState);
      if (nextState.lastDnsResult) {
        setDnsResults((prev) => ({
          ...prev,
          [domain]: nextState.lastDnsResult!
        }));
      }
      recordSpan(span);
    } finally {
      setBusyKey(null);
    }
  };

  const handleToggleAccessPolicy = (
    key: 'requireWarp' | 'requireDiskEncryption' | 'requireMinOs'
  ) => {
    setState((prev) => ({
      ...prev,
      accessPolicy: {
        ...prev.accessPolicy,
        [key]: !prev.accessPolicy[key]
      }
    }));
  };

  const handleToggleDnsPolicy = (key: 'blockC2' | 'blockMalware' | 'blockShadowAi') => {
    setState((prev) => ({
      ...prev,
      dnsPolicy: {
        ...prev.dnsPolicy,
        [key]: !prev.dnsPolicy[key]
      }
    }));
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

  const handleDownloadReport = () => {
    const blob = new Blob([exportSasePostureReport(state)], {
      type: 'application/json'
    });
    const url = URL.createObjectURL(blob);
    const a = document.createElement('a');
    a.href = url;
    a.download = `lab5-sase-posture-${sessionId}.json`;
    a.click();
    URL.revokeObjectURL(url);
  };

  const allPoliciesHardened = isAllPoliciesHardened(state);
  const globalStatusLabel = getGlobalStatusLabel(state);

  const seats: RoleSeatItem<SaseSeatId>[] = useMemo(
    () => buildSaseSeats(state),
    [state]
  );

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

  return (
    <div
      style={{
        minHeight: '100vh',
        display: 'flex',
        flexDirection: 'column',
        backgroundColor: 'var(--bg-canvas)',
        color: 'var(--text-primary)'
      }}
    >
      {/* 1. Compact AppShell Top Header */}
      <header
        style={{
          position: 'sticky',
          top: 0,
          zIndex: 40,
          backgroundColor: 'rgba(255, 255, 255, 0.96)',
          backdropFilter: 'blur(8px)',
          borderBottom: '1px solid var(--border-subtle)'
        }}
      >
        <div
          style={{
            maxWidth: '1280px',
            margin: '0 auto',
            padding: '0 16px',
            height: '56px',
            display: 'flex',
            alignItems: 'center',
            justifyContent: 'space-between',
            gap: '12px'
          }}
        >
          <div style={{ display: 'flex', alignItems: 'center', gap: '10px', minWidth: 0 }}>
            <button
              type="button"
              onClick={onBack}
              className="btn btn-sm"
              style={{ padding: '5px 9px' }}
              title="All Labs"
            >
              <ArrowLeft size={13} />
              <span>All Labs</span>
            </button>
            <span
              style={{
                fontSize: '14px',
                fontWeight: 700,
                color: 'var(--text-primary)',
                whiteSpace: 'nowrap'
              }}
            >
              Zero-Trust SASE &amp; Browser-to-Origin Tunnel
            </span>
            <span
              className={`badge ${allPoliciesHardened ? 'badge-emerald' : 'badge-amber'}`}
              style={{ whiteSpace: 'nowrap', fontSize: '12px' }}
            >
              {globalStatusLabel}
            </span>
          </div>

          <div style={{ display: 'flex', alignItems: 'center', gap: '8px', flexShrink: 0 }}>
            <RoleSwitcherBar
              seats={seats}
              activeSeatId={activeSeat}
              onSelectSeat={setActiveSeat}
              variant="dropdown"
              ariaLabel="Switch workspace persona"
            />

            <div id="tour-lab-controls" style={{ display: 'flex', alignItems: 'center', gap: '6px' }}>
              <button
                type="button"
                onClick={startLabTour}
                className="btn btn-sm"
                style={{
                  backgroundColor: 'var(--accent-primary-dim)',
                  borderColor: 'var(--accent-primary-border)',
                  color: 'var(--accent-primary-ink)',
                  fontSize: '13px'
                }}
              >
                <Compass size={14} />
                <span>Lab Tour</span>
              </button>
              <button
                type="button"
                onClick={handleReset}
                className="btn btn-sm"
                style={{ fontSize: '13px' }}
              >
                <RotateCcw size={14} />
                <span>Reset</span>
              </button>
            </div>
          </div>
        </div>
      </header>

      {/* 2. Center Role Workspace */}
      <main id="tour-workspace" style={{ flex: 1, padding: '16px', paddingBottom: '88px' }}>
        <div
          style={{
            maxWidth: '1280px',
            margin: '0 auto',
            display: 'flex',
            flexDirection: 'column',
            gap: '14px'
          }}
        >
          {/* ==================== SEAT 1: SAMIRA AL-MANSOOR — CORPORATE BROWSER & INTERNAL APP PORTAL ==================== */}
          {activeSeat === 'remote-employee' && (
            <section
              aria-label="Corporate Browser and Internal App Portal"
              style={{
                backgroundColor: 'var(--bg-surface)',
                border: '1px solid var(--border-subtle)',
                borderRadius: 'var(--radius-lg)',
                boxShadow: 'var(--shadow-sm)',
                overflow: 'hidden'
              }}
            >
              <div
                style={{
                  padding: '10px 18px',
                  backgroundColor: '#0f172a',
                  color: '#ffffff',
                  display: 'flex',
                  alignItems: 'center',
                  justifyContent: 'space-between',
                  gap: '12px',
                  flexWrap: 'wrap'
                }}
              >
                <div style={{ display: 'flex', alignItems: 'center', gap: '10px' }}>
                  <span
                    style={{
                      width: '26px',
                      height: '26px',
                      borderRadius: '5px',
                      backgroundColor: '#2563eb',
                      display: 'inline-flex',
                      alignItems: 'center',
                      justifyContent: 'center',
                      fontWeight: 700,
                      fontSize: '12px'
                    }}
                  >
                    <Globe size={15} />
                  </span>
                  <span style={{ fontSize: '15px', fontWeight: 700 }}>
                    Corporate Browser &amp; Internal App Portal
                  </span>
                </div>
                <span style={{ fontSize: '13.5px', color: '#e2e8f0' }}>
                  Samira Al-Mansoor · Remote Staff
                </span>
              </div>

              <div style={{ padding: '18px', display: 'flex', flexDirection: 'column', gap: '18px' }}>
                {/* Device Posture Profile Selector */}
                <div
                  style={{
                    border: '1px solid var(--border-subtle)',
                    borderRadius: 'var(--radius-md)',
                    backgroundColor: 'var(--bg-canvas)',
                    padding: '14px 16px',
                    display: 'flex',
                    flexDirection: 'column',
                    gap: '10px'
                  }}
                >
                  <div
                    style={{
                      display: 'flex',
                      alignItems: 'center',
                      justifyContent: 'space-between',
                      gap: '12px',
                      flexWrap: 'wrap'
                    }}
                  >
                    <div style={{ display: 'flex', alignItems: 'center', gap: '8px' }}>
                      <Laptop size={16} style={{ color: 'var(--accent-primary)' }} />
                      <span style={{ fontSize: '14.5px', fontWeight: 700 }}>Active Endpoint Device</span>
                    </div>
                    <div style={{ display: 'flex', gap: '8px', flexWrap: 'wrap' }}>
                      <span className={`badge ${activeProfile.warpConnected ? 'badge-emerald' : 'badge-crimson'}`}>
                        WARP: {activeProfile.warpConnected ? 'CONNECTED' : 'OFF'}
                      </span>
                      <span className={`badge ${activeProfile.diskEncrypted ? 'badge-emerald' : 'badge-crimson'}`}>
                        Disk Encryption: {activeProfile.diskEncrypted ? 'ON' : 'OFF'}
                      </span>
                      <span className={`badge ${activeProfile.osVersionOk ? 'badge-emerald' : 'badge-amber'}`}>
                        {activeProfile.osVersion}
                      </span>
                    </div>
                  </div>

                  <div style={{ display: 'flex', gap: '8px', flexWrap: 'wrap' }}>
                    {DEVICE_IDS.map((pid) => {
                      const prof = DEVICE_PROFILES[pid];
                      const isSelected = state.deviceProfile === pid;
                      return (
                        <button
                          key={pid}
                          type="button"
                          className={`btn btn-sm ${isSelected ? 'btn-primary' : ''}`}
                          style={{ fontSize: '13.5px', padding: '7px 13px' }}
                          onClick={() => setState((prev) => ({ ...prev, deviceProfile: pid }))}
                        >
                          {prof.label}
                        </button>
                      );
                    })}
                  </div>
                </div>

                {/* Internal Applications Table */}
                <div style={{ display: 'flex', flexDirection: 'column', gap: '10px' }}>
                  <div>
                    <h2 style={{ fontSize: '15.5px', fontWeight: 700, margin: 0 }}>
                      Internal Applications (Zero-Trust Tunnel)
                    </h2>
                    <p style={{ fontSize: '13.5px', color: 'var(--text-secondary)', margin: '2px 0 0' }}>
                      Access private corporate applications without a legacy VPN; every request is verified against endpoint posture at the edge.
                    </p>
                  </div>

                  <div className="data-table-wrapper">
                    <table className="data-table">
                      <thead>
                        <tr>
                          <th>Application</th>
                          <th>Private Origin</th>
                          <th>Tunnel Exposure</th>
                          <th>Access Status</th>
                          <th style={{ textAlign: 'right' }}>Action</th>
                        </tr>
                      </thead>
                      <tbody>
                        {APP_IDS.map((appId) => {
                          const app = TARGET_APPS[appId];
                          const res = appResults[appId];
                          const isBusy = busyKey === `app:${appId}`;
                          return (
                            <tr key={appId}>
                              <td>
                                <div style={{ fontWeight: 700, fontSize: '14px' }}>{app.label}</div>
                                <div className="mono" style={{ fontSize: '12.5px', color: 'var(--text-muted)' }}>
                                  https://{app.hostname}
                                </div>
                              </td>
                              <td className="mono">{app.originIp}</td>
                              <td>
                                <span className="badge badge-blue">0 Public Ports · QUIC</span>
                              </td>
                              <td>
                                {res ? (
                                  res.status === 'ACCESS_GRANTED' ? (
                                    <span className="badge badge-emerald">GRANTED (200)</span>
                                  ) : (
                                    <span className="badge badge-crimson">DENIED (403)</span>
                                  )
                                ) : (
                                  <span className="badge">NOT CONNECTED</span>
                                )}
                              </td>
                              <td style={{ textAlign: 'right', whiteSpace: 'nowrap' }}>
                                <button
                                  type="button"
                                  className="btn btn-primary btn-sm"
                                  style={{ fontSize: '13px', padding: '6px 12px' }}
                                  disabled={busyKey !== null}
                                  onClick={() => void handleLaunchApp(appId)}
                                >
                                  {isBusy ? 'Connecting…' : 'Open App'}
                                </button>
                              </td>
                            </tr>
                          );
                        })}
                      </tbody>
                    </table>
                  </div>

                  {state.lastAccessResult && (
                    <div
                      style={{
                        padding: '12px 14px',
                        borderRadius: '8px',
                        backgroundColor:
                          state.lastAccessResult.status === 'ACCESS_GRANTED'
                            ? 'var(--accent-emerald-dim)'
                            : 'var(--accent-crimson-dim)',
                        border: `1px solid ${
                          state.lastAccessResult.status === 'ACCESS_GRANTED'
                            ? 'var(--accent-emerald-border)'
                            : 'var(--accent-crimson-border)'
                        }`,
                        color:
                          state.lastAccessResult.status === 'ACCESS_GRANTED'
                            ? 'var(--accent-emerald-ink)'
                            : 'var(--accent-crimson-ink)',
                        fontSize: '13.5px'
                      }}
                    >
                      <strong>
                        {state.lastAccessResult.status === 'ACCESS_GRANTED'
                          ? `Connected via ${state.tunnelConnectorId} (HTTP 200):`
                          : 'Access Denied by Edge Policy (HTTP 403):'}
                      </strong>{' '}
                      {state.lastAccessResult.message}
                    </div>
                  )}
                </div>

                {/* Outbound Web & DNS Destinations Table */}
                <div style={{ display: 'flex', flexDirection: 'column', gap: '10px' }}>
                  <div>
                    <h2 style={{ fontSize: '15.5px', fontWeight: 700, margin: 0 }}>
                      Web &amp; DNS Destinations (Gateway Resolver)
                    </h2>
                    <p style={{ fontSize: '13.5px', color: 'var(--text-secondary)', margin: '2px 0 0' }}>
                      Test how corporate Gateway DNS handles internal hosts, approved SaaS, and restricted external domains.
                    </p>
                  </div>

                  <div className="data-table-wrapper">
                    <table className="data-table">
                      <thead>
                        <tr>
                          <th>Destination</th>
                          <th>Category</th>
                          <th>DNS Resolution</th>
                          <th style={{ textAlign: 'right' }}>Action</th>
                        </tr>
                      </thead>
                      <tbody>
                        {DNS_PRESETS.map((preset) => {
                          const res = dnsResults[preset.domain];
                          const isBusy = busyKey === `dns:${preset.domain}`;
                          return (
                            <tr key={preset.domain}>
                              <td>
                                <div style={{ fontWeight: 600, fontSize: '14px' }}>{preset.label}</div>
                                <div className="mono" style={{ fontSize: '12.5px', color: 'var(--text-muted)' }}>
                                  {preset.domain}
                                </div>
                              </td>
                              <td>
                                <span className="badge">{preset.riskTag}</span>
                              </td>
                              <td>
                                {res ? (
                                  res.status === 'BLOCKED_SINKHOLE' ? (
                                    <span className="badge badge-crimson">
                                      BLOCKED · NXDOMAIN (0.0.0.0)
                                    </span>
                                  ) : (
                                    <span className="badge badge-emerald">
                                      RESOLVED · {res.resolved_ip}
                                      {res.integration_mode === 'live-doh' ? ' · Live DoH' : ''}
                                    </span>
                                  )
                                ) : (
                                  <span style={{ color: 'var(--text-muted)', fontSize: '13px' }}>
                                    Not queried
                                  </span>
                                )}
                              </td>
                              <td style={{ textAlign: 'right', whiteSpace: 'nowrap' }}>
                                <button
                                  type="button"
                                  className="btn btn-sm"
                                  style={{ fontSize: '13px', padding: '6px 12px' }}
                                  disabled={busyKey !== null}
                                  onClick={() => void handleResolveDns(preset.domain)}
                                >
                                  {isBusy ? 'Resolving…' : 'Resolve DNS'}
                                </button>
                              </td>
                            </tr>
                          );
                        })}
                      </tbody>
                    </table>
                  </div>
                </div>
              </div>
            </section>
          )}

          {/* ==================== SEAT 2: CARLOS MENDEZ — ACCESS & TUNNEL POLICY CONSOLE ==================== */}
          {activeSeat === 'net-admin' && (
            <section
              aria-label="Access and Tunnel Policy Console"
              style={{
                backgroundColor: 'var(--bg-surface)',
                border: '1px solid var(--border-subtle)',
                borderRadius: 'var(--radius-lg)',
                boxShadow: 'var(--shadow-sm)',
                overflow: 'hidden'
              }}
            >
              <div
                style={{
                  padding: '10px 18px',
                  backgroundColor: 'var(--bg-canvas)',
                  borderBottom: '1px solid var(--border-subtle)',
                  display: 'flex',
                  alignItems: 'center',
                  justifyContent: 'space-between',
                  gap: '12px',
                  flexWrap: 'wrap'
                }}
              >
                <div style={{ display: 'flex', alignItems: 'center', gap: '10px' }}>
                  <span
                    style={{
                      width: '26px',
                      height: '26px',
                      borderRadius: '5px',
                      backgroundColor: '#7c3aed',
                      color: '#ffffff',
                      display: 'inline-flex',
                      alignItems: 'center',
                      justifyContent: 'center',
                      fontWeight: 700,
                      fontSize: '12px'
                    }}
                  >
                    NS
                  </span>
                  <span style={{ fontSize: '15px', fontWeight: 700 }}>
                    Access &amp; Tunnel Policy Console
                  </span>
                </div>
                <span style={{ fontSize: '13.5px', color: 'var(--text-secondary)', fontWeight: 600 }}>
                  Carlos Mendez · Network Security
                </span>
              </div>

              <div style={{ padding: '18px', display: 'flex', flexDirection: 'column', gap: '18px' }}>
                {/* Policy Table Header */}
                <div
                  style={{
                    display: 'flex',
                    alignItems: 'center',
                    justifyContent: 'space-between',
                    gap: '12px',
                    flexWrap: 'wrap'
                  }}
                >
                  <div>
                    <h2 style={{ fontSize: '15.5px', fontWeight: 700, margin: 0 }}>
                      Access Device Posture &amp; Gateway DNS Policies
                    </h2>
                    <p style={{ fontSize: '13.5px', color: 'var(--text-secondary)', margin: '2px 0 0' }}>
                      Enforce endpoint posture requirements for private tunnel access and sinkhole high-risk outbound DNS categories.
                    </p>
                  </div>
                  <div style={{ display: 'flex', gap: '8px', flexWrap: 'wrap' }}>
                    <button
                      type="button"
                      className="btn btn-sm"
                      style={{ fontSize: '13px', padding: '7px 12px' }}
                      onClick={handleDownloadReport}
                    >
                      <Download size={14} />
                      <span>Export Posture JSON</span>
                    </button>
                    <button
                      type="button"
                      className="btn btn-primary btn-sm"
                      style={{ fontSize: '13px', padding: '7px 13px' }}
                      disabled={allPoliciesHardened}
                      onClick={handleApplyZeroTrustBaseline}
                    >
                      <ShieldCheck size={14} />
                      <span>{allPoliciesHardened ? 'Zero-Trust Baseline Active' : 'Apply Zero-Trust Baseline'}</span>
                    </button>
                  </div>
                </div>

                <div className="data-table-wrapper">
                  <table className="data-table">
                    <thead>
                      <tr>
                        <th>Policy Rule</th>
                        <th>Plane</th>
                        <th>Status</th>
                        <th style={{ textAlign: 'right' }}>Action</th>
                      </tr>
                    </thead>
                    <tbody>
                      <tr>
                        <td>
                          <div style={{ fontWeight: 700, fontSize: '14px' }}>Require Cloudflare WARP Client</div>
                          <div style={{ fontSize: '13px', color: 'var(--text-secondary)' }}>
                            Block internal application requests unless the endpoint maintains an active WARP tunnel.
                          </div>
                        </td>
                        <td><span className="badge badge-blue">Access Posture</span></td>
                        <td>
                          {state.accessPolicy.requireWarp ? (
                            <span className="badge badge-emerald">ENFORCED</span>
                          ) : (
                            <span className="badge badge-amber">DISABLED</span>
                          )}
                        </td>
                        <td style={{ textAlign: 'right' }}>
                          <button
                            type="button"
                            className={`btn btn-sm ${state.accessPolicy.requireWarp ? '' : 'btn-primary'}`}
                            style={{ fontSize: '13px', padding: '6px 12px' }}
                            onClick={() => handleToggleAccessPolicy('requireWarp')}
                          >
                            {state.accessPolicy.requireWarp ? 'Disable' : 'Enforce'}
                          </button>
                        </td>
                      </tr>
                      <tr>
                        <td>
                          <div style={{ fontWeight: 700, fontSize: '14px' }}>Require Full Disk Encryption</div>
                          <div style={{ fontSize: '13px', color: 'var(--text-secondary)' }}>
                            Verify FileVault / BitLocker disk encryption before minting a Cloudflare Access JWT.
                          </div>
                        </td>
                        <td><span className="badge badge-blue">Access Posture</span></td>
                        <td>
                          {state.accessPolicy.requireDiskEncryption ? (
                            <span className="badge badge-emerald">ENFORCED</span>
                          ) : (
                            <span className="badge badge-amber">DISABLED</span>
                          )}
                        </td>
                        <td style={{ textAlign: 'right' }}>
                          <button
                            type="button"
                            className={`btn btn-sm ${state.accessPolicy.requireDiskEncryption ? '' : 'btn-primary'}`}
                            style={{ fontSize: '13px', padding: '6px 12px' }}
                            onClick={() => handleToggleAccessPolicy('requireDiskEncryption')}
                          >
                            {state.accessPolicy.requireDiskEncryption ? 'Disable' : 'Enforce'}
                          </button>
                        </td>
                      </tr>
                      <tr>
                        <td>
                          <div style={{ fontWeight: 700, fontSize: '14px' }}>Require Minimum OS Version (macOS 14.5+)</div>
                          <div style={{ fontSize: '13px', color: 'var(--text-secondary)' }}>
                            Reject endpoints running outdated operating system patch levels from accessing private origins.
                          </div>
                        </td>
                        <td><span className="badge badge-blue">Access Posture</span></td>
                        <td>
                          {state.accessPolicy.requireMinOs ? (
                            <span className="badge badge-emerald">ENFORCED</span>
                          ) : (
                            <span className="badge badge-amber">DISABLED</span>
                          )}
                        </td>
                        <td style={{ textAlign: 'right' }}>
                          <button
                            type="button"
                            className={`btn btn-sm ${state.accessPolicy.requireMinOs ? '' : 'btn-primary'}`}
                            style={{ fontSize: '13px', padding: '6px 12px' }}
                            onClick={() => handleToggleAccessPolicy('requireMinOs')}
                          >
                            {state.accessPolicy.requireMinOs ? 'Disable' : 'Enforce'}
                          </button>
                        </td>
                      </tr>
                      <tr>
                        <td>
                          <div style={{ fontWeight: 700, fontSize: '14px' }}>Block Command &amp; Control (C2) Domains</div>
                          <div style={{ fontSize: '13px', color: 'var(--text-secondary)' }}>
                            Sinkhole known C2 beacon domains to NXDOMAIN (0.0.0.0) at the edge DNS resolver.
                          </div>
                        </td>
                        <td><span className="badge">Gateway DNS</span></td>
                        <td>
                          {state.dnsPolicy.blockC2 ? (
                            <span className="badge badge-emerald">SINKHOLE</span>
                          ) : (
                            <span className="badge badge-amber">ALLOW</span>
                          )}
                        </td>
                        <td style={{ textAlign: 'right' }}>
                          <button
                            type="button"
                            className={`btn btn-sm ${state.dnsPolicy.blockC2 ? '' : 'btn-primary'}`}
                            style={{ fontSize: '13px', padding: '6px 12px' }}
                            onClick={() => handleToggleDnsPolicy('blockC2')}
                          >
                            {state.dnsPolicy.blockC2 ? 'Allow' : 'Block'}
                          </button>
                        </td>
                      </tr>
                      <tr>
                        <td>
                          <div style={{ fontWeight: 700, fontSize: '14px' }}>Block Malware Dropper Hosts</div>
                          <div style={{ fontSize: '13px', color: 'var(--text-secondary)' }}>
                            Prevent endpoints from resolving malware payload staging and dropper hosts.
                          </div>
                        </td>
                        <td><span className="badge">Gateway DNS</span></td>
                        <td>
                          {state.dnsPolicy.blockMalware ? (
                            <span className="badge badge-emerald">SINKHOLE</span>
                          ) : (
                            <span className="badge badge-amber">ALLOW</span>
                          )}
                        </td>
                        <td style={{ textAlign: 'right' }}>
                          <button
                            type="button"
                            className={`btn btn-sm ${state.dnsPolicy.blockMalware ? '' : 'btn-primary'}`}
                            style={{ fontSize: '13px', padding: '6px 12px' }}
                            onClick={() => handleToggleDnsPolicy('blockMalware')}
                          >
                            {state.dnsPolicy.blockMalware ? 'Allow' : 'Block'}
                          </button>
                        </td>
                      </tr>
                      <tr>
                        <td>
                          <div style={{ fontWeight: 700, fontSize: '14px' }}>Block Unsanctioned Shadow-AI Uploads</div>
                          <div style={{ fontSize: '13px', color: 'var(--text-secondary)' }}>
                            Sinkhole unauthorized GenAI upload endpoints to prevent corporate data exfiltration.
                          </div>
                        </td>
                        <td><span className="badge">Gateway DNS</span></td>
                        <td>
                          {state.dnsPolicy.blockShadowAi ? (
                            <span className="badge badge-emerald">SINKHOLE</span>
                          ) : (
                            <span className="badge badge-amber">ALLOW</span>
                          )}
                        </td>
                        <td style={{ textAlign: 'right' }}>
                          <button
                            type="button"
                            className={`btn btn-sm ${state.dnsPolicy.blockShadowAi ? '' : 'btn-primary'}`}
                            style={{ fontSize: '13px', padding: '6px 12px' }}
                            onClick={() => handleToggleDnsPolicy('blockShadowAi')}
                          >
                            {state.dnsPolicy.blockShadowAi ? 'Allow' : 'Block'}
                          </button>
                        </td>
                      </tr>
                    </tbody>
                  </table>
                </div>

                {/* Tunnel Connector Table */}
                <div style={{ display: 'flex', flexDirection: 'column', gap: '10px' }}>
                  <h2 style={{ fontSize: '15.5px', fontWeight: 700, margin: 0 }}>
                    Active `cloudflared` Tunnel Connectors
                  </h2>
                  <div className="data-table-wrapper">
                    <table className="data-table">
                      <thead>
                        <tr>
                          <th>Connector ID</th>
                          <th>Edge Colo</th>
                          <th>Protocol</th>
                          <th>Origin Network</th>
                          <th>Inbound Ports</th>
                          <th>Status</th>
                        </tr>
                      </thead>
                      <tbody>
                        <tr>
                          <td className="mono" style={{ fontWeight: 700 }}>{state.tunnelConnectorId}</td>
                          <td className="mono">SIN</td>
                          <td className="mono">QUIC (Outbound-Only)</td>
                          <td className="mono">10.24.0.0/24</td>
                          <td><span className="badge badge-emerald">0 Public Ports</span></td>
                          <td><span className="badge badge-emerald">HEALTHY</span></td>
                        </tr>
                      </tbody>
                    </table>
                  </div>
                </div>

                {/* Recent Gateway DNS Activity */}
                {state.dnsHistory.length > 0 && (
                  <div style={{ display: 'flex', flexDirection: 'column', gap: '10px' }}>
                    <h2 style={{ fontSize: '15.5px', fontWeight: 700, margin: 0 }}>
                      Recent Gateway DNS Queries
                    </h2>
                    <div className="data-table-wrapper">
                      <table className="data-table">
                        <thead>
                          <tr>
                            <th>Domain</th>
                            <th>Category</th>
                            <th>Matched Policy</th>
                            <th>Result</th>
                          </tr>
                        </thead>
                        <tbody>
                          {state.dnsHistory.slice(0, 6).map((item, idx) => (
                            <tr key={`${item.domain}-${item.timestamp}-${idx}`}>
                              <td className="mono" style={{ fontWeight: 600 }}>{item.domain}</td>
                              <td><span className="badge">{item.category}</span></td>
                              <td className="mono" style={{ fontSize: '12.5px' }}>{item.matched_policy}</td>
                              <td>
                                {item.status === 'BLOCKED_SINKHOLE' ? (
                                  <span className="badge badge-crimson">NXDOMAIN · 0.0.0.0</span>
                                ) : (
                                  <span className="badge badge-emerald">NOERROR · {item.resolved_ip}</span>
                                )}
                              </td>
                            </tr>
                          ))}
                        </tbody>
                      </table>
                    </div>
                  </div>
                )}
              </div>
            </section>
          )}
        </div>
      </main>

      {/* 3. Sticky-Bottom X-Ray Telemetry Drawer */}
      <XRayTelemetryDrawer
        spans={spans}
        decodedProofSections={decodedProofSections}
        onClear={() => setSpans([])}
      />
    </div>
  );
}
