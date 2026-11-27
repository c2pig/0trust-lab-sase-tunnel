import assert from 'node:assert/strict';
import { describe, it } from 'node:test';
import {
  createInitialSaseState,
  createSaseSessionId,
  createSaseSpan,
  createTraceparent,
  evaluateAccessWithEdgeFallback,
  exportSasePostureReport,
  resolveDnsWithEdgeFallback
} from '../src/engine/saseTunnelEngine';

describe('Lab 5 (sase-tunnel) Layer 3 Engine — SASE Tunnel & DNS Fallback', () => {
  it('generates valid session IDs, W3C traceparents, and redacted spans', () => {
    const sid = createSaseSessionId();
    assert.match(sid, /^sase-[0-9a-f]{12}$/);

    const tp = createTraceparent();
    assert.match(tp, /^00-[0-9a-f]{32}-[0-9a-f]{16}-01$/);

    const span = createSaseSpan({
      sessionId: sid,
      traceparent: tp,
      method: 'POST',
      path: '/api/sase-tunnel/evaluate-access',
      status: 200,
      latencyMs: 12,
      origin: 'browser-webcrypto-fallback',
      summary: { decision: 'ACCESS_GRANTED' }
    });
    assert.equal(span.session_id, sid);
    assert.equal(span.redaction_applied, true);
    assert.equal(span.redacted_auth_header, null);
  });

  it('evaluates access locally in Node fallback for denied, granted, and direct-origin probe', async () => {
    const state = createInitialSaseState();

    // Default state: unmanaged-byod -> ACCESS_DENIED
    const denied = await evaluateAccessWithEdgeFallback(state, 'sase-test-1');
    assert.equal(denied.nextState.lastAccessResult?.status, 'ACCESS_DENIED');
    assert.equal(denied.span.execution_origin, 'browser-webcrypto-fallback');
    assert.ok(denied.nextState.lastAccessResult?.failed_checks?.includes('WARP_CLIENT_MISSING'));

    // Managed corp -> ACCESS_GRANTED
    state.deviceProfile = 'managed-corp';
    const granted = await evaluateAccessWithEdgeFallback(state, 'sase-test-1');
    assert.equal(granted.nextState.lastAccessResult?.status, 'ACCESS_GRANTED');
    assert.ok(granted.nextState.lastAccessResult?.cf_access_jwt_assertion);

    // Direct origin probe -> BLOCKED_NO_PUBLIC_INGRESS
    const probe = await evaluateAccessWithEdgeFallback(state, 'sase-test-1', true);
    assert.equal(probe.nextState.lastAccessResult?.status, 'BLOCKED_NO_PUBLIC_INGRESS');
    assert.equal(probe.nextState.lastAccessResult?.public_ports_open, 0);
  });

  it('resolves DNS locally in Node fallback and exports posture report JSON', async () => {
    const state = createInitialSaseState();
    state.dnsPolicy.blockC2 = true;

    const blocked = await resolveDnsWithEdgeFallback(state, 'sase-test-2', 'c2-beacon.bad');
    assert.equal(blocked.nextState.lastDnsResult?.status, 'BLOCKED_SINKHOLE');
    assert.equal(blocked.nextState.lastDnsResult?.dns_rcode, 'NXDOMAIN');

    const allowed = await resolveDnsWithEdgeFallback(
      blocked.nextState,
      'sase-test-2',
      'erp.internal.0trust.corp'
    );
    assert.equal(allowed.nextState.lastDnsResult?.status, 'ALLOWED');
    assert.equal(allowed.nextState.lastDnsResult?.dns_rcode, 'NOERROR');

    const reportJson = exportSasePostureReport(allowed.nextState);
    const parsed = JSON.parse(reportJson) as { lab: string };
    assert.equal(parsed.lab, '0trust-lab-sase-tunnel');
  });
});
