import assert from 'node:assert/strict';
import { describe, it } from 'node:test';
import { createInitialSaseState } from '../src/engine/saseTunnelEngine';
import {
  buildSaseSeats,
  doesStaffNeedVerify,
  getGlobalStatusLabel,
  hasRiskyDnsAllowed,
  isAllAccessProtected,
  isAllDnsProtected,
  isAllPoliciesHardened
} from '../src/engine/saseTunnelSelectors';
import { AccessEvaluationResult, DnsResolveResult } from '../src/contracts/saseTunnelContract';

function makeHardenedState() {
  const state = createInitialSaseState();
  state.accessPolicy = {
    requireWarp: true,
    requireDiskEncryption: true,
    requireMinOs: true
  };
  state.dnsPolicy = {
    blockC2: true,
    blockMalware: true,
    blockShadowAi: true
  };
  return state;
}

describe('Lab 5 (sase-tunnel) Layer 3 Selectors — Pure UI Policy & Seat Gates', () => {
  it('computes isAllAccessProtected and isAllDnsProtected across toggle combinations', () => {
    const state = createInitialSaseState();
    assert.equal(isAllAccessProtected(state.accessPolicy), false);
    assert.equal(isAllDnsProtected(state.dnsPolicy), false);
    assert.equal(isAllPoliciesHardened(state), false);

    state.accessPolicy.requireMinOs = true;
    assert.equal(isAllAccessProtected(state.accessPolicy), true);
    assert.equal(isAllPoliciesHardened(state), false);

    state.dnsPolicy = { blockC2: true, blockMalware: true, blockShadowAi: true };
    assert.equal(isAllDnsProtected(state.dnsPolicy), true);
    assert.equal(isAllPoliciesHardened(state), true);
  });

  it('computes staffNeedsVerify, globalStatusLabel, and seat badges', () => {
    const state = createInitialSaseState();
    assert.equal(doesStaffNeedVerify(state), false);
    assert.equal(getGlobalStatusLabel(state), 'Policy Gaps Open');

    let seats = buildSaseSeats(state);
    assert.equal(seats[0].id, 'remote-employee');
    assert.equal(seats[0].badge, null);
    assert.equal(seats[1].id, 'net-admin');
    assert.deepEqual(seats[1].badge, { text: 'Policy Gaps', tone: 'amber', pulse: true });

    // Risky DNS allowed triggers Egress Alert on net-admin
    const riskyDns: DnsResolveResult = {
      status: 'ALLOWED',
      http_status: 200,
      domain: 'c2-beacon.bad',
      category: 'COMMAND_AND_CONTROL',
      dns_rcode: 'NOERROR',
      resolved_ip: '203.0.113.99',
      matched_policy: 'GATEWAY_DNS_ALLOW_DEFAULT',
      resolver_colo: 'SIN',
      storage: 'browser-fallback',
      kv_ttl_seconds: 3600,
      timestamp: new Date().toISOString(),
      message: 'Allowed'
    };
    state.dnsHistory = [riskyDns];
    assert.equal(hasRiskyDnsAllowed(state.dnsHistory), true);
    seats = buildSaseSeats(state);
    assert.deepEqual(seats[1].badge, { text: 'Egress Alert', tone: 'crimson', pulse: true });

    // Hardened policies without ACCESS_GRANTED -> staffNeedsVerify = true
    const hardened = makeHardenedState();
    assert.equal(doesStaffNeedVerify(hardened), true);
    assert.equal(getGlobalStatusLabel(hardened), 'Policies Hardened');
    seats = buildSaseSeats(hardened);
    assert.deepEqual(seats[0].badge, { text: 'Verify Access', tone: 'blue', pulse: true });
    assert.equal(seats[1].badge, null);

    // Hardened + ACCESS_GRANTED -> Zero-Trust Verified, no badges
    hardened.lastAccessResult = {
      status: 'ACCESS_GRANTED'
    } as AccessEvaluationResult;
    assert.equal(doesStaffNeedVerify(hardened), false);
    assert.equal(getGlobalStatusLabel(hardened), 'Zero-Trust Verified');
    seats = buildSaseSeats(hardened);
    assert.equal(seats[0].badge, null);
    assert.equal(seats[1].badge, null);
  });
});
