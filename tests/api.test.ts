import assert from 'node:assert/strict';
import { describe, it } from 'node:test';
import { onRequestPost as evaluateAccessPost } from '../functions/api/sase-tunnel/evaluate-access';
import { onRequestPost as dnsResolvePost } from '../functions/api/sase-tunnel/dns-resolve';
import { onRequestGet as healthGet } from '../functions/api/sase-tunnel/health';
import { MemoryKvAdapter } from '../server/kvAdapter';

function postJson(url: string, body: unknown, sessionId?: string): Request {
  const headers: Record<string, string> = { 'Content-Type': 'application/json' };
  if (sessionId) headers['X-Session-Id'] = sessionId;
  return new Request(url, {
    method: 'POST',
    headers,
    body: typeof body === 'string' ? body : JSON.stringify(body)
  });
}

describe('Lab 5 (sase-tunnel) Layer 2 API — Edge Functions with MemoryKvAdapter', () => {
  it('GET /api/sase-tunnel/health returns 200 ok', async () => {
    const res = await healthGet();
    assert.equal(res.status, 200);
    assert.deepEqual(await res.json(), { ok: true, service: '0trust-lab-sase-tunnel' });
  });

  describe('evaluate-access posture matrix', () => {
    it('grants access (200 ACCESS_GRANTED) when all required posture checks pass', async () => {
      const kv = new MemoryKvAdapter({ labSlug: 'sase-tunnel' });
      const res = await evaluateAccessPost({
        request: postJson(
          'https://lab.0trust.dev/api/sase-tunnel/evaluate-access',
          {
            target_app: 'finance-portal',
            device_profile: 'managed-corp',
            warp_connected: true,
            disk_encrypted: true,
            os_version_ok: true,
            require_warp: true,
            require_disk_encryption: true,
            require_min_os: true
          },
          'sess-grant-1'
        ),
        env: { STATE_KV: kv }
      });

      assert.equal(res.status, 200);
      const data = (await res.json()) as Record<string, unknown>;
      assert.equal(data.status, 'ACCESS_GRANTED');
      assert.equal(data.target_app, 'finance-portal');
      assert.equal(data.target_hostname, 'finance.internal.0trust.corp');
      assert.equal(data.storage, 'cloudflare-kv');
      assert.ok(typeof data.cf_access_jwt_assertion === 'string');
      assert.ok((data.cf_access_jwt_assertion as string).split('.').length === 3);
    });

    it('denies access (403 ACCESS_DENIED) if any single required posture check fails', async () => {
      const kv = new MemoryKvAdapter({ labSlug: 'sase-tunnel' });
      const cases = [
        {
          name: 'missing WARP',
          payload: { warp_connected: false, disk_encrypted: true, os_version_ok: true },
          expectedFailed: 'WARP_CLIENT_MISSING'
        },
        {
          name: 'unencrypted disk',
          payload: { warp_connected: true, disk_encrypted: false, os_version_ok: true },
          expectedFailed: 'DISK_UNENCRYPTED'
        },
        {
          name: 'stale OS',
          payload: { warp_connected: true, disk_encrypted: true, os_version_ok: false },
          expectedFailed: 'OS_VERSION_STALE'
        }
      ];

      for (const tc of cases) {
        const res = await evaluateAccessPost({
          request: postJson(
            'https://lab.0trust.dev/api/sase-tunnel/evaluate-access',
            {
              target_app: 'internal-erp',
              device_profile: 'unmanaged-byod',
              ...tc.payload,
              require_warp: true,
              require_disk_encryption: true,
              require_min_os: true
            },
            'sess-deny-matrix'
          ),
          env: { STATE_KV: kv }
        });

        assert.equal(res.status, 403, `Expected 403 for ${tc.name}`);
        const data = (await res.json()) as { status: string; failed_checks: string[] };
        assert.equal(data.status, 'ACCESS_DENIED');
        assert.deepEqual(data.failed_checks, [tc.expectedFailed]);
      }
    });

    it('blocks direct-to-origin probes (403 BLOCKED_NO_PUBLIC_INGRESS)', async () => {
      const kv = new MemoryKvAdapter({ labSlug: 'sase-tunnel' });
      const res = await evaluateAccessPost({
        request: postJson(
          'https://lab.0trust.dev/api/sase-tunnel/evaluate-access',
          { target_app: 'admin-ssh-bastion', direct_origin_probe: true },
          'sess-probe'
        ),
        env: { STATE_KV: kv }
      });

      assert.equal(res.status, 403);
      const data = (await res.json()) as Record<string, unknown>;
      assert.equal(data.status, 'BLOCKED_NO_PUBLIC_INGRESS');
      assert.equal(data.public_ports_open, 0);
      assert.equal(data.outbound_only_tunnel, true);
    });
  });

  describe('dns-resolve Gateway sinkhole', () => {
    it('allows corporate internal and approved SaaS domains (200 NOERROR)', async () => {
      const kv = new MemoryKvAdapter({ labSlug: 'sase-tunnel' });
      for (const domain of ['erp.internal.0trust.corp', 'api.github.com'] as const) {
        const res = await dnsResolvePost({
          request: postJson(
            'https://lab.0trust.dev/api/sase-tunnel/dns-resolve',
            { domain, block_c2: true, block_malware: true, block_shadow_ai: true },
            'sess-dns-allow'
          ),
          env: { STATE_KV: kv }
        });
        assert.equal(res.status, 200);
        const data = (await res.json()) as { status: string; dns_rcode: string };
        assert.equal(data.status, 'ALLOWED');
        assert.equal(data.dns_rcode, 'NOERROR');
      }
    });

    it('sinkholes C2, malware, and shadow AI domains when policies are enabled, and allows when toggled off', async () => {
      const kv = new MemoryKvAdapter({ labSlug: 'sase-tunnel' });
      const riskyCases = [
        {
          domain: 'c2-beacon.bad',
          policyKey: 'block_c2',
          expectedPolicy: 'GATEWAY_DNS_BLOCK_C2'
        },
        {
          domain: 'dropper-payload.malicious.example',
          policyKey: 'block_malware',
          expectedPolicy: 'GATEWAY_DNS_BLOCK_MALWARE'
        },
        {
          domain: 'shadow-llm-upload.example',
          policyKey: 'block_shadow_ai',
          expectedPolicy: 'GATEWAY_DNS_BLOCK_SHADOW_AI'
        }
      ] as const;

      for (const tc of riskyCases) {
        const blockedRes = await dnsResolvePost({
          request: postJson(
            'https://lab.0trust.dev/api/sase-tunnel/dns-resolve',
            { domain: tc.domain, [tc.policyKey]: true },
            'sess-dns-toggle'
          ),
          env: { STATE_KV: kv }
        });
        assert.equal(blockedRes.status, 403);
        const blockedData = (await blockedRes.json()) as {
          status: string;
          dns_rcode: string;
          resolved_ip: string;
          matched_policy: string;
        };
        assert.equal(blockedData.status, 'BLOCKED_SINKHOLE');
        assert.equal(blockedData.dns_rcode, 'NXDOMAIN');
        assert.equal(blockedData.resolved_ip, '0.0.0.0');
        assert.equal(blockedData.matched_policy, tc.expectedPolicy);

        // Toggle policy off -> immediately allowed
        const allowedRes = await dnsResolvePost({
          request: postJson(
            'https://lab.0trust.dev/api/sase-tunnel/dns-resolve',
            { domain: tc.domain, [tc.policyKey]: false },
            'sess-dns-toggle'
          ),
          env: { STATE_KV: kv }
        });
        assert.equal(allowedRes.status, 200);
        const allowedData = (await allowedRes.json()) as { status: string; dns_rcode: string };
        assert.equal(allowedData.status, 'ALLOWED');
        assert.equal(allowedData.dns_rcode, 'NOERROR');
      }
    });
  });

  describe('negative payloads and session isolation', () => {
    it('rejects >64 KB payloads (413), malformed JSON (400), and invalid domain presets (400)', async () => {
      const kv = new MemoryKvAdapter({ labSlug: 'sase-tunnel' });
      const oversized = JSON.stringify({ domain: 'api.github.com', pad: 'a'.repeat(65 * 1024) });

      const res413 = await dnsResolvePost({
        request: postJson('https://lab.0trust.dev/api/sase-tunnel/dns-resolve', oversized, 'sess-neg'),
        env: { STATE_KV: kv }
      });
      assert.equal(res413.status, 413);

      const res400Json = await evaluateAccessPost({
        request: postJson('https://lab.0trust.dev/api/sase-tunnel/evaluate-access', '{bad', 'sess-neg'),
        env: { STATE_KV: kv }
      });
      assert.equal(res400Json.status, 400);

      const res400Domain = await dnsResolvePost({
        request: postJson(
          'https://lab.0trust.dev/api/sase-tunnel/dns-resolve',
          { domain: 'evil.example.com' },
          'sess-neg'
        ),
        env: { STATE_KV: kv }
      });
      assert.equal(res400Domain.status, 400);
    });

    it('isolates KV state between distinct sessions', async () => {
      const kv = new MemoryKvAdapter({ labSlug: 'sase-tunnel' });

      await evaluateAccessPost({
        request: postJson(
          'https://lab.0trust.dev/api/sase-tunnel/evaluate-access',
          { target_app: 'internal-erp', warp_connected: true, disk_encrypted: true, os_version_ok: true },
          'session-alpha'
        ),
        env: { STATE_KV: kv }
      });

      await dnsResolvePost({
        request: postJson(
          'https://lab.0trust.dev/api/sase-tunnel/dns-resolve',
          { domain: 'c2-beacon.bad', block_c2: true },
          'session-beta'
        ),
        env: { STATE_KV: kv }
      });

      const alphaRaw = await kv.get('lab5:sase:session-alpha');
      const betaRaw = await kv.get('lab5:sase:session-beta');
      assert.ok(alphaRaw && betaRaw);

      const alpha = JSON.parse(alphaRaw) as { access_checks_run: number; dns_queries_run: number };
      const beta = JSON.parse(betaRaw) as { access_checks_run?: number; dns_queries_run: number; dns_queries_blocked: number };

      assert.equal(alpha.access_checks_run, 1);
      assert.equal(alpha.dns_queries_run, 0);
      assert.equal(beta.access_checks_run ?? 0, 0);
      assert.equal(beta.dns_queries_run, 1);
      assert.equal(beta.dns_queries_blocked, 1);
    });
  });
});
