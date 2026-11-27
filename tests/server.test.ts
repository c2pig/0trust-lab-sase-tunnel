import assert from 'node:assert/strict';
import { describe, it } from 'node:test';
import { createCloudRunApp, verifyRouterSecret } from '../server/app';
import {
  buildKvDocId,
  FirestoreKvAdapter,
  MemoryKvAdapter,
  type FirestoreCollectionLike,
  type FirestoreKvDoc
} from '../server/kvAdapter';
import { resolvePublicOrigin } from '../server/origin';

const TEST_ROUTER_SECRET = 'test-router-secret-value-0123456789';

function createMockFirestoreCollection(): {
  collection: FirestoreCollectionLike;
  store: Map<string, FirestoreKvDoc>;
} {
  const store = new Map<string, FirestoreKvDoc>();
  const collection: FirestoreCollectionLike = {
    doc(id: string) {
      return {
        async get() {
          const data = store.get(id);
          return {
            exists: Boolean(data),
            data: () => data
          };
        },
        async set(data: FirestoreKvDoc) {
          store.set(id, data);
        },
        async delete() {
          store.delete(id);
        }
      };
    }
  };
  return { collection, store };
}

describe('Lab 5 (sase-tunnel) Cloud Run Adapter — Red-Team & Security Invariants', () => {
  it('blocks direct *.run.app /api/* requests without or with invalid X-Lab-Router-Secret (fail-closed 403)', async () => {
    const app = createCloudRunApp({
      env: {
        ENVIRONMENT: 'production',
        LAB_SLUG: 'sase-tunnel',
        LAB_ROUTER_SECRET: TEST_ROUTER_SECRET
      },
      kv: new MemoryKvAdapter({ labSlug: 'sase-tunnel' })
    });

    // Missing header
    const resMissing = await app.request(
      'https://0trust-lab-sase-tunnel-abc.run.app/api/sase-tunnel/health'
    );
    assert.equal(resMissing.status, 403);
    assert.deepEqual(await resMissing.json(), { error: 'FORBIDDEN_DIRECT_ORIGIN' });

    // Wrong secret (same length & different length)
    const resWrongSameLen = await app.request(
      'https://0trust-lab-sase-tunnel-abc.run.app/api/sase-tunnel/health',
      {
        headers: { 'x-lab-router-secret': 'wrong-router-secret-value-987654321' }
      }
    );
    assert.equal(resWrongSameLen.status, 403);
    assert.deepEqual(await resWrongSameLen.json(), { error: 'FORBIDDEN_DIRECT_ORIGIN' });

    const resWrongDiffLen = await app.request(
      'https://0trust-lab-sase-tunnel-abc.run.app/api/sase-tunnel/health',
      {
        headers: { 'x-lab-router-secret': 'short' }
      }
    );
    assert.equal(resWrongDiffLen.status, 403);

    // Fail-closed when LAB_ROUTER_SECRET is unset in production
    const appUnconfigured = createCloudRunApp({
      env: {
        ENVIRONMENT: 'production',
        LAB_SLUG: 'sase-tunnel'
      },
      kv: new MemoryKvAdapter({ labSlug: 'sase-tunnel' })
    });
    const resUnconfigured = await appUnconfigured.request(
      'https://0trust-lab-sase-tunnel-abc.run.app/api/sase-tunnel/health',
      {
        headers: { 'x-lab-router-secret': TEST_ROUTER_SECRET }
      }
    );
    assert.equal(resUnconfigured.status, 403);
    assert.deepEqual(await resUnconfigured.json(), { error: 'FORBIDDEN_DIRECT_ORIGIN' });

    // Valid secret succeeds
    const resValid = await app.request(
      'https://0trust-lab-sase-tunnel-abc.run.app/api/sase-tunnel/health',
      {
        headers: { 'x-lab-router-secret': TEST_ROUTER_SECRET }
      }
    );
    assert.equal(resValid.status, 200);
    const json = (await resValid.json()) as Record<string, unknown>;
    assert.equal(json.ok, true);
    assert.equal(json.service, '0trust-lab-sase-tunnel');
    assert.equal(verifyRouterSecret(TEST_ROUTER_SECRET, TEST_ROUTER_SECRET), true);
  });

  it('serves GET /healthz without X-Lab-Router-Secret (Cloud Run probe)', async () => {
    const app = createCloudRunApp({
      env: {
        ENVIRONMENT: 'production',
        LAB_SLUG: 'sase-tunnel',
        LAB_ROUTER_SECRET: TEST_ROUTER_SECRET
      },
      kv: new MemoryKvAdapter({ labSlug: 'sase-tunnel' })
    });

    const res = await app.request('https://0trust-lab-sase-tunnel-abc.run.app/healthz');
    assert.equal(res.status, 200);
    assert.deepEqual(await res.json(), { ok: true, lab: 'sase-tunnel' });
  });

  it('synchronously returns null on expired TTL docs in FirestoreKvAdapter & MemoryKvAdapter', async () => {
    let nowMs = 1_700_000_000_000;
    const { collection, store } = createMockFirestoreCollection();
    const firestoreKv = new FirestoreKvAdapter({
      labSlug: 'sase-tunnel',
      collectionRef: collection,
      nowFn: () => nowMs
    });

    await firestoreKv.put('lab5:sase:session/1', '{"v":1}', { expirationTtl: 3600 });
    const expectedDocId = buildKvDocId('sase-tunnel', 'lab5:sase:session/1');
    assert.equal(expectedDocId, 'sase-tunnel:lab5%3Asase%3Asession%2F1');

    const storedDoc = store.get(expectedDocId);
    assert.ok(storedDoc);
    assert.equal(storedDoc.labSlug, 'sase-tunnel');
    assert.equal(storedDoc.value, '{"v":1}');
    assert.equal(storedDoc.expireAt?.toMillis(), nowMs + 3_600_000);

    // Before expiry
    assert.equal(await firestoreKv.get('lab5:sase:session/1'), '{"v":1}');

    // Advance clock past TTL without deleting doc from Firestore
    nowMs += 3_600_000;
    assert.equal(store.has(expectedDocId), true);
    assert.equal(await firestoreKv.get('lab5:sase:session/1'), null);

    // MemoryKvAdapter parity
    let memNow = 1_700_000_000_000;
    const memKv = new MemoryKvAdapter({ labSlug: 'sase-tunnel', nowFn: () => memNow });
    await memKv.put('lab5:sase:abc', 'ok', { expirationTtl: 10 });
    assert.equal(await memKv.get('lab5:sase:abc'), 'ok');
    memNow += 10_000;
    assert.equal(await memKv.get('lab5:sase:abc'), null);
  });

  it('rejects forged X-Forwarded-Host headers and allows lab.0trust.dev + localhost', () => {
    const forgedReq = new Request(
      'https://0trust-lab-sase-tunnel-abc.run.app/api/sase-tunnel/health',
      {
        headers: {
          'x-forwarded-host': 'evil.com',
          'x-forwarded-proto': 'https'
        }
      }
    );
    assert.equal(resolvePublicOrigin(forgedReq), 'https://0trust-lab-sase-tunnel-abc.run.app');

    const prodReq = new Request(
      'https://0trust-lab-sase-tunnel-abc.run.app/api/sase-tunnel/health',
      {
        headers: {
          'x-forwarded-host': 'lab.0trust.dev',
          'x-forwarded-proto': 'https'
        }
      }
    );
    assert.equal(resolvePublicOrigin(prodReq), 'https://lab.0trust.dev');

    const localReq = new Request('http://127.0.0.1:8080/api/sase-tunnel/health', {
      headers: {
        'x-forwarded-host': 'localhost:5180',
        'x-forwarded-proto': 'http'
      }
    });
    assert.equal(resolvePublicOrigin(localReq), 'http://localhost:5180');
  });

  it('redacts JWT signatures in _telemetry and never leaks X-Lab-Router-Secret or OTLP_AUTH_HEADER', async () => {
    const otlpAuthSecret = 'Bearer otlp-super-secret-header-token';
    const capturedOtlpBodies: string[] = [];
    const originalFetch = globalThis.fetch;

    globalThis.fetch = (async (_input: string | URL | Request, init?: RequestInit) => {
      capturedOtlpBodies.push(String(init?.body || ''));
      return new Response('{}', { status: 200 });
    }) as typeof fetch;

    try {
      const app = createCloudRunApp({
        env: {
          ENVIRONMENT: 'production',
          LAB_SLUG: 'sase-tunnel',
          LAB_ROUTER_SECRET: TEST_ROUTER_SECRET,
          OTLP_ENDPOINT: 'https://otlp.example.com',
          OTLP_AUTH_HEADER: otlpAuthSecret
        },
        kv: new MemoryKvAdapter({ labSlug: 'sase-tunnel' })
      });

      const fakeJwt = 'eyJhbGciOiJIUzI1NiJ9.eyJzdWIiOiJ1c2VyLTEifQ.SuperSecretSignatureXYZ123';
      const res = await app.request(
        'https://0trust-lab-sase-tunnel-abc.run.app/api/sase-tunnel/health',
        {
          headers: {
            'x-lab-router-secret': TEST_ROUTER_SECRET,
            authorization: `Bearer ${fakeJwt}`,
            traceparent: '00-4bf92f3577b34da6a3ce929d0e0e4736-00f067aa0ba902b7-01'
          }
        }
      );

      assert.equal(res.status, 200);
      assert.ok(res.headers.get('traceparent')?.startsWith('00-4bf92f3577b34da6a3ce929d0e0e4736-'));
      assert.ok(res.headers.get('X-Edge-Latency-Ms'));

      const bodyText = await res.text();
      assert.ok(!bodyText.includes('SuperSecretSignatureXYZ123'), 'JWT signature must be redacted');
      assert.ok(!bodyText.includes(TEST_ROUTER_SECRET), 'Router secret must never appear in response');
      assert.ok(!bodyText.includes(otlpAuthSecret), 'OTLP auth header must never appear in response');

      const parsed = JSON.parse(bodyText) as {
        _telemetry: { redacted_auth_header: string; redaction_applied: boolean };
      };
      assert.equal(parsed._telemetry.redaction_applied, true);
      assert.equal(
        parsed._telemetry.redacted_auth_header,
        'Bearer eyJhbGciOiJIUzI1NiJ9.eyJzdWIiOiJ1c2VyLTEifQ.***REDACTED***'
      );

      await new Promise((r) => setTimeout(r, 10));
      assert.equal(capturedOtlpBodies.length, 2);
      for (const otlpBody of capturedOtlpBodies) {
        assert.ok(!otlpBody.includes(TEST_ROUTER_SECRET));
        assert.ok(!otlpBody.includes('SuperSecretSignatureXYZ123'));
        assert.ok(!otlpBody.includes(otlpAuthSecret));
      }
    } finally {
      globalThis.fetch = originalFetch;
    }
  });

  it('executes Lab 5 SASE evaluate-access & dns-resolve flows on Cloud Run adapter', async () => {
    const kv = new MemoryKvAdapter({ labSlug: 'sase-tunnel' });
    const app = createCloudRunApp({
      env: {
        ENVIRONMENT: 'development',
        LAB_SLUG: 'sase-tunnel'
      },
      kv
    });

    const sessionId = 'test-sase-session';

    // 1. Compliant device posture -> 200 ACCESS_GRANTED
    const grantRes = await app.request('http://127.0.0.1:8080/api/sase-tunnel/evaluate-access', {
      method: 'POST',
      headers: { 'Content-Type': 'application/json', 'X-Session-Id': sessionId },
      body: JSON.stringify({
        target_app: 'internal-erp',
        device_profile: 'managed-corp',
        warp_connected: true,
        disk_encrypted: true,
        os_version_ok: true
      })
    });
    assert.equal(grantRes.status, 200);
    const grantData = (await grantRes.json()) as {
      status: string;
      cf_access_jwt_assertion: string;
    };
    assert.equal(grantData.status, 'ACCESS_GRANTED');
    assert.ok(grantData.cf_access_jwt_assertion.endsWith('***REDACTED***'));

    // 2. Unmanaged BYOD device posture -> 403 ACCESS_DENIED
    const denyRes = await app.request('http://127.0.0.1:8080/api/sase-tunnel/evaluate-access', {
      method: 'POST',
      headers: { 'Content-Type': 'application/json', 'X-Session-Id': sessionId },
      body: JSON.stringify({
        target_app: 'internal-erp',
        device_profile: 'unmanaged-byod',
        warp_connected: false,
        disk_encrypted: false,
        os_version_ok: true
      })
    });
    assert.equal(denyRes.status, 403);
    const denyData = (await denyRes.json()) as { status: string; failed_checks: string[] };
    assert.equal(denyData.status, 'ACCESS_DENIED');
    assert.ok(denyData.failed_checks.includes('WARP_CLIENT_MISSING'));

    // 3. Direct-to-origin probe -> 403 BLOCKED_NO_PUBLIC_INGRESS
    const probeRes = await app.request('http://127.0.0.1:8080/api/sase-tunnel/evaluate-access', {
      method: 'POST',
      headers: { 'Content-Type': 'application/json', 'X-Session-Id': sessionId },
      body: JSON.stringify({
        target_app: 'internal-erp',
        direct_origin_probe: true
      })
    });
    assert.equal(probeRes.status, 403);
    const probeData = (await probeRes.json()) as { status: string; public_ports_open: number };
    assert.equal(probeData.status, 'BLOCKED_NO_PUBLIC_INGRESS');
    assert.equal(probeData.public_ports_open, 0);

    // 4. Gateway DNS resolve allowed corporate internal domain -> 200 NOERROR
    const allowDnsRes = await app.request('http://127.0.0.1:8080/api/sase-tunnel/dns-resolve', {
      method: 'POST',
      headers: { 'Content-Type': 'application/json', 'X-Session-Id': sessionId },
      body: JSON.stringify({
        domain: 'erp.internal.0trust.corp',
        block_c2: true,
        block_malware: true,
        block_shadow_ai: true
      })
    });
    assert.equal(allowDnsRes.status, 200);
    const allowDnsData = (await allowDnsRes.json()) as { status: string; dns_rcode: string };
    assert.equal(allowDnsData.status, 'ALLOWED');
    assert.equal(allowDnsData.dns_rcode, 'NOERROR');

    // 5. Gateway DNS sinkhole C2 domain -> 403 NXDOMAIN
    const blockDnsRes = await app.request('http://127.0.0.1:8080/api/sase-tunnel/dns-resolve', {
      method: 'POST',
      headers: { 'Content-Type': 'application/json', 'X-Session-Id': sessionId },
      body: JSON.stringify({
        domain: 'c2-beacon.bad',
        block_c2: true
      })
    });
    assert.equal(blockDnsRes.status, 403);
    const blockDnsData = (await blockDnsRes.json()) as {
      status: string;
      dns_rcode: string;
      resolved_ip: string;
    };
    assert.equal(blockDnsData.status, 'BLOCKED_SINKHOLE');
    assert.equal(blockDnsData.dns_rcode, 'NXDOMAIN');
    assert.equal(blockDnsData.resolved_ip, '0.0.0.0');

    // Verify persisted session KV state
    const rawState = await kv.get(`lab5:sase:${sessionId}`);
    assert.ok(rawState);
    const state = JSON.parse(rawState) as {
      access_checks_run: number;
      dns_queries_run: number;
      dns_queries_blocked: number;
    };
    assert.equal(state.access_checks_run, 3);
    assert.equal(state.dns_queries_run, 2);
    assert.equal(state.dns_queries_blocked, 1);
  });

  it('rejects oversized (>64 KB) JSON bodies with 413 PAYLOAD_TOO_LARGE', async () => {
    const app = createCloudRunApp({
      env: {
        ENVIRONMENT: 'development',
        LAB_SLUG: 'sase-tunnel'
      },
      kv: new MemoryKvAdapter({ labSlug: 'sase-tunnel' })
    });

    const oversizedBody = JSON.stringify({
      target_app: 'internal-erp',
      padding: 'x'.repeat(65 * 1024)
    });

    const accessRes = await app.request('http://127.0.0.1:8080/api/sase-tunnel/evaluate-access', {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: oversizedBody
    });
    assert.equal(accessRes.status, 413);
    const accessJson = (await accessRes.json()) as { error: string; message: string };
    assert.equal(accessJson.error, 'PAYLOAD_TOO_LARGE');

    const dnsRes = await app.request('http://127.0.0.1:8080/api/sase-tunnel/dns-resolve', {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: oversizedBody
    });
    assert.equal(dnsRes.status, 413);
    const dnsJson = (await dnsRes.json()) as { error: string; message: string };
    assert.equal(dnsJson.error, 'PAYLOAD_TOO_LARGE');
  });

  it('fails closed with 400 on malformed JSON or invalid DNS domain preset', async () => {
    const app = createCloudRunApp({
      env: {
        ENVIRONMENT: 'development',
        LAB_SLUG: 'sase-tunnel'
      },
      kv: new MemoryKvAdapter({ labSlug: 'sase-tunnel' })
    });

    const badAccessRes = await app.request('http://127.0.0.1:8080/api/sase-tunnel/evaluate-access', {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: '{invalid-json'
    });
    assert.equal(badAccessRes.status, 400);
    const badAccessJson = (await badAccessRes.json()) as { error: string };
    assert.equal(badAccessJson.error, 'INVALID_JSON');

    const badDnsJsonRes = await app.request('http://127.0.0.1:8080/api/sase-tunnel/dns-resolve', {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: '{invalid-json'
    });
    assert.equal(badDnsJsonRes.status, 400);
    const badDnsJson = (await badDnsJsonRes.json()) as { error: string };
    assert.equal(badDnsJson.error, 'INVALID_JSON');

    const missingDomainRes = await app.request('http://127.0.0.1:8080/api/sase-tunnel/dns-resolve', {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({})
    });
    assert.equal(missingDomainRes.status, 400);
    const missingDomainJson = (await missingDomainRes.json()) as { error: string };
    assert.equal(missingDomainJson.error, 'INVALID_DOMAIN_PRESET');
  });
});
