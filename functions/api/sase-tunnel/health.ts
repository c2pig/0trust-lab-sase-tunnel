import {
  isCloudflareOneConfigured,
  resolveIntegrationMode,
  type SaseAdapterEnv
} from '../lib/saseAdapter';

export async function onRequestGet(context?: {
  request?: Request;
  env?: SaseAdapterEnv;
}): Promise<Response> {
  const mode = resolveIntegrationMode(context?.env);
  const cfOneConfigured = isCloudflareOneConfigured(context?.env);
  return new Response(
    JSON.stringify({
      ok: true,
      service: '0trust-lab-sase-tunnel',
      integration_mode: mode,
      capabilities: {
        doh_live: mode !== 'sandbox',
        cf_one_configured: cfOneConfigured
      }
    }),
    {
      status: 200,
      headers: {
        'Content-Type': 'application/json',
        'Cache-Control': 'no-store'
      }
    }
  );
}
