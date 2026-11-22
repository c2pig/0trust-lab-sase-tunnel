export async function onRequestGet(): Promise<Response> {
  return new Response(
    JSON.stringify({ ok: true, service: '0trust-lab-sase-tunnel' }),
    {
      status: 200,
      headers: {
        'Content-Type': 'application/json',
        'Cache-Control': 'no-store'
      }
    }
  );
}
