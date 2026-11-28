import type { Hono } from 'hono';
import { onRequestPost as dnsResolvePost } from '../functions/api/sase-tunnel/dns-resolve';
import { onRequestPost as evaluateAccessPost } from '../functions/api/sase-tunnel/evaluate-access';
import { onRequestGet as healthGet } from '../functions/api/sase-tunnel/health';
import type { KVNamespace } from './kvAdapter';
import {
  createBaseLabApp,
  verifyRouterSecret,
  type BaseCloudRunEnv
} from './runtime';

import type { SaseAdapterEnv } from '../functions/api/lib/saseAdapter';

export { verifyRouterSecret };

export interface CloudRunEnv extends BaseCloudRunEnv, SaseAdapterEnv {}

export function createCloudRunApp(options?: {
  env?: CloudRunEnv;
  kv?: KVNamespace;
}): Hono {
  return createBaseLabApp<CloudRunEnv>({
    labSlug: 'sase-tunnel',
    env: options?.env,
    kv: options?.kv,
    registerRoutes(app, wrap) {
      app.get('/api/sase-tunnel/health', wrap(healthGet));
      app.post('/api/sase-tunnel/evaluate-access', wrap(evaluateAccessPost));
      app.post('/api/sase-tunnel/dns-resolve', wrap(dnsResolvePost));
    }
  });
}
