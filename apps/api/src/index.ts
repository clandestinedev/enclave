import { serve } from '@hono/node-server';

import { createApp } from './app';
import { loadConfig } from './config';

const config = loadConfig();
const app = createApp();

serve({ fetch: app.fetch, port: config.port }, (info) => {
  console.log(`[enclave] ${config.serviceName} listening on :${info.port} (${config.nodeEnv})`);
});
