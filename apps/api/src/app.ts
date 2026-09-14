import { Hono } from 'hono';

import { fail } from './lib/envelope';
import { healthRoutes } from './routes/health';

export function createApp(): Hono {
  const app = new Hono();

  app.route('/health', healthRoutes);

  app.notFound((c) => c.json(fail('NOT_FOUND', 'Route not found'), 404));

  app.onError((err, c) => {
    console.error(`[enclave] unhandled error: ${err.name}: ${err.message}`);
    return c.json(fail('INTERNAL_ERROR', 'Internal server error'), 500);
  });

  return app;
}
