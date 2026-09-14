import { Hono } from 'hono';
import { WIRE_VERSION } from '@enclave/contracts';

import { API_VERSION } from '../config';
import { ok } from '../lib/envelope';

export const healthRoutes = new Hono().get('/', (c) =>
  c.json(
    ok({
      service: 'enclave-api',
      apiVersion: API_VERSION,
      wireVersion: WIRE_VERSION,
      time: new Date().toISOString(),
    }),
  ),
);
