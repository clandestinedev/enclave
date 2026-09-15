import { Hono } from 'hono';
import { encryptedPayloadCreateSchema } from '@enclave/contracts';

import { type AppEnv, requireAccount } from '../../auth/middleware';
import { ok } from '../../lib/envelope';
import { forbidden, invalidRequest, notFound } from '../../lib/errors';
import type { UsersRepository } from '../../repositories/users';
import type { PayloadService, DeviceService } from '../../services/identity';

export function payloadRoutes(
  payloadService: PayloadService,
  users: UsersRepository,
  deviceService: DeviceService,
): Hono<AppEnv> {
  const r = new Hono<AppEnv>();
  r.use('*', requireAccount(users));

  // POST /v1/payloads
  r.post('/', async (c) => {
    const userId = c.get('userId');
    let body: unknown;
    try {
      body = await c.req.json();
    } catch {
      throw invalidRequest('Invalid JSON');
    }

    const parsed = encryptedPayloadCreateSchema.safeParse(body);
    if (!parsed.success) throw invalidRequest('Invalid envelope');

    const keyRefParts = parsed.data.keyRef.split(':');
    const deviceId = keyRefParts[0];
    if (!deviceId) throw invalidRequest('Invalid keyRef');

    const device = await deviceService.getOwnDevice(userId, deviceId);
    if (!device) throw forbidden();
    if (device.revokedAt !== null) throw forbidden('Device revoked');

    const envelope = parsed.data;
    const serialized = JSON.stringify(envelope);
    const byteLength = Buffer.byteLength(serialized, 'utf8');

    const { payloadId, createdAt } = await payloadService.store(userId, deviceId, envelope);

    return c.json(
      ok({
        payloadId,
        userId,
        deviceId,
        byteLength,
        createdAt: createdAt.toISOString(),
      }),
      201,
    );
  });

  // GET /v1/payloads/:payloadId
  r.get('/:payloadId', async (c) => {
    const userId = c.get('userId');
    const payloadId = c.req.param('payloadId');
    const payload = await payloadService.getOwn(userId, payloadId);
    if (!payload) throw notFound();
    return c.json(ok(payload));
  });

  return r;
}
