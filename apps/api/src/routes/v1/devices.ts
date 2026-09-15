import { Hono } from 'hono';
import { createDeviceRequestSchema } from '@enclave/contracts';

import { type AppEnv, requireAccount } from '../../auth/middleware';
import { ok } from '../../lib/envelope';
import { invalidRequest, notFound } from '../../lib/errors';
import type { UsersRepository } from '../../repositories/users';
import type { DevicesRepository } from '../../repositories/devices';
import type { DeviceService } from '../../services/identity';

export function deviceRoutes(
  devices: DevicesRepository,
  users: UsersRepository,
  deviceService: DeviceService,
): Hono<AppEnv> {
  const r = new Hono<AppEnv>();
  r.use('*', requireAccount(users));

  // POST /v1/devices
  r.post('/', async (c) => {
    const userId = c.get('userId');
    let body: unknown;
    try {
      body = await c.req.json();
    } catch {
      throw invalidRequest('Invalid JSON');
    }

    const parsed = createDeviceRequestSchema.safeParse(body);
    if (!parsed.success) throw invalidRequest('Invalid request body');

    const view = await deviceService.registerDevice(userId, parsed.data);
    return c.json(ok(view), 201);
  });

  // GET /v1/devices/:deviceId
  r.get('/:deviceId', async (c) => {
    const userId = c.get('userId');
    const deviceId = c.req.param('deviceId');
    const view = await deviceService.getOwnDevice(userId, deviceId);
    if (!view) throw notFound();
    await devices.markSeen(deviceId, new Date());
    return c.json(ok(view));
  });

  // GET /v1/devices
  r.get('/', async (c) => {
    const userId = c.get('userId');
    const views = await deviceService.listOwnDevices(userId);
    return c.json(ok(views));
  });

  // POST /v1/devices/:deviceId/revoke
  r.post('/:deviceId/revoke', async (c) => {
    const userId = c.get('userId');
    const deviceId = c.req.param('deviceId');
    const view = await deviceService.revokeDevice(userId, deviceId);
    if (!view) throw notFound();
    return c.json(ok(view));
  });

  return r;
}
