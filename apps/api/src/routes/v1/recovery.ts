import { Hono } from 'hono';
import {
  completeRecoveryRequestSchema,
  createRecoveryBlobRequestSchema,
  createRecoveryChallengeRequestSchema,
} from '@enclave/contracts';

import { type AppEnv, requirePrincipal } from '../../auth/middleware';
import { ok } from '../../lib/envelope';
import { forbidden, invalidRequest } from '../../lib/errors';
import type { UsersRepository } from '../../repositories/users';
import type { DevicesRepository } from '../../repositories/devices';
import type { RecoveryService } from '../../services/recovery';

export function recoveryRoutes(
  users: UsersRepository,
  devices: DevicesRepository,
  recovery: RecoveryService,
): Hono<AppEnv> {
  const r = new Hono<AppEnv>();

  // POST /v1/recovery/challenge — no auth: a lost device proves identity control.
  r.post('/challenge', async (c) => {
    let body: unknown;
    try {
      body = await c.req.json();
    } catch {
      throw invalidRequest('Invalid JSON');
    }

    const parsed = createRecoveryChallengeRequestSchema.safeParse(body);
    if (!parsed.success) throw invalidRequest('Invalid public key');

    const challenge = await recovery.createChallenge(parsed.data.identityPublicKey);
    return c.json(ok(challenge), 201);
  });

  // POST /v1/recovery/complete — no auth: verifies identity signature, enrolls
  // a fresh device, returns a one-time device secret.
  r.post('/complete', async (c) => {
    let body: unknown;
    try {
      body = await c.req.json();
    } catch {
      throw invalidRequest('Invalid JSON');
    }

    const parsed = completeRecoveryRequestSchema.safeParse(body);
    if (!parsed.success) throw invalidRequest('Invalid recovery payload');

    const result = await recovery.completeRecovery({
      ...parsed.data,
      deviceKey: parsed.data.deviceKey,
    });
    return c.json(ok(result), 201);
  });

  // Blob store/read requires an authenticated principal (account OR device).
  r.use('/blobs*', requirePrincipal(users, devices));

  // GET /v1/recovery/blobs
  r.get('/blobs', async (c) => {
    const userId = c.get('userId');
    const views = await recovery.listBlobs(userId);
    return c.json(ok(views));
  });

  // POST /v1/recovery/blobs — uploaded by a recovered/enrolled device that
  // possesses its device secret (not the account secret).
  r.post('/blobs', async (c) => {
    let body: unknown;
    try {
      body = await c.req.json();
    } catch {
      throw invalidRequest('Invalid JSON');
    }

    const parsed = createRecoveryBlobRequestSchema.safeParse(body);
    if (!parsed.success) throw invalidRequest('Invalid recovery blob');

    const principalDeviceId = c.get('principalDeviceId');
    if (principalDeviceId && parsed.data.envelope.deviceId !== principalDeviceId) {
      throw forbidden('Recovery blobs require the authenticated device');
    }

    const view = await recovery.storeBlob({
      userId: c.get('userId'),
      deviceId: parsed.data.envelope.deviceId,
      envelope: parsed.data.envelope,
    });
    return c.json(ok(view), 201);
  });

  return r;
}
