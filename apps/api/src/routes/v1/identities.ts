import { Hono } from 'hono';
import { createIdentityRequestSchema } from '@enclave/contracts';

import { type AppEnv, requireAccount } from '../../auth/middleware';
import { ok } from '../../lib/envelope';
import { invalidRequest } from '../../lib/errors';
import type { UsersRepository } from '../../repositories/users';
import type { RecoveryService } from '../../services/recovery';

export function identityRoutes(users: UsersRepository, recovery: RecoveryService): Hono<AppEnv> {
  const r = new Hono<AppEnv>();
  r.use('*', requireAccount(users));

  // POST /v1/identities
  r.post('/', async (c) => {
    const userId = c.get('userId');
    let body: unknown;
    try {
      body = await c.req.json();
    } catch {
      throw invalidRequest('Invalid JSON');
    }

    const parsed = createIdentityRequestSchema.safeParse(body);
    if (!parsed.success) throw invalidRequest('Invalid public key');

    const view = await recovery.createIdentity(userId, parsed.data.identityPublicKey);
    return c.json(ok(view), 201);
  });

  return r;
}
