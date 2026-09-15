import { randomBytes } from 'node:crypto';
import { Hono } from 'hono';
import { createUserRequestSchema } from '@enclave/contracts';

import type { AppEnv } from '../../auth/middleware';
import { digestSecret } from '../../auth/account';
import { ok } from '../../lib/envelope';
import { invalidRequest } from '../../lib/errors';
import type { IdentityService } from '../../services/identity';

function generateSecret(): string {
  return randomBytes(32).toString('base64url');
}

export function userRoutes(identity: IdentityService): Hono<AppEnv> {
  const r = new Hono<AppEnv>();

  // Phase 1 dev-bootstrap: server issues a secret, returns it once.
  // The client stores it; it is never transmitted again in plaintext.
  // This is clearly not production authentication — see Phase 1 docs.
  r.post('/', async (c) => {
    let body: unknown;
    try {
      body = await c.req.json();
    } catch {
      throw invalidRequest('Invalid JSON');
    }

    const parsed = createUserRequestSchema.safeParse(body);
    if (!parsed.success) throw invalidRequest('Invalid request body');

    const secret = generateSecret();
    const accountSecretHash = digestSecret(secret);

    const { userId, createdAt } = await identity.createUser(accountSecretHash);

    return c.json(ok({ userId, secret, createdAt: createdAt.toISOString() }), 201);
  });

  return r;
}
