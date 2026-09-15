import type { MiddlewareHandler } from 'hono';

import { digestSecret, verifySecret } from '../auth/account';
import { unauthorized } from '../lib/errors';
import type { UsersRepository } from '../repositories/users';

export interface AppEnv {
  Variables: {
    userId: string;
    accountSecretDigest: string;
  };
}

function getAuthSecret(c: { req: { header(name: string): string | undefined } }): string | null {
  const header = c.req.header('authorization');
  if (!header) return null;
  const [scheme, token] = header.split(' ');
  if (scheme?.toLowerCase() !== 'bearer' || !token) return null;
  return token.trim();
}

export function requireAccount(users: UsersRepository): MiddlewareHandler<AppEnv> {
  return async (c, next) => {
    const secret = getAuthSecret(c);
    if (!secret) throw unauthorized();

    const digest = digestSecret(secret);
    const user = await users.findByAccountSecretHash(digest);
    if (!user || !verifySecret(secret, user.accountSecretHash)) throw unauthorized();

    c.set('userId', user.id);
    c.set('accountSecretDigest', digest);
    await next();
  };
}
