import type { MiddlewareHandler } from 'hono';

import { digestSecret, verifySecret } from '../auth/account';
import { unauthorized } from '../lib/errors';
import type { UsersRepository } from '../repositories/users';
import type { DevicesRepository } from '../repositories/devices';

export interface AppEnv {
  Variables: {
    userId: string;
    accountSecretDigest: string;
    principalDeviceId: string | null;
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
    c.set('principalDeviceId', null);
    await next();
  };
}

/**
 * Accepts either the account secret (existing clients) or a device secret
 * (issued once during recovery to the newly recovered device). Sets `userId`
 * in both cases; when authenticated as a device, `principalDeviceId` is set so
 * routes can scope recovery-blob operations to the authenticated device.
 */
export function requirePrincipal(
  users: UsersRepository,
  devices: DevicesRepository,
): MiddlewareHandler<AppEnv> {
  return async (c, next) => {
    const secret = getAuthSecret(c);
    if (!secret) throw unauthorized();

    const accountDigest = digestSecret(secret);
    const user = await users.findByAccountSecretHash(accountDigest);
    if (user && verifySecret(secret, user.accountSecretHash)) {
      c.set('userId', user.id);
      c.set('accountSecretDigest', accountDigest);
      c.set('principalDeviceId', null);
      return next();
    }

    const device = await devices.findByDeviceSecretHash(accountDigest);
    if (
      device &&
      device.deviceSecretHash !== null &&
      device.revokedAt === null &&
      verifySecret(secret, device.deviceSecretHash)
    ) {
      c.set('userId', device.userId);
      c.set('accountSecretDigest', '');
      c.set('principalDeviceId', device.id);
      return next();
    }

    throw unauthorized();
  };
}
