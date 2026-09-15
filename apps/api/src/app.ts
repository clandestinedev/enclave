import { Hono } from 'hono';

import { type AppEnv } from './auth/middleware';
import { fail } from './lib/envelope';
import { AppError } from './lib/errors';
import type { ContentfulStatusCode } from 'hono/utils/http-status';
import { healthRoutes } from './routes/health';
import { userRoutes } from './routes/v1/users';
import { deviceRoutes } from './routes/v1/devices';
import { payloadRoutes } from './routes/v1/payloads';
import type { IdentityService, DeviceService, PayloadService } from './services/identity';
import type { UsersRepository } from './repositories/users';
import type { DevicesRepository } from './repositories/devices';
import type { EncryptedPayloadsRepository } from './repositories/payloads';

export interface AppDeps {
  identityService: IdentityService;
  deviceService: DeviceService;
  payloadService: PayloadService;
  users: UsersRepository;
  devices: DevicesRepository;
  payloads: EncryptedPayloadsRepository;
}

export function createApp(deps: AppDeps): Hono<AppEnv> {
  const app = new Hono<AppEnv>();

  app.route('/health', healthRoutes);

  app.route('/v1/users', userRoutes(deps.identityService));
  app.route('/v1/devices', deviceRoutes(deps.devices, deps.users, deps.deviceService));
  app.route('/v1/payloads', payloadRoutes(deps.payloadService, deps.users, deps.deviceService));

  app.notFound((c) => c.json(fail('NOT_FOUND', 'Route not found'), 404));

  app.onError((err, c) => {
    if (err instanceof AppError) {
      return c.json(fail(err.code, err.message), err.status as ContentfulStatusCode);
    }
    console.error(`[enclave] unhandled error: ${err.name}: ${err.message}`);
    return c.json(fail('INTERNAL_ERROR', 'Internal server error'), 500);
  });

  return app;
}
