import { serve } from '@hono/node-server';

import { createApp } from './app';
import { loadConfig } from './config';
import { createDbClient } from './db/client';
import { PgUsersRepository } from './repositories/users';
import { PgDevicesRepository } from './repositories/devices';
import { PgEncryptedPayloadsRepository } from './repositories/payloads';
import { IdentityService, DeviceService, PayloadService } from './services/identity';

const config = loadConfig();
const { db } = createDbClient(config.databaseUrl);

const users = new PgUsersRepository(db);
const devices = new PgDevicesRepository(db);
const payloads = new PgEncryptedPayloadsRepository(db);

const identityService = new IdentityService(users);
const deviceService = new DeviceService(devices);
const payloadService = new PayloadService(payloads, devices);

const app = createApp({ identityService, deviceService, payloadService, users, devices, payloads });

serve({ fetch: app.fetch, port: config.port }, (info) => {
  console.log(`[enclave] ${config.serviceName} listening on :${info.port} (${config.nodeEnv})`);
});
