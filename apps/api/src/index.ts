import { serve } from '@hono/node-server';

import { createApp } from './app';
import { loadConfig } from './config';
import { createDbClient } from './db/client';
import { PgUsersRepository } from './repositories/users';
import { PgDevicesRepository } from './repositories/devices';
import { PgEncryptedPayloadsRepository } from './repositories/payloads';
import { PgIdentitiesRepository } from './repositories/identities';
import { PgRecoveryChallengesRepository } from './repositories/recovery-challenges';
import { PgRecoveryBlobsRepository } from './repositories/recovery-blobs';
import { IdentityService, DeviceService, PayloadService } from './services/identity';
import { RecoveryService } from './services/recovery';

const config = loadConfig();
const { db } = createDbClient(config.databaseUrl);

const users = new PgUsersRepository(db);
const devices = new PgDevicesRepository(db);
const payloads = new PgEncryptedPayloadsRepository(db);
const identities = new PgIdentitiesRepository(db);
const challenges = new PgRecoveryChallengesRepository(db);
const blobs = new PgRecoveryBlobsRepository(db);

const identityService = new IdentityService(users);
const deviceService = new DeviceService(devices);
const payloadService = new PayloadService(payloads, devices);
const recoveryService = new RecoveryService({ identities, challenges, blobs, devices });

const app = createApp({
  identityService,
  deviceService,
  payloadService,
  recoveryService,
  users,
  devices,
  payloads,
});

serve({ fetch: app.fetch, port: config.port }, (info) => {
  console.log(`[enclave] ${config.serviceName} listening on :${info.port} (${config.nodeEnv})`);
});
