import { resolve } from 'node:path';
import { migrate } from 'drizzle-orm/node-postgres/migrator';
import type { Hono } from 'hono';
import type { Pool } from 'pg';

import { createDbClient, type Database } from '../src/db/client';
import { PgUsersRepository } from '../src/repositories/users';
import { PgDevicesRepository } from '../src/repositories/devices';
import { PgEncryptedPayloadsRepository } from '../src/repositories/payloads';
import { PgIdentitiesRepository } from '../src/repositories/identities';
import { PgRecoveryChallengesRepository } from '../src/repositories/recovery-challenges';
import { PgRecoveryBlobsRepository } from '../src/repositories/recovery-blobs';
import { IdentityService, DeviceService, PayloadService } from '../src/services/identity';
import { RecoveryService } from '../src/services/recovery';
import { createApp } from '../src/app';
import type { AppEnv } from '../src/auth/middleware';

export const TEST_DB_URL =
  process.env.TEST_DATABASE_URL ?? 'postgres://enclave:enclave_dev@localhost:5432/enclave_test';

export interface TestContext {
  db: Database;
  pool: Pool;
  app: Hono<AppEnv>;
  truncate(): Promise<void>;
  close(): Promise<void>;
}

export async function createTestContext(): Promise<TestContext> {
  const { pool, db } = createDbClient(TEST_DB_URL, { max: 5 });
  await migrate(db, { migrationsFolder: resolve(process.cwd(), 'migrations') });

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

  return {
    db,
    pool,
    app,
    async truncate() {
      await pool.query(
        'TRUNCATE TABLE device_recovery_blobs, recovery_challenges, identities, encrypted_payloads, devices, users RESTART IDENTITY CASCADE',
      );
    },
    async close() {
      await pool.end();
    },
  };
}

export function authHeaders(secret: string): Record<string, string> {
  return { authorization: `Bearer ${secret}` };
}

export function jsonHeaders(extra?: Record<string, string>): Record<string, string> {
  return { 'content-type': 'application/json', ...extra };
}

export async function createUser(app: Hono<AppEnv>): Promise<{ userId: string; secret: string }> {
  const res = await app.request('/v1/users', {
    method: 'POST',
    body: '{}',
    headers: jsonHeaders(),
  });
  if (res.status !== 201) throw new Error(`createUser failed: ${await res.text()}`);
  const body = (await res.json()) as { ok: true; data: { userId: string; secret: string } };
  return body.data;
}

export function makeX25519PublicKey(seed: number): string {
  return Buffer.alloc(32, seed).toString('base64');
}

export async function createDevice(
  app: Hono<AppEnv>,
  secret: string,
  label?: string,
): Promise<string> {
  const res = await app.request('/v1/devices', {
    method: 'POST',
    headers: jsonHeaders(authHeaders(secret)),
    body: JSON.stringify({ label, publicKey: { type: 'x25519', value: makeX25519PublicKey(3) } }),
  });
  if (res.status !== 201) throw new Error(`createDevice failed: ${await res.text()}`);
  const body = (await res.json()) as { ok: true; data: { deviceId: string } };
  return body.data.deviceId;
}

export function validEnvelope(deviceId: string): {
  v: 1;
  alg: 'xchacha20poly1305';
  keyRef: string;
  nonce: string;
  ciphertext: string;
} {
  return {
    v: 1,
    alg: 'xchacha20poly1305',
    keyRef: `${deviceId}:0`,
    nonce: Buffer.alloc(24, 1).toString('base64'),
    ciphertext: Buffer.alloc(32, 2).toString('base64'),
  };
}
