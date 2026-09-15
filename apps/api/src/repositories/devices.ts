import { eq } from 'drizzle-orm';

import type { Database } from '../db/client';
import { devices } from '../db/schema';

export interface DeviceRecord {
  id: string;
  userId: string;
  label: string | null;
  publicKeyType: string;
  publicKeyValue: string;
  keyVersion: number;
  createdAt: Date;
  lastSeenAt: Date | null;
  revokedAt: Date | null;
}

export interface DevicesRepository {
  create(device: DeviceRecord): Promise<void>;
  getById(id: string): Promise<DeviceRecord | null>;
  listByUserId(userId: string): Promise<DeviceRecord[]>;
  markSeen(id: string, at: Date): Promise<void>;
  revoke(id: string, at: Date): Promise<void>;
}

export class PgDevicesRepository implements DevicesRepository {
  constructor(private readonly db: Database) {}

  async create(device: DeviceRecord): Promise<void> {
    await this.db.insert(devices).values({
      id: device.id,
      userId: device.userId,
      label: device.label,
      publicKeyType: device.publicKeyType,
      publicKeyValue: device.publicKeyValue,
      keyVersion: device.keyVersion,
      createdAt: device.createdAt,
    });
  }

  async getById(id: string): Promise<DeviceRecord | null> {
    const rows = await this.db.select().from(devices).where(eq(devices.id, id)).limit(1);
    const row = rows[0];
    return row ? toRecord(row) : null;
  }

  async listByUserId(userId: string): Promise<DeviceRecord[]> {
    const rows = await this.db.select().from(devices).where(eq(devices.userId, userId));
    return rows.map(toRecord);
  }

  async markSeen(id: string, at: Date): Promise<void> {
    await this.db.update(devices).set({ lastSeenAt: at }).where(eq(devices.id, id));
  }

  async revoke(id: string, at: Date): Promise<void> {
    await this.db.update(devices).set({ revokedAt: at }).where(eq(devices.id, id));
  }
}

export function getOwnDevice(
  repo: DevicesRepository,
  userId: string,
  deviceId: string,
): Promise<DeviceRecord | null> {
  return repo
    .getById(deviceId)
    .then((device) => (device && device.userId === userId ? device : null));
}

function toRecord(row: typeof devices.$inferSelect): DeviceRecord {
  return {
    id: row.id,
    userId: row.userId,
    label: row.label,
    publicKeyType: row.publicKeyType,
    publicKeyValue: row.publicKeyValue,
    keyVersion: row.keyVersion,
    createdAt: row.createdAt,
    lastSeenAt: row.lastSeenAt,
    revokedAt: row.revokedAt,
  };
}
