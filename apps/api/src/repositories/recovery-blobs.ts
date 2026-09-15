import { and, eq, isNull } from 'drizzle-orm';

import type { Database } from '../db/client';
import { deviceRecoveryBlobs } from '../db/schema';

export interface RecoveryBlobRecord {
  id: string;
  userId: string;
  deviceId: string;
  envelope: string;
  revokedAt: Date | null;
  createdAt: Date;
}

export interface RecoveryBlobsRepository {
  /**
   * Creates or replaces the opaque recovery blob for a device. Upsert is keyed
   * by the unique `device_id`, so enrollment/recovery is idempotent and
   * concurrent writes converge on the latest envelope.
   */
  upsert(blob: RecoveryBlobRecord): Promise<RecoveryBlobRecord>;
  getByDeviceId(deviceId: string): Promise<RecoveryBlobRecord | null>;
  listActiveByUserId(userId: string): Promise<RecoveryBlobRecord[]>;
  revokeByDeviceId(deviceId: string, at: Date): Promise<void>;
}

export class PgRecoveryBlobsRepository implements RecoveryBlobsRepository {
  constructor(private readonly db: Database) {}

  async upsert(blob: RecoveryBlobRecord): Promise<RecoveryBlobRecord> {
    const rows = await this.db
      .insert(deviceRecoveryBlobs)
      .values({
        id: blob.id,
        userId: blob.userId,
        deviceId: blob.deviceId,
        envelope: blob.envelope,
        revokedAt: blob.revokedAt,
        createdAt: blob.createdAt,
      })
      .onConflictDoUpdate({
        target: deviceRecoveryBlobs.deviceId,
        set: { envelope: blob.envelope, revokedAt: blob.revokedAt },
      })
      .returning();
    return toRecord(rows[0]!);
  }

  async getByDeviceId(deviceId: string): Promise<RecoveryBlobRecord | null> {
    const rows = await this.db
      .select()
      .from(deviceRecoveryBlobs)
      .where(eq(deviceRecoveryBlobs.deviceId, deviceId))
      .limit(1);
    const row = rows[0];
    return row ? toRecord(row) : null;
  }

  async listActiveByUserId(userId: string): Promise<RecoveryBlobRecord[]> {
    const rows = await this.db
      .select()
      .from(deviceRecoveryBlobs)
      .where(and(eq(deviceRecoveryBlobs.userId, userId), isNull(deviceRecoveryBlobs.revokedAt)));
    return rows.map(toRecord);
  }

  async revokeByDeviceId(deviceId: string, at: Date): Promise<void> {
    await this.db
      .update(deviceRecoveryBlobs)
      .set({ revokedAt: at })
      .where(
        and(eq(deviceRecoveryBlobs.deviceId, deviceId), isNull(deviceRecoveryBlobs.revokedAt)),
      );
  }
}

function toRecord(row: typeof deviceRecoveryBlobs.$inferSelect): RecoveryBlobRecord {
  return {
    id: row.id,
    userId: row.userId,
    deviceId: row.deviceId,
    envelope: row.envelope,
    revokedAt: row.revokedAt,
    createdAt: row.createdAt,
  };
}
