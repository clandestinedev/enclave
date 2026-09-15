import { eq } from 'drizzle-orm';

import type { Database } from '../db/client';
import { encryptedPayloads } from '../db/schema';

export interface EncryptedPayloadRecord {
  id: string;
  userId: string;
  deviceId: string;
  envelope: string;
  byteLength: number;
  createdAt: Date;
}

export interface EncryptedPayloadsRepository {
  create(payload: EncryptedPayloadRecord): Promise<void>;
  getById(id: string): Promise<EncryptedPayloadRecord | null>;
}

export class PgEncryptedPayloadsRepository implements EncryptedPayloadsRepository {
  constructor(private readonly db: Database) {}

  async create(payload: EncryptedPayloadRecord): Promise<void> {
    await this.db.insert(encryptedPayloads).values({
      id: payload.id,
      userId: payload.userId,
      deviceId: payload.deviceId,
      envelope: payload.envelope,
      byteLength: payload.byteLength,
      createdAt: payload.createdAt,
    });
  }

  async getById(id: string): Promise<EncryptedPayloadRecord | null> {
    const rows = await this.db
      .select()
      .from(encryptedPayloads)
      .where(eq(encryptedPayloads.id, id))
      .limit(1);
    const row = rows[0];
    return row ? toRecord(row) : null;
  }
}

function toRecord(row: typeof encryptedPayloads.$inferSelect): EncryptedPayloadRecord {
  return {
    id: row.id,
    userId: row.userId,
    deviceId: row.deviceId,
    envelope: row.envelope,
    byteLength: row.byteLength,
    createdAt: row.createdAt,
  };
}
