import { eq } from 'drizzle-orm';

import type { Database } from '../db/client';
import { identities } from '../db/schema';

export interface IdentityRecord {
  id: string;
  userId: string;
  identityPublicKey: string;
  keyVersion: number;
  createdAt: Date;
}

export interface IdentitiesRepository {
  create(identity: IdentityRecord): Promise<void>;
  getById(id: string): Promise<IdentityRecord | null>;
  getByPublicKey(publicKey: string): Promise<IdentityRecord | null>;
  getByUserId(userId: string): Promise<IdentityRecord | null>;
}

export class PgIdentitiesRepository implements IdentitiesRepository {
  constructor(private readonly db: Database) {}

  async create(identity: IdentityRecord): Promise<void> {
    await this.db.insert(identities).values({
      id: identity.id,
      userId: identity.userId,
      identityPublicKey: identity.identityPublicKey,
      keyVersion: identity.keyVersion,
      createdAt: identity.createdAt,
    });
  }

  async getById(id: string): Promise<IdentityRecord | null> {
    const rows = await this.db.select().from(identities).where(eq(identities.id, id)).limit(1);
    const row = rows[0];
    return row ? toRecord(row) : null;
  }

  async getByPublicKey(publicKey: string): Promise<IdentityRecord | null> {
    const rows = await this.db
      .select()
      .from(identities)
      .where(eq(identities.identityPublicKey, publicKey))
      .limit(1);
    const row = rows[0];
    return row ? toRecord(row) : null;
  }

  async getByUserId(userId: string): Promise<IdentityRecord | null> {
    const rows = await this.db
      .select()
      .from(identities)
      .where(eq(identities.userId, userId))
      .limit(1);
    const row = rows[0];
    return row ? toRecord(row) : null;
  }
}

function toRecord(row: typeof identities.$inferSelect): IdentityRecord {
  return {
    id: row.id,
    userId: row.userId,
    identityPublicKey: row.identityPublicKey,
    keyVersion: row.keyVersion,
    createdAt: row.createdAt,
  };
}
