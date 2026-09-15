import { eq } from 'drizzle-orm';

import type { Database } from '../db/client';
import { users } from '../db/schema';

export interface UserRecord {
  id: string;
  accountSecretHash: string;
  createdAt: Date;
}

export interface UsersRepository {
  create(user: UserRecord): Promise<void>;
  getById(id: string): Promise<UserRecord | null>;
  findByAccountSecretHash(hash: string): Promise<UserRecord | null>;
}

export class PgUsersRepository implements UsersRepository {
  constructor(private readonly db: Database) {}

  async create(user: UserRecord): Promise<void> {
    await this.db.insert(users).values({
      id: user.id,
      accountSecretHash: user.accountSecretHash,
      createdAt: user.createdAt,
    });
  }

  async getById(id: string): Promise<UserRecord | null> {
    const rows = await this.db.select().from(users).where(eq(users.id, id)).limit(1);
    const row = rows[0];
    return row ? toRecord(row) : null;
  }

  async findByAccountSecretHash(hash: string): Promise<UserRecord | null> {
    const rows = await this.db
      .select()
      .from(users)
      .where(eq(users.accountSecretHash, hash))
      .limit(1);
    const row = rows[0];
    return row ? toRecord(row) : null;
  }
}

function toRecord(row: typeof users.$inferSelect): UserRecord {
  return {
    id: row.id,
    accountSecretHash: row.accountSecretHash,
    createdAt: row.createdAt,
  };
}
