import { and, eq, gt, isNull } from 'drizzle-orm';

import type { Database } from '../db/client';
import { recoveryChallenges } from '../db/schema';

export type ChallengeState = 'pending' | 'used' | 'expired';

export interface RecoveryChallengeRecord {
  id: string;
  userId: string;
  identityPublicKey: string;
  state: ChallengeState;
  expiresAt: Date;
  usedAt: Date | null;
  createdAt: Date;
}

export interface RecoveryChallengesRepository {
  create(challenge: RecoveryChallengeRecord): Promise<void>;
  getById(id: string): Promise<RecoveryChallengeRecord | null>;
  /**
   * Atomically transitions a challenge from `pending` to `used` iff it is
   * still pending and not expired. Returns the claimed record, or null if the
   * challenge was not claimable (missing, used, or expired). Single-statement
   * UPDATE ... WHERE guard makes concurrent completions race-safe.
   */
  claim(id: string, at: Date): Promise<RecoveryChallengeRecord | null>;
}

export class PgRecoveryChallengesRepository implements RecoveryChallengesRepository {
  constructor(private readonly db: Database) {}

  async create(challenge: RecoveryChallengeRecord): Promise<void> {
    await this.db.insert(recoveryChallenges).values({
      id: challenge.id,
      userId: challenge.userId,
      identityPublicKey: challenge.identityPublicKey,
      state: challenge.state,
      expiresAt: challenge.expiresAt,
      usedAt: challenge.usedAt,
      createdAt: challenge.createdAt,
    });
  }

  async getById(id: string): Promise<RecoveryChallengeRecord | null> {
    const rows = await this.db
      .select()
      .from(recoveryChallenges)
      .where(eq(recoveryChallenges.id, id))
      .limit(1);
    const row = rows[0];
    return row ? toRecord(row) : null;
  }

  async claim(id: string, at: Date): Promise<RecoveryChallengeRecord | null> {
    const rows = await this.db
      .update(recoveryChallenges)
      .set({ state: 'used', usedAt: at })
      .where(
        and(
          eq(recoveryChallenges.id, id),
          eq(recoveryChallenges.state, 'pending'),
          isNull(recoveryChallenges.usedAt),
          gt(recoveryChallenges.expiresAt, at),
        ),
      )
      .returning();
    const row = rows[0];
    return row ? toRecord(row) : null;
  }
}

function toRecord(row: typeof recoveryChallenges.$inferSelect): RecoveryChallengeRecord {
  return {
    id: row.id,
    userId: row.userId,
    identityPublicKey: row.identityPublicKey,
    state: row.state,
    expiresAt: row.expiresAt,
    usedAt: row.usedAt,
    createdAt: row.createdAt,
  };
}
