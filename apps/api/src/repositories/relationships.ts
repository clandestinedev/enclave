import { and, eq, inArray, notInArray, or, sql } from 'drizzle-orm';

import type { Database } from '../db/client';
import { relationships } from '../db/schema';
import type { RelationshipRow } from '../db/schema';

export type RelationshipState =
  | 'PENDING'
  | 'ACCEPTED'
  | 'ESTABLISHED'
  | 'REJECTED'
  | 'EXPIRED'
  | 'CANCELLED'
  | 'TERMINATED'
  | 'MEMORIALIZED';

const ACTIVE_STATES: RelationshipState[] = ['PENDING', 'ACCEPTED', 'ESTABLISHED'];

export interface RelationshipRecord {
  id: string;
  userA: string;
  userB: string;
  initiatorUserId: string;
  state: RelationshipState;
  epoch: number;
  epochNonce: string;
  offerRecord: string | null;
  transcript: string | null;
  offerConsentSignature: string | null;
  acceptConsentSignature: string | null;
  confirmConsentSignature: string | null;
  sasProofA: string | null;
  sasProofB: string | null;
  rkaPublicA: string;
  rkaPublicB: string | null;
  expiresAt: Date;
  establishedAt: Date | null;
  terminatedAt: Date | null;
  createdAt: Date;
  updatedAt: Date;
}

export interface RelationshipsRepository {
  /**
   * Inserts a new relationship offer. Returns `'created'`, or `'duplicate'`
   * when the one-active-per-pole partial unique indexes reject the insert
   * (concurrent or repeated offer for an already-active pair/user).
   */
  create(record: NewRelationshipRecord): Promise<'created' | 'duplicate'>;
  getById(id: string): Promise<RelationshipRecord | null>;
  getActiveForPair(userA: string, userB: string): Promise<RelationshipRecord | null>;
  listByUserId(userId: string): Promise<RelationshipRecord[]>;
  /**
   * Atomically rewinds a relationship from one of `from` states into `to`
   * (plus any patch). The pairing TTL (`expires_at`) is enforced ONLY when the
   * current state is PENDING or ACCEPTED; ESTABLISHED is independent of the
   * original offer TTL (audit HIGH-1), so e.g. ESTABLISHED → TERMINATED works
   * even after the offer's `expires_at` has passed. Returns the new row or null.
   */
  transition(
    id: string,
    from: RelationshipState[],
    to: RelationshipState,
    patch: Partial<Omit<RelationshipRecord, 'id'>>,
    at: Date,
  ): Promise<RelationshipRecord | null>;
  /** Marks a PENDING/ACCEPTED relationship EXPIRED iff now is past `expires_at`. */
  expireIfPast(id: string, at: Date): Promise<RelationshipRecord | null>;
}

export type NewRelationshipRecord = Omit<RelationshipRecord, 'updatedAt'> & {
  updatedAt?: Date | undefined;
};

function isUniqueViolation(err: unknown): boolean {
  if (typeof err !== 'object' || err === null) return false;
  // drizzle-orm wraps the underlying pg error: the SQLSTATE code lives on the
  // original error (`.cause`), not on the DrizzleQueryError wrapper.
  const wrapped = err as { code?: unknown; cause?: { code?: unknown } };
  return wrapped.code === '23505' || wrapped.cause?.code === '23505';
}

export class PgRelationshipsRepository implements RelationshipsRepository {
  constructor(private readonly db: Database) {}

  async create(record: NewRelationshipRecord): Promise<'created' | 'duplicate'> {
    try {
      await this.db.insert(relationships).values({
        id: record.id,
        userA: record.userA,
        userB: record.userB,
        initiatorUserId: record.initiatorUserId,
        state: record.state,
        epoch: record.epoch,
        epochNonce: record.epochNonce,
        offerRecord: record.offerRecord,
        transcript: record.transcript ?? null,
        offerConsentSignature: record.offerConsentSignature ?? null,
        acceptConsentSignature: record.acceptConsentSignature ?? null,
        confirmConsentSignature: record.confirmConsentSignature ?? null,
        sasProofA: record.sasProofA ?? null,
        sasProofB: record.sasProofB ?? null,
        rkaPublicA: record.rkaPublicA,
        rkaPublicB: record.rkaPublicB ?? null,
        expiresAt: record.expiresAt,
        establishedAt: record.establishedAt ?? null,
        terminatedAt: record.terminatedAt ?? null,
        createdAt: record.createdAt,
        updatedAt: record.updatedAt ?? record.createdAt,
      });
      return 'created';
    } catch (err) {
      if (isUniqueViolation(err)) return 'duplicate';
      throw err;
    }
  }

  async getById(id: string): Promise<RelationshipRecord | null> {
    const rows = await this.db
      .select()
      .from(relationships)
      .where(eq(relationships.id, id))
      .limit(1);
    const row = rows[0];
    return row ? toRecord(row) : null;
  }

  async getActiveForPair(userA: string, userB: string): Promise<RelationshipRecord | null> {
    const rows = await this.db
      .select()
      .from(relationships)
      .where(
        and(
          or(eq(relationships.userA, userA), eq(relationships.userA, userB)),
          or(eq(relationships.userB, userA), eq(relationships.userB, userB)),
          inArray(relationships.state, ACTIVE_STATES),
        ),
      )
      .limit(1);
    const row = rows[0];
    return row ? toRecord(row) : null;
  }

  async listByUserId(userId: string): Promise<RelationshipRecord[]> {
    const rows = await this.db
      .select()
      .from(relationships)
      .where(or(eq(relationships.userA, userId), eq(relationships.userB, userId)))
      .orderBy(relationships.createdAt);
    return rows.map(toRecord);
  }

  async transition(
    id: string,
    from: RelationshipState[],
    to: RelationshipState,
    patch: Partial<Omit<RelationshipRecord, 'id'>>,
    at: Date,
  ): Promise<RelationshipRecord | null> {
    const rows = await this.db
      .update(relationships)
      .set({
        state: to,
        transcript: patch.transcript ?? undefined,
        offerConsentSignature: patch.offerConsentSignature ?? undefined,
        acceptConsentSignature: patch.acceptConsentSignature ?? undefined,
        confirmConsentSignature: patch.confirmConsentSignature ?? undefined,
        sasProofA: patch.sasProofA ?? undefined,
        sasProofB: patch.sasProofB ?? undefined,
        rkaPublicB: patch.rkaPublicB ?? undefined,
        establishedAt: patch.establishedAt ?? undefined,
        terminatedAt: patch.terminatedAt ?? undefined,
        updatedAt: at,
      })
      .where(
        and(
          eq(relationships.id, id),
          inArray(relationships.state, from),
          // Pairing TTL applies to the ephemeral states only; ESTABLISHED is
          // not subject to the original offer's `expires_at` (audit HIGH-1).
          or(
            notInArray(relationships.state, ['PENDING', 'ACCEPTED']),
            sql`${relationships.expiresAt} > ${at}`,
          ),
        ),
      )
      .returning();
    const row = rows[0];
    return row ? toRecord(row) : null;
  }

  async expireIfPast(id: string, at: Date): Promise<RelationshipRecord | null> {
    const rows = await this.db
      .update(relationships)
      .set({ state: 'EXPIRED', updatedAt: at })
      .where(
        and(
          eq(relationships.id, id),
          inArray(relationships.state, ['PENDING', 'ACCEPTED']),
          sql`${relationships.expiresAt} <= ${at}`,
        ),
      )
      .returning();
    const row = rows[0];
    return row ? toRecord(row) : null;
  }
}

export function toRecord(row: RelationshipRow): RelationshipRecord {
  return {
    id: row.id,
    userA: row.userA,
    userB: row.userB,
    initiatorUserId: row.initiatorUserId,
    state: row.state as RelationshipState,
    epoch: row.epoch,
    epochNonce: row.epochNonce,
    offerRecord: row.offerRecord,
    transcript: row.transcript,
    offerConsentSignature: row.offerConsentSignature,
    acceptConsentSignature: row.acceptConsentSignature,
    confirmConsentSignature: row.confirmConsentSignature,
    sasProofA: row.sasProofA,
    sasProofB: row.sasProofB,
    rkaPublicA: row.rkaPublicA,
    rkaPublicB: row.rkaPublicB,
    expiresAt: row.expiresAt,
    establishedAt: row.establishedAt,
    terminatedAt: row.terminatedAt,
    createdAt: row.createdAt,
    updatedAt: row.updatedAt,
  };
}
