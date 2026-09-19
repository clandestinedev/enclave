import { and, eq } from 'drizzle-orm';

import type { Database } from '../db/client';
import { relationshipEpochs } from '../db/schema';

export type RotationCause = 'initial' | 'rekey' | 'breakup' | 'memorialize';

export interface RelationshipEpochRecord {
  id: string;
  relationshipId: string;
  epoch: number;
  epochNonce: string;
  rotationCause: RotationCause;
  createdAt: Date;
}

export interface RelationshipEpochsRepository {
  create(record: RelationshipEpochRecord): Promise<void>;
  getByRelationship(relationshipId: string): Promise<RelationshipEpochRecord[]>;
  getByRelationshipAndEpoch(
    relationshipId: string,
    epoch: number,
  ): Promise<RelationshipEpochRecord | null>;
}

export class PgRelationshipEpochsRepository implements RelationshipEpochsRepository {
  constructor(private readonly db: Database) {}

  async create(record: RelationshipEpochRecord): Promise<void> {
    await this.db.insert(relationshipEpochs).values({
      id: record.id,
      relationshipId: record.relationshipId,
      epoch: record.epoch,
      epochNonce: record.epochNonce,
      rotationCause: record.rotationCause,
      createdAt: record.createdAt,
    });
  }

  async getByRelationship(relationshipId: string): Promise<RelationshipEpochRecord[]> {
    const rows = await this.db
      .select()
      .from(relationshipEpochs)
      .where(eq(relationshipEpochs.relationshipId, relationshipId))
      .orderBy(relationshipEpochs.epoch);
    return rows.map(toRecord);
  }

  async getByRelationshipAndEpoch(
    relationshipId: string,
    epoch: number,
  ): Promise<RelationshipEpochRecord | null> {
    const rows = await this.db
      .select()
      .from(relationshipEpochs)
      .where(
        and(
          eq(relationshipEpochs.relationshipId, relationshipId),
          eq(relationshipEpochs.epoch, epoch),
        ),
      )
      .limit(1);
    const row = rows[0];
    return row ? toRecord(row) : null;
  }
}

function toRecord(row: typeof relationshipEpochs.$inferSelect): RelationshipEpochRecord {
  return {
    id: row.id,
    relationshipId: row.relationshipId,
    epoch: row.epoch,
    epochNonce: row.epochNonce,
    rotationCause: row.rotationCause as RotationCause,
    createdAt: row.createdAt,
  };
}
