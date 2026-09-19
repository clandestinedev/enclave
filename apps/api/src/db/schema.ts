import { integer, pgTable, text, timestamp } from 'drizzle-orm/pg-core';

export const users = pgTable('users', {
  id: text('id').primaryKey(),
  accountSecretHash: text('account_secret_hash').notNull().unique(),
  createdAt: timestamp('created_at', { withTimezone: true }).notNull().defaultNow(),
});

export type UserRow = typeof users.$inferSelect;
export type NewUserRow = typeof users.$inferInsert;

export const devices = pgTable('devices', {
  id: text('id').primaryKey(),
  userId: text('user_id')
    .notNull()
    .references(() => users.id, { onDelete: 'cascade' }),
  label: text('label'),
  publicKeyType: text('public_key_type').notNull(),
  publicKeyValue: text('public_key_value').notNull(),
  keyVersion: integer('key_version').notNull(),
  deviceSecretHash: text('device_secret_hash'),
  certSignature: text('cert_signature'),
  certVersion: integer('cert_version'),
  createdAt: timestamp('created_at', { withTimezone: true }).notNull().defaultNow(),
  lastSeenAt: timestamp('last_seen_at', { withTimezone: true }),
  revokedAt: timestamp('revoked_at', { withTimezone: true }),
});

export type DeviceRow = typeof devices.$inferSelect;
export type NewDeviceRow = typeof devices.$inferInsert;

/**
 * Phase 3 relationship trust / pairing (ADR 0004). `user_a < user_b` by
 * canonical ordering (see `poleId`); `initiator_user_id` records who made the
 * offer so the transcript `a`/`b` roles are unambiguous regardless of the
 * sorted column order. The one-active-per-pole invariant is enforced by the
 * partial unique indexes created in the migration (not expressed in the table
 * definition when it conflicts with drizzle-kit snapshots).
 */
export const relationships = pgTable('relationships', {
  id: text('id').primaryKey(),
  userA: text('user_a')
    .notNull()
    .references(() => users.id, { onDelete: 'cascade' }),
  userB: text('user_b')
    .notNull()
    .references(() => users.id, { onDelete: 'cascade' }),
  initiatorUserId: text('initiator_user_id')
    .notNull()
    .references(() => users.id, { onDelete: 'cascade' }),
  state: text('state', {
    enum: [
      'PENDING',
      'ACCEPTED',
      'ESTABLISHED',
      'REJECTED',
      'EXPIRED',
      'CANCELLED',
      'TERMINATED',
      'MEMORIALIZED',
    ],
  })
    .notNull()
    .default('PENDING'),
  epoch: integer('epoch').notNull(),
  epochNonce: text('epoch_nonce').notNull(),
  offerRecord: text('offer_record'),
  transcript: text('transcript'),
  offerConsentSignature: text('offer_consent'),
  acceptConsentSignature: text('accept_consent'),
  confirmConsentSignature: text('confirm_consent'),
  sasProofA: text('sas_proof_a'),
  sasProofB: text('sas_proof_b'),
  rkaPublicA: text('rka_public_a').notNull(),
  rkaPublicB: text('rka_public_b'),
  expiresAt: timestamp('expires_at', { withTimezone: true }).notNull(),
  establishedAt: timestamp('established_at', { withTimezone: true }),
  terminatedAt: timestamp('terminated_at', { withTimezone: true }),
  createdAt: timestamp('created_at', { withTimezone: true }).notNull().defaultNow(),
  updatedAt: timestamp('updated_at', { withTimezone: true }).notNull().defaultNow(),
});

export type RelationshipRow = typeof relationships.$inferSelect;
export type NewRelationshipRow = typeof relationships.$inferInsert;

export const relationshipEpochs = pgTable('relationship_epochs', {
  id: text('id').primaryKey(),
  relationshipId: text('relationship_id')
    .notNull()
    .references(() => relationships.id, { onDelete: 'cascade' }),
  epoch: integer('epoch').notNull(),
  epochNonce: text('epoch_nonce').notNull(),
  rotationCause: text('rotation_cause', {
    enum: ['initial', 'rekey', 'breakup', 'memorialize'],
  }).notNull(),
  createdAt: timestamp('created_at', { withTimezone: true }).notNull().defaultNow(),
});

export type RelationshipEpochRow = typeof relationshipEpochs.$inferSelect;
export type NewRelationshipEpochRow = typeof relationshipEpochs.$inferInsert;

export const identities = pgTable('identities', {
  id: text('id').primaryKey(),
  userId: text('user_id')
    .notNull()
    .references(() => users.id, { onDelete: 'cascade' }),
  identityPublicKey: text('identity_public_key').notNull().unique(),
  keyVersion: integer('key_version').notNull().default(0),
  createdAt: timestamp('created_at', { withTimezone: true }).notNull().defaultNow(),
});

export type IdentityRow = typeof identities.$inferSelect;
export type NewIdentityRow = typeof identities.$inferInsert;

export const recoveryChallenges = pgTable('recovery_challenges', {
  id: text('id').primaryKey(),
  userId: text('user_id')
    .notNull()
    .references(() => users.id, { onDelete: 'cascade' }),
  identityPublicKey: text('identity_public_key').notNull(),
  state: text('state', { enum: ['pending', 'used', 'expired'] })
    .notNull()
    .default('pending'),
  expiresAt: timestamp('expires_at', { withTimezone: true }).notNull(),
  usedAt: timestamp('used_at', { withTimezone: true }),
  createdAt: timestamp('created_at', { withTimezone: true }).notNull().defaultNow(),
});

export type RecoveryChallengeRow = typeof recoveryChallenges.$inferSelect;
export type NewRecoveryChallengeRow = typeof recoveryChallenges.$inferInsert;

export const deviceRecoveryBlobs = pgTable('device_recovery_blobs', {
  id: text('id').primaryKey(),
  userId: text('user_id')
    .notNull()
    .references(() => users.id, { onDelete: 'cascade' }),
  deviceId: text('device_id')
    .notNull()
    .unique()
    .references(() => devices.id, { onDelete: 'cascade' }),
  envelope: text('envelope').notNull(),
  revokedAt: timestamp('revoked_at', { withTimezone: true }),
  createdAt: timestamp('created_at', { withTimezone: true }).notNull().defaultNow(),
});

export type DeviceRecoveryBlobRow = typeof deviceRecoveryBlobs.$inferSelect;
export type NewDeviceRecoveryBlobRow = typeof deviceRecoveryBlobs.$inferInsert;

export const encryptedPayloads = pgTable('encrypted_payloads', {
  id: text('id').primaryKey(),
  userId: text('user_id')
    .notNull()
    .references(() => users.id, { onDelete: 'cascade' }),
  deviceId: text('device_id')
    .notNull()
    .references(() => devices.id, { onDelete: 'cascade' }),
  envelope: text('envelope').notNull(),
  byteLength: integer('byte_length').notNull(),
  createdAt: timestamp('created_at', { withTimezone: true }).notNull().defaultNow(),
});

export type EncryptedPayloadRow = typeof encryptedPayloads.$inferSelect;
export type NewEncryptedPayloadRow = typeof encryptedPayloads.$inferInsert;
