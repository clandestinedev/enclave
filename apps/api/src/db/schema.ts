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
  createdAt: timestamp('created_at', { withTimezone: true }).notNull().defaultNow(),
  lastSeenAt: timestamp('last_seen_at', { withTimezone: true }),
  revokedAt: timestamp('revoked_at', { withTimezone: true }),
});

export type DeviceRow = typeof devices.$inferSelect;
export type NewDeviceRow = typeof devices.$inferInsert;

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
