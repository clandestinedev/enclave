import type {
  CreateRecoveryChallengeResponse,
  IdentityView,
  RecoveryBlobEnvelope,
  RecoveryBlobView,
} from '@enclave/contracts';
import { recoveryBlobEnvelopeSchema } from '@enclave/contracts';

import { generateAccountSecret, digestSecret } from '../auth/account';
import { verifyEd25519 } from '../lib/ed25519';
import {
  challengeExpired,
  challengeNotFound,
  challengeUsed,
  conflict,
  forbidden,
  identityInUse,
  invalidRequest,
  notFound,
  signatureInvalid,
} from '../lib/errors';
import { newId } from '../lib/id';
import { recoveryChallengeMessage } from '../lib/recovery-message';
import type { IdentitiesRepository } from '../repositories/identities';
import type { DevicesRepository } from '../repositories/devices';
import type { RecoveryBlobsRepository } from '../repositories/recovery-blobs';
import type { RecoveryChallengesRepository } from '../repositories/recovery-challenges';

export const RECOVERY_CHALLENGE_TTL_SECONDS = 30 * 60;
export const DEVICE_KEY_VERSION = 0;

export interface RecoveryServiceDeps {
  identities: IdentitiesRepository;
  challenges: RecoveryChallengesRepository;
  blobs: RecoveryBlobsRepository;
  devices: DevicesRepository;
}

export class RecoveryService {
  constructor(private readonly deps: RecoveryServiceDeps) {}

  /**
   * Anchors an account's recovery identity public key. Idempotent for the same
   * key; refuses to silently replace an existing identity with a different
   * key. A key already bound to another account is rejected.
   */
  async createIdentity(userId: string, identityPublicKey: string): Promise<IdentityView> {
    const existingForUser = await this.deps.identities.getByUserId(userId);
    if (existingForUser) {
      if (existingForUser.identityPublicKey !== identityPublicKey) {
        throw conflict('Account already has a recovery identity');
      }
      return toIdentityView(existingForUser);
    }

    const existingKey = await this.deps.identities.getByPublicKey(identityPublicKey);
    if (existingKey) throw identityInUse();

    const id = newId();
    const createdAt = new Date();
    await this.deps.identities.create({
      id,
      userId,
      identityPublicKey,
      keyVersion: 0,
      createdAt,
    });
    return {
      identityId: id,
      userId,
      identityPublicKey,
      keyVersion: 0,
      createdAt: createdAt.toISOString(),
    };
  }

  /** Issues a single-use, time-boxed challenge bound to an identity. */
  async createChallenge(identityPublicKey: string): Promise<CreateRecoveryChallengeResponse> {
    const identity = await this.deps.identities.getByPublicKey(identityPublicKey);
    if (!identity) throw notFound();

    const challengeId = newId();
    const createdAt = new Date();
    const expiresAt = new Date(createdAt.getTime() + RECOVERY_CHALLENGE_TTL_SECONDS * 1000);
    await this.deps.challenges.create({
      id: challengeId,
      userId: identity.userId,
      identityPublicKey,
      state: 'pending',
      expiresAt,
      usedAt: null,
      createdAt,
    });
    return {
      challengeId,
      userId: identity.userId,
      expiresAt: expiresAt.toISOString(),
      ttlSeconds: RECOVERY_CHALLENGE_TTL_SECONDS,
    };
  }

  /**
   * Completes recovery: verifies the identity signature, atomically consumes
   * the challenge, enrolls a new device, and returns its one-time device
   * secret. Signature is verified BEFORE the challenge is claimed so that a
   * bad signature does not burn a valid challenge.
   */
  async completeRecovery(input: {
    challengeId: string;
    signature: string;
    deviceKey: { type: 'x25519'; value: string };
  }): Promise<{
    userId: string;
    deviceId: string;
    deviceSecret: string;
    keyVersion: number;
    deviceKey: { type: 'x25519'; value: string };
  }> {
    const challenge = await this.deps.challenges.getById(input.challengeId);
    if (!challenge) throw challengeNotFound();
    if (challenge.state !== 'pending') throw challengeUsed();
    if (challenge.expiresAt.getTime() <= Date.now()) throw challengeExpired();

    const message = recoveryChallengeMessage({
      userId: challenge.userId,
      challengeId: challenge.id,
      devicePublicKeyValue: input.deviceKey.value,
    });
    const valid = verifyEd25519(
      Buffer.from(challenge.identityPublicKey, 'base64'),
      message,
      Buffer.from(input.signature, 'base64'),
    );
    if (!valid) throw signatureInvalid();

    const claimed = await this.deps.challenges.claim(challenge.id, new Date());
    if (!claimed) {
      const current = await this.deps.challenges.getById(challenge.id);
      if (!current) throw challengeNotFound();
      if (current.state === 'used') throw challengeUsed();
      if (current.expiresAt.getTime() <= Date.now()) throw challengeExpired();
      throw challengeUsed();
    }

    const deviceId = newId();
    const deviceSecret = generateAccountSecret();
    await this.deps.devices.create({
      id: deviceId,
      userId: claimed.userId,
      label: null,
      publicKeyType: input.deviceKey.type,
      publicKeyValue: input.deviceKey.value,
      keyVersion: DEVICE_KEY_VERSION,
      deviceSecretHash: digestSecret(deviceSecret),
      certSignature: null,
      certVersion: null,
      createdAt: new Date(),
      lastSeenAt: null,
      revokedAt: null,
    });

    return {
      userId: claimed.userId,
      deviceId,
      deviceSecret,
      keyVersion: DEVICE_KEY_VERSION,
      deviceKey: input.deviceKey,
    };
  }

  /** Stores (or replaces) a device's opaque recovery blob. */
  async storeBlob(input: {
    userId: string;
    deviceId: string;
    envelope: RecoveryBlobEnvelope;
  }): Promise<RecoveryBlobView> {
    const parsed = recoveryBlobEnvelopeSchema.safeParse(input.envelope);
    if (!parsed.success) throw invalidRequest('Invalid recovery blob envelope');
    const envelope = parsed.data;

    if (envelope.userId !== input.userId) throw forbidden('Blob account mismatch');
    if (envelope.deviceId !== input.deviceId) throw forbidden('Blob device mismatch');

    const device = await this.deps.devices.getById(input.deviceId);
    if (!device || device.userId !== input.userId || device.revokedAt !== null) {
      throw forbidden('Device not eligible for recovery blob');
    }

    const record = await this.deps.blobs.upsert({
      id: newId(),
      userId: input.userId,
      deviceId: input.deviceId,
      envelope: JSON.stringify(envelope),
      revokedAt: null,
      createdAt: new Date(),
    });
    return {
      blobId: record.id,
      deviceId: record.deviceId,
      createdAt: record.createdAt.toISOString(),
      envelope,
    };
  }

  /** Lists a user's active (non-revoked) recovery blobs. */
  async listBlobs(userId: string): Promise<RecoveryBlobView[]> {
    const records = await this.deps.blobs.listActiveByUserId(userId);
    return records.map((record) => ({
      blobId: record.id,
      deviceId: record.deviceId,
      createdAt: record.createdAt.toISOString(),
      envelope: JSON.parse(record.envelope) as RecoveryBlobEnvelope,
    }));
  }

  /** Revokes a device's recovery blob without touching other devices' blobs. */
  async revokeBlobForDevice(deviceId: string): Promise<void> {
    await this.deps.blobs.revokeByDeviceId(deviceId, new Date());
  }
}

function toIdentityView(identity: {
  id: string;
  userId: string;
  identityPublicKey: string;
  keyVersion: number;
  createdAt: Date;
}): IdentityView {
  return {
    identityId: identity.id,
    userId: identity.userId,
    identityPublicKey: identity.identityPublicKey,
    keyVersion: identity.keyVersion,
    createdAt: identity.createdAt.toISOString(),
  };
}
