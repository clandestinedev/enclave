import {
  type AcceptRelationshipRequest,
  type ConfirmRelationshipRequest,
  type CreateRelationshipRequest,
  type CreateRelationshipResponse,
  type EstablishRelationshipRequest,
  type RelationshipView,
  pairingOfferRecordSchema,
  pairingTranscriptSchema,
} from '@enclave/contracts';

import { verifyEd25519 } from '../lib/ed25519';
import {
  deviceCertMissing,
  forbidden,
  idempotencyReplay,
  invalidRequest,
  notFound,
  pairingAlreadyActive,
  pairingExpired,
  pairingRejected,
  pairingStateInvalid,
  relationshipTerminated,
  signatureInvalid,
  tokenConflict,
  transcriptMismatch,
} from '../lib/errors';
import { newId } from '../lib/id';
import {
  PAIRING_OFFER_TTL_SECONDS,
  buildOfferRecordBytes,
  buildTranscriptBytes,
  pairingConsentMessage,
  type CanonicalParty,
} from '../lib/relationship';
import type { DeviceRecord, DevicesRepository } from '../repositories/devices';
import type { IdentitiesRepository } from '../repositories/identities';
import type { RelationshipEpochsRepository } from '../repositories/relationship-epochs';
import {
  type RelationshipRecord,
  type RelationshipsRepository,
} from '../repositories/relationships';
import type { UsersRepository } from '../repositories/users';

export const RELATIONSHIP_INITIAL_EPOCH = 1;

export interface RelationshipServiceDeps {
  relationships: RelationshipsRepository;
  epochs: RelationshipEpochsRepository;
  devices: DevicesRepository;
  identities: IdentitiesRepository;
  users: UsersRepository;
}

export class RelationshipService {
  constructor(private readonly deps: RelationshipServiceDeps) {}

  /**
   * Initiator A creates an offer. The server assembles the canonical offer
   * record (a-fields from stored identity + acting certified device; b = the
   * partner identity only, per founder decision) and returns its exact bytes
   * for A to sign with offerConsent_A.
   */
  async createOffer(
    userId: string,
    principalDeviceId: string | null,
    input: CreateRelationshipRequest,
  ): Promise<CreateRelationshipResponse> {
    if (input.partnerUserId === userId) throw invalidRequest('Cannot pair with yourself');
    const partner = await this.deps.users.getById(input.partnerUserId);
    if (!partner) throw notFound();

    const device = await this.requireCertifiedDevice(userId, principalDeviceId);

    const now = new Date();
    const relationshipId = newId();
    const [userA, userB] = sortPoles(userId, input.partnerUserId);

    const aParty = await this.canonicalPartyForDevice(userId, device, {
      relationshipStaticPublicKey: input.relationshipStaticPublicKey.value,
      ephemeralPublicKey: input.ephemeralPublicKey.value,
    });

    const offerRecord = buildOfferRecordBytes({
      relationshipId,
      epochNonce: input.epochNonce,
      epoch: RELATIONSHIP_INITIAL_EPOCH,
      a: aParty,
      partnerUserId: input.partnerUserId,
    }).toString('utf8');

    const createdAt = now;
    const expiresAt = new Date(now.getTime() + PAIRING_OFFER_TTL_SECONDS * 1000);

    const created = await this.deps.relationships.create({
      id: relationshipId,
      userA,
      userB,
      initiatorUserId: userId,
      state: 'PENDING',
      epoch: RELATIONSHIP_INITIAL_EPOCH,
      epochNonce: input.epochNonce,
      offerRecord,
      transcript: null,
      offerConsentSignature: null,
      acceptConsentSignature: null,
      confirmConsentSignature: null,
      sasProofA: null,
      sasProofB: null,
      rkaPublicA: input.relationshipStaticPublicKey.value,
      rkaPublicB: null,
      expiresAt,
      establishedAt: null,
      terminatedAt: null,
      createdAt,
      updatedAt: createdAt,
    });
    if (created === 'duplicate') throw pairingAlreadyActive();

    await this.deps.epochs.create({
      id: newId(),
      relationshipId,
      epoch: RELATIONSHIP_INITIAL_EPOCH,
      epochNonce: input.epochNonce,
      rotationCause: 'initial',
      createdAt,
    });

    return {
      relationshipId,
      state: 'PENDING',
      epoch: RELATIONSHIP_INITIAL_EPOCH,
      epochNonce: input.epochNonce,
      offerRecord,
      expiresAt: expiresAt.toISOString(),
      createdAt: createdAt.toISOString(),
    };
  }

  /** A signs offerConsent_A over the canonical offer record bytes. */
  async submitOfferConsent(
    userId: string,
    principalDeviceId: string | null,
    relationshipId: string,
    consentSignature: string,
  ): Promise<RelationshipView> {
    const rel = await this.mustMember(relationshipId, userId);
    await this.expireGuard(rel);
    if (!this.isInitiator(rel, userId))
      throw forbidden('Only the initiator can post offer consent');
    const device = await this.requireCertifiedDevice(userId, principalDeviceId);

    const offerRecord = rel.offerRecord;
    if (offerRecord === null) throw pairingStateInvalid('Missing offer record');
    const offerRecordBytes = Buffer.from(offerRecord, 'utf8');
    this.requireTranscriptDevice(offerRecord, 'a', device);

    const identity = await this.requireIdentity(userId);
    if (
      !verifyEd25519(
        Buffer.from(identity.identityPublicKey, 'base64'),
        pairingConsentMessage(offerRecordBytes),
        Buffer.from(consentSignature, 'base64'),
      )
    ) {
      throw signatureInvalid('Offer consent signature is invalid');
    }

    if (rel.offerConsentSignature !== null) return this.toView(rel, userId);

    const now = new Date();
    const updated = await this.deps.relationships.transition(
      rel.id,
      ['PENDING'],
      'PENDING',
      { offerConsentSignature: consentSignature },
      now,
    );
    if (!updated) {
      const fresh = await this.mustMember(relationshipId, userId);
      await this.expireGuard(fresh);
      throw pairingStateInvalid('Offer consent could not be recorded');
    }
    return this.toView(updated, userId);
  }

  /** B accepts: submits the canonical transcript + acceptConsent_B over its bytes. */
  async accept(
    userId: string,
    principalDeviceId: string | null,
    relationshipId: string,
    input: AcceptRelationshipRequest,
  ): Promise<RelationshipView> {
    const rel = await this.mustMember(relationshipId, userId);
    await this.expireGuard(rel);
    if (this.isInitiator(rel, userId)) throw forbidden('The initiator cannot accept its own offer');
    if (rel.offerConsentSignature === null)
      throw pairingStateInvalid('Offer consent is required first');
    const device = await this.requireCertifiedDevice(userId, principalDeviceId);

    const submittedBytes = Buffer.from(input.transcript, 'utf8');
    this.assertStructurallyValidTranscript(submittedBytes);

    const bParty = await this.canonicalPartyForDevice(userId, device, {
      relationshipStaticPublicKey: input.relationshipStaticPublicKey.value,
      ephemeralPublicKey: input.ephemeralPublicKey.value,
    });
    const canonicalBytes = buildTranscriptBytes({
      relationshipId: rel.id,
      epochNonce: rel.epochNonce,
      epoch: rel.epoch,
      a: this.canonicOfferParty(rel),
      b: bParty,
    });

    const identity = await this.requireIdentity(userId);
    if (
      !verifyEd25519(
        Buffer.from(identity.identityPublicKey, 'base64'),
        pairingConsentMessage(submittedBytes),
        Buffer.from(input.consentSignature, 'base64'),
      )
    ) {
      throw signatureInvalid('Accept consent signature is invalid');
    }
    if (!submittedBytes.equals(canonicalBytes)) throw transcriptMismatch();

    const transcript = canonicalBytes.toString('utf8');
    const now = new Date();
    const updated = await this.deps.relationships.transition(
      rel.id,
      ['PENDING'],
      'ACCEPTED',
      {
        transcript,
        acceptConsentSignature: input.consentSignature,
        rkaPublicB: input.relationshipStaticPublicKey.value,
      },
      now,
    );
    if (!updated) {
      const fresh = await this.mustMember(relationshipId, userId);
      await this.expireGuard(fresh);
      if (fresh.state === 'ACCEPTED' && fresh.acceptConsentSignature !== null) {
        return this.toView(fresh, userId);
      }
      throw pairingStateInvalid('Accept could not be recorded');
    }
    return this.toView(updated, userId);
  }

  /** A confirms: signs confirmConsent_A over the canonical stored transcript. */
  async confirm(
    userId: string,
    principalDeviceId: string | null,
    relationshipId: string,
    input: ConfirmRelationshipRequest,
  ): Promise<RelationshipView> {
    const rel = await this.mustMember(relationshipId, userId);
    await this.expireGuard(rel);
    if (rel.state !== 'ACCEPTED') throw pairingStateInvalid('Pairing must be accepted first');
    if (!this.isInitiator(rel, userId)) throw forbidden('Only the initiator can confirm');
    if (rel.acceptConsentSignature === null)
      throw pairingStateInvalid('Accept consent is required first');
    const device = await this.requireCertifiedDevice(userId, principalDeviceId);

    const transcript = rel.transcript;
    if (transcript === null) throw pairingStateInvalid('Missing transcript');
    if (input.transcript !== transcript) throw transcriptMismatch();
    this.requireTranscriptDevice(transcript, 'a', device);

    const identity = await this.requireIdentity(userId);
    if (
      !verifyEd25519(
        Buffer.from(identity.identityPublicKey, 'base64'),
        pairingConsentMessage(Buffer.from(transcript, 'utf8')),
        Buffer.from(input.consentSignature, 'base64'),
      )
    ) {
      throw signatureInvalid('Confirm consent signature is invalid');
    }

    if (rel.confirmConsentSignature !== null) return this.toView(rel, userId);

    const now = new Date();
    const updated = await this.deps.relationships.transition(
      rel.id,
      ['ACCEPTED'],
      'ACCEPTED',
      { confirmConsentSignature: input.consentSignature, sasProofA: input.sasProof },
      now,
    );
    if (!updated) {
      const fresh = await this.mustMember(relationshipId, userId);
      await this.expireGuard(fresh);
      throw pairingStateInvalid('Confirm could not be recorded');
    }
    return this.toView(updated, userId);
  }

  /** B establishes: posts sasProof_B; equality with stored sasProof_A ⇒ ESTABLISHED. */
  async establish(
    userId: string,
    principalDeviceId: string | null,
    relationshipId: string,
    input: EstablishRelationshipRequest,
  ): Promise<RelationshipView> {
    const rel = await this.mustMember(relationshipId, userId);
    await this.expireGuard(rel);
    if (this.isInitiator(rel, userId)) throw forbidden('Only the responder can establish');
    if (rel.state === 'ESTABLISHED') throw idempotencyReplay('Relationship already established');
    if (rel.state === 'REJECTED') throw pairingRejected();
    if (rel.state !== 'ACCEPTED') throw pairingStateInvalid('Pairing must be accepted first');
    if (rel.confirmConsentSignature === null)
      throw pairingStateInvalid('Confirm consent is required first');
    const transcript = rel.transcript;
    if (transcript === null) throw pairingStateInvalid('Missing transcript');
    const device = await this.requireCertifiedDevice(userId, principalDeviceId);
    this.requireTranscriptDevice(transcript, 'b', device);

    const now = new Date();
    const equal = rel.sasProofA !== null && rel.sasProofA === input.sasProof;
    const patch: Record<string, string | Date> = { sasProofB: input.sasProof };
    if (equal) patch.establishedAt = now;
    const updated = await this.deps.relationships.transition(
      rel.id,
      ['ACCEPTED'],
      equal ? 'ESTABLISHED' : 'REJECTED',
      patch,
      now,
    );
    if (!updated) {
      const fresh = await this.mustMember(relationshipId, userId);
      await this.expireGuard(fresh);
      if (fresh.state === 'ESTABLISHED')
        throw idempotencyReplay('Relationship already established');
      if (fresh.state === 'REJECTED') throw pairingRejected();
      throw pairingStateInvalid('Establish could not be recorded');
    }
    if (!equal) throw tokenConflict();
    return this.toView(updated, userId);
  }

  /**
   * Responder refusal — pole-authenticated, unsigned (founder decision).
   * Terminal; sticky.
   */
  async reject(
    userId: string,
    principalDeviceId: string | null,
    relationshipId: string,
  ): Promise<RelationshipView> {
    const rel = await this.mustMember(relationshipId, userId);
    await this.expireGuard(rel);
    if (this.isInitiator(rel, userId)) throw forbidden('Only the responder can reject');
    await this.requireCertifiedDevice(userId, principalDeviceId);
    if (rel.state === 'REJECTED') throw idempotencyReplay('Pairing already rejected');
    const updated = await this.transitionOrThrow(rel, userId, ['PENDING', 'ACCEPTED'], 'REJECTED');
    return this.toView(updated, userId);
  }

  /**
   * Initiator withdrawal before acceptance — pole-authenticated, unsigned.
   * Terminal; sticky.
   */
  async cancel(
    userId: string,
    principalDeviceId: string | null,
    relationshipId: string,
  ): Promise<RelationshipView> {
    const rel = await this.mustMember(relationshipId, userId);
    await this.expireGuard(rel);
    if (!this.isInitiator(rel, userId)) throw forbidden('Only the initiator can cancel');
    await this.requireCertifiedDevice(userId, principalDeviceId);
    if (rel.state === 'CANCELLED') throw idempotencyReplay('Pairing already cancelled');
    const updated = await this.transitionOrThrow(rel, userId, ['PENDING', 'ACCEPTED'], 'CANCELLED');
    return this.toView(updated, userId);
  }

  /** Breakup — either pole, pole-authenticated, unsigned. Terminal; sticky. */
  async terminate(
    userId: string,
    principalDeviceId: string | null,
    relationshipId: string,
  ): Promise<RelationshipView> {
    const rel = await this.mustMember(relationshipId, userId);
    if (rel.state === 'TERMINATED') throw idempotencyReplay('Relationship already terminated');
    if (rel.state === 'MEMORIALIZED') throw relationshipTerminated('Relationship is memorialized');
    await this.requireCertifiedDevice(userId, principalDeviceId);
    const updated = await this.transitionOrThrow(
      rel,
      userId,
      ['PENDING', 'ACCEPTED', 'ESTABLISHED'],
      'TERMINATED',
    );
    return this.toView(updated, userId);
  }

  async getOwn(relationshipId: string, userId: string): Promise<RelationshipView | null> {
    const rel = await this.deps.relationships.getById(relationshipId);
    if (!rel || !isMember(rel, userId)) return null;
    await this.expireSilently(rel);
    const fresh = await this.deps.relationships.getById(relationshipId);
    if (!fresh) return null;
    return this.toView(fresh, userId);
  }

  async listOwn(userId: string): Promise<RelationshipView[]> {
    const rels = await this.deps.relationships.listByUserId(userId);
    const views: RelationshipView[] = [];
    for (const rel of rels) {
      await this.expireSilently(rel);
      const fresh = await this.deps.relationships.getById(rel.id);
      if (fresh && isMember(fresh, userId)) views.push(this.toView(fresh, userId));
    }
    return views;
  }

  /** Lazily flips a PENDING/ACCEPTED relationship to EXPIRED (reads only). */
  private async expireSilently(rel: RelationshipRecord): Promise<void> {
    if (
      (rel.state === 'PENDING' || rel.state === 'ACCEPTED') &&
      rel.expiresAt.getTime() <= Date.now()
    ) {
      await this.deps.relationships.expireIfPast(rel.id, new Date());
    }
  }

  private async mustMember(relationshipId: string, userId: string): Promise<RelationshipRecord> {
    const rel = await this.deps.relationships.getById(relationshipId);
    if (!rel || !isMember(rel, userId)) throw notFound();
    return rel;
  }

  private isInitiator(rel: RelationshipRecord, userId: string): boolean {
    return rel.initiatorUserId === userId;
  }

  /** Lazily flips a PENDING/ACCEPTED relationship to EXPIRED and rejects writes. */
  private async expireGuard(rel: RelationshipRecord): Promise<void> {
    if (
      (rel.state === 'PENDING' || rel.state === 'ACCEPTED') &&
      rel.expiresAt.getTime() <= Date.now()
    ) {
      await this.deps.relationships.expireIfPast(rel.id, new Date());
      throw pairingExpired();
    }
  }

  /**
   * Relationship participation requires acting as a CERTIFIED, non-revoked
   * device (ADR 0004 §7). Account-secret principals (no device) cannot write.
   */
  private async requireCertifiedDevice(
    userId: string,
    principalDeviceId: string | null,
  ): Promise<DeviceRecord> {
    if (principalDeviceId === null) {
      throw forbidden('Relationship operations require a device credential');
    }
    const device = await this.deps.devices.getById(principalDeviceId);
    if (!device || device.userId !== userId) throw forbidden();
    if (device.revokedAt !== null) throw forbidden('Device revoked');
    if (device.certSignature === null || device.certVersion === null) {
      throw deviceCertMissing();
    }
    return device;
  }

  /** Verifies an Ed25519 consent signature with the pole's stored identity key. */
  private async requireIdentity(userId: string): Promise<{ identityPublicKey: string }> {
    const identity = await this.deps.identities.getByUserId(userId);
    if (!identity) throw signatureInvalid('Account has no recovery identity');
    return { identityPublicKey: identity.identityPublicKey };
  }

  /** Builds the canonical party record from the acting device's stored cert. */
  private async canonicalPartyForDevice(
    userId: string,
    device: DeviceRecord,
    keys: { relationshipStaticPublicKey: string; ephemeralPublicKey: string },
  ): Promise<CanonicalParty> {
    const identity = await this.requireIdentity(userId);
    return {
      userId,
      identityPublicKey: identity.identityPublicKey,
      relationshipStaticPublicKey: keys.relationshipStaticPublicKey,
      ephemeralPublicKey: keys.ephemeralPublicKey,
      deviceCert: {
        deviceId: device.id,
        devicePublicKey: device.publicKeyValue,
        keyVersion: device.certVersion as number,
        certSignature: device.certSignature as string,
      },
    };
  }

  private canonicOfferParty(rel: RelationshipRecord): CanonicalParty {
    if (rel.offerRecord === null) throw pairingStateInvalid('Missing offer record');
    const parsed = pairingOfferRecordSchema.safeParse(JSON.parse(rel.offerRecord));
    if (!parsed.success) throw pairingStateInvalid('Stored offer record is malformed');
    return parsed.data.a;
  }

  private assertStructurallyValidTranscript(bytes: Buffer): void {
    let parsed: unknown;
    try {
      parsed = JSON.parse(bytes.toString('utf8'));
    } catch {
      throw invalidRequest('Invalid transcript JSON');
    }
    const result = pairingTranscriptSchema.safeParse(parsed);
    if (!result.success) throw invalidRequest('Transcript does not match the pairing schema');
    if (result.data.relationshipId === undefined) throw invalidRequest('Missing relationship id');
  }

  /** The signed-transcript device must be the acting principal device. */
  private requireTranscriptDevice(artifact: string, role: 'a' | 'b', device: DeviceRecord): void {
    let obj: unknown;
    try {
      obj = JSON.parse(artifact);
    } catch {
      throw invalidRequest('Invalid canonical artifact');
    }
    const cert = (
      obj as {
        a?: { deviceCert?: { deviceId?: string } };
        b?: { deviceCert?: { deviceId?: string } };
      }
    )[role]?.deviceCert;
    if (cert?.deviceId !== device.id) {
      throw forbidden('The signing device is not the certified device in the transcript');
    }
  }

  private async transitionOrThrow(
    rel: RelationshipRecord,
    userId: string,
    from: Array<RelationshipRecord['state']>,
    to: RelationshipRecord['state'],
  ): Promise<RelationshipRecord> {
    const now = new Date();
    const updated = await this.deps.relationships.transition(rel.id, from, to, {}, now);
    if (!updated) {
      const fresh = await this.mustMember(rel.id, userId);
      await this.expireGuard(fresh);
      throw pairingStateInvalid(`Transition to ${to} is not allowed from ${fresh.state}`);
    }
    return updated;
  }

  private toView(rel: RelationshipRecord, userId: string): RelationshipView {
    void userId;
    return {
      relationshipId: rel.id,
      state: rel.state,
      epoch: rel.epoch,
      epochNonce: rel.epochNonce,
      initiatorUserId: rel.initiatorUserId,
      userA: rel.userA,
      userB: rel.userB,
      offerRecord: rel.offerRecord,
      transcript: rel.transcript,
      offerConsentSignature: rel.offerConsentSignature,
      acceptConsentSignature: rel.acceptConsentSignature,
      confirmConsentSignature: rel.confirmConsentSignature,
      sasProofA: rel.sasProofA,
      sasProofB: rel.sasProofB,
      relationshipStaticPublicKeyA: rel.rkaPublicA,
      relationshipStaticPublicKeyB: rel.rkaPublicB,
      expiresAt: rel.expiresAt.toISOString(),
      establishedAt: rel.establishedAt?.toISOString() ?? null,
      terminatedAt: rel.terminatedAt?.toISOString() ?? null,
      createdAt: rel.createdAt.toISOString(),
    };
  }
}

function isMember(rel: RelationshipRecord, userId: string): boolean {
  return rel.userA === userId || rel.userB === userId;
}

function sortPoles(a: string, b: string): [string, string] {
  return a < b ? [a, b] : [b, a];
}
