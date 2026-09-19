import { z } from 'zod';

import { ed25519SignatureSchema, idSchema, keyVersionSchema, publicKeySchema } from './identity';
import { identityPublicKeySchema } from './recovery';

function decodedByteLength(b64: string): number {
  const clean = b64.replace(/=+$/, '');
  return Math.floor((clean.length * 3) / 4);
}

const base64 = z.string().base64();

/** 16 random bytes issued by the initiator; binds RK to a specific epoch. */
export const epochNonceSchema = base64.refine(
  (s) => decodedByteLength(s) === 16,
  'epochNonce must be 16 bytes',
);

/** A bare base64 X25519 public key value (used inside canonical artifacts). */
export const x25519ValueSchema = base64.refine(
  (s) => decodedByteLength(s) === 32,
  'public key value must be 32 bytes',
);

/** Canonical relationship lifecycle states (ratified ADR 0004 §6). */
export const relationshipStateSchema = z.enum([
  'PENDING',
  'ACCEPTED',
  'ESTABLISHED',
  'REJECTED',
  'EXPIRED',
  'CANCELLED',
  'TERMINATED',
  'MEMORIALIZED',
]);

export type RelationshipState = z.infer<typeof relationshipStateSchema>;

/** Client-submitted device certificate (wire shape: wrapped x25519 key). */
export const deviceCertificateSchema = z
  .object({
    deviceId: idSchema,
    devicePublicKey: publicKeySchema,
    keyVersion: keyVersionSchema,
    certSignature: ed25519SignatureSchema,
  })
  .strict();

export type DeviceCertificate = z.infer<typeof deviceCertificateSchema>;

/** Device certificate serialized inside canonical transcript/offer artifacts. */
export const transcriptDeviceCertificateSchema = z
  .object({
    deviceId: idSchema,
    devicePublicKey: x25519ValueSchema,
    keyVersion: keyVersionSchema,
    certSignature: ed25519SignatureSchema,
  })
  .strict();

/** One pole's full set of authenticated transcript fields (ratified §5.3). */
export const transcriptPartySchema = z
  .object({
    userId: idSchema,
    identityPublicKey: identityPublicKeySchema,
    relationshipStaticPublicKey: x25519ValueSchema,
    ephemeralPublicKey: x25519ValueSchema,
    deviceCert: transcriptDeviceCertificateSchema,
  })
  .strict();

export const pairingTranscriptSchema = z
  .object({
    t: z.literal('enclave/pairing-transcript-v1'),
    relationshipId: idSchema,
    epochNonce: epochNonceSchema,
    epoch: z.number().int().positive(),
    a: transcriptPartySchema,
    b: transcriptPartySchema,
  })
  .strict();

export type PairingTranscript = z.infer<typeof pairingTranscriptSchema>;

/**
 * The offer record A signs (offerConsent_A). `b` carries only the partner's
 * identity at offer time; the full `b` party is assembled when the responder
 * registers on `/accept` (founder decision, Step 1).
 */
export const pairingOfferRecordSchema = z
  .object({
    t: z.literal('enclave/pairing-offer-v1'),
    relationshipId: idSchema,
    epochNonce: epochNonceSchema,
    epoch: z.number().int().positive(),
    a: transcriptPartySchema,
    b: z.object({ userId: idSchema }).strict(),
  })
  .strict();

export type PairingOfferRecord = z.infer<typeof pairingOfferRecordSchema>;

export const sasProofSchema = base64.refine(
  (s) => decodedByteLength(s) === 16,
  'sasProof must be 16 bytes',
);

const transcriptStringSchema = z.string().min(1);

export const createRelationshipRequestSchema = z
  .object({
    partnerUserId: idSchema,
    epochNonce: epochNonceSchema,
    relationshipStaticPublicKey: publicKeySchema,
    ephemeralPublicKey: publicKeySchema,
  })
  .strict();

export type CreateRelationshipRequest = z.infer<typeof createRelationshipRequestSchema>;

export const createRelationshipResponseSchema = z.object({
  relationshipId: idSchema,
  state: relationshipStateSchema,
  epoch: z.number().int().positive(),
  epochNonce: epochNonceSchema,
  offerRecord: z.string().min(1),
  expiresAt: z.string(),
  createdAt: z.string(),
});

export type CreateRelationshipResponse = z.infer<typeof createRelationshipResponseSchema>;

export const offerConsentRequestSchema = z
  .object({
    consentSignature: ed25519SignatureSchema,
  })
  .strict();

export type OfferConsentRequest = z.infer<typeof offerConsentRequestSchema>;

export const acceptRelationshipRequestSchema = z
  .object({
    transcript: transcriptStringSchema,
    consentSignature: ed25519SignatureSchema,
    relationshipStaticPublicKey: publicKeySchema,
    ephemeralPublicKey: publicKeySchema,
  })
  .strict();

export type AcceptRelationshipRequest = z.infer<typeof acceptRelationshipRequestSchema>;

export const confirmRelationshipRequestSchema = z
  .object({
    transcript: transcriptStringSchema,
    consentSignature: ed25519SignatureSchema,
    sasProof: sasProofSchema,
  })
  .strict();

export type ConfirmRelationshipRequest = z.infer<typeof confirmRelationshipRequestSchema>;

export const establishRelationshipRequestSchema = z
  .object({
    sasProof: sasProofSchema,
  })
  .strict();

export type EstablishRelationshipRequest = z.infer<typeof establishRelationshipRequestSchema>;

export const relationshipViewSchema = z.object({
  relationshipId: idSchema,
  state: relationshipStateSchema,
  epoch: z.number().int().positive(),
  epochNonce: epochNonceSchema,
  initiatorUserId: idSchema,
  userA: idSchema,
  userB: idSchema,
  offerRecord: z.string().nullable(),
  transcript: z.string().nullable(),
  offerConsentSignature: ed25519SignatureSchema.nullable(),
  acceptConsentSignature: ed25519SignatureSchema.nullable(),
  confirmConsentSignature: ed25519SignatureSchema.nullable(),
  sasProofA: sasProofSchema.nullable(),
  sasProofB: sasProofSchema.nullable(),
  relationshipStaticPublicKeyA: x25519ValueSchema.nullable(),
  relationshipStaticPublicKeyB: x25519ValueSchema.nullable(),
  expiresAt: z.string().nullable(),
  establishedAt: z.string().nullable(),
  terminatedAt: z.string().nullable(),
  createdAt: z.string(),
});

export type RelationshipView = z.infer<typeof relationshipViewSchema>;

export const listRelationshipsResponseSchema = z.array(relationshipViewSchema);

export type ListRelationshipsResponse = z.infer<typeof listRelationshipsResponseSchema>;
