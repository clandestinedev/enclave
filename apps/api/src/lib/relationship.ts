/**
 * Server-side reconstruction of the Phase 3 pairing artifacts (ADR 0004 §5.3).
 *
 * The server assembles ONE canonical transcript and returns its exact bytes to
 * both clients; every consent signature and the sasProof digest are computed
 * over those exact bytes, so both poles commit to a byte-identical view. The
 * reference client (`test/reference-relationship.ts`) MUST mirror these
 * builders byte-for-byte — the "deterministic transcript" test asserts it.
 *
 * Trust boundary: the server constructs canonical JSON but NEVER derives or
 * holds RK, SAS values, or any private scalar. It only relays, validates
 * structure, and byte-compares client-submitted artifacts against its own
 * canonical reconstruction.
 */

export const PAIRING_TRANSCRIPT_PREFIX = 'enclave/pairing-transcript-v1';
export const PAIRING_OFFER_PREFIX = 'enclave/pairing-offer-v1';
export const PAIRING_CONSENT_PREFIX = 'enclave/pairing-consent-v1';
export const DEVICE_CERT_PREFIX = 'enclave/device-cert-v1';

export const PAIRING_OFFER_TTL_SECONDS = 24 * 60 * 60;

export interface CanonicalDeviceCert {
  deviceId: string;
  devicePublicKey: string;
  keyVersion: number;
  certSignature: string;
}

export interface CanonicalParty {
  userId: string;
  identityPublicKey: string;
  relationshipStaticPublicKey: string;
  ephemeralPublicKey: string;
  deviceCert: CanonicalDeviceCert;
}

export interface TranscriptInput {
  relationshipId: string;
  epochNonce: string;
  epoch: number;
  a: CanonicalParty;
  b: CanonicalParty;
}

function partyObject(party: CanonicalParty): CanonicalParty {
  return {
    userId: party.userId,
    identityPublicKey: party.identityPublicKey,
    relationshipStaticPublicKey: party.relationshipStaticPublicKey,
    ephemeralPublicKey: party.ephemeralPublicKey,
    deviceCert: {
      deviceId: party.deviceCert.deviceId,
      devicePublicKey: party.deviceCert.devicePublicKey,
      keyVersion: party.deviceCert.keyVersion,
      certSignature: party.deviceCert.certSignature,
    },
  };
}

/** Canonical transcript T as UTF-8 bytes (ratified §5.3 layout). */
export function buildTranscriptBytes(input: TranscriptInput): Buffer {
  const obj = {
    t: PAIRING_TRANSCRIPT_PREFIX,
    relationshipId: input.relationshipId,
    epochNonce: input.epochNonce,
    epoch: input.epoch,
    a: partyObject(input.a),
    b: partyObject(input.b),
  };
  return Buffer.from(JSON.stringify(obj), 'utf8');
}

/** Offer record over which offerConsent_A is computed (b = partner identity only). */
export function buildOfferRecordBytes(input: {
  relationshipId: string;
  epochNonce: string;
  epoch: number;
  a: CanonicalParty;
  partnerUserId: string;
}): Buffer {
  const obj = {
    t: PAIRING_OFFER_PREFIX,
    relationshipId: input.relationshipId,
    epochNonce: input.epochNonce,
    epoch: input.epoch,
    a: partyObject(input.a),
    b: { userId: input.partnerUserId },
  };
  return Buffer.from(JSON.stringify(obj), 'utf8');
}

/**
 * Consent message: `enclave/pairing-consent-v1` 0x00 payloadBytes. Every
 * consent signature (offer/accept/confirm) is Ed25519 over this prefix plus the
 * exact canonical payload bytes.
 */
export function pairingConsentMessage(payloadBytes: Buffer): Buffer {
  return Buffer.concat([
    Buffer.from(PAIRING_CONSENT_PREFIX, 'utf8'),
    Buffer.from([0x00]),
    payloadBytes,
  ]);
}

/**
 * Device certificate message:
 * `enclave/device-cert-v1` 0x00 userId 0x00 deviceId 0x00 devicePublicKeyValue
 * 0x00 keyVersion (decimal). Ed25519-signed by the account's identity key.
 */
export function deviceCertMessage(input: {
  userId: string;
  deviceId: string;
  devicePublicKeyValue: string;
  keyVersion: number;
}): Buffer {
  return Buffer.concat([
    Buffer.from(DEVICE_CERT_PREFIX, 'utf8'),
    Buffer.from([0x00]),
    Buffer.from(input.userId, 'utf8'),
    Buffer.from([0x00]),
    Buffer.from(input.deviceId, 'utf8'),
    Buffer.from([0x00]),
    Buffer.from(input.devicePublicKeyValue, 'utf8'),
    Buffer.from([0x00]),
    Buffer.from(String(input.keyVersion), 'utf8'),
  ]);
}
