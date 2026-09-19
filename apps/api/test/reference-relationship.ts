import { ed25519, x25519 } from '@noble/curves/ed25519.js';
import { hkdf } from '@noble/hashes/hkdf.js';
import { sha256, sha512 } from '@noble/hashes/sha2.js';
import { randomBytes } from '@noble/ciphers/utils.js';

import { fromBase64, toBase64 } from './reference-client';
import type { IdentityKeyMaterial } from './reference-recovery';

/**
 * Reference implementation of the Phase 3 relationship crypto (ADR 0004 / the
 * ratified Model F design). TEST-ONLY executable specification that the Dart
 * core (`packages/dart_core`) and the production server (`lib/relationship.ts`)
 * must mirror byte-for-byte.
 *
 * Trust boundary: the server only ever sees public statics, ephemeral publics,
 * device certificates, consent signatures, the canonical transcript, and the
 * 16-byte sasProof — where it may only RELAY and compare them for equality.
 * The seed, RKA/RKB private scalars, ephemeral privates, RK, and SAS are
 * never transmitted and never stored server-side.
 *
 * The Phase-3 RK is a LONG-LIVED per-epoch wrapping key. It is intentionally
 * independent of the ephemerals and provides NO forward secrecy; the Phase-4
 * double ratchet will own forward secrecy. Do not describe it as
 * forward-secret (RATIFIED O2).
 */

export const RELATIONSHIP_STATIC_SALT = 'enclave/relationship-identity-v1';
export const RELATIONSHIP_STATIC_INFO = 'x25519';
export const RELATIONSHIP_RK_SALT = 'enclave/relationship-rk-v1';
export const SAS_PROOF_SALT = 'enclave/sas-proof-v1';
export const PAIRING_TRANSCRIPT_PREFIX = 'enclave/pairing-transcript-v1';
export const PAIRING_OFFER_PREFIX = 'enclave/pairing-offer-v1';
export const PAIRING_CONSENT_PREFIX = 'enclave/pairing-consent-v1';
export const DEVICE_CERT_PREFIX = 'enclave/device-cert-v1';

const utf8 = (s: string) => new TextEncoder().encode(s);
const sep = new Uint8Array([0x00]);

export interface RelationshipKeyMaterial {
  /** 32-byte X25519 private scalar (Model F, recomputable from the BIP39 seed). */
  relationshipStaticPrivateKey: Uint8Array;
  /** Base64 of the 32-byte X25519 public key. */
  relationshipStaticPublicKey: string;
}

/** Model F: RKA/RKB derived from the BIP39 seed (ratified O1). */
export function deriveRelationshipStatic(seed: Uint8Array): RelationshipKeyMaterial {
  const relationshipStaticPrivateKey = hkdf(
    sha512,
    seed,
    utf8(RELATIONSHIP_STATIC_SALT),
    utf8(RELATIONSHIP_STATIC_INFO),
    32,
  );
  return {
    relationshipStaticPrivateKey,
    relationshipStaticPublicKey: toBase64(x25519.getPublicKey(relationshipStaticPrivateKey)),
  };
}

export function createPairingEphemeral(seed?: Uint8Array): {
  ephemeralPrivateKey: Uint8Array;
  ephemeralPublicKey: string;
} {
  const ephemeralPrivateKey = seed ?? randomBytes(32);
  return {
    ephemeralPrivateKey,
    ephemeralPublicKey: toBase64(x25519.getPublicKey(ephemeralPrivateKey)),
  };
}

/**
 * Canonical relationship RK (RATIFIED O2: ephemeral-free, epoch-bound):
 * HKDF-SHA512(ikm = X25519(RKA_priv, RKB_pub),
 *             salt = "enclave/relationship-rk-v1",
 *             info = "rk" 0x00 relationshipId 0x00 epoch 0x00 epochNonce,
 *             dkLen = 32).
 * The shared secret is symmetric, so deriveRelationshipRK is symmetric too.
 */
export function deriveRelationshipRK(input: {
  relationshipId: string;
  epoch: number;
  epochNonce: string;
  staticPrivateKey: Uint8Array;
  partnerStaticPublicKey: string;
}): Uint8Array {
  const dh = x25519.getSharedSecret(
    input.staticPrivateKey,
    fromBase64(input.partnerStaticPublicKey),
  );
  const info = utf8(`rk\x00${input.relationshipId}\x00${input.epoch}\x00${input.epochNonce}`);
  return hkdf(sha512, dh, utf8(RELATIONSHIP_RK_SALT), info, 32);
}

/**
 * sasProof: HKDF-SHA512(ikm = RK, salt = "enclave/sas-proof-v1",
 *                       info = SHA-256(T bytes), dkLen = 16).
 * Equality of the two poles' proofs is key confirmation AND byte-exact
 * transcript confirmation (ratified §5.3). One-shot: asserted only at
 * ACCEPTED → ESTABLISHED.
 */
export function deriveSasProof(rk: Uint8Array, transcriptBytes: Uint8Array): string {
  return toBase64(hkdf(sha512, rk, utf8(SAS_PROOF_SALT), sha256(transcriptBytes), 16));
}

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

/**
 * Device certificate message (ADR 0004 §7):
 * `enclave/device-cert-v1` 0x00 userId 0x00 deviceId 0x00
 * devicePublicKeyValue 0x00 keyVersion.
 */
export function deviceCertMessage(input: {
  userId: string;
  deviceId: string;
  devicePublicKeyValue: string;
  keyVersion: number;
}): Uint8Array {
  const parts = [
    utf8(DEVICE_CERT_PREFIX),
    sep,
    utf8(input.userId),
    sep,
    utf8(input.deviceId),
    sep,
    utf8(input.devicePublicKeyValue),
    sep,
    utf8(String(input.keyVersion)),
  ];
  return concatenate(parts);
}

export function signDeviceCert(
  identity: IdentityKeyMaterial,
  input: { userId: string; deviceId: string; devicePublicKeyValue: string; keyVersion: number },
): string {
  return toBase64(ed25519.sign(deviceCertMessage(input), identity.signingPrivateKey));
}

/** Consent message: `enclave/pairing-consent-v1` 0x00 payloadBytes. */
export function pairingConsentMessage(payloadBytes: Uint8Array): Uint8Array {
  return concatenate([utf8(PAIRING_CONSENT_PREFIX), sep, payloadBytes]);
}

export function signPairingConsent(
  identity: IdentityKeyMaterial,
  payloadBytes: Uint8Array,
): string {
  return toBase64(ed25519.sign(pairingConsentMessage(payloadBytes), identity.signingPrivateKey));
}

/** Canonical offer record (b = partner identity only). A signs offerConsent_A over it. */
export function canonicalOfferRecord(input: {
  relationshipId: string;
  epochNonce: string;
  epoch: number;
  a: CanonicalParty;
  partnerUserId: string;
}): string {
  return JSON.stringify({
    t: PAIRING_OFFER_PREFIX,
    relationshipId: input.relationshipId,
    epochNonce: input.epochNonce,
    epoch: input.epoch,
    a: partyObject(input.a),
    b: { userId: input.partnerUserId },
  });
}

/** Canonical transcript T. Both poles sign consents over its exact bytes. */
export function canonicalTranscript(input: {
  relationshipId: string;
  epochNonce: string;
  epoch: number;
  a: CanonicalParty;
  b: CanonicalParty;
}): string {
  return JSON.stringify({
    t: PAIRING_TRANSCRIPT_PREFIX,
    relationshipId: input.relationshipId,
    epochNonce: input.epochNonce,
    epoch: input.epoch,
    a: partyObject(input.a),
    b: partyObject(input.b),
  });
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

function concatenate(parts: Uint8Array[]): Uint8Array {
  const total = parts.reduce((n, p) => n + p.length, 0);
  const out = new Uint8Array(total);
  let offset = 0;
  for (const part of parts) {
    out.set(part, offset);
    offset += part.length;
  }
  return out;
}
