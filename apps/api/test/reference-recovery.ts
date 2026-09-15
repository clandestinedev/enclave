import { ed25519 } from '@noble/curves/ed25519.js';
import { xchacha20poly1305 } from '@noble/ciphers/chacha.js';
import { hkdf } from '@noble/hashes/hkdf.js';
import { sha512 } from '@noble/hashes/sha2.js';
import { randomBytes } from '@noble/ciphers/utils.js';
import { generateMnemonic, mnemonicToSeedSync, validateMnemonic } from '@scure/bip39';
import { wordlist } from '@scure/bip39/wordlists/english.js';

import type { RecoveryBlobEnvelope } from '@enclave/contracts';

import { fromBase64, toBase64, type DeviceKeyMaterial } from './reference-client';

/**
 * Reference implementation of Encore's Phase 2 identity / recovery crypto.
 *
 * TEST-ONLY executable specification that the Dart core
 * (`packages/dart_core/lib/src/recovery.dart`) must mirror byte-for-byte.
 *
 * Trust boundary: the server only ever sees the identity PUBLIC key, a
 * challenge, an Ed25519 signature, and an OPAQUE recovery blob. The mnemonic,
 * BIP39 seed, identity private key, and recovery wrapping key never leave the
 * device. BIP39-derived material NEVER encrypts application content — the
 * wrapping key only wraps device key material (see ADR 0003 §5).
 */

export const IDENTITY_SIGNING_SALT = 'enclave/identity-signing-v1';
export const IDENTITY_SIGNING_INFO = 'ed25519';
export const RECOVERY_WRAP_SALT = 'enclave/recovery-wrap-v1';
export const RECOVERY_WRAP_INFO = 'xchacha20';
export const RECOVERY_MESSAGE_PREFIX = 'enclave/recovery-v1';
export const RECOVERY_BLOB_AAD_PREFIX = 'enclave/recovery-blob-v1/';
export const BLOB_VERSION = 1 as const;
export const BLOB_ALG = 'xchacha20poly1305' as const;
export const MNEMONIC_WORD_COUNT = 12 as const;

export interface IdentityKeyMaterial {
  /** 64-byte BIP39 seed. Never persisted; zero after derivation. */
  seed: Uint8Array;
  /** 32-byte Ed25519 seed used to sign recovery challenges. */
  signingPrivateKey: Uint8Array;
  /** Base64 Ed25519 public key. This is the account's recovery anchor. */
  identityPublicKeyValue: string;
  /** 32-byte XChaCha20 key that wraps device key material. */
  wrappingKey: Uint8Array;
}

/** Generates a fresh 12-word English BIP39 mnemonic (128-bit entropy). */
export function generateRecoveryMnemonic(strength: 128 | 256 = 128): string {
  return generateMnemonic(wordlist, strength);
}

export function isValidMnemonic(mnemonic: string): boolean {
  return validateMnemonic(mnemonic, wordlist);
}

/**
 * Derives the identity + recovery key material from a BIP39 mnemonic and an
 * optional passphrase.
 *
 * The passphrase is OPTIONAL. If the user enables one it is required for
 * recovery and is never stored by Enclave (server or device). It is appended
 * to the BIP39 salt by `mnemonicToSeedSync`, exactly as BIP39 specifies.
 */
export function deriveIdentity(mnemonic: string, passphrase = ''): IdentityKeyMaterial {
  const seed = Uint8Array.from(mnemonicToSeedSync(mnemonic, passphrase));
  const signingPrivateKey = hkdf(
    sha512,
    seed,
    new TextEncoder().encode(IDENTITY_SIGNING_SALT),
    new TextEncoder().encode(IDENTITY_SIGNING_INFO),
    32,
  );
  const wrappingKey = hkdf(
    sha512,
    seed,
    new TextEncoder().encode(RECOVERY_WRAP_SALT),
    new TextEncoder().encode(RECOVERY_WRAP_INFO),
    32,
  );
  return {
    seed,
    signingPrivateKey,
    identityPublicKeyValue: toBase64(ed25519.getPublicKey(signingPrivateKey)),
    wrappingKey,
  };
}

/** Byte-exact Ed25519 message signed to prove control of an identity. */
export function recoveryChallengeMessage(input: {
  userId: string;
  challengeId: string;
  devicePublicKeyValue: string;
}): Uint8Array {
  const sep = new Uint8Array([0x00]);
  const parts = [
    new TextEncoder().encode(RECOVERY_MESSAGE_PREFIX),
    sep,
    new TextEncoder().encode(input.userId),
    sep,
    new TextEncoder().encode(input.challengeId),
    sep,
    new TextEncoder().encode(input.devicePublicKeyValue),
  ];
  const total = parts.reduce((n, p) => n + p.length, 0);
  const out = new Uint8Array(total);
  let offset = 0;
  for (const part of parts) {
    out.set(part, offset);
    offset += part.length;
  }
  return out;
}

export function signRecoveryChallenge(
  identity: IdentityKeyMaterial,
  input: { userId: string; challengeId: string; devicePublicKeyValue: string },
): string {
  const message = recoveryChallengeMessage(input);
  return toBase64(ed25519.sign(message, identity.signingPrivateKey));
}

function blobAad(userId: string, deviceId: string, keyVersion: number): Uint8Array {
  return new TextEncoder().encode(`${RECOVERY_BLOB_AAD_PREFIX}${userId}/${deviceId}/${keyVersion}`);
}

/**
 * Seals a device's full key material under the recovery wrapping key.
 * `nonceOverride` is TEST-ONLY (mirrors `sealPayload`).
 */
export function sealRecoveryBlob(
  material: DeviceKeyMaterial,
  userId: string,
  deviceId: string,
  wrappingKey: Uint8Array,
  nonceOverride?: Uint8Array,
): RecoveryBlobEnvelope {
  const plaintext = new TextEncoder().encode(
    JSON.stringify({
      v: BLOB_VERSION,
      deviceId,
      keyVersion: material.keyVersion,
      sealingKey: toBase64(material.sealingKey),
      privateKey: toBase64(material.privateKey),
      publicKeyValue: material.publicKeyValue,
    }),
  );
  const nonce = nonceOverride ?? randomBytes(24);
  const ciphertext = xchacha20poly1305(
    wrappingKey,
    nonce,
    blobAad(userId, deviceId, material.keyVersion),
  ).encrypt(plaintext);
  return {
    v: BLOB_VERSION,
    alg: BLOB_ALG,
    userId,
    deviceId,
    keyVersion: material.keyVersion,
    nonce: toBase64(nonce),
    ciphertext: toBase64(ciphertext),
  };
}

/** Opens a recovery blob and reconstructs the device key material. */
export function openRecoveryBlob(
  envelope: RecoveryBlobEnvelope,
  wrappingKey: Uint8Array,
): DeviceKeyMaterial {
  const plaintext = xchacha20poly1305(
    wrappingKey,
    fromBase64(envelope.nonce),
    blobAad(envelope.userId, envelope.deviceId, envelope.keyVersion),
  ).decrypt(fromBase64(envelope.ciphertext));
  const payload = JSON.parse(new TextDecoder().decode(plaintext)) as {
    v: number;
    deviceId: string;
    keyVersion: number;
    sealingKey: string;
    privateKey: string;
    publicKeyValue: string;
  };
  return {
    privateKey: fromBase64(payload.privateKey),
    publicKeyValue: payload.publicKeyValue,
    sealingKey: fromBase64(payload.sealingKey),
    keyVersion: payload.keyVersion,
  };
}
