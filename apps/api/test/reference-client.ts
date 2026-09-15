import { x25519 } from '@noble/curves/ed25519.js';
import { randomBytes } from '@noble/ciphers/utils.js';
import { xchacha20poly1305 } from '@noble/ciphers/chacha.js';

import { encryptedPayloadEnvelopeSchema, type EncryptedPayloadEnvelope } from '@enclave/contracts';

/**
 * Reference implementation of the Encore client-side device crypto.
 *
 * This is a TEST-ONLY executable specification of what the Dart mobile core
 * (`packages/dart_core`) must mirror. It is never imported by server source.
 * Trust boundary: the server only ever sees device public keys and opaque
 * envelopes. The X25519 private key and the 256-bit device sealing key never
 * leave the client (they live in secure storage on the device).
 */

export const PAYLOAD_ALG = 'xchacha20poly1305' as const;
export const PAYLOAD_VERSION = 1 as const;
export const AAD_PREFIX = 'enclave/payload-v1/';
export const DEVICE_KEY_VERSION = 0 as const;

export function toBase64(bytes: Uint8Array): string {
  return Buffer.from(bytes).toString('base64');
}

export function fromBase64(value: string): Uint8Array {
  return new Uint8Array(Buffer.from(value, 'base64'));
}

export interface DeviceKeyMaterial {
  /** X25519 private scalar. Never transmitted. */
  privateKey: Uint8Array;
  /** Base64 of the 32-byte X25519 public key. This is what gets registered. */
  publicKeyValue: string;
  /**
   * 256-bit symmetric device sealing key. Random, CSPRNG-generated, NEVER
   * transmitted, never stored server-side. Lives only in device secure storage.
   */
  sealingKey: Uint8Array;
  /** keyVersion used to build `keyRef` in the envelope. Starts at 0. */
  keyVersion: number;
}

export function derivePublicKeyValue(privateKey: Uint8Array): string {
  return toBase64(x25519.getPublicKey(privateKey));
}

export function createDeviceKeyMaterial(seed?: Uint8Array): DeviceKeyMaterial {
  const privateKey = seed ?? randomBytes(32);
  return {
    privateKey,
    publicKeyValue: derivePublicKeyValue(privateKey),
    sealingKey: randomBytes(32),
    keyVersion: DEVICE_KEY_VERSION,
  };
}

function aadFor(keyRef: string): Uint8Array {
  return new TextEncoder().encode(`${AAD_PREFIX}${keyRef}`);
}

/**
 * Seal a payload. `nonceOverride` is TEST-ONLY: production callers omit it and
 * get a fresh 24-byte CSPRNG nonce per call. It exists solely so the
 * cross-language interop test can reproduce deterministic output.
 */
export function sealPayload(
  material: DeviceKeyMaterial,
  deviceId: string,
  plaintext: Uint8Array,
  nonceOverride?: Uint8Array,
): EncryptedPayloadEnvelope {
  const keyRef = `${deviceId}:${material.keyVersion}`;
  const nonce = nonceOverride ?? randomBytes(24);
  const ciphertext = xchacha20poly1305(material.sealingKey, nonce, aadFor(keyRef)).encrypt(
    plaintext,
  );
  const envelope = {
    v: PAYLOAD_VERSION,
    alg: PAYLOAD_ALG,
    keyRef,
    nonce: toBase64(nonce),
    ciphertext: toBase64(ciphertext),
  };
  return encryptedPayloadEnvelopeSchema.parse(envelope);
}

export function openPayload(
  material: DeviceKeyMaterial,
  envelope: EncryptedPayloadEnvelope,
): Uint8Array {
  const parsed = encryptedPayloadEnvelopeSchema.parse(envelope);
  if (parsed.v !== PAYLOAD_VERSION || parsed.alg !== PAYLOAD_ALG) {
    throw new Error('unsupported envelope version/algorithm');
  }
  return xchacha20poly1305(
    material.sealingKey,
    fromBase64(parsed.nonce),
    aadFor(parsed.keyRef),
  ).decrypt(fromBase64(parsed.ciphertext));
}

/** Convenience: base64 hashing of public key value, to keep tests readable. */
export function exportPublicKeyValue(material: DeviceKeyMaterial): {
  type: 'x25519';
  value: string;
} {
  return { type: 'x25519', value: material.publicKeyValue };
}
