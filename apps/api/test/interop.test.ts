import { readFileSync } from 'node:fs';
import { fileURLToPath } from 'node:url';
import { dirname, resolve } from 'node:path';
import { describe, expect, it } from 'vitest';

import {
  fromBase64,
  toBase64,
  sealPayload,
  openPayload,
  derivePublicKeyValue,
  type DeviceKeyMaterial,
} from './reference-client';
import { encryptedPayloadEnvelopeSchema } from '@enclave/contracts';

const VECTOR_PATH = resolve(
  dirname(fileURLToPath(import.meta.url)),
  '../../../packages/contracts/test-vectors/interop-v1.json',
);

const vector = JSON.parse(readFileSync(VECTOR_PATH, 'utf8'));
const parsedEnvelope = encryptedPayloadEnvelopeSchema.parse(vector.envelope);

const material: DeviceKeyMaterial = {
  privateKey: fromBase64(vector.privateKey),
  publicKeyValue: vector.publicKey,
  sealingKey: fromBase64(vector.sealingKey),
  keyVersion: vector.keyVersion,
};

/**
 * Interop assertion strategy (no independent random values):
 * The committed vector's ciphertext was produced by the TS reference client
 * (noble). The Dart suite asserts its seal() output is BYTE-IDENTICAL to that
 * ciphertext with the same fixed nonce, and its open() recovers the plaintext.
 * Here TS re-encrypts with the same fixed nonce and must produce byte-identical
 * output, and TS open() must recover the plaintext. Together:
 *   - TS seal == vector == Dart seal  (both directions byte-equal)
 *   - TS open(vector) == Dart open(vector) == plaintext  (both can decrypt)
 */
describe('cross-language interop (vector: packages/contracts/test-vectors/interop-v1.json)', () => {
  it('TS private key derives the vector X25519 public key', () => {
    expect(derivePublicKeyValue(material.privateKey)).toBe(vector.publicKey);
  });

  it('TS seal with fixed nonce is byte-identical to the vector ciphertext', () => {
    const envelope = sealPayload(
      material,
      vector.deviceId,
      fromBase64(vector.plaintext),
      fromBase64(vector.nonce),
    );
    expect(envelope).toEqual(parsedEnvelope);
  });

  it('TS opens the vector ciphertext (== Dart seal output) to the plaintext', () => {
    const opened = openPayload(material, parsedEnvelope);
    expect(toBase64(opened)).toBe(vector.plaintext);
  });
});
