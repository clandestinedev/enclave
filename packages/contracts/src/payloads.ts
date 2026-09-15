import { z } from 'zod';

export const PAYLOAD_ALG = 'xchacha20poly1305';

export const PAYLOAD_VERSION = 1;

function decodedByteLength(b64: string): number {
  const clean = b64.replace(/=+$/, '');
  return Math.floor((clean.length * 3) / 4);
}

const base64 = z.string().base64();

export const encryptedPayloadEnvelopeSchema = z
  .object({
    v: z.literal(PAYLOAD_VERSION),
    alg: z.literal(PAYLOAD_ALG),
    keyRef: z.string().min(1).max(255),
    nonce: base64.refine((s) => decodedByteLength(s) === 24, 'nonce must be 24 bytes'),
    ciphertext: base64.refine(
      (s) => decodedByteLength(s) >= 16,
      'ciphertext must include a 16-byte tag',
    ),
  })
  .strict();

export type EncryptedPayloadEnvelope = z.infer<typeof encryptedPayloadEnvelopeSchema>;

export const encryptedPayloadCreateSchema = encryptedPayloadEnvelopeSchema;

export type EncryptedPayloadCreate = z.infer<typeof encryptedPayloadCreateSchema>;

export const encryptedPayloadViewSchema = z.object({
  payloadId: z.string().uuid(),
  userId: z.string().uuid(),
  deviceId: z.string().uuid(),
  byteLength: z.number().int().nonnegative(),
  createdAt: z.string(),
  envelope: encryptedPayloadEnvelopeSchema,
});

export type EncryptedPayloadView = z.infer<typeof encryptedPayloadViewSchema>;

export const encryptedPayloadStoredSchema = encryptedPayloadCreateSchema.extend({
  payloadId: z.string().uuid(),
  userId: z.string().uuid(),
  deviceId: z.string().uuid(),
  byteLength: z.number().int().nonnegative(),
  createdAt: z.string(),
});

export type EncryptedPayloadStored = z.infer<typeof encryptedPayloadStoredSchema>;
