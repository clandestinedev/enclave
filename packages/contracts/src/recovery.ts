import { z } from 'zod';

import { publicKeySchema } from './identity';

export const identityKeyVersionSchema = z.number().int().nonnegative().default(0);

export const identityPublicKeySchema = z
  .string()
  .base64()
  .refine(
    (s) => Math.floor((s.replace(/=+$/, '').length * 3) / 4) === 32,
    'identity public key must be 32 bytes (Ed25519)',
  );

export const createIdentityRequestSchema = z
  .object({
    identityPublicKey: identityPublicKeySchema,
  })
  .strict();

export type CreateIdentityRequest = z.infer<typeof createIdentityRequestSchema>;

export const identityViewSchema = z.object({
  identityId: z.string().uuid(),
  userId: z.string().uuid(),
  identityPublicKey: identityPublicKeySchema,
  keyVersion: identityKeyVersionSchema,
  createdAt: z.string(),
});

export type IdentityView = z.infer<typeof identityViewSchema>;

export const createIdentityResponseSchema = identityViewSchema;

export type CreateIdentityResponse = z.infer<typeof createIdentityResponseSchema>;

export const createRecoveryChallengeRequestSchema = z
  .object({
    identityPublicKey: identityPublicKeySchema,
  })
  .strict();

export type CreateRecoveryChallengeRequest = z.infer<typeof createRecoveryChallengeRequestSchema>;

export const createRecoveryChallengeResponseSchema = z.object({
  challengeId: z.string().uuid(),
  userId: z.string().uuid(),
  expiresAt: z.string(),
  ttlSeconds: z.number().int().positive(),
});

export type CreateRecoveryChallengeResponse = z.infer<typeof createRecoveryChallengeResponseSchema>;

export const recoverySignatureSchema = z
  .string()
  .base64()
  .refine(
    (s) => Math.floor((s.replace(/=+$/, '').length * 3) / 4) === 64,
    'signature must be 64 bytes (Ed25519)',
  );

export const completeRecoveryRequestSchema = z
  .object({
    challengeId: z.string().uuid(),
    signature: recoverySignatureSchema,
    deviceKey: publicKeySchema,
  })
  .strict();

export type CompleteRecoveryRequest = z.infer<typeof completeRecoveryRequestSchema>;

export const completeRecoveryResponseSchema = z.object({
  userId: z.string().uuid(),
  deviceId: z.string().uuid(),
  deviceSecret: z.string().min(1),
  keyVersion: z.number().int().nonnegative(),
  deviceKey: publicKeySchema,
});

export type CompleteRecoveryResponse = z.infer<typeof completeRecoveryResponseSchema>;

export const recoveryBlobEnvelopeSchema = z
  .object({
    v: z.literal(1),
    alg: z.literal('xchacha20poly1305'),
    userId: z.string().uuid(),
    deviceId: z.string().uuid(),
    keyVersion: z.number().int().nonnegative(),
    nonce: z
      .string()
      .base64()
      .refine(
        (s) => Math.floor((s.replace(/=+$/, '').length * 3) / 4) === 24,
        'nonce must be 24 bytes',
      ),
    ciphertext: z
      .string()
      .base64()
      .refine(
        (s) => Math.floor((s.replace(/=+$/, '').length * 3) / 4) >= 16,
        'ciphertext must include a 16-byte tag',
      ),
  })
  .strict();

export type RecoveryBlobEnvelope = z.infer<typeof recoveryBlobEnvelopeSchema>;

export const createRecoveryBlobRequestSchema = z
  .object({
    envelope: recoveryBlobEnvelopeSchema,
  })
  .strict();

export type CreateRecoveryBlobRequest = z.infer<typeof createRecoveryBlobRequestSchema>;

export const recoveryBlobViewSchema = z.object({
  blobId: z.string().uuid(),
  deviceId: z.string().uuid(),
  createdAt: z.string(),
  envelope: recoveryBlobEnvelopeSchema,
});

export type RecoveryBlobView = z.infer<typeof recoveryBlobViewSchema>;

export const listRecoveryBlobsResponseSchema = z.array(recoveryBlobViewSchema);

export type ListRecoveryBlobsResponse = z.infer<typeof listRecoveryBlobsResponseSchema>;
