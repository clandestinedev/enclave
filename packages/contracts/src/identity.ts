import { z } from 'zod';

export const idSchema = z.string().uuid();

export const publicKeyTypeSchema = z.literal('x25519');

const base64 = z.string().base64();

export const publicKeySchema = z.object({
  type: publicKeyTypeSchema,
  value: base64.refine(
    (s) => Math.floor((s.replace(/=+$/, '').length * 3) / 4) === 32,
    'public key must be 32 bytes',
  ),
});

export type PublicKey = z.infer<typeof publicKeySchema>;

export const keyVersionSchema = z.number().int().nonnegative();

export const ed25519SignatureSchema = z
  .string()
  .base64()
  .refine(
    (s) => Math.floor((s.replace(/=+$/, '').length * 3) / 4) === 64,
    'signature must be 64 bytes (Ed25519)',
  );

export const createUserRequestSchema = z.object({}).strict();

export type CreateUserRequest = z.infer<typeof createUserRequestSchema>;

export const createUserResponseSchema = z.object({
  userId: idSchema,
  createdAt: z.string(),
});

export type CreateUserResponse = z.infer<typeof createUserResponseSchema>;

export const createDeviceRequestSchema = z
  .object({
    label: z.string().trim().min(1).max(80).optional(),
    publicKey: publicKeySchema,
    certSignature: ed25519SignatureSchema.optional(),
    certVersion: keyVersionSchema.optional(),
  })
  .strict()
  .refine((body) => (body.certSignature === undefined) === (body.certVersion === undefined), {
    message: 'certSignature and certVersion must be provided together',
  });

export type CreateDeviceRequest = z.infer<typeof createDeviceRequestSchema>;

export const certifyDeviceRequestSchema = z
  .object({
    certSignature: ed25519SignatureSchema,
    certVersion: keyVersionSchema,
  })
  .strict();

export type CertifyDeviceRequest = z.infer<typeof certifyDeviceRequestSchema>;

export const deviceViewSchema = z.object({
  userId: z.string().uuid(),
  deviceId: z.string().uuid(),
  label: z.string().optional(),
  publicKey: publicKeySchema,
  keyVersion: z.number().int().nonnegative(),
  certSignature: ed25519SignatureSchema.nullable(),
  certVersion: keyVersionSchema.nullable(),
  createdAt: z.string(),
  lastSeenAt: z.string().nullable(),
  revokedAt: z.string().nullable(),
});

export type DeviceView = z.infer<typeof deviceViewSchema>;

export const createDeviceResponseSchema = deviceViewSchema;

export type CreateDeviceResponse = z.infer<typeof createDeviceResponseSchema>;
