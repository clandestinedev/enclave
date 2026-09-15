import { createHash, randomBytes, timingSafeEqual } from 'node:crypto';

export const ACCOUNT_SECRET_BYTES = 32;

export function generateAccountSecret(): string {
  return randomBytes(ACCOUNT_SECRET_BYTES).toString('base64url');
}

function secretToBytes(b64: string): Buffer {
  return Buffer.from(b64, 'base64url');
}

export function digestSecret(b64: string): string {
  return createHash('sha256').update(secretToBytes(b64)).digest('base64');
}

export function verifySecret(secretB64: string, expectedDigestB64: string): boolean {
  const actual = createHash('sha256').update(secretToBytes(secretB64)).digest();
  const expected = Buffer.from(expectedDigestB64, 'base64');
  return actual.length === expected.length && timingSafeEqual(actual, expected);
}
