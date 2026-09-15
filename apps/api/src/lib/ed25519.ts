import { createPublicKey, verify as cryptoVerify } from 'node:crypto';

/**
 * Verifies an Ed25519 signature against a raw 32-byte public key.
 *
 * Uses Node's built-in crypto (no third-party dependency): the raw key is
 * imported as a JWK and verified with the `null` algorithm, which selects
 * Ed25519 for an OKP/Ed25519 key. Returns `false` on any malformed input
 * rather than throwing, so callers can map to a single error response.
 */
export function verifyEd25519(publicKey: Buffer, message: Buffer, signature: Buffer): boolean {
  if (publicKey.length !== 32 || signature.length !== 64) return false;
  try {
    const key = createPublicKey({
      key: { kty: 'OKP', crv: 'Ed25519', x: publicKey.toString('base64url') },
      format: 'jwk',
    });
    return cryptoVerify(null, message, key, signature);
  } catch {
    return false;
  }
}
