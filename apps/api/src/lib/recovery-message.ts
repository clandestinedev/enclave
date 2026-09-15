/**
 * Server-side reconstruction of the Ed25519 message a client signs to prove
 * control of an identity. MUST byte-match the client (reference-recovery.ts /
 * dart_core/lib/src/recovery.dart).
 *
 * Layout: "enclave/recovery-v1" 0x00 userId 0x00 challengeId 0x00 devicePublicKeyValue
 */
export const RECOVERY_MESSAGE_PREFIX = 'enclave/recovery-v1';

export function recoveryChallengeMessage(input: {
  userId: string;
  challengeId: string;
  devicePublicKeyValue: string;
}): Buffer {
  return Buffer.concat([
    Buffer.from(RECOVERY_MESSAGE_PREFIX, 'utf8'),
    Buffer.from([0x00]),
    Buffer.from(input.userId, 'utf8'),
    Buffer.from([0x00]),
    Buffer.from(input.challengeId, 'utf8'),
    Buffer.from([0x00]),
    Buffer.from(input.devicePublicKeyValue, 'utf8'),
  ]);
}
