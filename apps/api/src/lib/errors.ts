import type { API_ERROR_CODES } from '@enclave/contracts';

export type ApiErrorCode = (typeof API_ERROR_CODES)[number];

export class AppError extends Error {
  constructor(
    readonly status: number,
    readonly code: ApiErrorCode,
    message: string,
  ) {
    super(message);
    this.name = 'AppError';
  }
}

export function invalidRequest(message = 'Invalid request'): AppError {
  return new AppError(400, 'INVALID_REQUEST', message);
}

export function unauthorized(message = 'Authentication required'): AppError {
  return new AppError(401, 'UNAUTHORIZED', message);
}

export function forbidden(message = 'Forbidden'): AppError {
  return new AppError(403, 'FORBIDDEN', message);
}

export function notFound(): AppError {
  return new AppError(404, 'NOT_FOUND', 'Not found');
}

export function conflict(message: string): AppError {
  return new AppError(409, 'CONFLICT', message);
}

export function identityInUse(message = 'Identity public key already registered'): AppError {
  return new AppError(409, 'IDENTITY_IN_USE', message);
}

export function signatureInvalid(message = 'Recovery signature is invalid'): AppError {
  return new AppError(401, 'SIGNATURE_INVALID', message);
}

export function challengeNotFound(): AppError {
  return new AppError(404, 'CHALLENGE_NOT_FOUND', 'Recovery challenge not found');
}

export function challengeUsed(): AppError {
  return new AppError(409, 'CHALLENGE_USED', 'Recovery challenge already used');
}

export function challengeExpired(): AppError {
  return new AppError(410, 'CHALLENGE_EXPIRED', 'Recovery challenge expired');
}

export function pairingStateInvalid(
  message = 'Relationship state does not allow this transition',
): AppError {
  return new AppError(409, 'PAIRING_STATE_INVALID', message);
}

export function pairingAlreadyActive(
  message = 'An active relationship already exists for this account',
): AppError {
  return new AppError(409, 'PAIRING_ALREADY_ACTIVE', message);
}

export function pairingExpired(): AppError {
  return new AppError(410, 'PAIRING_EXPIRED', 'Pairing offer has expired');
}

export function pairingRejected(): AppError {
  return new AppError(409, 'PAIRING_REJECTED', 'Pairing was rejected');
}

export function deviceCertMissing(
  message = 'Device is not certified for relationship participation',
): AppError {
  return new AppError(403, 'DEVICE_CERT_MISSING', message);
}

export function deviceCertInvalid(message = 'Device certificate is invalid'): AppError {
  return new AppError(401, 'DEVICE_CERT_INVALID', message);
}

export function relationshipTerminated(message = 'Relationship has been terminated'): AppError {
  return new AppError(409, 'RELATIONSHIP_TERMINATED', message);
}

export function transcriptMismatch(): AppError {
  return new AppError(
    400,
    'TRANSCRIPT_MISMATCH',
    'Transcript does not match the canonical pairing record',
  );
}

export function tokenConflict(): AppError {
  return new AppError(409, 'TOKEN_CONFLICT', 'sasProof values do not match');
}

export function idempotencyReplay(message = 'Operation already applied'): AppError {
  return new AppError(409, 'IDEMPOTENCY_REPLAY', message);
}
