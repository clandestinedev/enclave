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
