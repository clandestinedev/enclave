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
