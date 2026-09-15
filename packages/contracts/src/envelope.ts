import type { API_ERROR_CODES } from './errors';

export interface ApiError {
  code: (typeof API_ERROR_CODES)[number];
  message: string;
}

export interface ApiEnvelope<T> {
  ok: boolean;
  data?: T;
  error?: ApiError;
}
