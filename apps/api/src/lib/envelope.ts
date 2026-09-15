import type { ApiEnvelope } from '@enclave/contracts';

import type { ApiErrorCode } from './errors';

export function ok<T>(data: T): ApiEnvelope<T> {
  return { ok: true, data };
}

export function fail(code: ApiErrorCode, message: string): ApiEnvelope<never> {
  return { ok: false, error: { code, message } };
}
