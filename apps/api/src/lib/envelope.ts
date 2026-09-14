import type { ApiEnvelope } from '@enclave/contracts';

export function ok<T>(data: T): ApiEnvelope<T> {
  return { ok: true, data };
}

export function fail(code: string, message: string): ApiEnvelope<never> {
  return { ok: false, error: { code, message } };
}
