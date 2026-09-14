import { describe, expect, it } from 'vitest';

import { createApp } from '../src/app';

type HealthBody = {
  ok: true;
  data: { service: string; apiVersion: string; wireVersion: number; time: string };
};

type NotFoundBody = { ok: false; error: { code: string; message: string } };

describe('health route', () => {
  it('responds with a healthy envelope', async () => {
    const app = createApp();
    const res = await app.request('/health');

    expect(res.status).toBe(200);

    const body = (await res.json()) as HealthBody;
    expect(body.ok).toBe(true);
    expect(body.data.service).toBe('enclave-api');
    expect(typeof body.data.time).toBe('string');
  });

  it('responds with a structured not-found envelope', async () => {
    const app = createApp();
    const res = await app.request('/does-not-exist');

    expect(res.status).toBe(404);

    const body = (await res.json()) as NotFoundBody;
    expect(body.ok).toBe(false);
    expect(body.error.code).toBe('NOT_FOUND');
  });
});
