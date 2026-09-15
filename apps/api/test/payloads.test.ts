import { afterAll, beforeAll, beforeEach, describe, expect, it } from 'vitest';

import {
  createTestContext,
  createUser,
  createDevice,
  validEnvelope,
  jsonHeaders,
  authHeaders,
  type TestContext,
} from './helpers';

describe('encrypted payloads (v1 payloads)', () => {
  let ctx: TestContext;

  beforeAll(async () => {
    ctx = await createTestContext();
  });

  afterAll(async () => {
    await ctx.close();
  });

  beforeEach(async () => {
    await ctx.truncate();
  });

  it('stores an opaque encrypted envelope and returns it verbatim', async () => {
    const { secret } = await createUser(ctx.app);
    const deviceId = await createDevice(ctx.app, secret);
    const envelope = validEnvelope(deviceId);

    const createRes = await ctx.app.request('/v1/payloads', {
      method: 'POST',
      headers: jsonHeaders(authHeaders(secret)),
      body: JSON.stringify(envelope),
    });
    const createBody = (await createRes.json()) as {
      ok: true;
      data: { payloadId: string; byteLength: number };
    };

    expect(createRes.status).toBe(201);
    expect(createBody.data.payloadId).toBeTruthy();
    expect(createBody.data.byteLength).toBeGreaterThan(0);

    const getRes = await ctx.app.request(`/v1/payloads/${createBody.data.payloadId}`, {
      headers: authHeaders(secret),
    });
    const getBody = (await getRes.json()) as { ok: true; data: { envelope: unknown } };

    expect(getRes.status).toBe(200);
    expect(getBody.data.envelope).toEqual(envelope);
  });

  it('rejects an envelope with an unsupported version', async () => {
    const { secret } = await createUser(ctx.app);
    const deviceId = await createDevice(ctx.app, secret);
    const envelope = { ...validEnvelope(deviceId), v: 2 };

    const res = await ctx.app.request('/v1/payloads', {
      method: 'POST',
      headers: jsonHeaders(authHeaders(secret)),
      body: JSON.stringify(envelope),
    });
    const body = (await res.json()) as { ok: false; error: { code: string } };

    expect(res.status).toBe(400);
    expect(body.error.code).toBe('INVALID_REQUEST');
  });

  it('rejects an envelope with an unsupported algorithm', async () => {
    const { secret } = await createUser(ctx.app);
    const deviceId = await createDevice(ctx.app, secret);
    const envelope = { ...validEnvelope(deviceId), alg: 'aes-256-gcm' };

    const res = await ctx.app.request('/v1/payloads', {
      method: 'POST',
      headers: jsonHeaders(authHeaders(secret)),
      body: JSON.stringify(envelope),
    });
    const body = (await res.json()) as { ok: false; error: { code: string } };

    expect(res.status).toBe(400);
    expect(body.error.code).toBe('INVALID_REQUEST');
  });

  it('rejects an envelope with a malformed nonce', async () => {
    const { secret } = await createUser(ctx.app);
    const deviceId = await createDevice(ctx.app, secret);
    const envelope = { ...validEnvelope(deviceId), nonce: Buffer.alloc(4, 1).toString('base64') };

    const res = await ctx.app.request('/v1/payloads', {
      method: 'POST',
      headers: jsonHeaders(authHeaders(secret)),
      body: JSON.stringify(envelope),
    });
    const body = (await res.json()) as { ok: false; error: { code: string } };

    expect(res.status).toBe(400);
    expect(body.error.code).toBe('INVALID_REQUEST');
  });

  it('rejects payloads for a device the caller does not own', async () => {
    const userA = await createUser(ctx.app);
    const deviceB = await (async () => {
      const userB = await createUser(ctx.app);
      return createDevice(ctx.app, userB.secret);
    })();
    const envelope = validEnvelope(deviceB);

    const res = await ctx.app.request('/v1/payloads', {
      method: 'POST',
      headers: jsonHeaders(authHeaders(userA.secret)),
      body: JSON.stringify(envelope),
    });
    const body = (await res.json()) as { ok: false; error: { code: string } };

    expect(res.status).toBe(403);
    expect(body.error.code).toBe('FORBIDDEN');
  });

  it('rejects stores for a revoked device', async () => {
    const { secret } = await createUser(ctx.app);
    const deviceId = await createDevice(ctx.app, secret);

    await ctx.app.request(`/v1/devices/${deviceId}/revoke`, {
      method: 'POST',
      headers: authHeaders(secret),
    });

    const res = await ctx.app.request('/v1/payloads', {
      method: 'POST',
      headers: jsonHeaders(authHeaders(secret)),
      body: JSON.stringify(validEnvelope(deviceId)),
    });
    const body = (await res.json()) as { ok: false; error: { code: string } };

    expect(res.status).toBe(403);
    expect(body.error.code).toBe('FORBIDDEN');
  });

  it('hides other users payloads (404, no leak)', async () => {
    const userA = await createUser(ctx.app);
    const deviceA = await createDevice(ctx.app, userA.secret);
    const envelope = validEnvelope(deviceA);

    const createRes = await ctx.app.request('/v1/payloads', {
      method: 'POST',
      headers: jsonHeaders(authHeaders(userA.secret)),
      body: JSON.stringify(envelope),
    });
    const createBody = (await createRes.json()) as { ok: true; data: { payloadId: string } };

    const userB = await createUser(ctx.app);
    const getRes = await ctx.app.request(`/v1/payloads/${createBody.data.payloadId}`, {
      headers: authHeaders(userB.secret),
    });
    const getBody = (await getRes.json()) as { ok: false; error: { code: string } };

    expect(getRes.status).toBe(404);
    expect(getBody.error.code).toBe('NOT_FOUND');
  });

  it('requires authentication', async () => {
    const res = await ctx.app.request('/v1/payloads', {
      method: 'POST',
      body: '{}',
      headers: jsonHeaders(),
    });
    const body = (await res.json()) as { ok: false; error: { code: string } };

    expect(res.status).toBe(401);
    expect(body.error.code).toBe('UNAUTHORIZED');
  });
});
