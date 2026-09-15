import { afterAll, beforeAll, beforeEach, describe, expect, it } from 'vitest';

import {
  createTestContext,
  createUser,
  createDevice,
  makeX25519PublicKey,
  jsonHeaders,
  authHeaders,
  type TestContext,
} from './helpers';

describe('devices (v1 devices)', () => {
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

  it('requires authentication', async () => {
    const res = await ctx.app.request('/v1/devices', {
      method: 'POST',
      body: '{}',
      headers: jsonHeaders(),
    });
    const body = (await res.json()) as { ok: false; error: { code: string } };

    expect(res.status).toBe(401);
    expect(body.ok).toBe(false);
    expect(body.error.code).toBe('UNAUTHORIZED');
  });

  it('registers a device public key', async () => {
    const { secret } = await createUser(ctx.app);
    const res = await ctx.app.request('/v1/devices', {
      method: 'POST',
      headers: jsonHeaders(authHeaders(secret)),
      body: JSON.stringify({ publicKey: { type: 'x25519', value: makeX25519PublicKey(3) } }),
    });
    const body = (await res.json()) as {
      ok: true;
      data: {
        userId: string;
        deviceId: string;
        keyVersion: number;
        publicKey: { type: string; value: string };
      };
    };

    expect(res.status).toBe(201);
    expect(body.ok).toBe(true);
    expect(body.data.keyVersion).toBe(0);
    expect(body.data.publicKey.type).toBe('x25519');
    expect(body.data.publicKey.value).toBe(makeX25519PublicKey(3));
  });

  it('a user can register multiple devices', async () => {
    const { secret } = await createUser(ctx.app);
    const d1 = await createDevice(ctx.app, secret, 'phone');
    const d2 = await createDevice(ctx.app, secret, 'tablet');

    const listRes = await ctx.app.request('/v1/devices', { headers: authHeaders(secret) });
    const listBody = (await listRes.json()) as { ok: true; data: { deviceId: string }[] };

    expect(listBody.data.map((d) => d.deviceId)).toEqual(expect.arrayContaining([d1, d2]));
  });

  it('rejects an invalid public key (400)', async () => {
    const { secret } = await createUser(ctx.app);
    const res = await ctx.app.request('/v1/devices', {
      method: 'POST',
      headers: jsonHeaders(authHeaders(secret)),
      body: JSON.stringify({
        publicKey: { type: 'x25519', value: Buffer.alloc(16).toString('base64') },
      }),
    });
    const body = (await res.json()) as { ok: false; error: { code: string } };

    expect(res.status).toBe(400);
    expect(body.error.code).toBe('INVALID_REQUEST');
  });

  it('revokes a device (device no longer listed)', async () => {
    const { secret } = await createUser(ctx.app);
    const deviceId = await createDevice(ctx.app, secret);

    const revoked = await ctx.app.request(`/v1/devices/${deviceId}/revoke`, {
      method: 'POST',
      headers: authHeaders(secret),
    });
    expect(revoked.status).toBe(200);

    const listRes = await ctx.app.request('/v1/devices', { headers: authHeaders(secret) });
    const listBody = (await listRes.json()) as { ok: true; data: { deviceId: string }[] };
    expect(listBody.data.map((d) => d.deviceId)).not.toContain(deviceId);

    const getRes = await ctx.app.request(`/v1/devices/${deviceId}`, {
      headers: authHeaders(secret),
    });
    const getBody = (await getRes.json()) as { ok: true; data: { revokedAt: string | null } };
    expect(getBody.data.revokedAt).toBeTruthy();
  });
});
