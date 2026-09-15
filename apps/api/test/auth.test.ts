import { afterAll, beforeAll, beforeEach, describe, expect, it } from 'vitest';

import {
  createTestContext,
  createUser,
  createDevice,
  jsonHeaders,
  authHeaders,
  type TestContext,
} from './helpers';

describe('authorization boundaries', () => {
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

  it('user A cannot read user B device', async () => {
    const userA = await createUser(ctx.app);
    const userB = await createUser(ctx.app);
    const deviceB = await createDevice(ctx.app, userB.secret, 'phone');

    const res = await ctx.app.request(`/v1/devices/${deviceB}`, {
      headers: authHeaders(userA.secret),
    });
    const body = (await res.json()) as { ok: false; error: { code: string } };

    expect(res.status).toBe(404);
    expect(body.error.code).toBe('NOT_FOUND');
  });

  it('user A cannot revoke user B device', async () => {
    const userA = await createUser(ctx.app);
    const userB = await createUser(ctx.app);
    const deviceB = await createDevice(ctx.app, userB.secret, 'phone');

    const res = await ctx.app.request(`/v1/devices/${deviceB}/revoke`, {
      method: 'POST',
      headers: authHeaders(userA.secret),
    });

    expect(res.status).toBe(404);
  });

  it('a wrong secret is rejected', async () => {
    const { secret } = await createUser(ctx.app);

    const res = await ctx.app.request('/v1/devices', {
      method: 'POST',
      headers: jsonHeaders(authHeaders(secret + 'tampered')),
      body: JSON.stringify({
        publicKey: { type: 'x25519', value: Buffer.alloc(32).toString('base64') },
      }),
    });
    const body = (await res.json()) as { ok: false; error: { code: string } };

    expect(res.status).toBe(401);
    expect(body.error.code).toBe('UNAUTHORIZED');
  });

  it('device list of a user is isolated from other users', async () => {
    const userA = await createUser(ctx.app);
    const userB = await createUser(ctx.app);
    await createDevice(ctx.app, userA.secret, 'a-phone');
    await createDevice(ctx.app, userB.secret, 'b-phone');

    const res = await ctx.app.request('/v1/devices', { headers: authHeaders(userA.secret) });
    const body = (await res.json()) as { ok: true; data: { label?: string; deviceId: string }[] };

    expect(body.data.length).toBe(1);
    expect(body.data[0]?.label).toBe('a-phone');
  });
});
