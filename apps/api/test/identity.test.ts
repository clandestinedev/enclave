import { afterAll, beforeAll, beforeEach, describe, expect, it } from 'vitest';

import { createTestContext, createUser, jsonHeaders, type TestContext } from './helpers';

describe('identity (v1 users)', () => {
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

  it('creates a user with a stable application-level id', async () => {
    const { userId, secret } = await createUser(ctx.app);

    expect(userId).toMatch(/^[0-9a-f]{8}-[0-9a-f]{4}-7[0-9a-f]{3}-[0-9a-f]{4}-[0-9a-f]{12}$/);
    expect(typeof secret).toBe('string');
    expect(secret.length).toBeGreaterThanOrEqual(32);
  });

  it('returns a valid envelope shape on success', async () => {
    const res = await ctx.app.request('/v1/users', {
      method: 'POST',
      body: '{}',
      headers: jsonHeaders(),
    });
    const body = (await res.json()) as { ok: boolean; data: { userId: string } };

    expect(res.status).toBe(201);
    expect(body.ok).toBe(true);
    expect(body.data.userId).toBeTruthy();
  });

  it('rejects invalid JSON with the standard error envelope (400)', async () => {
    const res = await ctx.app.request('/v1/users', {
      method: 'POST',
      body: 'not-json',
      headers: jsonHeaders(),
    });
    const body = (await res.json()) as { ok: false; error: { code: string } };

    expect(res.status).toBe(400);
    expect(body.ok).toBe(false);
    expect(body.error.code).toBe('INVALID_REQUEST');
  });

  it('rejects an invalid body shape (400)', async () => {
    const res = await ctx.app.request('/v1/users', {
      method: 'POST',
      body: JSON.stringify({ unexpected: true }),
      headers: jsonHeaders(),
    });
    const body = (await res.json()) as { ok: false; error: { code: string } };

    expect(res.status).toBe(400);
    expect(body.ok).toBe(false);
    expect(body.error.code).toBe('INVALID_REQUEST');
  });
});
