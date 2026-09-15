import { eq } from 'drizzle-orm';
import { afterAll, beforeAll, beforeEach, describe, expect, it } from 'vitest';

import type { EncryptedPayloadEnvelope } from '@enclave/contracts';

import type { createDbClient } from '../src/db/client';
import { devices, encryptedPayloads } from '../src/db/schema';
import {
  createTestContext,
  createUser,
  jsonHeaders,
  authHeaders,
  type TestContext,
} from './helpers';
import {
  createDeviceKeyMaterial,
  exportPublicKeyValue,
  openPayload,
  sealPayload,
  fromBase64,
} from './reference-client';

describe('e2ee roundtrip (reference client -> api -> db -> open)', () => {
  let ctx: TestContext;
  let db: ReturnType<typeof createDbClient>['db'];

  beforeAll(async () => {
    ctx = await createTestContext();
    db = ctx.db;
  });

  afterAll(async () => {
    await ctx.close();
  });

  beforeEach(async () => {
    await ctx.truncate();
  });

  async function registerDevice(
    secret: string,
  ): Promise<{ material: ReturnType<typeof createDeviceKeyMaterial>; deviceId: string }> {
    const material = createDeviceKeyMaterial();
    const res = await ctx.app.request('/v1/devices', {
      method: 'POST',
      headers: jsonHeaders(authHeaders(secret)),
      body: JSON.stringify({ publicKey: exportPublicKeyValue(material) }),
    });
    const body = (await res.json()) as { ok: true; data: { deviceId: string } };
    expect(res.status).toBe(201);
    return { material, deviceId: body.data.deviceId };
  }

  async function store(secret: string, envelope: EncryptedPayloadEnvelope): Promise<string> {
    const res = await ctx.app.request('/v1/payloads', {
      method: 'POST',
      headers: jsonHeaders(authHeaders(secret)),
      body: JSON.stringify(envelope),
    });
    const body = (await res.json()) as { ok: true; data: { payloadId: string } };
    expect(res.status).toBe(201);
    return body.data.payloadId;
  }

  it('seals, stores, fetches and opens a payload end-to-end', async () => {
    const { secret } = await createUser(ctx.app);
    const { material, deviceId } = await registerDevice(secret);

    const plaintext = new TextEncoder().encode('{"kind":"test","message":"secret hello"}');
    const envelope = sealPayload(material, deviceId, plaintext);
    const payloadId = await store(secret, envelope);

    const getRes = await ctx.app.request(`/v1/payloads/${payloadId}`, {
      headers: authHeaders(secret),
    });
    const getBody = (await getRes.json()) as {
      ok: true;
      data: { envelope: EncryptedPayloadEnvelope };
    };
    expect(getRes.status).toBe(200);

    const opened = openPayload(material, getBody.data.envelope);
    expect(new TextDecoder().decode(opened)).toBe('{"kind":"test","message":"secret hello"}');
  });

  it('the server holds no key material that can decrypt the stored payload', async () => {
    const { secret } = await createUser(ctx.app);
    const { material, deviceId } = await registerDevice(secret);

    const envelope = sealPayload(
      material,
      deviceId,
      new TextEncoder().encode('server must not read this'),
    );
    await store(secret, envelope);

    const storedDevice = (
      await db.select().from(devices).where(eq(devices.id, deviceId)).limit(1)
    )[0];
    const storedPayload = (await db.select().from(encryptedPayloads).limit(1))[0];
    expect(storedDevice).toBeDefined();
    expect(storedPayload).toBeDefined();
    if (storedDevice === undefined || storedPayload === undefined) throw new Error('expected rows');

    // The server only ever sees the public key, the envelope, and metadata —
    // there is no private-key / sealing-key column on the device row.
    expect(storedDevice.publicKeyType).toBe('x25519');
    expect(storedDevice.publicKeyValue).toHaveLength(44);
    expect(storedDevice).not.toHaveProperty('privateKey');
    expect(storedDevice).not.toHaveProperty('sealingKey');

    // Sword-and-shield sanity: using every server-held byte as the AEAD key fails.
    const envelopeFromDb = JSON.parse(storedPayload.envelope) as EncryptedPayloadEnvelope;
    const attackerKeys: { verdict: string; bytes: Uint8Array }[] = [
      { verdict: 'device public key', bytes: fromBase64(storedDevice.publicKeyValue) },
      { verdict: 'device id', bytes: new TextEncoder().encode(deviceId) },
      { verdict: 'empty key', bytes: new Uint8Array(32) },
    ];
    for (const attack of attackerKeys) {
      expect(
        () =>
          openPayload({ ...createDeviceKeyMaterial(), sealingKey: attack.bytes }, envelopeFromDb),
        attack.verdict,
      ).toThrow();
    }
  });

  it('rejects a payload whose ciphertext was tampered with', async () => {
    const { secret } = await createUser(ctx.app);
    const { material, deviceId } = await registerDevice(secret);
    const envelope = sealPayload(material, deviceId, new TextEncoder().encode('original'));

    const tampered = fromBase64(envelope.ciphertext);
    tampered[0] = (tampered[0] ?? 0) ^ 0xff;
    expect(() =>
      openPayload(material, { ...envelope, ciphertext: Buffer.from(tampered).toString('base64') }),
    ).toThrow();
  });

  it('a different device cannot open a payload sealed for another device', async () => {
    const { secret } = await createUser(ctx.app);
    const { material: aliceMaterial, deviceId } = await registerDevice(secret);
    const bobMaterial = createDeviceKeyMaterial();

    const envelope = sealPayload(aliceMaterial, deviceId, new TextEncoder().encode('mine'));
    expect(() => openPayload(bobMaterial, envelope)).toThrow();
  });
});
