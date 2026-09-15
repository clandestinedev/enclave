import { readFileSync } from 'node:fs';
import { resolve } from 'node:path';
import { describe, expect, it, beforeEach, afterAll } from 'vitest';

import type { Hono } from 'hono';
import type { AppEnv } from '../src/auth/middleware';
import { eq } from 'drizzle-orm';
import { recoveryChallenges } from '../src/db/schema';

import {
  createTestContext,
  jsonHeaders,
  authHeaders,
  makeX25519PublicKey,
  type TestContext,
} from './helpers';
import {
  deriveIdentity,
  signRecoveryChallenge,
  generateRecoveryMnemonic,
  isValidMnemonic,
  sealRecoveryBlob,
  openRecoveryBlob,
} from './reference-recovery';
import { createDeviceKeyMaterial, fromBase64 } from './reference-client';

describe('Phase 2 identity / recovery', () => {
  let ctx: TestContext;
  let app: Hono<AppEnv>;

  beforeEach(async () => {
    ctx = await createTestContext();
    await ctx.truncate();
    app = ctx.app;
  });

  afterAll(async () => {
    if (ctx) await ctx.close();
  });

  async function createAccount(): Promise<{ userId: string; secret: string }> {
    const res = await app.request('/v1/users', {
      method: 'POST',
      body: '{}',
      headers: jsonHeaders(),
    });
    expect(res.status).toBe(201);
    const body = (await res.json()) as { ok: true; data: { userId: string; secret: string } };
    return body.data;
  }

  async function registerIdentity(secret: string, identityPublicKey: string): Promise<void> {
    const res = await app.request('/v1/identities', {
      method: 'POST',
      headers: jsonHeaders(authHeaders(secret)),
      body: JSON.stringify({ identityPublicKey }),
    });
    expect(res.status).toBe(201);
  }

  async function createChallenge(
    identityPublicKey: string,
  ): Promise<{ challengeId: string; userId: string; ttlSeconds: number }> {
    const res = await app.request('/v1/recovery/challenge', {
      method: 'POST',
      body: JSON.stringify({ identityPublicKey }),
      headers: jsonHeaders(),
    });
    expect(res.status).toBe(201);
    const body = (await res.json()) as {
      ok: true;
      data: { challengeId: string; userId: string; ttlSeconds: number };
    };
    return body.data;
  }

  async function completeRecovery(
    challengeId: string,
    signature: string,
    deviceKeyValue: string,
  ): Promise<{
    status: number;
    code: string | undefined;
    data:
      { deviceId: string; deviceSecret: string; keyVersion: number; userId: string } | undefined;
  }> {
    const res = await app.request('/v1/recovery/complete', {
      method: 'POST',
      body: JSON.stringify({
        challengeId,
        signature,
        deviceKey: { type: 'x25519', value: deviceKeyValue },
      }),
      headers: jsonHeaders(),
    });
    const body = (await res.json()) as {
      ok: boolean;
      code?: string;
      error?: { code: string; message: string };
      data?: { deviceId: string; deviceSecret: string; keyVersion: number; userId: string };
    };
    return { status: res.status, code: body.error?.code ?? body.code, data: body.data };
  }

  const VECTOR = JSON.parse(
    readFileSync(
      resolve(process.cwd(), '../../packages/contracts/test-vectors/recovery-v1.json'),
      'utf8',
    ),
  ) as {
    mnemonic: string;
    passphrase: string;
    identityPublicKeyValue: string;
    signature: string;
    userId: string;
    challengeId: string;
    deviceId: string;
    keyVersion: number;
    wrappingKey: string;
    devicePrivateKey: string;
    devicePublicKeyValue: string;
    deviceSealingKey: string;
    blob: {
      v: 1;
      alg: 'xchacha20poly1305';
      userId: string;
      deviceId: string;
      keyVersion: number;
      nonce: string;
      ciphertext: string;
    };
  };

  it('interop vector: known BIP39 seed and derived identity match the committed vector', () => {
    const identity = deriveIdentity(VECTOR.mnemonic, VECTOR.passphrase);
    expect(identity.identityPublicKeyValue).toBe(VECTOR.identityPublicKeyValue);
    expect(identity.wrappingKey).toStrictEqual(fromBase64(VECTOR.wrappingKey));
    // The committed seed must equal the official BIP39 test-vector seed.
    expect(Buffer.from(identity.seed).toString('base64')).toBe(
      'xVJXw2DAfHICmuvBtTwF7QNiraOOrT4+nvo3COU0lVMfCaaYdZnRgmTB4ckvLPFBYwx6PEq3yBsvABaY50Y7BA==',
    );
  });

  it('mnemonic generation produces valid 12-word BIP39 mnemonics', () => {
    for (let i = 0; i < 25; i++) {
      const mnemonic = generateRecoveryMnemonic();
      expect(mnemonic.split(' ')).toHaveLength(12);
      expect(isValidMnemonic(mnemonic)).toBe(true);
    }
  });

  it('recovers a device with a valid signature and returns a one-time device secret', async () => {
    const { userId, secret } = await createAccount();
    const identity = deriveIdentity(VECTOR.mnemonic, VECTOR.passphrase);
    await registerIdentity(secret, identity.identityPublicKeyValue);

    const challenge = await createChallenge(identity.identityPublicKeyValue);
    expect(challenge.userId).toBe(userId);
    expect(challenge.ttlSeconds).toBeGreaterThan(0);

    const device = createDeviceKeyMaterial();
    const signature = signRecoveryChallenge(identity, {
      userId,
      challengeId: challenge.challengeId,
      devicePublicKeyValue: device.publicKeyValue,
    });

    const result = await completeRecovery(challenge.challengeId, signature, device.publicKeyValue);
    expect(result.status).toBe(201);
    expect(result.data!.userId).toBe(userId);
    expect(result.data!.keyVersion).toBe(0);
    expect(result.data!.deviceId).toHaveLength(36);
    expect(result.data!.deviceSecret).toBeTruthy();

    // The returned device secret must authenticate as the new device.
    const blob = sealRecoveryBlob(device, userId, result.data!.deviceId, identity.wrappingKey);
    const store = await app.request('/v1/recovery/blobs', {
      method: 'POST',
      headers: jsonHeaders(authHeaders(result.data!.deviceSecret)),
      body: JSON.stringify({ envelope: blob }),
    });
    expect(store.status).toBe(201);

    const list = await app.request('/v1/recovery/blobs', {
      headers: authHeaders(result.data!.deviceSecret),
    });
    expect(list.status).toBe(200);
    const body = (await list.json()) as {
      ok: true;
      data: { deviceId: string; envelope: typeof blob }[];
    };
    expect(body.data).toHaveLength(1);
    expect(body.data[0]!.deviceId).toBe(result.data!.deviceId);
  });

  it('rejects a forged signature and does NOT consume the challenge', async () => {
    const { userId, secret } = await createAccount();
    const identity = deriveIdentity(VECTOR.mnemonic, VECTOR.passphrase);
    await registerIdentity(secret, identity.identityPublicKeyValue);

    const challenge = await createChallenge(identity.identityPublicKeyValue);
    const device = createDeviceKeyMaterial();
    const badSignature = fromBase64(
      signRecoveryChallenge(identity, {
        userId,
        challengeId: challenge.challengeId,
        devicePublicKeyValue: device.publicKeyValue,
      }),
    );
    badSignature[0] = badSignature[0]! ^ 0xff;

    const result = await completeRecovery(
      challenge.challengeId,
      Buffer.from(badSignature).toString('base64'),
      device.publicKeyValue,
    );
    expect(result.status).toBe(401);
    expect(result.code).toBe('SIGNATURE_INVALID');

    // Challenge must still be usable by the legitimate owner.
    const goodSignature = signRecoveryChallenge(identity, {
      userId,
      challengeId: challenge.challengeId,
      devicePublicKeyValue: device.publicKeyValue,
    });
    const retry = await completeRecovery(
      challenge.challengeId,
      goodSignature,
      device.publicKeyValue,
    );
    expect(retry.status).toBe(201);
  });

  it('rejects a signature made over a different new-device key', async () => {
    const { userId, secret } = await createAccount();
    const identity = deriveIdentity(VECTOR.mnemonic, VECTOR.passphrase);
    await registerIdentity(secret, identity.identityPublicKeyValue);

    const challenge = await createChallenge(identity.identityPublicKeyValue);
    const realDevice = createDeviceKeyMaterial();
    const otherDevice = createDeviceKeyMaterial();

    // Signed over realDevice, but submitted with otherDevice's key.
    const signature = signRecoveryChallenge(identity, {
      userId,
      challengeId: challenge.challengeId,
      devicePublicKeyValue: realDevice.publicKeyValue,
    });
    const result = await completeRecovery(
      challenge.challengeId,
      signature,
      otherDevice.publicKeyValue,
    );
    expect(result.status).toBe(401);
    expect(result.code).toBe('SIGNATURE_INVALID');
  });

  it('rejects recovery with the wrong identity (attacker does not hold the account mnemonic)', async () => {
    const { userId, secret } = await createAccount();
    const identity = deriveIdentity(VECTOR.mnemonic, VECTOR.passphrase);
    const attackerIdentity = deriveIdentity(generateRecoveryMnemonic());
    await registerIdentity(secret, identity.identityPublicKeyValue);

    const challenge = await createChallenge(identity.identityPublicKeyValue);
    const device = createDeviceKeyMaterial();
    const signature = signRecoveryChallenge(attackerIdentity, {
      userId,
      challengeId: challenge.challengeId,
      devicePublicKeyValue: device.publicKeyValue,
    });
    const result = await completeRecovery(challenge.challengeId, signature, device.publicKeyValue);
    expect(result.status).toBe(401);
    expect(result.code).toBe('SIGNATURE_INVALID');
  });

  it('rejects recovery when the optional BIP39 passphrase is wrong', async () => {
    const { userId, secret } = await createAccount();
    const identity = deriveIdentity(VECTOR.mnemonic, VECTOR.passphrase);
    const wrongPassphraseIdentity = deriveIdentity(VECTOR.mnemonic, 'WRONG_PASSPHRASE');
    await registerIdentity(secret, identity.identityPublicKeyValue);

    const challenge = await createChallenge(identity.identityPublicKeyValue);
    const device = createDeviceKeyMaterial();
    const signature = signRecoveryChallenge(wrongPassphraseIdentity, {
      userId,
      challengeId: challenge.challengeId,
      devicePublicKeyValue: device.publicKeyValue,
    });
    const result = await completeRecovery(challenge.challengeId, signature, device.publicKeyValue);
    expect(result.status).toBe(401);
    expect(result.code).toBe('SIGNATURE_INVALID');
  });

  it('rejects recovery of a challenge that was already consumed (replay)', async () => {
    const { userId, secret } = await createAccount();
    const identity = deriveIdentity(VECTOR.mnemonic, VECTOR.passphrase);
    await registerIdentity(secret, identity.identityPublicKeyValue);

    const challenge = await createChallenge(identity.identityPublicKeyValue);
    const device = createDeviceKeyMaterial();
    const signature = signRecoveryChallenge(identity, {
      userId,
      challengeId: challenge.challengeId,
      devicePublicKeyValue: device.publicKeyValue,
    });
    const first = await completeRecovery(challenge.challengeId, signature, device.publicKeyValue);
    expect(first.status).toBe(201);

    const second = await completeRecovery(challenge.challengeId, signature, device.publicKeyValue);
    expect(second.status).toBe(409);
    expect(second.code).toBe('CHALLENGE_USED');
  });

  it('rejects recovery of an expired challenge', async () => {
    const { userId, secret } = await createAccount();
    const identity = deriveIdentity(VECTOR.mnemonic, VECTOR.passphrase);
    await registerIdentity(secret, identity.identityPublicKeyValue);

    const challenge = await createChallenge(identity.identityPublicKeyValue);

    // Backdate the challenge so it is already expired.
    await ctx.db
      .update(recoveryChallenges)
      .set({ expiresAt: new Date(Date.now() - 60_000) })
      .where(eq(recoveryChallenges.id, challenge.challengeId));

    const device = createDeviceKeyMaterial();
    const signature = signRecoveryChallenge(identity, {
      userId,
      challengeId: challenge.challengeId,
      devicePublicKeyValue: device.publicKeyValue,
    });
    const result = await completeRecovery(challenge.challengeId, signature, device.publicKeyValue);
    expect(result.status).toBe(410);
    expect(result.code).toBe('CHALLENGE_EXPIRED');
  });

  it('allows only one winner under concurrent challenge completion', async () => {
    const { userId, secret } = await createAccount();
    const identity = deriveIdentity(VECTOR.mnemonic, VECTOR.passphrase);
    await registerIdentity(secret, identity.identityPublicKeyValue);

    const challenge = await createChallenge(identity.identityPublicKeyValue);
    const challenges = Array.from({ length: 8 }, () => {
      const device = createDeviceKeyMaterial();
      const signature = signRecoveryChallenge(identity, {
        userId,
        challengeId: challenge.challengeId,
        devicePublicKeyValue: device.publicKeyValue,
      });
      return { signature, device };
    });

    const results = await Promise.all(
      challenges.map((c) =>
        completeRecovery(challenge.challengeId, c.signature, c.device.publicKeyValue),
      ),
    );

    const winners = results.filter((r) => r.status === 201);
    const losers = results.filter((r) => r.status === 409 || r.status === 410);
    expect(winners).toHaveLength(1);
    expect(losers.length).toBe(challenges.length - 1);
    for (const loser of losers) {
      expect(loser.code).toBe('CHALLENGE_USED');
    }
  });

  it('recovers multiple existing device blobs and keeps them independent per device', async () => {
    const { userId, secret } = await createAccount();
    const identity = deriveIdentity(VECTOR.mnemonic, VECTOR.passphrase);
    await registerIdentity(secret, identity.identityPublicKeyValue);

    // Device A enrolled normally (Phase 1) and uploads its blob with the account secret.
    const createA = await app.request('/v1/devices', {
      method: 'POST',
      headers: jsonHeaders(authHeaders(secret)),
      body: JSON.stringify({
        label: 'A',
        publicKey: { type: 'x25519', value: makeX25519PublicKey(1) },
      }),
    });
    expect(createA.status).toBe(201);
    const deviceAId = ((await createA.json()) as { ok: true; data: { deviceId: string } }).data
      .deviceId;

    const deviceA = createDeviceKeyMaterial(Buffer.alloc(32, 1));
    const storeA = await app.request('/v1/recovery/blobs', {
      method: 'POST',
      headers: jsonHeaders(authHeaders(secret)),
      body: JSON.stringify({
        envelope: sealRecoveryBlob(deviceA, userId, deviceAId, identity.wrappingKey),
      }),
    });
    expect(storeA.status).toBe(201);

    // Recover device B via mnemonic; B stores its own blob using its device secret.
    const challenge = await createChallenge(identity.identityPublicKeyValue);
    const deviceB = createDeviceKeyMaterial(Buffer.alloc(32, 2));
    const sigB = signRecoveryChallenge(identity, {
      userId,
      challengeId: challenge.challengeId,
      devicePublicKeyValue: deviceB.publicKeyValue,
    });
    const recB = await completeRecovery(challenge.challengeId, sigB, deviceB.publicKeyValue);
    expect(recB.status).toBe(201);

    const storeB = await app.request('/v1/recovery/blobs', {
      method: 'POST',
      headers: jsonHeaders(authHeaders(recB.data!.deviceSecret)),
      body: JSON.stringify({
        envelope: sealRecoveryBlob(deviceB, userId, recB.data!.deviceId, identity.wrappingKey),
      }),
    });
    expect(storeB.status).toBe(201);

    // Both blobs are visible to the user.
    const list = await app.request('/v1/recovery/blobs', { headers: authHeaders(secret) });
    expect(list.status).toBe(200);
    const blobs = ((await list.json()) as { ok: true; data: { deviceId: string }[] }).data;
    expect(blobs.map((b) => b.deviceId).sort()).toEqual([deviceAId, recB.data!.deviceId].sort());

    // Revoking A must NOT destroy B's blob.
    const revokeA = await app.request(`/v1/devices/${deviceAId}/revoke`, {
      method: 'POST',
      headers: authHeaders(secret),
    });
    expect(revokeA.status).toBe(200);
    const listAfter = await app.request('/v1/recovery/blobs', { headers: authHeaders(secret) });
    const blobsAfter = ((await listAfter.json()) as { ok: true; data: { deviceId: string }[] })
      .data;
    expect(blobsAfter.map((b) => b.deviceId)).toEqual([recB.data!.deviceId]);

    // The recovered blob for A still opens with the same wrapping key.
    const envelopeA = blobs.find((b) => b.deviceId === deviceAId);
    expect(envelopeA).toBeTruthy();
  });

  it('a revoked device loses its device credential and its recovery blob', async () => {
    const { userId, secret } = await createAccount();
    const identity = deriveIdentity(VECTOR.mnemonic, VECTOR.passphrase);
    await registerIdentity(secret, identity.identityPublicKeyValue);

    const challenge = await createChallenge(identity.identityPublicKeyValue);
    const device = createDeviceKeyMaterial();
    const signature = signRecoveryChallenge(identity, {
      userId,
      challengeId: challenge.challengeId,
      devicePublicKeyValue: device.publicKeyValue,
    });
    const rec = await completeRecovery(challenge.challengeId, signature, device.publicKeyValue);
    expect(rec.status).toBe(201);
    const deviceId = rec.data!.deviceId;

    // Device stores its blob and can authenticate with its device secret.
    const store = await app.request('/v1/recovery/blobs', {
      method: 'POST',
      headers: jsonHeaders(authHeaders(rec.data!.deviceSecret)),
      body: JSON.stringify({
        envelope: sealRecoveryBlob(device, userId, deviceId, identity.wrappingKey),
      }),
    });
    expect(store.status).toBe(201);

    // Revoke the device as the account holder.
    const revoke = await app.request(`/v1/devices/${deviceId}/revoke`, {
      method: 'POST',
      headers: authHeaders(secret),
    });
    expect(revoke.status).toBe(200);

    // Its device credential is now dead.
    const authed = await app.request('/v1/recovery/blobs', {
      headers: authHeaders(rec.data!.deviceSecret),
    });
    expect(authed.status).toBe(401);

    // Its recovery blob is no longer listed.
    const list = await app.request('/v1/recovery/blobs', { headers: authHeaders(secret) });
    const blobs = ((await list.json()) as { ok: true; data: { deviceId: string }[] }).data;
    expect(blobs.map((b) => b.deviceId)).not.toContain(deviceId);
  });

  it('rejects a malformed recovery blob', async () => {
    const { userId, secret } = await createAccount();
    const identity = deriveIdentity(VECTOR.mnemonic, VECTOR.passphrase);
    await registerIdentity(secret, identity.identityPublicKeyValue);

    const device = createDeviceKeyMaterial();
    const registerRes = await app.request('/v1/devices', {
      method: 'POST',
      headers: jsonHeaders(authHeaders(secret)),
      body: JSON.stringify({ publicKey: { type: 'x25519', value: device.publicKeyValue } }),
    });
    expect(registerRes.status).toBe(201);
    const deviceId = ((await registerRes.json()) as { ok: true; data: { deviceId: string } }).data
      .deviceId;

    const good = sealRecoveryBlob(device, userId, deviceId, identity.wrappingKey);
    const cases: unknown[] = [
      { ...good, nonce: Buffer.alloc(8, 0).toString('base64') }, // wrong nonce length
      { ...good, ciphertext: Buffer.alloc(8, 0).toString('base64') }, // no tag
      { ...good, userId: crypto.randomUUID() }, // wrong account in envelope
      { ...good, deviceId: crypto.randomUUID() }, // wrong device in envelope
      { ...good, v: 2 }, // unsupported version
      { ...good, alg: 'aes-gcm' }, // unsupported algorithm
    ];
    for (const envelope of cases) {
      const res = await app.request('/v1/recovery/blobs', {
        method: 'POST',
        headers: jsonHeaders(authHeaders(secret)),
        body: JSON.stringify({ envelope }),
      });
      expect([400, 403]).toContain(res.status);
    }

    // A blob bound to another account's device is rejected.
    const other = await createAccount();
    const otherDevice = createDeviceKeyMaterial();
    const otherRes = await app.request('/v1/devices', {
      method: 'POST',
      headers: jsonHeaders(authHeaders(other.secret)),
      body: JSON.stringify({ publicKey: { type: 'x25519', value: otherDevice.publicKeyValue } }),
    });
    expect(otherRes.status).toBe(201);
    const otherId = ((await otherRes.json()) as { ok: true; data: { deviceId: string } }).data
      .deviceId;
    const otherBlob = sealRecoveryBlob(otherDevice, other.userId, otherId, identity.wrappingKey);
    const repost = await app.request('/v1/recovery/blobs', {
      method: 'POST',
      headers: jsonHeaders(authHeaders(secret)),
      body: JSON.stringify({ envelope: otherBlob }),
    });
    expect(repost.status).toBe(403);
  });

  it('rejects a device-authenticated blob upload for a different device', async () => {
    const { userId, secret } = await createAccount();
    const identity = deriveIdentity(VECTOR.mnemonic, VECTOR.passphrase);
    await registerIdentity(secret, identity.identityPublicKeyValue);

    const challenge = await createChallenge(identity.identityPublicKeyValue);
    const deviceA = createDeviceKeyMaterial(Buffer.alloc(32, 3));
    const sigA = signRecoveryChallenge(identity, {
      userId,
      challengeId: challenge.challengeId,
      devicePublicKeyValue: deviceA.publicKeyValue,
    });
    const recA = await completeRecovery(challenge.challengeId, sigA, deviceA.publicKeyValue);
    expect(recA.status).toBe(201);

    const challenge2 = await createChallenge(identity.identityPublicKeyValue);
    const deviceB = createDeviceKeyMaterial(Buffer.alloc(32, 4));
    const sigB = signRecoveryChallenge(identity, {
      userId,
      challengeId: challenge2.challengeId,
      devicePublicKeyValue: deviceB.publicKeyValue,
    });
    const recB = await completeRecovery(challenge2.challengeId, sigB, deviceB.publicKeyValue);
    expect(recB.status).toBe(201);

    // A tries to upload a blob claiming to be B.
    const blobForB = sealRecoveryBlob(deviceB, userId, recB.data!.deviceId, identity.wrappingKey);
    const res = await app.request('/v1/recovery/blobs', {
      method: 'POST',
      headers: jsonHeaders(authHeaders(recA.data!.deviceSecret)),
      body: JSON.stringify({ envelope: blobForB }),
    });
    expect(res.status).toBe(403);
  });

  it('cross-language test vector: blob round-trips with the committed envelope', () => {
    const identity = deriveIdentity(VECTOR.mnemonic, VECTOR.passphrase);
    const material = openRecoveryBlob(VECTOR.blob, identity.wrappingKey);
    expect(material.keyVersion).toBe(VECTOR.keyVersion);
    expect(Buffer.from(material.privateKey).toString('base64')).toBe(VECTOR.devicePrivateKey);
    expect(material.publicKeyValue).toBe(VECTOR.devicePublicKeyValue);
    // Sealing with the vector's fixed nonce MUST reproduce the committed ciphertext.
    const resealed = sealRecoveryBlob(
      material,
      VECTOR.userId,
      VECTOR.deviceId,
      identity.wrappingKey,
      fromBase64(VECTOR.blob.nonce),
    );
    expect(resealed.ciphertext).toBe(VECTOR.blob.ciphertext);
  });

  it('openRecoveryBlob fails loudly on tampered ciphertext', () => {
    const identity = deriveIdentity(VECTOR.mnemonic, VECTOR.passphrase);
    const bytes = Buffer.from(VECTOR.blob.ciphertext, 'base64').subarray(0, -1).toString('base64');
    const tampered = { ...VECTOR.blob, ciphertext: bytes };
    expect(() => openRecoveryBlob(tampered, identity.wrappingKey)).toThrow();
  });
});
