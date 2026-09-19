import { describe, expect, it, beforeEach, afterAll } from 'vitest';
import { randomBytes } from '@noble/ciphers/utils.js';
import { eq } from 'drizzle-orm';

import type { Hono } from 'hono';
import type { AppEnv } from '../src/auth/middleware';
import { relationships } from '../src/db/schema';

import { createTestContext, jsonHeaders, authHeaders, type TestContext } from './helpers';
import {
  deriveIdentity,
  generateRecoveryMnemonic,
  signRecoveryChallenge,
} from './reference-recovery';
import { createDeviceKeyMaterial, toBase64 } from './reference-client';
import {
  canonicalTranscript,
  createPairingEphemeral,
  deriveRelationshipRK,
  deriveRelationshipStatic,
  deriveSasProof,
  signPairingConsent,
  signDeviceCert,
} from './reference-relationship';
import type { CanonicalParty } from './reference-relationship';

interface Member {
  userId: string;
  accountSecret: string;
  identity: ReturnType<typeof deriveIdentity>;
  staticKey: ReturnType<typeof deriveRelationshipStatic>;
  deviceId: string;
  deviceSecret: string;
  devicePublicKeyValue: string;
  certSignature: string;
  certVersion: number;
}

async function setupMember(app: Hono<AppEnv>): Promise<Member> {
  const create = await app.request('/v1/users', {
    method: 'POST',
    body: '{}',
    headers: jsonHeaders(),
  });
  expect(create.status).toBe(201);
  const account = (await create.json()) as { ok: true; data: { userId: string; secret: string } };

  const identity = deriveIdentity(generateRecoveryMnemonic());
  const register = await app.request('/v1/identities', {
    method: 'POST',
    headers: jsonHeaders(authHeaders(account.data.secret)),
    body: JSON.stringify({ identityPublicKey: identity.identityPublicKeyValue }),
  });
  expect(register.status).toBe(201);

  const challengeRes = await app.request('/v1/recovery/challenge', {
    method: 'POST',
    headers: jsonHeaders(),
    body: JSON.stringify({ identityPublicKey: identity.identityPublicKeyValue }),
  });
  expect(challengeRes.status).toBe(201);
  const challenge = (await challengeRes.json()) as {
    ok: true;
    data: { challengeId: string; userId: string };
  };

  const device = createDeviceKeyMaterial();
  const signature = signRecoveryChallenge(identity, {
    userId: challenge.data.userId,
    challengeId: challenge.data.challengeId,
    devicePublicKeyValue: device.publicKeyValue,
  });
  const complete = await app.request('/v1/recovery/complete', {
    method: 'POST',
    headers: jsonHeaders(),
    body: JSON.stringify({
      challengeId: challenge.data.challengeId,
      signature,
      deviceKey: { type: 'x25519', value: device.publicKeyValue },
    }),
  });
  expect(complete.status).toBe(201);
  const recovered = (await complete.json()) as {
    ok: true;
    data: { deviceId: string; deviceSecret: string };
  };

  const certSignature = signDeviceCert(identity, {
    userId: account.data.userId,
    deviceId: recovered.data.deviceId,
    devicePublicKeyValue: device.publicKeyValue,
    keyVersion: 0,
  });
  const cert = await app.request(`/v1/devices/${recovered.data.deviceId}/cert`, {
    method: 'POST',
    headers: jsonHeaders(authHeaders(account.data.secret)),
    body: JSON.stringify({ certSignature, certVersion: 0 }),
  });
  expect(cert.status).toBe(200);

  return {
    userId: account.data.userId,
    accountSecret: account.data.secret,
    identity,
    staticKey: deriveRelationshipStatic(identity.seed),
    deviceId: recovered.data.deviceId,
    deviceSecret: recovered.data.deviceSecret,
    devicePublicKeyValue: device.publicKeyValue,
    certSignature,
    certVersion: 0,
  };
}

async function createOffer(
  app: Hono<AppEnv>,
  initiator: Member,
  partnerUserId: string,
): Promise<{ relationshipId: string; epochNonce: string; offerRecord: string }> {
  const epochNonce = toBase64(randomBytes(16));
  const ephemeral = createPairingEphemeral();
  const res = await app.request('/v1/relationships', {
    method: 'POST',
    headers: jsonHeaders(authHeaders(initiator.deviceSecret)),
    body: JSON.stringify({
      partnerUserId,
      epochNonce,
      relationshipStaticPublicKey: {
        type: 'x25519',
        value: initiator.staticKey.relationshipStaticPublicKey,
      },
      ephemeralPublicKey: { type: 'x25519', value: ephemeral.ephemeralPublicKey },
    }),
  });
  expect(res.status).toBe(201);
  const body = (await res.json()) as {
    ok: true;
    data: { relationshipId: string; epochNonce: string; offerRecord: string };
  };
  return body.data;
}

async function postOfferConsent(
  app: Hono<AppEnv>,
  initiator: Member,
  relationshipId: string,
  offerRecord: string,
): Promise<Response> {
  const signature = signPairingConsent(initiator.identity, new TextEncoder().encode(offerRecord));
  return app.request(`/v1/relationships/${relationshipId}/offer-consent`, {
    method: 'POST',
    headers: jsonHeaders(authHeaders(initiator.deviceSecret)),
    body: JSON.stringify({ consentSignature: signature }),
  });
}

interface AcceptInput {
  transcript: string;
  consentSignature: string;
  relationshipStaticPublicKey: { type: 'x25519'; value: string };
  ephemeralPublicKey: { type: 'x25519'; value: string };
}

function buildAcceptPayload(
  _app: Hono<AppEnv>,
  responder: Member,
  relationshipId: string,
  epochNonce: string,
  offerRecord: string,
  opts?: {
    transcriptOverride?: string;
    aEphemeralFlip?: boolean;
    signOverride?: (bytes: Uint8Array) => string;
  },
): Promise<{ payload: AcceptInput; transcript: string; ephemeral: string }> {
  const a = JSON.parse(offerRecord).a as CanonicalParty;
  const ephemeral = createPairingEphemeral();
  const aForTranscript =
    opts?.aEphemeralFlip === true ? { ...a, ephemeralPublicKey: toBase64(randomBytes(32)) } : a;
  const b: CanonicalParty = {
    userId: responder.userId,
    identityPublicKey: responder.identity.identityPublicKeyValue,
    relationshipStaticPublicKey: responder.staticKey.relationshipStaticPublicKey,
    ephemeralPublicKey: ephemeral.ephemeralPublicKey,
    deviceCert: {
      deviceId: responder.deviceId,
      devicePublicKey: responder.devicePublicKeyValue,
      keyVersion: responder.certVersion,
      certSignature: responder.certSignature,
    },
  };
  const transcript =
    opts?.transcriptOverride ??
    canonicalTranscript({
      relationshipId,
      epochNonce,
      epoch: 1,
      a: aForTranscript,
      b,
    });
  const sign =
    opts?.signOverride ?? ((bytes: Uint8Array) => signPairingConsent(responder.identity, bytes));
  const consentSignature = sign(new TextEncoder().encode(transcript));
  return Promise.resolve({
    payload: {
      transcript,
      consentSignature,
      relationshipStaticPublicKey: {
        type: 'x25519',
        value: responder.staticKey.relationshipStaticPublicKey,
      },
      ephemeralPublicKey: { type: 'x25519', value: ephemeral.ephemeralPublicKey },
    },
    transcript,
    ephemeral: ephemeral.ephemeralPublicKey,
  });
}

async function acceptOffer(
  app: Hono<AppEnv>,
  responder: Member,
  relationshipId: string,
  epochNonce: string,
  offerRecord: string,
  opts?: {
    transcriptOverride?: string;
    aEphemeralFlip?: boolean;
    signOverride?: (bytes: Uint8Array) => string;
  },
): Promise<{ status: number; code: string | undefined; transcript: string }> {
  const { payload, transcript } = await buildAcceptPayload(
    app,
    responder,
    relationshipId,
    epochNonce,
    offerRecord,
    opts,
  );
  const res = await app.request(`/v1/relationships/${relationshipId}/accept`, {
    method: 'POST',
    headers: jsonHeaders(authHeaders(responder.deviceSecret)),
    body: JSON.stringify(payload),
  });
  const body = (await res.json()) as { ok: boolean; error?: { code: string } };
  return { status: res.status, code: body.error?.code, transcript };
}

async function confirmOffer(
  app: Hono<AppEnv>,
  initiator: Member,
  responder: Member,
  relationshipId: string,
  epochNonce: string,
  transcript: string,
  opts?: { transcriptOverride?: string; sasProofOverride?: string },
): Promise<{ status: number; code: string | undefined; sasProofA: string }> {
  const rk = deriveRelationshipRK({
    relationshipId,
    epoch: 1,
    epochNonce,
    staticPrivateKey: initiator.staticKey.relationshipStaticPrivateKey,
    partnerStaticPublicKey: responder.staticKey.relationshipStaticPublicKey,
  });
  const transcriptBytes = new TextEncoder().encode(transcript);
  const sasProofA = opts?.sasProofOverride ?? deriveSasProof(rk, transcriptBytes);
  const consentSignature = signPairingConsent(initiator.identity, transcriptBytes);
  const res = await app.request(`/v1/relationships/${relationshipId}/confirm`, {
    method: 'POST',
    headers: jsonHeaders(authHeaders(initiator.deviceSecret)),
    body: JSON.stringify({
      transcript: opts?.transcriptOverride ?? transcript,
      consentSignature,
      sasProof: sasProofA,
    }),
  });
  const body = (await res.json()) as { ok: boolean; error?: { code: string } };
  return { status: res.status, code: body.error?.code, sasProofA };
}

async function establishOffer(
  app: Hono<AppEnv>,
  responder: Member,
  initiator: Member,
  relationshipId: string,
  epochNonce: string,
  transcript: string,
  opts?: { sasProofOverride?: string },
): Promise<{ status: number; code: string | undefined }> {
  const rk = deriveRelationshipRK({
    relationshipId,
    epoch: 1,
    epochNonce,
    staticPrivateKey: responder.staticKey.relationshipStaticPrivateKey,
    partnerStaticPublicKey: initiator.staticKey.relationshipStaticPublicKey,
  });
  const sasProofB =
    opts?.sasProofOverride ?? deriveSasProof(rk, new TextEncoder().encode(transcript));
  const res = await app.request(`/v1/relationships/${relationshipId}/establish`, {
    method: 'POST',
    headers: jsonHeaders(authHeaders(responder.deviceSecret)),
    body: JSON.stringify({ sasProof: sasProofB }),
  });
  const body = (await res.json()) as { ok: boolean; error?: { code: string } };
  return { status: res.status, code: body.error?.code };
}

async function getView(app: Hono<AppEnv>, member: Member, relationshipId: string) {
  const res = await app.request(`/v1/relationships/${relationshipId}`, {
    headers: authHeaders(member.deviceSecret),
  });
  expect(res.status).toBe(200);
  const body = (await res.json()) as {
    ok: true;
    data: {
      state: string;
      transcript: string | null;
      offerConsentSignature: string | null;
      sasProofA: string | null;
      sasProofB: string | null;
      establishedAt: string | null;
    };
  };
  return body.data;
}

async function fullPairing(app: Hono<AppEnv>, initiator: Member, responder: Member) {
  const offer = await createOffer(app, initiator, responder.userId);
  const consent = await postOfferConsent(app, initiator, offer.relationshipId, offer.offerRecord);
  expect(consent.status).toBe(200);

  const accepted = await acceptOffer(
    app,
    responder,
    offer.relationshipId,
    offer.epochNonce,
    offer.offerRecord,
  );
  expect(accepted.status).toBe(200);

  const view = await getView(app, initiator, offer.relationshipId);
  const transcript = view.transcript as string;

  const confirmed = await confirmOffer(
    app,
    initiator,
    responder,
    offer.relationshipId,
    offer.epochNonce,
    transcript,
  );
  expect(confirmed.status).toBe(200);

  const established = await establishOffer(
    app,
    responder,
    initiator,
    offer.relationshipId,
    offer.epochNonce,
    transcript,
  );
  expect(established.status).toBe(200);

  return { ...offer, transcript, sasProofA: confirmed.sasProofA };
}

describe('Phase 3 — relationship trust / pairing (Step 1)', () => {
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

  /* ------------------------------------------------------------------ */
  /* Group A: crypto unit tests (reference client, no server DB state)  */
  /* ------------------------------------------------------------------ */

  it('A1: deriveRelationshipStatic is deterministic from the seed', () => {
    const a = deriveIdentity(generateRecoveryMnemonic());
    const k1 = deriveRelationshipStatic(a.seed);
    const k2 = deriveRelationshipStatic(Uint8Array.from(a.seed));
    expect(k1.relationshipStaticPublicKey).toBe(k2.relationshipStaticPublicKey);
  });

  it('A2: RK is symmetric — RK(A,B) === RK(B,A)', () => {
    const a = deriveRelationshipStatic(deriveIdentity(generateRecoveryMnemonic()).seed);
    const b = deriveRelationshipStatic(deriveIdentity(generateRecoveryMnemonic()).seed);
    const common = {
      relationshipId: crypto.randomUUID(),
      epoch: 1,
      epochNonce: toBase64(randomBytes(16)),
    };
    const rkAB = deriveRelationshipRK({
      ...common,
      staticPrivateKey: a.relationshipStaticPrivateKey,
      partnerStaticPublicKey: b.relationshipStaticPublicKey,
    });
    const rkBA = deriveRelationshipRK({
      ...common,
      staticPrivateKey: b.relationshipStaticPrivateKey,
      partnerStaticPublicKey: a.relationshipStaticPublicKey,
    });
    expect(toBase64(rkAB)).toBe(toBase64(rkBA));
  });

  it('A3: RK changes when epoch / epochNonce / relationshipId changes', () => {
    const a = deriveRelationshipStatic(deriveIdentity(generateRecoveryMnemonic()).seed);
    const b = deriveRelationshipStatic(deriveIdentity(generateRecoveryMnemonic()).seed);
    const base = {
      relationshipId: crypto.randomUUID(),
      epoch: 1,
      epochNonce: toBase64(randomBytes(16)),
      staticPrivateKey: a.relationshipStaticPrivateKey,
      partnerStaticPublicKey: b.relationshipStaticPublicKey,
    };
    const rk = deriveRelationshipRK(base);
    expect(deriveRelationshipRK({ ...base, epoch: 2 })).not.toStrictEqual(rk);
    expect(
      deriveRelationshipRK({ ...base, epochNonce: toBase64(randomBytes(16)) }),
    ).not.toStrictEqual(rk);
    expect(
      deriveRelationshipRK({ ...base, relationshipId: crypto.randomUUID() }),
    ).not.toStrictEqual(rk);
  });

  it('A4 / I10: RK is independent of the ephemerals, but sasProof (transcript confirmation) is not', () => {
    const a = deriveRelationshipStatic(deriveIdentity(generateRecoveryMnemonic()).seed);
    const b = deriveRelationshipStatic(deriveIdentity(generateRecoveryMnemonic()).seed);
    const ephA = createPairingEphemeral();
    const ephB = createPairingEphemeral();
    const flipped = createPairingEphemeral();
    const base = {
      relationshipId: crypto.randomUUID(),
      epoch: 1,
      epochNonce: toBase64(randomBytes(16)),
    };

    const rkA = deriveRelationshipRK({
      ...base,
      staticPrivateKey: a.relationshipStaticPrivateKey,
      partnerStaticPublicKey: b.relationshipStaticPublicKey,
    });
    // Changing an ephemeral in T changes the transcript (and thus sasProof)
    // but leaves RK untouched.
    const tReal = canonicalTranscript({
      ...base,
      a: { ...makeParty(), ephemeralPublicKey: ephA.ephemeralPublicKey },
      b: { ...makeParty(), ephemeralPublicKey: ephB.ephemeralPublicKey },
    });
    const tFlip = canonicalTranscript({
      ...base,
      a: { ...makeParty(), ephemeralPublicKey: flipped.ephemeralPublicKey },
      b: { ...makeParty(), ephemeralPublicKey: ephB.ephemeralPublicKey },
    });
    const proofReal = deriveSasProof(rkA, new TextEncoder().encode(tReal));
    const proofFlip = deriveSasProof(rkA, new TextEncoder().encode(tFlip));
    expect(proofReal).not.toBe(proofFlip);
    // RK is the same regardless of which ephemerals appear in the transcript.
    const rkB = deriveRelationshipRK({
      ...base,
      staticPrivateKey: b.relationshipStaticPrivateKey,
      partnerStaticPublicKey: a.relationshipStaticPublicKey,
    });
    expect(toBase64(rkB)).toBe(toBase64(rkA));
  });

  it('A5 / I11: the server (holding only T, consents, statics) cannot forge either sasProof', async () => {
    const initiator = await setupMember(app);
    const responder = await setupMember(app);
    const pairing = await fullPairing(app, initiator, responder);
    const view = await getView(app, initiator, pairing.relationshipId);

    // The server merely relays and compares: the stored proofs are exactly what
    // the two poles derived client-side, and BOTH are present so the equality
    // check at establish is observable.
    const real = view.sasProofA as string;
    expect(view.sasProofB).toBe(real);
    expect(pairing.sasProofA).toBe(real);

    // The server never holds RK / ephemeral privates / RKA privates, so any
    // guess it could make from server-visible data differs from the real proof.
    const transcriptBytes = new TextEncoder().encode(pairing.transcript);
    const guesses = [
      deriveSasProof(randomBytes(32), transcriptBytes),
      deriveSasProof(new Uint8Array(32), transcriptBytes),
      deriveSasProof(randomBytes(32), new TextEncoder().encode('tampered')),
    ];
    for (const guess of guesses) {
      expect(guess).not.toBe(real);
      expect(guess.length).toBeGreaterThan(0);
    }
  });

  it('A6: domain labels never collide across Phase 1/2/3 artifacts', () => {
    const labels = [
      'enclave/recovery-v1',
      'enclave/recovery-blob-v1/',
      'enclave/identity-signing-v1',
      'enclave/recovery-wrap-v1',
      'enclave/payload-v1/',
      'enclave/pairing-transcript-v1',
      'enclave/pairing-offer-v1',
      'enclave/pairing-consent-v1',
      'enclave/device-cert-v1',
      'enclave/relationship-identity-v1',
      'enclave/relationship-rk-v1',
      'enclave/sas-proof-v1',
      'enclave/sas-v1',
    ];
    expect(new Set(labels).size).toBe(labels.length);
    expect(labels.length).toBeGreaterThan(8);
  });

  /* ------------------------------------------------------------------ */
  /* Group B: happy path + protocol fidelity                             */
  /* ------------------------------------------------------------------ */

  it('B1: a full pairing reaches ESTABLISHED with all three signed consents and one epoch', async () => {
    const initiator = await setupMember(app);
    const responder = await setupMember(app);
    const pairing = await fullPairing(app, initiator, responder);

    const view = await getView(app, initiator, pairing.relationshipId);
    expect(view.state).toBe('ESTABLISHED');
    expect(view.offerConsentSignature).toBeTruthy();

    const epochs = await ctx.db.query.relationshipEpochs.findMany();
    expect(epochs).toHaveLength(1);
    expect(epochs[0]!.rotationCause).toBe('initial');
    expect(epochs[0]!.epoch).toBe(1);
  });

  it('B2: GET list shows each pole its own relationships; transcripts and consents are exposed', async () => {
    const initiator = await setupMember(app);
    const responder = await setupMember(app);
    await fullPairing(app, initiator, responder);

    const listRes = await app.request('/v1/relationships', {
      headers: authHeaders(initiator.deviceSecret),
    });
    const listBody = (await listRes.json()) as { ok: true; data: { relationshipId: string }[] };
    expect(listBody.data).toHaveLength(1);

    const other = await setupMember(app);
    const listOther = await app.request('/v1/relationships', {
      headers: authHeaders(other.deviceSecret),
    });
    const otherBody = (await listOther.json()) as { ok: true; data: unknown[] };
    expect(otherBody.data).toHaveLength(0);
  });

  it('B3 / I12: the client-built transcript equals the server-canonical transcript byte-for-byte', async () => {
    const initiator = await setupMember(app);
    const responder = await setupMember(app);
    const offer = await createOffer(app, initiator, responder.userId);
    await postOfferConsent(app, initiator, offer.relationshipId, offer.offerRecord);

    const { payload, transcript } = await buildAcceptPayload(
      app,
      responder,
      offer.relationshipId,
      offer.epochNonce,
      offer.offerRecord,
    );
    const res = await app.request(`/v1/relationships/${offer.relationshipId}/accept`, {
      method: 'POST',
      headers: jsonHeaders(authHeaders(responder.deviceSecret)),
      body: JSON.stringify(payload),
    });
    expect(res.status).toBe(200);

    const view = await getView(app, initiator, offer.relationshipId);
    expect(view.transcript).toBe(transcript);
    expect(view.transcript).toBe(
      canonicalTranscript({
        relationshipId: offer.relationshipId,
        epochNonce: offer.epochNonce,
        epoch: 1,
        a: JSON.parse(offer.offerRecord).a as CanonicalParty,
        b: JSON.parse(transcript).b as CanonicalParty,
      }),
    );
  });

  /* ------------------------------------------------------------------ */
  /* Group C: adversarials — consent signatures                         */
  /* ------------------------------------------------------------------ */

  it('C1: an invalid offer-consent signature is rejected (SIGNATURE_INVALID), state stays PENDING', async () => {
    const initiator = await setupMember(app);
    const responder = await setupMember(app);
    const offer = await createOffer(app, initiator, responder.userId);

    const bad = signPairingConsent(
      initiator.identity,
      new TextEncoder().encode(offer.offerRecord + 'x'),
    );
    const res = await app.request(`/v1/relationships/${offer.relationshipId}/offer-consent`, {
      method: 'POST',
      headers: jsonHeaders(authHeaders(initiator.deviceSecret)),
      body: JSON.stringify({ consentSignature: bad }),
    });
    const body = (await res.json()) as { ok: false; error: { code: string } };
    expect(res.status).toBe(401);
    expect(body.error.code).toBe('SIGNATURE_INVALID');

    const view = await getView(app, initiator, offer.relationshipId);
    expect(view.state).toBe('PENDING');
    expect(view.offerConsentSignature).toBeNull();
  });

  it('C2: only the initiator can post the offer consent (responder → FORBIDDEN)', async () => {
    const initiator = await setupMember(app);
    const responder = await setupMember(app);
    const offer = await createOffer(app, initiator, responder.userId);

    // The responder signs the offer record with its OWN identity key. The
    // operation is initiator-only, so the server refuses before signature
    // verification (the wrong-pole check fires first).
    const responderSigned = signPairingConsent(
      responder.identity,
      new TextEncoder().encode(offer.offerRecord),
    );
    const res = await app.request(`/v1/relationships/${offer.relationshipId}/offer-consent`, {
      method: 'POST',
      headers: jsonHeaders(authHeaders(responder.deviceSecret)),
      body: JSON.stringify({ consentSignature: responderSigned }),
    });
    const body = (await res.json()) as { ok: false; error: { code: string } };
    expect(res.status).toBe(403);
    expect(body.error.code).toBe('FORBIDDEN');
  });

  it('C3: a third party (non-member) cannot see or accept another pair offer', async () => {
    const initiator = await setupMember(app);
    const responder = await setupMember(app);
    const attacker = await setupMember(app);
    const offer = await createOffer(app, initiator, responder.userId);

    const get = await app.request(`/v1/relationships/${offer.relationshipId}`, {
      headers: authHeaders(attacker.deviceSecret),
    });
    expect(get.status).toBe(404);

    const { payload } = await buildAcceptPayload(
      app,
      attacker,
      offer.relationshipId,
      offer.epochNonce,
      offer.offerRecord,
    );
    const res = await app.request(`/v1/relationships/${offer.relationshipId}/accept`, {
      method: 'POST',
      headers: jsonHeaders(authHeaders(attacker.deviceSecret)),
      body: JSON.stringify(payload),
    });
    expect(res.status).toBe(404);
  });

  it('C4: a consent signature over different bytes than submitted is rejected (SIGNATURE_INVALID)', async () => {
    const initiator = await setupMember(app);
    const responder = await setupMember(app);
    const offer = await createOffer(app, initiator, responder.userId);
    await postOfferConsent(app, initiator, offer.relationshipId, offer.offerRecord);

    const real = JSON.parse(offer.offerRecord).a as CanonicalParty;
    const ephemeral = createPairingEphemeral();
    const b: CanonicalParty = {
      userId: responder.userId,
      identityPublicKey: responder.identity.identityPublicKeyValue,
      relationshipStaticPublicKey: responder.staticKey.relationshipStaticPublicKey,
      ephemeralPublicKey: ephemeral.ephemeralPublicKey,
      deviceCert: {
        deviceId: responder.deviceId,
        devicePublicKey: responder.devicePublicKeyValue,
        keyVersion: responder.certVersion,
        certSignature: responder.certSignature,
      },
    };
    const transcript = canonicalTranscript({
      relationshipId: offer.relationshipId,
      epochNonce: offer.epochNonce,
      epoch: 1,
      a: real,
      b,
    });
    // Sign the real canonical transcript, then submit a copy that is still
    // structurally valid JSON but byte-different (epoch altered).
    const signature = signPairingConsent(responder.identity, new TextEncoder().encode(transcript));
    const corrupt = transcript.replace('"epoch":1', '"epoch":2');
    const res = await app.request(`/v1/relationships/${offer.relationshipId}/accept`, {
      method: 'POST',
      headers: jsonHeaders(authHeaders(responder.deviceSecret)),
      body: JSON.stringify({
        transcript: corrupt,
        consentSignature: signature,
        relationshipStaticPublicKey: {
          type: 'x25519',
          value: responder.staticKey.relationshipStaticPublicKey,
        },
        ephemeralPublicKey: { type: 'x25519', value: ephemeral.ephemeralPublicKey },
      }),
    });
    const body = (await res.json()) as { ok: false; error: { code: string } };
    expect(res.status).toBe(401);
    expect(body.error.code).toBe('SIGNATURE_INVALID');
  });

  it('C5: a transcript with substituted a-fields is byte-rejected (TRANSCRIPT_MISMATCH)', async () => {
    const initiator = await setupMember(app);
    const responder = await setupMember(app);
    const offer = await createOffer(app, initiator, responder.userId);
    await postOfferConsent(app, initiator, offer.relationshipId, offer.offerRecord);

    const result = await acceptOffer(
      app,
      responder,
      offer.relationshipId,
      offer.epochNonce,
      offer.offerRecord,
      { aEphemeralFlip: true },
    );
    expect(result.status).toBe(400);
    expect(result.code).toBe('TRANSCRIPT_MISMATCH');
  });

  /* ------------------------------------------------------------------ */
  /* Group D: state machine                                              */
  /* ------------------------------------------------------------------ */

  it('D1: duplicate offer for an already-active pair → PAIRING_ALREADY_ACTIVE', async () => {
    const initiator = await setupMember(app);
    const responder = await setupMember(app);
    await fullPairing(app, initiator, responder);

    const offer = { partnerUserId: responder.userId, epochNonce: toBase64(randomBytes(16)) };
    const res = await app.request('/v1/relationships', {
      method: 'POST',
      headers: jsonHeaders(authHeaders(initiator.deviceSecret)),
      body: JSON.stringify({
        partnerUserId: offer.partnerUserId,
        epochNonce: offer.epochNonce,
        relationshipStaticPublicKey: {
          type: 'x25519',
          value: initiator.staticKey.relationshipStaticPublicKey,
        },
        ephemeralPublicKey: { type: 'x25519', value: createPairingEphemeral().ephemeralPublicKey },
      }),
    });
    expect(res.status).toBe(409);
    const body = (await res.json()) as { ok: false; error: { code: string } };
    expect(body.error.code).toBe('PAIRING_ALREADY_ACTIVE');
  });

  it('D2: concurrent offers for the same pair → exactly one winner', async () => {
    const initiator = await setupMember(app);
    const responder = await setupMember(app);
    const requests = [initiator, responder].map(() =>
      app.request('/v1/relationships', {
        method: 'POST',
        headers: jsonHeaders(authHeaders(initiator.deviceSecret)),
        body: JSON.stringify({
          partnerUserId: responder.userId,
          epochNonce: toBase64(randomBytes(16)),
          relationshipStaticPublicKey: {
            type: 'x25519',
            value: initiator.staticKey.relationshipStaticPublicKey,
          },
          ephemeralPublicKey: {
            type: 'x25519',
            value: createPairingEphemeral().ephemeralPublicKey,
          },
        }),
      }),
    );
    const results = await Promise.all(requests);
    const statuses = results.map((r) => r.status);
    expect(statuses.filter((s) => s === 201)).toHaveLength(1);
    const losers = statuses.filter((s) => s !== 201);
    expect(losers.length).toBe(1);
    expect(losers[0]).toBe(409);
  });

  it('D3: one active relationship per user pole — a new offer with a third user is refused', async () => {
    const initiator = await setupMember(app);
    const responder = await setupMember(app);
    const third = await setupMember(app);
    await fullPairing(app, initiator, responder);

    const res = await app.request('/v1/relationships', {
      method: 'POST',
      headers: jsonHeaders(authHeaders(initiator.deviceSecret)),
      body: JSON.stringify({
        partnerUserId: third.userId,
        epochNonce: toBase64(randomBytes(16)),
        relationshipStaticPublicKey: {
          type: 'x25519',
          value: initiator.staticKey.relationshipStaticPublicKey,
        },
        ephemeralPublicKey: { type: 'x25519', value: createPairingEphemeral().ephemeralPublicKey },
      }),
    });
    const body = (await res.json()) as { ok: false; error: { code: string } };
    expect(res.status).toBe(409);
    expect(body.error.code).toBe('PAIRING_ALREADY_ACTIVE');
  });

  it('D4: after TERMINATED, a fresh pairing for the same pair is allowed', async () => {
    const initiator = await setupMember(app);
    const responder = await setupMember(app);
    const pairing = await fullPairing(app, initiator, responder);

    const term = await app.request(`/v1/relationships/${pairing.relationshipId}/terminate`, {
      method: 'POST',
      headers: authHeaders(initiator.deviceSecret),
    });
    expect(term.status).toBe(200);

    const res = await createOffer(app, initiator, responder.userId);
    expect(res.relationshipId).toBeTruthy();
  });

  it('D11 (HIGH-1 regression): ESTABLISHED → TERMINATED is not blocked by the original offer TTL', async () => {
    const initiator = await setupMember(app);
    const responder = await setupMember(app);
    const pairing = await fullPairing(app, initiator, responder);

    // Backdate expiresAt beyond the original 24h pairing TTL.
    await ctx.db
      .update(relationships)
      .set({ expiresAt: new Date(Date.now() - 60_000) })
      .where(eq(relationships.id, pairing.relationshipId));

    // An authorized certified device (a member's device credential) terminates.
    const term = await app.request(`/v1/relationships/${pairing.relationshipId}/terminate`, {
      method: 'POST',
      headers: authHeaders(initiator.deviceSecret),
    });
    expect(term.status).toBe(200);
    expect((await getView(app, initiator, pairing.relationshipId)).state).toBe('TERMINATED');

    // The one-active-per-pole constraint no longer applies: a new pairing for
    // the same two users can subsequently be created.
    const res = await createOffer(app, initiator, responder.userId);
    expect(res.relationshipId).toBeTruthy();
  });

  it('D12: an ACCEPTED pairing still expires correctly once the TTL passes', async () => {
    const initiator = await setupMember(app);
    const responder = await setupMember(app);
    const offer = await createOffer(app, initiator, responder.userId);
    await postOfferConsent(app, initiator, offer.relationshipId, offer.offerRecord);
    const accepted = await acceptOffer(
      app,
      responder,
      offer.relationshipId,
      offer.epochNonce,
      offer.offerRecord,
    );
    expect(accepted.status).toBe(200);

    await ctx.db
      .update(relationships)
      .set({ expiresAt: new Date(Date.now() - 60_000) })
      .where(eq(relationships.id, offer.relationshipId));

    const confirmed = await confirmOffer(
      app,
      initiator,
      responder,
      offer.relationshipId,
      offer.epochNonce,
      accepted.transcript,
    );
    expect(confirmed.status).toBe(410);
    expect(confirmed.code).toBe('PAIRING_EXPIRED');
    expect((await getView(app, initiator, offer.relationshipId)).state).toBe('EXPIRED');
  });

  it('D5: an expired offer is rejected with PAIRING_EXPIRED and becomes EXPIRED', async () => {
    const initiator = await setupMember(app);
    const responder = await setupMember(app);
    const offer = await createOffer(app, initiator, responder.userId);
    await postOfferConsent(app, initiator, offer.relationshipId, offer.offerRecord);

    await ctx.db
      .update(relationships)
      .set({ expiresAt: new Date(Date.now() - 60_000) })
      .where(eq(relationships.id, offer.relationshipId));

    const result = await acceptOffer(
      app,
      responder,
      offer.relationshipId,
      offer.epochNonce,
      offer.offerRecord,
    );
    expect(result.status).toBe(410);
    expect(result.code).toBe('PAIRING_EXPIRED');

    const view = await getView(app, initiator, offer.relationshipId);
    expect(view.state).toBe('EXPIRED');
  });

  it('D6: responder rejection is terminal and sticky (accept afterward → PAIRING_STATE_INVALID)', async () => {
    const initiator = await setupMember(app);
    const responder = await setupMember(app);
    const offer = await createOffer(app, initiator, responder.userId);
    await postOfferConsent(app, initiator, offer.relationshipId, offer.offerRecord);

    const reject = await app.request(`/v1/relationships/${offer.relationshipId}/reject`, {
      method: 'POST',
      headers: authHeaders(responder.deviceSecret),
    });
    expect(reject.status).toBe(200);
    expect((await getView(app, initiator, offer.relationshipId)).state).toBe('REJECTED');

    const retry = await acceptOffer(
      app,
      responder,
      offer.relationshipId,
      offer.epochNonce,
      offer.offerRecord,
    );
    expect(retry.status).toBe(409);
    expect(retry.code).toBe('PAIRING_STATE_INVALID');
  });

  it('D7: initiator cancel is terminal and sticky', async () => {
    const initiator = await setupMember(app);
    const responder = await setupMember(app);
    const offer = await createOffer(app, initiator, responder.userId);

    const cancel = await app.request(`/v1/relationships/${offer.relationshipId}/cancel`, {
      method: 'POST',
      headers: authHeaders(initiator.deviceSecret),
    });
    expect(cancel.status).toBe(200);
    expect((await getView(app, initiator, offer.relationshipId)).state).toBe('CANCELLED');

    const reject = await app.request(`/v1/relationships/${offer.relationshipId}/reject`, {
      method: 'POST',
      headers: authHeaders(responder.deviceSecret),
    });
    expect(reject.status).toBe(409);
  });

  it('D8: wrong-pole terminal actions are forbidden', async () => {
    const initiator = await setupMember(app);
    const responder = await setupMember(app);
    const offer = await createOffer(app, initiator, responder.userId);

    const cancelByB = await app.request(`/v1/relationships/${offer.relationshipId}/cancel`, {
      method: 'POST',
      headers: authHeaders(responder.deviceSecret),
    });
    expect(cancelByB.status).toBe(403);

    const rejectByA = await app.request(`/v1/relationships/${offer.relationshipId}/reject`, {
      method: 'POST',
      headers: authHeaders(initiator.deviceSecret),
    });
    expect(rejectByA.status).toBe(403);
  });

  it('D9: establish is blocked before the initiator confirms', async () => {
    const initiator = await setupMember(app);
    const responder = await setupMember(app);
    const offer = await createOffer(app, initiator, responder.userId);
    await postOfferConsent(app, initiator, offer.relationshipId, offer.offerRecord);
    const accepted = await acceptOffer(
      app,
      responder,
      offer.relationshipId,
      offer.epochNonce,
      offer.offerRecord,
    );
    expect(accepted.status).toBe(200);

    const view = await getView(app, responder, offer.relationshipId);
    const established = await establishOffer(
      app,
      responder,
      initiator,
      offer.relationshipId,
      offer.epochNonce,
      view.transcript as string,
    );
    expect(established.status).toBe(409);
    expect(established.code).toBe('PAIRING_STATE_INVALID');
  });

  it('D10: concurrent establishment yields exactly one winner', async () => {
    const initiator = await setupMember(app);
    const responder = await setupMember(app);
    const offer = await createOffer(app, initiator, responder.userId);
    await postOfferConsent(app, initiator, offer.relationshipId, offer.offerRecord);
    const accepted = await acceptOffer(
      app,
      responder,
      offer.relationshipId,
      offer.epochNonce,
      offer.offerRecord,
    );
    expect(accepted.status).toBe(200);
    const view = await getView(app, initiator, offer.relationshipId);
    const transcript = view.transcript as string;
    const confirmed = await confirmOffer(
      app,
      initiator,
      responder,
      offer.relationshipId,
      offer.epochNonce,
      transcript,
    );
    expect(confirmed.status).toBe(200);

    const results = await Promise.all(
      Array.from({ length: 4 }, () =>
        establishOffer(
          app,
          responder,
          initiator,
          offer.relationshipId,
          offer.epochNonce,
          transcript,
        ),
      ),
    );
    const winners = results.filter((r) => r.status === 200);
    const replays = results.filter((r) => r.code === 'IDEMPOTENCY_REPLAY');
    expect(winners).toHaveLength(1);
    expect(replays.length).toBe(3);
  });

  /* ------------------------------------------------------------------ */
  /* Group E: Establish + sasProof                                       */
  /* ------------------------------------------------------------------ */

  it('E1: mismatched sasProof → TOKEN_CONFLICT and the pairing is REJECTED (single-use, sticky)', async () => {
    const initiator = await setupMember(app);
    const responder = await setupMember(app);
    const offer = await createOffer(app, initiator, responder.userId);
    await postOfferConsent(app, initiator, offer.relationshipId, offer.offerRecord);
    const accepted = await acceptOffer(
      app,
      responder,
      offer.relationshipId,
      offer.epochNonce,
      offer.offerRecord,
    );
    expect(accepted.status).toBe(200);
    const view = await getView(app, initiator, offer.relationshipId);
    const transcript = view.transcript as string;
    const confirmed = await confirmOffer(
      app,
      initiator,
      responder,
      offer.relationshipId,
      offer.epochNonce,
      transcript,
    );
    expect(confirmed.status).toBe(200);

    // Responder posts a proof over a transcript that was never confirmed.
    const forged = deriveSasProof(randomBytes(32), new TextEncoder().encode('tampered'));
    const establish = await establishOffer(
      app,
      responder,
      initiator,
      offer.relationshipId,
      offer.epochNonce,
      transcript,
      { sasProofOverride: forged },
    );
    expect(establish.status).toBe(409);
    expect(establish.code).toBe('TOKEN_CONFLICT');
    expect((await getView(app, initiator, offer.relationshipId)).state).toBe('REJECTED');

    const retry = await establishOffer(
      app,
      responder,
      initiator,
      offer.relationshipId,
      offer.epochNonce,
      transcript,
    );
    expect(retry.status).toBe(409);
    expect(retry.code).toBe('PAIRING_REJECTED');
  });

  it('E2: a noisy sasProof equals a signed transcript-confirmed proof and establishes', async () => {
    const initiator = await setupMember(app);
    const responder = await setupMember(app);
    const pairing = await fullPairing(app, initiator, responder);
    const aView = await getView(app, initiator, pairing.relationshipId);
    const bView = await getView(app, responder, pairing.relationshipId);
    expect(aView.state).toBe('ESTABLISHED');
    expect(bView.state).toBe('ESTABLISHED');
    // `establishedAt` is stamped at the winning establish and exposed to both poles.
    expect(aView.establishedAt).toBeTruthy();
    expect(bView.establishedAt).toBe(aView.establishedAt);
    expect(new Date(aView.establishedAt as string).getTime()).toBeGreaterThan(0);
  });

  it('E3: establish replay after ESTABLISHED → IDEMPOTENCY_REPLAY; offer-consent stays idempotent', async () => {
    const initiator = await setupMember(app);
    const responder = await setupMember(app);
    const offer = await createOffer(app, initiator, responder.userId);

    // Initiation is idempotent when repeated while PENDING (same artifacts).
    const consent1 = await postOfferConsent(
      app,
      initiator,
      offer.relationshipId,
      offer.offerRecord,
    );
    expect(consent1.status).toBe(200);
    const consent2 = await postOfferConsent(
      app,
      initiator,
      offer.relationshipId,
      offer.offerRecord,
    );
    expect(consent2.status).toBe(200);

    await acceptOffer(app, responder, offer.relationshipId, offer.epochNonce, offer.offerRecord);
    const view = await getView(app, initiator, offer.relationshipId);
    const confirmed = await confirmOffer(
      app,
      initiator,
      responder,
      offer.relationshipId,
      offer.epochNonce,
      view.transcript as string,
    );
    expect(confirmed.status).toBe(200);
    const established = await establishOffer(
      app,
      responder,
      initiator,
      offer.relationshipId,
      offer.epochNonce,
      view.transcript as string,
    );
    expect(established.status).toBe(200);

    const replay = await establishOffer(
      app,
      responder,
      initiator,
      offer.relationshipId,
      offer.epochNonce,
      view.transcript as string,
    );
    expect(replay.status).toBe(409);
    expect(replay.code).toBe('IDEMPOTENCY_REPLAY');
  });

  /* ------------------------------------------------------------------ */
  /* Group F: device certificates                                       */
  /* ------------------------------------------------------------------ */

  it('F1: an uncertified device cannot participate (DEVICE_CERT_MISSING)', async () => {
    const initiator = await setupMember(app);
    const responder = await setupMember(app);
    const offer = await createOffer(app, initiator, responder.userId);
    await postOfferConsent(app, initiator, offer.relationshipId, offer.offerRecord);

    // A second device for the responder that is recovered but never certified.
    const challenge = await app.request('/v1/recovery/challenge', {
      method: 'POST',
      headers: jsonHeaders(),
      body: JSON.stringify({ identityPublicKey: responder.identity.identityPublicKeyValue }),
    });
    const challengeData = (await challenge.json()) as {
      ok: true;
      data: { challengeId: string; userId: string };
    };
    const device = createDeviceKeyMaterial();
    const signature = signRecoveryChallenge(responder.identity, {
      userId: challengeData.data.userId,
      challengeId: challengeData.data.challengeId,
      devicePublicKeyValue: device.publicKeyValue,
    });
    const complete = await app.request('/v1/recovery/complete', {
      method: 'POST',
      headers: jsonHeaders(),
      body: JSON.stringify({
        challengeId: challengeData.data.challengeId,
        signature,
        deviceKey: { type: 'x25519', value: device.publicKeyValue },
      }),
    });
    const recovered = (await complete.json()) as {
      ok: true;
      data: { deviceId: string; deviceSecret: string; userId: string };
    };

    const res = await app.request(`/v1/relationships/${offer.relationshipId}/accept`, {
      method: 'POST',
      headers: jsonHeaders(authHeaders(recovered.data.deviceSecret)),
      body: JSON.stringify({
        transcript: 'x',
        consentSignature: toBase64(new Uint8Array(64)),
        relationshipStaticPublicKey: { type: 'x25519', value: device.publicKeyValue },
        ephemeralPublicKey: { type: 'x25519', value: device.publicKeyValue },
      }),
    });
    const body = (await res.json()) as { ok: false; error: { code: string } };
    expect(res.status).toBe(403);
    expect(body.error.code).toBe('DEVICE_CERT_MISSING');
  });

  it('F2: a certificate signed by the wrong identity is rejected (DEVICE_CERT_INVALID)', async () => {
    const { userId, secret: accountSecret } = await (async () => {
      const create = await app.request('/v1/users', {
        method: 'POST',
        body: '{}',
        headers: jsonHeaders(),
      });
      return ((await create.json()) as { ok: true; data: { userId: string; secret: string } }).data;
    })();
    const identity = deriveIdentity(generateRecoveryMnemonic());
    const register = await app.request('/v1/identities', {
      method: 'POST',
      headers: jsonHeaders(authHeaders(accountSecret)),
      body: JSON.stringify({ identityPublicKey: identity.identityPublicKeyValue }),
    });
    expect(register.status).toBe(201);

    const device = createDeviceKeyMaterial();
    const devRes = await app.request('/v1/devices', {
      method: 'POST',
      headers: jsonHeaders(authHeaders(accountSecret)),
      body: JSON.stringify({ publicKey: { type: 'x25519', value: device.publicKeyValue } }),
    });
    const devData = (await devRes.json()) as { ok: true; data: { deviceId: string } };

    // Attacker (different mnemonic) signs a cert for the victim's device.
    const attacker = deriveIdentity(generateRecoveryMnemonic());
    const forged = signDeviceCert(attacker, {
      userId,
      deviceId: devData.data.deviceId,
      devicePublicKeyValue: device.publicKeyValue,
      keyVersion: 0,
    });
    const cert = await app.request(`/v1/devices/${devData.data.deviceId}/cert`, {
      method: 'POST',
      headers: jsonHeaders(authHeaders(accountSecret)),
      body: JSON.stringify({ certSignature: forged, certVersion: 0 }),
    });
    const body = (await cert.json()) as { ok: false; error: { code: string } };
    expect(cert.status).toBe(401);
    expect(body.error.code).toBe('DEVICE_CERT_INVALID');
  });

  it('F3: a certificate over a different device key is rejected (DEVICE_CERT_INVALID)', async () => {
    const { userId, secret: accountSecret } = await (async () => {
      const create = await app.request('/v1/users', {
        method: 'POST',
        body: '{}',
        headers: jsonHeaders(),
      });
      return ((await create.json()) as { ok: true; data: { userId: string; secret: string } }).data;
    })();
    const identity = deriveIdentity(generateRecoveryMnemonic());
    await app.request('/v1/identities', {
      method: 'POST',
      headers: jsonHeaders(authHeaders(accountSecret)),
      body: JSON.stringify({ identityPublicKey: identity.identityPublicKeyValue }),
    });
    const device = createDeviceKeyMaterial();
    const otherDevice = createDeviceKeyMaterial();
    const devRes = await app.request('/v1/devices', {
      method: 'POST',
      headers: jsonHeaders(authHeaders(accountSecret)),
      body: JSON.stringify({ publicKey: { type: 'x25519', value: device.publicKeyValue } }),
    });
    const devData = (await devRes.json()) as { ok: true; data: { deviceId: string } };

    // Sign cert over otherDevice's key, but the registered device is `device`.
    const signed = signDeviceCert(identity, {
      userId,
      deviceId: devData.data.deviceId,
      devicePublicKeyValue: otherDevice.publicKeyValue,
      keyVersion: 0,
    });
    const cert = await app.request(`/v1/devices/${devData.data.deviceId}/cert`, {
      method: 'POST',
      headers: jsonHeaders(authHeaders(accountSecret)),
      body: JSON.stringify({ certSignature: signed, certVersion: 0 }),
    });
    const body = (await cert.json()) as { ok: false; error: { code: string } };
    expect(cert.status).toBe(401);
    expect(body.error.code).toBe('DEVICE_CERT_INVALID');
  });

  it('F4: certifications are stored, served, and bound to the server-assigned deviceId', async () => {
    const { userId, secret: accountSecret } = await (async () => {
      const create = await app.request('/v1/users', {
        method: 'POST',
        body: '{}',
        headers: jsonHeaders(),
      });
      return ((await create.json()) as { ok: true; data: { userId: string; secret: string } }).data;
    })();
    const identity = deriveIdentity(generateRecoveryMnemonic());
    await app.request('/v1/identities', {
      method: 'POST',
      headers: jsonHeaders(authHeaders(accountSecret)),
      body: JSON.stringify({ identityPublicKey: identity.identityPublicKeyValue }),
    });

    // A device starts out uncertified.
    const device = createDeviceKeyMaterial();
    const regRes = await app.request('/v1/devices', {
      method: 'POST',
      headers: jsonHeaders(authHeaders(accountSecret)),
      body: JSON.stringify({ publicKey: { type: 'x25519', value: device.publicKeyValue } }),
    });
    expect(regRes.status).toBe(201);
    const regData = (await regRes.json()) as {
      ok: true;
      data: { deviceId: string; certSignature: string | null; certVersion: number | null };
    };
    expect(regData.data.certSignature).toBeNull();
    expect(regData.data.certVersion).toBeNull();

    // Certify it over the SERVER-assigned deviceId (ADR 0004 §7).
    const certSignature = signDeviceCert(identity, {
      userId,
      deviceId: regData.data.deviceId,
      devicePublicKeyValue: device.publicKeyValue,
      keyVersion: 0,
    });
    const certRes = await app.request(`/v1/devices/${regData.data.deviceId}/cert`, {
      method: 'POST',
      headers: jsonHeaders(authHeaders(accountSecret)),
      body: JSON.stringify({ certSignature, certVersion: 0 }),
    });
    expect(certRes.status).toBe(200);

    // The certificate is served on both the detail and the list views.
    for (const path of [`/v1/devices/${regData.data.deviceId}`, '/v1/devices']) {
      const res = await app.request(path, { headers: authHeaders(accountSecret) });
      expect(res.status).toBe(200);
      const body = (await res.json()) as {
        ok: true;
        data:
          | { deviceId: string; certSignature: string | null; certVersion: number | null }
          | { deviceId: string; certSignature: string | null; certVersion: number | null }[];
      };
      const list = Array.isArray(body.data) ? body.data : [body.data];
      const mine = list.find((d) => d.deviceId === regData.data.deviceId);
      expect(mine?.certSignature).toBe(certSignature);
      expect(mine?.certVersion).toBe(0);
    }

    // A certificate bound to a DIFFERENT deviceId can never be attached: the
    // deviceId is server-assigned and the signed message is bound to it, so
    // inline registration with a mismatched cert is refused.
    const mismatched = signDeviceCert(identity, {
      userId,
      deviceId: crypto.randomUUID(),
      devicePublicKeyValue: device.publicKeyValue,
      keyVersion: 0,
    });
    const inlineRes = await app.request('/v1/devices', {
      method: 'POST',
      headers: jsonHeaders(authHeaders(accountSecret)),
      body: JSON.stringify({
        publicKey: { type: 'x25519', value: createDeviceKeyMaterial().publicKeyValue },
        certSignature: mismatched,
        certVersion: 0,
      }),
    });
    const inlineBody = (await inlineRes.json()) as { ok: false; error: { code: string } };
    expect(inlineRes.status).toBe(401);
    expect(inlineBody.error.code).toBe('DEVICE_CERT_INVALID');
  });

  it('F5: a revoked device is refused all new relationship operations', async () => {
    const initiator = await setupMember(app);
    const responder = await setupMember(app);
    const offer = await createOffer(app, initiator, responder.userId);
    await postOfferConsent(app, initiator, offer.relationshipId, offer.offerRecord);

    const revoke = await app.request(`/v1/devices/${initiator.deviceId}/revoke`, {
      method: 'POST',
      headers: authHeaders(initiator.accountSecret),
    });
    expect(revoke.status).toBe(200);

    // Its device credential is dead at auth time.
    const after = await app.request(`/v1/relationships/${offer.relationshipId}/offer-consent`, {
      method: 'POST',
      headers: jsonHeaders(authHeaders(initiator.deviceSecret)),
      body: JSON.stringify({ consentSignature: toBase64(new Uint8Array(64)) }),
    });
    expect(after.status).toBe(401);
  });

  /* ------------------------------------------------------------------ */
  /* Group G: server trust boundary                                     */
  /* ------------------------------------------------------------------ */

  it('G1: no endpoint or DB row ever exposes private material', async () => {
    const initiator = await setupMember(app);
    const responder = await setupMember(app);
    const pairing = await fullPairing(app, initiator, responder);

    const serialized = JSON.stringify(await getView(app, initiator, pairing.relationshipId));
    // Quoted JSON keys: private material can never be a field of any view, and
    // bare-word substring checks are fragile (base64 can contain them by chance).
    for (const forbidden of [
      '"relationshipStaticPrivateKey"',
      '"seed"',
      '"mnemonic"',
      '"sealingKey"',
    ]) {
      expect(serialized).not.toContain(forbidden);
    }

    const rows = await ctx.db
      .select()
      .from(relationships)
      .where(eq(relationships.id, pairing.relationshipId));
    const rowSerialized = JSON.stringify(rows[0]);
    for (const forbidden of [
      '"relationshipStaticPrivateKey"',
      '"sealingKey"',
      '"seed"',
      '"mnemonic"',
      '"ciphertext"',
      '"rk"',
    ]) {
      expect(rowSerialized).not.toContain(forbidden);
    }
  });

  it('G2: an account secret (no device principal) cannot create a relationship offer', async () => {
    const initiator = await setupMember(app);
    const responder = await setupMember(app);
    const res = await app.request('/v1/relationships', {
      method: 'POST',
      headers: jsonHeaders(authHeaders(initiator.accountSecret)),
      body: JSON.stringify({
        partnerUserId: responder.userId,
        epochNonce: toBase64(randomBytes(16)),
        relationshipStaticPublicKey: {
          type: 'x25519',
          value: initiator.staticKey.relationshipStaticPublicKey,
        },
        ephemeralPublicKey: { type: 'x25519', value: createPairingEphemeral().ephemeralPublicKey },
      }),
    });
    expect(res.status).toBe(403);
  });
});

function makeParty(): CanonicalParty {
  return {
    userId: crypto.randomUUID(),
    identityPublicKey: toBase64(new Uint8Array(32)),
    relationshipStaticPublicKey: toBase64(new Uint8Array(32)),
    ephemeralPublicKey: toBase64(new Uint8Array(32)),
    deviceCert: {
      deviceId: crypto.randomUUID(),
      devicePublicKey: toBase64(new Uint8Array(32)),
      keyVersion: 0,
      certSignature: toBase64(new Uint8Array(64)),
    },
  };
}
