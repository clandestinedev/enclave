import { Hono } from 'hono';
import {
  acceptRelationshipRequestSchema,
  confirmRelationshipRequestSchema,
  createRelationshipRequestSchema,
  establishRelationshipRequestSchema,
  offerConsentRequestSchema,
} from '@enclave/contracts';

import { type AppEnv, requirePrincipal } from '../../auth/middleware';
import { ok } from '../../lib/envelope';
import { invalidRequest, notFound } from '../../lib/errors';
import type { UsersRepository } from '../../repositories/users';
import type { DevicesRepository } from '../../repositories/devices';
import type { RelationshipService } from '../../services/relationships';

export function relationshipRoutes(
  users: UsersRepository,
  devices: DevicesRepository,
  relationships: RelationshipService,
): Hono<AppEnv> {
  const r = new Hono<AppEnv>();
  r.use('*', requirePrincipal(users, devices));

  // POST /v1/relationships — initiator creates an offer (device principal).
  r.post('/', async (c) => {
    let body: unknown;
    try {
      body = await c.req.json();
    } catch {
      throw invalidRequest('Invalid JSON');
    }
    const parsed = createRelationshipRequestSchema.safeParse(body);
    if (!parsed.success) throw invalidRequest('Invalid relationship offer');

    const view = await relationships.createOffer(
      c.get('userId'),
      c.get('principalDeviceId'),
      parsed.data,
    );
    return c.json(ok(view), 201);
  });

  // POST /v1/relationships/:id/offer-consent — initiator A signs the offer.
  r.post('/:relationshipId/offer-consent', async (c) => {
    let body: unknown;
    try {
      body = await c.req.json();
    } catch {
      throw invalidRequest('Invalid JSON');
    }
    const parsed = offerConsentRequestSchema.safeParse(body);
    if (!parsed.success) throw invalidRequest('Invalid offer consent');

    const view = await relationships.submitOfferConsent(
      c.get('userId'),
      c.get('principalDeviceId'),
      c.req.param('relationshipId'),
      parsed.data.consentSignature,
    );
    return c.json(ok(view));
  });

  // POST /v1/relationships/:id/accept — responder B signs the canonical transcript.
  r.post('/:relationshipId/accept', async (c) => {
    let body: unknown;
    try {
      body = await c.req.json();
    } catch {
      throw invalidRequest('Invalid JSON');
    }
    const parsed = acceptRelationshipRequestSchema.safeParse(body);
    if (!parsed.success) throw invalidRequest('Invalid accept payload');

    const view = await relationships.accept(
      c.get('userId'),
      c.get('principalDeviceId'),
      c.req.param('relationshipId'),
      parsed.data,
    );
    return c.json(ok(view));
  });

  // POST /v1/relationships/:id/confirm — initiator A signs confirmConsent_A.
  r.post('/:relationshipId/confirm', async (c) => {
    let body: unknown;
    try {
      body = await c.req.json();
    } catch {
      throw invalidRequest('Invalid JSON');
    }
    const parsed = confirmRelationshipRequestSchema.safeParse(body);
    if (!parsed.success) throw invalidRequest('Invalid confirm payload');

    const view = await relationships.confirm(
      c.get('userId'),
      c.get('principalDeviceId'),
      c.req.param('relationshipId'),
      parsed.data,
    );
    return c.json(ok(view));
  });

  // POST /v1/relationships/:id/establish — responder B posts sasProof_B.
  r.post('/:relationshipId/establish', async (c) => {
    let body: unknown;
    try {
      body = await c.req.json();
    } catch {
      throw invalidRequest('Invalid JSON');
    }
    const parsed = establishRelationshipRequestSchema.safeParse(body);
    if (!parsed.success) throw invalidRequest('Invalid establish payload');

    const view = await relationships.establish(
      c.get('userId'),
      c.get('principalDeviceId'),
      c.req.param('relationshipId'),
      parsed.data,
    );
    return c.json(ok(view));
  });

  // POST /v1/relationships/:id/reject — responder refusal (pole-authenticated).
  r.post('/:relationshipId/reject', async (c) => {
    const view = await relationships.reject(
      c.get('userId'),
      c.get('principalDeviceId'),
      c.req.param('relationshipId'),
    );
    return c.json(ok(view));
  });

  // POST /v1/relationships/:id/cancel — initiator withdrawal (pole-authenticated).
  r.post('/:relationshipId/cancel', async (c) => {
    const view = await relationships.cancel(
      c.get('userId'),
      c.get('principalDeviceId'),
      c.req.param('relationshipId'),
    );
    return c.json(ok(view));
  });

  // POST /v1/relationships/:id/terminate — breakup (pole-authenticated).
  r.post('/:relationshipId/terminate', async (c) => {
    const view = await relationships.terminate(
      c.get('userId'),
      c.get('principalDeviceId'),
      c.req.param('relationshipId'),
    );
    return c.json(ok(view));
  });

  // GET /v1/relationships/:id
  r.get('/:relationshipId', async (c) => {
    const view = await relationships.getOwn(c.req.param('relationshipId'), c.get('userId'));
    if (!view) throw notFound();
    return c.json(ok(view));
  });

  // GET /v1/relationships
  r.get('/', async (c) => {
    const views = await relationships.listOwn(c.get('userId'));
    return c.json(ok(views));
  });

  return r;
}
