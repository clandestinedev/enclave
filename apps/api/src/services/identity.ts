import type { DevicesRepository } from '../repositories/devices';
import type { EncryptedPayloadsRepository } from '../repositories/payloads';
import type { UsersRepository } from '../repositories/users';
import type { IdentitiesRepository } from '../repositories/identities';
import type {
  PublicKey,
  CertifyDeviceRequest,
  CreateDeviceRequest,
  DeviceView,
} from '@enclave/contracts';
import { newId } from '../lib/id';
import { deviceCertInvalid, forbidden, notFound } from '../lib/errors';
import { deviceCertMessage } from '../lib/relationship';
import { verifyEd25519 } from '../lib/ed25519';

export class IdentityService {
  constructor(private readonly users: UsersRepository) {}

  async createUser(accountSecretHash: string): Promise<{ userId: string; createdAt: Date }> {
    const id = newId();
    const createdAt = new Date();
    await this.users.create({ id, accountSecretHash, createdAt });
    return { userId: id, createdAt };
  }

  async findUserIdByAccountSecretHash(hash: string): Promise<string | null> {
    const user = await this.users.findByAccountSecretHash(hash);
    return user?.id ?? null;
  }
}

export class DeviceService {
  constructor(
    private readonly devices: DevicesRepository,
    private readonly identities: IdentitiesRepository,
  ) {}

  /**
   * Registers a device public key. A device certificate is OPTIONAL at
   * registration for backward compatibility with Phase 1/2 clients, but MUST
   * be provided together with its keyVersion (schema-enforced). Certification
   * is MANDATORY for relationship participation (enforced by
   * RelationshipService, ADR 0004 §7).
   */
  async registerDevice(userId: string, input: CreateDeviceRequest): Promise<DeviceView> {
    const deviceId = newId();
    const createdAt = new Date();
    const certSignature = input.certSignature ?? null;
    const certVersion = input.certVersion ?? null;
    if (certSignature !== null && certVersion !== null) {
      await this.validateCert(userId, {
        deviceId,
        publicKeyValue: input.publicKey.value,
        certVersion,
        certSignature,
      });
    }
    await this.devices.create({
      id: deviceId,
      userId,
      label: input.label ?? null,
      publicKeyType: input.publicKey.type,
      publicKeyValue: input.publicKey.value,
      keyVersion: 0,
      deviceSecretHash: null,
      certSignature,
      certVersion,
      createdAt,
      lastSeenAt: null,
      revokedAt: null,
    });
    return {
      userId,
      deviceId,
      ...(input.label !== undefined ? { label: input.label } : {}),
      publicKey: input.publicKey,
      keyVersion: 0,
      certSignature,
      certVersion,
      createdAt: createdAt.toISOString(),
      lastSeenAt: null,
      revokedAt: null,
    };
  }

  /** Certifies an existing (e.g. recovered) device; account-level route. */
  async certifyDevice(
    userId: string,
    deviceId: string,
    cert: CertifyDeviceRequest,
  ): Promise<DeviceView | null> {
    const device = await this.devices.getById(deviceId);
    if (!device || device.userId !== userId || device.revokedAt !== null) return null;
    await this.validateCert(userId, {
      deviceId,
      publicKeyValue: device.publicKeyValue,
      certVersion: cert.certVersion,
      certSignature: cert.certSignature,
    });
    await this.devices.setCert(deviceId, cert.certSignature, cert.certVersion);
    return toView({
      ...device,
      certSignature: cert.certSignature,
      certVersion: cert.certVersion,
    });
  }

  async getOwnDevice(userId: string, deviceId: string): Promise<DeviceView | null> {
    const device = await this.devices.getById(deviceId);
    if (!device || device.userId !== userId) return null;
    return toView(device);
  }

  async listOwnDevices(userId: string): Promise<DeviceView[]> {
    const devices = await this.devices.listByUserId(userId);
    return devices.filter((d) => d.revokedAt === null).map(toView);
  }

  /**
   * Validates an identity-signed device certificate: Ed25519 over
   * `enclave/device-cert-v1` 0x00 userId 0x00 deviceId 0x00 devicePublicKeyValue
   * 0x00 keyVersion, verified against the account's registered identity key.
   */
  private async validateCert(
    userId: string,
    input: { deviceId: string; publicKeyValue: string; certVersion: number; certSignature: string },
  ): Promise<void> {
    const identity = await this.identities.getByUserId(userId);
    if (!identity) {
      throw deviceCertInvalid('Account has no recovery identity to verify the certificate');
    }
    const message = deviceCertMessage({
      userId,
      deviceId: input.deviceId,
      devicePublicKeyValue: input.publicKeyValue,
      keyVersion: input.certVersion,
    });
    const valid = verifyEd25519(
      Buffer.from(identity.identityPublicKey, 'base64'),
      message,
      Buffer.from(input.certSignature, 'base64'),
    );
    if (!valid) throw deviceCertInvalid();
  }

  async revokeDevice(userId: string, deviceId: string): Promise<DeviceView | null> {
    const device = await this.devices.getById(deviceId);
    if (!device || device.userId !== userId || device.revokedAt !== null) return null;
    const at = new Date();
    await this.devices.revoke(deviceId, at);
    return toView({ ...device, revokedAt: at });
  }
}

export class PayloadService {
  constructor(
    private readonly payloads: EncryptedPayloadsRepository,
    private readonly devices: DevicesRepository,
  ) {}

  async store(
    userId: string,
    deviceId: string,
    envelope: Record<string, unknown>,
  ): Promise<{ payloadId: string; createdAt: Date }> {
    const device = await this.devices.getById(deviceId);
    if (!device || device.userId !== userId) throw notFound();
    if (device.revokedAt !== null) throw forbidden('Device revoked');

    const serialized = JSON.stringify(envelope);
    const payloadId = newId();
    const createdAt = new Date();
    await this.payloads.create({
      id: payloadId,
      userId,
      deviceId,
      envelope: serialized,
      byteLength: Buffer.byteLength(serialized, 'utf8'),
      createdAt,
    });
    return { payloadId, createdAt };
  }

  async getOwn(
    userId: string,
    payloadId: string,
  ): Promise<{
    payloadId: string;
    userId: string;
    deviceId: string;
    byteLength: number;
    createdAt: string;
    envelope: unknown;
  } | null> {
    const record = await this.payloads.getById(payloadId);
    if (!record || record.userId !== userId) return null;
    return {
      payloadId: record.id,
      userId: record.userId,
      deviceId: record.deviceId,
      byteLength: record.byteLength,
      createdAt: record.createdAt.toISOString(),
      envelope: JSON.parse(record.envelope),
    };
  }
}

function toView(device: {
  id: string;
  userId: string;
  label: string | null;
  publicKeyType: string;
  publicKeyValue: string;
  keyVersion: number;
  certSignature: string | null;
  certVersion: number | null;
  createdAt: Date;
  lastSeenAt: Date | null;
  revokedAt: Date | null;
}): DeviceView {
  return {
    userId: device.userId,
    deviceId: device.id,
    ...(device.label !== null ? { label: device.label } : {}),
    publicKey: { type: 'x25519', value: device.publicKeyValue },
    keyVersion: device.keyVersion,
    certSignature: device.certSignature,
    certVersion: device.certVersion,
    createdAt: device.createdAt.toISOString(),
    lastSeenAt: device.lastSeenAt?.toISOString() ?? null,
    revokedAt: device.revokedAt?.toISOString() ?? null,
  };
}

export type { PublicKey };
