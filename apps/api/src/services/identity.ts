import type { DevicesRepository } from '../repositories/devices';
import type { EncryptedPayloadsRepository } from '../repositories/payloads';
import type { UsersRepository } from '../repositories/users';
import type { PublicKey, DeviceView } from '@enclave/contracts';
import { newId } from '../lib/id';
import { forbidden, notFound } from '../lib/errors';

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
  constructor(private readonly devices: DevicesRepository) {}

  async registerDevice(
    userId: string,
    input: { label?: string | undefined; publicKey: PublicKey },
  ): Promise<DeviceView> {
    const deviceId = newId();
    const createdAt = new Date();
    await this.devices.create({
      id: deviceId,
      userId,
      label: input.label ?? null,
      publicKeyType: input.publicKey.type,
      publicKeyValue: input.publicKey.value,
      keyVersion: 0,
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
      createdAt: createdAt.toISOString(),
      lastSeenAt: null,
      revokedAt: null,
    };
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
    createdAt: device.createdAt.toISOString(),
    lastSeenAt: device.lastSeenAt?.toISOString() ?? null,
    revokedAt: device.revokedAt?.toISOString() ?? null,
  };
}

export type { PublicKey };
