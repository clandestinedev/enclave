import 'dart:convert';
import 'dart:math';
import 'dart:typed_data';

import 'package:cryptography/cryptography.dart';

/// Device-local key material. `sealingKey` and `privateKey` NEVER leave the
/// device (they live in platform secure storage); only `publicKeyValue` is
/// ever transmitted to the server (device registration).
///
/// Mirrors `DeviceKeyMaterial` in apps/api/test/reference-client.ts.
class DeviceKeyMaterial {
  const DeviceKeyMaterial({
    required this.privateKey,
    required this.publicKeyValue,
    required this.sealingKey,
    required this.keyVersion,
  });

  final Uint8List privateKey;

  /// Base64 of the 32-byte X25519 public key. Registered on the server.
  final String publicKeyValue;

  /// 256-bit symmetric device sealing key. Random, CSPRNG-generated.
  final Uint8List sealingKey;

  /// Used to build `keyRef` inside the envelope. Currently always 0.
  final int keyVersion;
}

/// Cryptographically secure random bytes.
Uint8List csprng(int length) {
  final random = Random.secure();
  final bytes = Uint8List(length);
  for (var i = 0; i < length; i++) {
    bytes[i] = random.nextInt(256);
  }
  return bytes;
}

/// Derives the X25519 public key base64 string from a raw 32-byte private key.
/// Mirrors `derivePublicKeyValue` in apps/api/test/reference-client.ts.
Future<String> derivePublicKeyValue(Uint8List privateKey) async {
  final x25519 = X25519();
  final keyPair = await x25519.newKeyPairFromSeed(privateKey);
  final publicKey = await keyPair.extractPublicKey();
  return base64Encode(publicKey.bytes);
}

/// Creates a fresh device identity: X25519 keypair + 256-bit sealing key.
/// All randomness comes from the platform CSPRNG.
Future<DeviceKeyMaterial> createDeviceKeyMaterial() async {
  final x25519 = X25519();
  final keyPair = await x25519.newKeyPair();
  final publicKey = await keyPair.extractPublicKey();

  final sealingKey = csprng(32);

  final privateKey = Uint8List.fromList(await keyPair.extractPrivateKeyBytes());

  return DeviceKeyMaterial(
    privateKey: privateKey,
    publicKeyValue: base64Encode(publicKey.bytes),
    sealingKey: sealingKey,
    keyVersion: 0,
  );
}