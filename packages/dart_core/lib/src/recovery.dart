import 'dart:convert';
import 'dart:typed_data';

import 'package:cryptography/cryptography.dart';

import 'keys.dart';
import 'seal.dart';

/// Phase 2 identity / recovery crypto. Mirrors
/// `apps/api/test/reference-recovery.ts` (executable specification).
///
/// The server only ever sees the identity public key, a challenge, an Ed25519
/// signature, and an OPAQUE recovery blob. The mnemonic, BIP39 seed, identity
/// private key, and recovery wrapping key never leave the device.
/// BIP39-derived material NEVER encrypts application content — the wrapping
/// key only wraps device key material (ADR 0003 §5).

const String identitySigningSalt = 'enclave/identity-signing-v1';
const String identitySigningInfo = 'ed25519';
const String recoveryWrapSalt = 'enclave/recovery-wrap-v1';
const String recoveryWrapInfo = 'xchacha20';
const String recoveryMessagePrefix = 'enclave/recovery-v1';
const String recoveryBlobAadPrefix = 'enclave/recovery-blob-v1/';
const int blobVersion = 1;
const String blobAlg = 'xchacha20poly1305';
const int recoveryNonceLength = 24;

/// Identity + recovery key material derived from a BIP39 mnemonic + optional
/// passphrase. Mirrors `IdentityKeyMaterial` in reference-recovery.ts.
class IdentityKeyMaterial {
  const IdentityKeyMaterial({
    required this.seed,
    required this.signingPrivateKey,
    required this.identityPublicKeyValue,
    required this.wrappingKey,
  });

  /// 64-byte BIP39 seed. Never persisted.
  final Uint8List seed;

  /// 32-byte Ed25519 seed used to sign recovery challenges.
  final Uint8List signingPrivateKey;

  /// Base64 Ed25519 public key — the account's recovery anchor.
  final String identityPublicKeyValue;

  /// 32-byte XChaCha20 key that wraps device key material.
  final Uint8List wrappingKey;
}

/// Opaque recovery blob envelope. Mirrors `RecoveryBlobEnvelope`.
class RecoveryBlobEnvelope {
  const RecoveryBlobEnvelope({
    required this.v,
    required this.alg,
    required this.userId,
    required this.deviceId,
    required this.keyVersion,
    required this.nonce,
    required this.ciphertext,
  });

  final int v;
  final String alg;
  final String userId;
  final String deviceId;
  final int keyVersion;
  final String nonce;
  final String ciphertext;

  Map<String, dynamic> toJson() => {
        'v': v,
        'alg': alg,
        'userId': userId,
        'deviceId': deviceId,
        'keyVersion': keyVersion,
        'nonce': nonce,
        'ciphertext': ciphertext,
      };
}

/// BIP39 mnemonic → 64-byte seed (PBKDF2-HMAC-SHA512, 2048 rounds, salt
/// "mnemonic" + passphrase). The passphrase is OPTIONAL for MVP; if enabled it
/// is required for recovery and is never stored by Enclave.
Future<Uint8List> mnemonicToSeed(String mnemonic, [String passphrase = '']) async {
  final pbkdf2 = Pbkdf2(
    macAlgorithm: Hmac.sha512(),
    iterations: 2048,
    bits: 512,
  );
  final seed = await pbkdf2.deriveKey(
    secretKey: SecretKey(utf8.encode(mnemonic)),
    nonce: utf8.encode('mnemonic$passphrase'),
  );
  return Uint8List.fromList(await seed.extractBytes());
}

/// Derives the identity + recovery key material from a BIP39 mnemonic and an
/// optional passphrase. Mirrors `deriveIdentity` in reference-recovery.ts.
Future<IdentityKeyMaterial> deriveIdentity(String mnemonic, [String passphrase = '']) async {
  final seed = await mnemonicToSeed(mnemonic, passphrase);

  final signingSecret = await Hkdf(
    hmac: Hmac.sha512(),
    outputLength: 32,
  ).deriveKey(
    secretKey: SecretKey(seed),
    nonce: utf8.encode(identitySigningSalt),
    info: utf8.encode(identitySigningInfo),
  );

  final wrapSecret = await Hkdf(
    hmac: Hmac.sha512(),
    outputLength: 32,
  ).deriveKey(
    secretKey: SecretKey(seed),
    nonce: utf8.encode(recoveryWrapSalt),
    info: utf8.encode(recoveryWrapInfo),
  );

  final signingPrivateKey = Uint8List.fromList(await signingSecret.extractBytes());
  final identityPublicKey = await ed25519PublicKey(signingPrivateKey);

  return IdentityKeyMaterial(
    seed: seed,
    signingPrivateKey: signingPrivateKey,
    identityPublicKeyValue: identityPublicKey,
    wrappingKey: Uint8List.fromList(await wrapSecret.extractBytes()),
  );
}

Future<String> ed25519PublicKey(Uint8List seed) async {
  final keyPair = await Ed25519().newKeyPairFromSeed(seed);
  final publicKey = await keyPair.extractPublicKey();
  return base64Encode(publicKey.bytes);
}

Uint8List _text(String s) => Uint8List.fromList(utf8.encode(s));

/// Byte-exact Ed25519 message signed to prove control of an identity.
/// Layout: "enclave/recovery-v1" 0x00 userId 0x00 challengeId 0x00 devicePublicKeyValue
Uint8List recoveryChallengeMessage({
  required String userId,
  required String challengeId,
  required String devicePublicKeyValue,
}) {
  final parts = <Uint8List>[
    _text(recoveryMessagePrefix),
    Uint8List.fromList(const [0]),
    _text(userId),
    Uint8List.fromList(const [0]),
    _text(challengeId),
    Uint8List.fromList(const [0]),
    _text(devicePublicKeyValue),
  ];
  final out = Uint8List(parts.fold<int>(0, (n, p) => n + p.length));
  var offset = 0;
  for (final part in parts) {
    out.setAll(offset, part);
    offset += part.length;
  }
  return out;
}

/// Signs the recovery challenge with the identity signing key. Returns the
/// base64 Ed25519 signature. Mirrors `signRecoveryChallenge`.
Future<String> signRecoveryChallenge(
  IdentityKeyMaterial identity, {
  required String userId,
  required String challengeId,
  required String devicePublicKeyValue,
}) async {
  final message = recoveryChallengeMessage(
    userId: userId,
    challengeId: challengeId,
    devicePublicKeyValue: devicePublicKeyValue,
  );
  final keyPair = await Ed25519().newKeyPairFromSeed(identity.signingPrivateKey);
  final signature = await Ed25519().sign(message, keyPair: keyPair);
  return base64Encode(signature.bytes);
}

Uint8List _blobAad(String userId, String deviceId, int keyVersion) =>
    _text('$recoveryBlobAadPrefix$userId/$deviceId/$keyVersion');

/// Seals a device's full key material under the recovery wrapping key.
/// Returns an envelope ready to POST to /v1/recovery/blobs.
/// `[nonceOverride]` is TEST-ONLY (mirrors `sealPayload`).
Future<RecoveryBlobEnvelope> sealRecoveryBlob(
  DeviceKeyMaterial material,
  String userId,
  String deviceId,
  Uint8List wrappingKey, [
  Uint8List? nonceOverride,
]) async {
  final plaintext = utf8.encode(jsonEncode({
    'v': blobVersion,
    'deviceId': deviceId,
    'keyVersion': material.keyVersion,
    'sealingKey': base64Encode(material.sealingKey),
    'privateKey': base64Encode(material.privateKey),
    'publicKeyValue': material.publicKeyValue,
  }));
  final nonce = nonceOverride ?? csprng(recoveryNonceLength);
  final box = await Xchacha20.poly1305Aead().encrypt(
    plaintext,
    secretKey: SecretKey(wrappingKey),
    nonce: nonce,
    aad: _blobAad(userId, deviceId, material.keyVersion),
  );
  final ciphertext = Uint8List.fromList([...box.cipherText, ...box.mac.bytes]);
  return RecoveryBlobEnvelope(
    v: blobVersion,
    alg: blobAlg,
    userId: userId,
    deviceId: deviceId,
    keyVersion: material.keyVersion,
    nonce: base64Encode(nonce),
    ciphertext: base64Encode(ciphertext),
  );
}

/// Opens a recovery blob and reconstructs the device key material. Throws
/// [SecretBoxAuthenticationError] on tampering and [FormatException] on
/// malformed envelopes.
Future<DeviceKeyMaterial> openRecoveryBlob(
  Map<String, dynamic> envelopeJson,
  Uint8List wrappingKey,
) async {
  final envelope = parseRecoveryBlobEnvelope(envelopeJson);
  final rawCiphertext = base64Decode(envelope.ciphertext);
  final cipherText = rawCiphertext.sublist(0, rawCiphertext.length - tagLength);
  final mac = rawCiphertext.sublist(rawCiphertext.length - tagLength);

  final cipher = Xchacha20.poly1305Aead();
  final box = SecretBox(
    cipherText,
    nonce: base64Decode(envelope.nonce),
    mac: Mac(mac),
  );
  final plaintext = await cipher.decrypt(
    box,
    secretKey: SecretKey(wrappingKey),
    aad: _blobAad(envelope.userId, envelope.deviceId, envelope.keyVersion),
  );

  final payload = jsonDecode(utf8.decode(plaintext)) as Map<String, dynamic>;
  return DeviceKeyMaterial(
    privateKey: Uint8List.fromList(base64Decode(payload['privateKey'] as String)),
    publicKeyValue: payload['publicKeyValue'] as String,
    sealingKey: Uint8List.fromList(base64Decode(payload['sealingKey'] as String)),
    keyVersion: payload['keyVersion'] as int,
  );
}

/// Strictly validates a recovery blob envelope exactly as the server does
/// (zod schema in packages/contracts). Throws [FormatException] on violation.
RecoveryBlobEnvelope parseRecoveryBlobEnvelope(Map<String, dynamic> json) {
  final v = json['v'];
  final alg = json['alg'];
  final userId = json['userId'];
  final deviceId = json['deviceId'];
  final keyVersion = json['keyVersion'];
  final nonce = json['nonce'];
  final ciphertext = json['ciphertext'];

  if (v != blobVersion) throw const FormatException('unsupported blob version');
  if (alg != blobAlg) throw const FormatException('unsupported blob algorithm');
  if (userId is! String || userId.isEmpty) throw const FormatException('malformed userId');
  if (deviceId is! String || deviceId.isEmpty) throw const FormatException('malformed deviceId');
  if (keyVersion is! int || keyVersion < 0) throw const FormatException('malformed keyVersion');
  if (nonce is! String) throw const FormatException('malformed nonce');
  if (base64Decode(nonce).length != recoveryNonceLength) {
    throw const FormatException('nonce must be 24 bytes');
  }
  if (ciphertext is! String) throw const FormatException('malformed ciphertext');
  if (base64Decode(ciphertext).length < tagLength) {
    throw const FormatException('ciphertext must include a 16-byte tag');
  }

  return RecoveryBlobEnvelope(
    v: blobVersion,
    alg: blobAlg,
    userId: userId,
    deviceId: deviceId,
    keyVersion: keyVersion,
    nonce: nonce,
    ciphertext: ciphertext,
  );
}