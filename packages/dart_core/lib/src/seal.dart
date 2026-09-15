import 'dart:convert';
import 'dart:typed_data';

import 'package:cryptography/cryptography.dart';

import 'keys.dart';

const int payloadVersion = 1;
const String payloadAlg = 'xchacha20poly1305';
const int tagLength = 16;
const int nonceLength = 24;
const String aadPrefix = 'enclave/payload-v1/';

/// Mirrors `EncryptedPayloadEnvelope` in packages/contracts.
class EncryptedPayloadEnvelope {
  const EncryptedPayloadEnvelope({
    required this.v,
    required this.alg,
    required this.keyRef,
    required this.nonce,
    required this.ciphertext,
  });

  final int v;
  final String alg;
  final String keyRef;
  final String nonce;
  final String ciphertext;

  Map<String, dynamic> toJson() => {
        'v': v,
        'alg': alg,
        'keyRef': keyRef,
        'nonce': nonce,
        'ciphertext': ciphertext,
      };
}

/// Strictly validates an envelope exactly as the server does (zod schema in
/// packages/contracts). Throws [FormatException] on any violation.
EncryptedPayloadEnvelope parseEnvelope(Map<String, dynamic> json) {
  final v = json['v'];
  final alg = json['alg'];
  final keyRef = json['keyRef'];
  final nonce = json['nonce'];
  final ciphertext = json['ciphertext'];

  if (v != payloadVersion) throw const FormatException('unsupported envelope version');
  if (alg != payloadAlg) throw const FormatException('unsupported envelope algorithm');
  if (keyRef is! String || keyRef.isEmpty || keyRef.length > 255) {
    throw const FormatException('malformed keyRef');
  }
  if (nonce is! String) throw const FormatException('malformed nonce');
  if (base64Decode(nonce).length != nonceLength) {
    throw const FormatException('nonce must be 24 bytes');
  }
  if (ciphertext is! String) throw const FormatException('malformed ciphertext');
  if (base64Decode(ciphertext).length < tagLength) {
    throw const FormatException('ciphertext must include a 16-byte tag');
  }

  return EncryptedPayloadEnvelope(
    v: payloadVersion,
    alg: payloadAlg,
    keyRef: keyRef,
    nonce: nonce,
    ciphertext: ciphertext,
  );
}

Uint8List aadFor(String keyRef) => Uint8List.fromList(utf8.encode('$aadPrefix$keyRef'));

Xchacha20 _xchacha20() => Xchacha20.poly1305Aead();

/// Seals `plaintext` for `deviceId` under the device sealing key.
/// Returns an envelope ready to POST to /v1/payloads.
Future<EncryptedPayloadEnvelope> sealPayload(
  DeviceKeyMaterial material,
  String deviceId,
  List<int> plaintext,
) async {
  final keyRef = '$deviceId:${material.keyVersion}';
  final nonce = csprng(nonceLength);
  final box = await _xchacha20().encrypt(
    plaintext,
    secretKey: SecretKey(material.sealingKey),
    nonce: nonce,
    aad: aadFor(keyRef),
  );
  final ciphertext = Uint8List.fromList([...box.cipherText, ...box.mac.bytes]);
  return EncryptedPayloadEnvelope(
    v: payloadVersion,
    alg: payloadAlg,
    keyRef: keyRef,
    nonce: base64Encode(nonce),
    ciphertext: base64Encode(ciphertext),
  );
}

/// Opens an envelope with the device sealing key. Throws
/// [SecretBoxAuthenticationError] on any MAC mismatch (tampered ciphertext,
/// wrong device, wrong key version, wrong AAD) and [FormatException] on
/// envelope violations.
Future<Uint8List> openPayload(
  DeviceKeyMaterial material,
  Map<String, dynamic> envelopeJson,
) async {
  final envelope = parseEnvelope(envelopeJson);
  final rawCiphertext = base64Decode(envelope.ciphertext);
  final cipherText = rawCiphertext.sublist(0, rawCiphertext.length - tagLength);
  final mac = rawCiphertext.sublist(rawCiphertext.length - tagLength);

  final cipher = _xchacha20();
  final box = SecretBox(
    cipherText,
    nonce: base64Decode(envelope.nonce),
    mac: Mac(mac),
  );

  return Uint8List.fromList(await cipher.decrypt(box, secretKey: SecretKey(material.sealingKey), aad: aadFor(envelope.keyRef)));
}