import 'dart:convert';
import 'dart:io';
import 'dart:typed_data';

import 'package:enclave_crypto/enclave_crypto.dart';
import 'package:test/test.dart';

/// Loads the committed cross-language interop vector.
/// Tests run with cwd = packages/dart_core; the vector lives in
/// packages/contracts/test-vectors/interop-v1.json.
Map<String, dynamic> _loadVector() {
  final path = '../contracts/test-vectors/interop-v1.json';
  if (!File(path).existsSync()) {
    fail('vector not found at $path (run tests from packages/dart_core)');
  }
  return jsonDecode(File(path).readAsStringSync()) as Map<String, dynamic>;
}

void main() {
  final vector = _loadVector();

  DeviceKeyMaterial material() => DeviceKeyMaterial(
        privateKey: Uint8List.fromList(base64Decode(vector['privateKey'] as String)),
        publicKeyValue: vector['publicKey'] as String,
        sealingKey: Uint8List.fromList(base64Decode(vector['sealingKey'] as String)),
        keyVersion: vector['keyVersion'] as int,
      );

  group('cross-language interop (vector: packages/contracts/test-vectors/interop-v1.json)', () {
    test('Dart derives the vector X25519 public key from the private key', () async {
      final derived = await derivePublicKeyValue(
        Uint8List.fromList(base64Decode(vector['privateKey'] as String)),
      );
      expect(derived, vector['publicKey']);
    });

    test('Dart seal with fixed nonce is byte-identical to vector (TS) ciphertext', () async {
      final envelope = await sealPayload(
        material(),
        vector['deviceId'] as String,
        base64Decode(vector['plaintext'] as String),
        Uint8List.fromList(base64Decode(vector['nonce'] as String)),
      );
      expect(envelope.toJson(), vector['envelope']);
    });

    test('Dart opens the vector ciphertext (== TS seal output) to the plaintext', () async {
      final opened = await openPayload(
        material(),
        (vector['envelope'] as Map).cast<String, dynamic>(),
      );
      expect(base64Encode(opened), vector['plaintext']);
    });
  });
}