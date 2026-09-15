import 'dart:convert';
import 'dart:io';
import 'dart:typed_data';

import 'package:enclave_crypto/enclave_crypto.dart';
import 'package:test/test.dart';

void main() {
  late Map<String, dynamic> vector;

  setUpAll(() {
    final file = File('../../packages/contracts/test-vectors/recovery-v1.json');
    vector = jsonDecode(file.readAsStringSync()) as Map<String, dynamic>;
  });

  group('recovery interop vector', () {
    test('BIP39 seed derivation matches committed vector', () async {
      final seed = await mnemonicToSeed(vector['mnemonic'] as String, vector['passphrase'] as String);
      expect(base64Encode(seed), vector['seed']);
    });

    test('identity public key derived from vector mnemonic is byte-identical', () async {
      final identity = await deriveIdentity(vector['mnemonic'] as String, vector['passphrase'] as String);
      expect(identity.identityPublicKeyValue, vector['identityPublicKeyValue']);
      expect(base64Encode(identity.signingPrivateKey), vector['signingPrivateKey']);
      expect(base64Encode(identity.wrappingKey), vector['wrappingKey']);
    });

    test('recovery challenge message bytes match', () {
      final message = recoveryChallengeMessage(
        userId: vector['userId'] as String,
        challengeId: vector['challengeId'] as String,
        devicePublicKeyValue: vector['devicePublicKeyValue'] as String,
      );
      expect(bytesToHex(message), vector['messageHex']);
    });

    test('Ed25519 signature is byte-identical', () async {
      final identity = await deriveIdentity(vector['mnemonic'] as String, vector['passphrase'] as String);
      final sig = await signRecoveryChallenge(
        identity,
        userId: vector['userId'] as String,
        challengeId: vector['challengeId'] as String,
        devicePublicKeyValue: vector['devicePublicKeyValue'] as String,
      );
      expect(sig, vector['signature']);
    });

    test('blob opens to the committed device key material', () async {
      final identity = await deriveIdentity(vector['mnemonic'] as String, vector['passphrase'] as String);
      final blobMap = vector['blob'] as Map<String, dynamic>;
      final material = await openRecoveryBlob(blobMap, identity.wrappingKey);

      expect(material.keyVersion, vector['keyVersion']);
      expect(base64Encode(material.privateKey), vector['devicePrivateKey']);
      expect(material.publicKeyValue, vector['devicePublicKeyValue']);
      expect(base64Encode(material.sealingKey), vector['deviceSealingKey']);
    });

    test('blob re-sealed with fixed nonce reproduces committed ciphertext', () async {
      final identity = await deriveIdentity(vector['mnemonic'] as String, vector['passphrase'] as String);
      final material = DeviceKeyMaterial(
        privateKey: Uint8List.fromList(base64Decode(vector['devicePrivateKey'] as String)),
        publicKeyValue: vector['devicePublicKeyValue'] as String,
        sealingKey: Uint8List.fromList(base64Decode(vector['deviceSealingKey'] as String)),
        keyVersion: vector['keyVersion'] as int,
      );
      final nonce = base64Decode((vector['blob'] as Map<String, dynamic>)['nonce'] as String);

      final resealed = await sealRecoveryBlob(
        material,
        vector['userId'] as String,
        vector['deviceId'] as String,
        identity.wrappingKey,
        nonce,
      );
      expect(resealed.ciphertext, (vector['blob'] as Map<String, dynamic>)['ciphertext']);
    });
  });
}

String bytesToHex(List<int> bytes) {
  return bytes.map((b) => b.toRadixString(16).padLeft(2, '0')).join();
}