import 'dart:convert';

import 'package:cryptography/cryptography.dart';
import 'package:enclave_crypto/enclave_crypto.dart';
import 'package:test/test.dart';

Future<({DeviceKeyMaterial material, String deviceId})> makeDevice() async {
  final material = await createDeviceKeyMaterial();
  return (material: material, deviceId: '01950000-0000-7000-8000-000000000001');
}

void main() {
  test('generates X25519 public key + sealing key material', () async {
    final m = await createDeviceKeyMaterial();
    expect(m.privateKey.length, 32);
    expect(m.keyVersion, 0);
    expect(base64Decode(m.publicKeyValue).length, 32);
    expect(m.sealingKey.length, 32);
  });

  test('seal -> open roundtrip', () async {
    final d = await makeDevice();
    final plaintext = utf8.encode('{"kind":"test","message":"secret hello"}');

    final envelope = await sealPayload(d.material, d.deviceId, plaintext);
    expect(envelope.v, 1);
    expect(envelope.alg, 'xchacha20poly1305');
    expect(envelope.keyRef, '${d.deviceId}:0');
    expect(base64Decode(envelope.nonce).length, 24);

    final opened = await openPayload(d.material, envelope.toJson());
    expect(utf8.decode(opened), '{"kind":"test","message":"secret hello"}');
  });

  test('rejects tampered ciphertext', () async {
    final d = await makeDevice();
    final envelope = await sealPayload(d.material, d.deviceId, utf8.encode('original'));

    final bytes = base64Decode(envelope.ciphertext);
    bytes[0] ^= 0xff;
    expect(
      () => openPayload(
        d.material,
        {...envelope.toJson(), 'ciphertext': base64Encode(bytes)},
      ),
      throwsA(isA<SecretBoxAuthenticationError>()),
    );
  });

  test('a different device cannot open a payload', () async {
    final alice = await makeDevice();
    final bob = await createDeviceKeyMaterial();
    final envelope = await sealPayload(alice.material, alice.deviceId, utf8.encode('mine'));

    expect(
      () => openPayload(
        DeviceKeyMaterial(
          privateKey: bob.privateKey,
          publicKeyValue: bob.publicKeyValue,
          sealingKey: bob.sealingKey,
          keyVersion: bob.keyVersion,
        ),
        envelope.toJson(),
      ),
      throwsA(isA<SecretBoxAuthenticationError>()),
    );
  });

  test('rejects tampered keyRef (AAD mismatch)', () async {
    final d = await makeDevice();
    final envelope = await sealPayload(d.material, d.deviceId, utf8.encode('mine'));

    expect(
      () => openPayload(
        d.material,
        {...envelope.toJson(), 'keyRef': '0195ffff-0000-7000-8000-000000000099:0'},
      ),
      throwsA(isA<SecretBoxAuthenticationError>()),
    );
  });

  test('rejects unsupported version and algorithm', () {
    final d = {
      'v': payloadVersion,
      'alg': payloadAlg,
      'keyRef': '01950000-0000-7000-8000-000000000001:0',
      'nonce': base64Encode(csprng(24)),
      'ciphertext': base64Encode(csprng(32)),
    };

    expect(() => parseEnvelope({...d, 'v': 2}), throwsA(isA<FormatException>()));
    expect(() => parseEnvelope({...d, 'alg': 'aes-256-gcm'}), throwsA(isA<FormatException>()));
    expect(() => parseEnvelope({...d, 'nonce': base64Encode(csprng(4))}), throwsA(isA<FormatException>()));
    expect(() => parseEnvelope({...d, 'ciphertext': base64Encode(csprng(4))}), throwsA(isA<FormatException>()));
  });
}