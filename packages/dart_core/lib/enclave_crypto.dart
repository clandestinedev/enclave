library enclave_crypto;

export 'src/keys.dart'
    show DeviceKeyMaterial, createDeviceKeyMaterial, csprng;
export 'src/seal.dart'
    show
        EncryptedPayloadEnvelope,
        parseEnvelope,
        sealPayload,
        openPayload,
        payloadVersion,
        payloadAlg,
        nonceLength,
        tagLength,
        aadPrefix;