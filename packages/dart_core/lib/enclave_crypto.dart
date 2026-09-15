library enclave_crypto;

export 'src/keys.dart'
    show DeviceKeyMaterial, createDeviceKeyMaterial, derivePublicKeyValue, csprng;
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
export 'src/recovery.dart'
    show
        IdentityKeyMaterial,
        RecoveryBlobEnvelope,
        mnemonicToSeed,
        deriveIdentity,
        recoveryChallengeMessage,
        signRecoveryChallenge,
        sealRecoveryBlob,
        openRecoveryBlob,
        parseRecoveryBlobEnvelope,
        identitySigningSalt,
        recoveryWrapSalt,
        recoveryMessagePrefix;