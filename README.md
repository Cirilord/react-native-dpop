# react-native-dpop

React Native library for DPoP proof generation and key management.

## Features

- Generate DPoP proofs (`dpop+jwt`) signed with ES256
- Manage key pairs in the platform keystore
- Export the public key as `JWK`, `DER`, or `RAW`
- Calculate JWK thumbprints (`SHA-256`, base64url)
- Verify whether a proof is bound to a given key alias
- Retrieve non-sensitive key metadata, including secure hardware details
- Use Secure Enclave on iOS when available, with Keychain fallback
- Prefer StrongBox on Android when available, with hardware-backed fallback

## Platform support

- Android
- iOS

## Installation

```sh
npm install react-native-dpop
```

For iOS:

```sh
cd ios && pod install
```

## Quick start

```ts
import { DPoP } from 'react-native-dpop';

const dPoP = await DPoP.generateProof({
  htu: 'https://api.example.com/token',
  htm: 'POST',
  accessToken: 'ACCESS_TOKEN',
  nonce: 'SERVER_NONCE',
});

const proof = dPoP.proof;
const thumbprint = await dPoP.calculateThumbprint();
const publicJwk = await dPoP.getPublicKey('JWK');
const keyInfo = await DPoP.getKeyInfo();
```

## API

### Static methods

- `DPoP.generateProof(input): Promise<DPoP>`
- `DPoP.assertHardwareBacked(alias?): Promise<void>`
- `DPoP.deleteKeyPair(alias?): Promise<void>`
- `DPoP.getKeyInfo(alias?): Promise<DPoPKeyInfo>`
- `DPoP.hasKeyPair(alias?): Promise<boolean>`
- `DPoP.rotateKeyPair(alias?): Promise<void>`

### Instance members

- `proof: string`
- `proofContext: DPoPProofContext`
- `alias?: string`
- `calculateThumbprint(): Promise<string>`
- `getPublicKey(format): Promise<PublicJwk | string>`
- `signWithDPoPPrivateKey(payload): Promise<string>`
- `isBoundToAlias(alias?): Promise<boolean>`

### Main types

- `GenerateProofInput`
- `DPoPProofContext`
- `DPoPKeyInfo`
- `PublicJwk`
- `PublicKeyFormat = 'JWK' | 'DER' | 'RAW'`
- `SecureHardwareFallbackReason = 'UNAVAILABLE' | 'PROVIDER_ERROR' | 'POLICY_REJECTED' | 'UNKNOWN'`
- `AndroidSecurityLevelName = 'SOFTWARE' | 'TRUSTED_ENVIRONMENT' | 'STRONGBOX'`
- `IOSSecurityLevelName = 'SOFTWARE' | 'SECURE_ENCLAVE'`

## `getKeyInfo()`

`getKeyInfo()` returns shared fields plus platform-specific hardware metadata.

```ts
type DPoPKeyInfo = {
  alias: string;
  hasKeyPair: boolean;
  algorithm?: string;
  curve?: string;
  insideSecureHardware?: boolean;
  hardware?: {
    android?: {
      strongBoxAvailable: boolean;
      strongBoxBacked: boolean;
      securityLevel?: number;
      securityLevelName?: 'SOFTWARE' | 'TRUSTED_ENVIRONMENT' | 'STRONGBOX';
      strongBoxFallbackReason?: 'UNAVAILABLE' | 'PROVIDER_ERROR' | 'POLICY_REJECTED' | 'UNKNOWN' | null;
    };
    ios?: {
      secureEnclaveAvailable: boolean;
      secureEnclaveBacked: boolean;
      securityLevel?: number | null;
      securityLevelName?: 'SOFTWARE' | 'SECURE_ENCLAVE';
      secureEnclaveFallbackReason?: 'UNAVAILABLE' | 'PROVIDER_ERROR' | 'POLICY_REJECTED' | 'UNKNOWN' | null;
    };
  };
};
```

### Security level semantics

- `securityLevel = 1`
  Software-backed key material
- `securityLevel = 2`
  Hardware-backed key material
  On Android this usually means TEE
  On iOS this means Secure Enclave
- `securityLevel = 3`
  Android StrongBox-backed key
- `securityLevel = null`
  No key material available, or the native platform did not report a numeric level

### Fallback semantics

- On Android, the library tries StrongBox first when available
- On iOS, the library tries Secure Enclave first when available
- Fallback reasons are sanitized enums rather than raw native errors
- On iOS Simulator, `secureEnclaveFallbackReason` is expected to be `UNAVAILABLE`

## Notes

- Default alias: `react-native-dpop`
- `htm` is normalized to uppercase
- `ath` is derived from `accessToken` when provided
- `jti` and `iat` are auto-generated when omitted
- For React Native 0.75 on Android, the library ensures `iat` is sent as a number to avoid an older bridge nullability issue with `Double`

## Example apps

This repository includes two example apps:

- `examples/v0.75`
- `examples/v0.83`

The root `example` script points to `examples/v0.83`.

## Errors

Native rejections use codes such as:

- `ERR_DPOP_GENERATE_PROOF`
- `ERR_DPOP_CALCULATE_THUMBPRINT`
- `ERR_DPOP_PUBLIC_KEY`
- `ERR_DPOP_SIGN_WITH_PRIVATE_KEY`
- `ERR_DPOP_HAS_KEY_PAIR`
- `ERR_DPOP_GET_KEY_INFO`
- `ERR_DPOP_ROTATE_KEY_PAIR`
- `ERR_DPOP_DELETE_KEY_PAIR`
- `ERR_DPOP_ASSERT_HARDWARE_BACKED`
- `ERR_DPOP_IS_BOUND_TO_ALIAS`

## Contributing

- [Development workflow](CONTRIBUTING.md#development-workflow)
- [Sending a pull request](CONTRIBUTING.md#sending-a-pull-request)
- [Code of conduct](CODE_OF_CONDUCT.md)

## License

MIT
