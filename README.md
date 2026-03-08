# react-native-dpop

React Native library for DPoP proof generation and key management.

## Features

- Generate DPoP proofs (`dpop+jwt`) signed with ES256.
- Manage key pairs in the device keystore (create, rotate, delete).
- Export public key in `JWK`, `DER`, or `RAW` format.
- Calculate JWK thumbprint (`SHA-256`, base64url).
- Verify if a proof is bound to a given key alias.
- Retrieve non-sensitive key metadata (hardware-backed, StrongBox info, etc.).
- iOS key storage uses Secure Enclave when available, with Keychain fallback.

## Platform Support

- Android: supported.
- iOS: supported.

## Installation

```sh
npm install react-native-dpop
```

For iOS, install pods in your app project:

```sh
cd ios && pod install
```

## Quick Start

```ts
import { DPoP } from 'react-native-dpop';

const dpop = await DPoP.generateProof({
  htu: 'https://api.example.com/token',
  htm: 'POST',
  accessToken: 'ACCESS_TOKEN',
  nonce: 'server-nonce',
});

const proof = dpop.proof;
const thumbprint = await dpop.calculateThumbprint();
const publicJwk = await dpop.getPublicKey('JWK');
const isBound = await dpop.isBoundToAlias();
```

## API

### Types

- `GenerateProofInput`
- `DPoPProofContext`
- `DPoPKeyInfo`
- `SecureHardwareFallbackReason = 'UNAVAILABLE' | 'PROVIDER_ERROR' | 'POLICY_REJECTED' | 'UNKNOWN'`
- `PublicJwk`
- `PublicKeyFormat = 'JWK' | 'DER' | 'RAW'`

### `DPoP` static methods

- `DPoP.generateProof(input): Promise<DPoP>`
- `DPoP.assertHardwareBacked(alias?): Promise<void>`
- `DPoP.deleteKeyPair(alias?): Promise<void>`
- `DPoP.getKeyInfo(alias?): Promise<DPoPKeyInfo>`
- `DPoP.hasKeyPair(alias?): Promise<boolean>`
- `DPoP.rotateKeyPair(alias?): Promise<void>`

### `DPoP` instance fields

- `proof: string`
- `proofContext: DPoPProofContext`
- `alias?: string`

### `DPoP` instance methods

- `calculateThumbprint(): Promise<string>`
- `getPublicKey(format): Promise<PublicJwk | string>`
- `signWithDpopPrivateKey(payload): Promise<string>`
- `isBoundToAlias(alias?): Promise<boolean>`

## Error Codes

Native errors are rejected with codes such as:

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

## Notes

- If no alias is provided, the default alias is `react-native-dpop`.
- `getKeyInfo` returns cross-platform fields and platform-specific details in `hardware`:
  - Android: `hardware.android.strongBoxAvailable`, `hardware.android.strongBoxBacked`, `hardware.android.securityLevel`, `hardware.android.strongBoxFallbackReason`
  - iOS: `hardware.ios.secureEnclaveAvailable`, `hardware.ios.secureEnclaveBacked`, `hardware.ios.securityLevel`, `hardware.ios.secureEnclaveFallbackReason`
- Fallback reasons are sanitized enums (no raw native error): `UNAVAILABLE`, `PROVIDER_ERROR`, `POLICY_REJECTED`, `UNKNOWN`.
- `securityLevel` semantics:
  - `null`: no key material available (or not reported)
  - `1`: not backed by secure enclave/strong dedicated hardware
  - `2`: hardware-backed (iOS Secure Enclave, Android typically TEE)
  - `3`: Android-only StrongBox (when reported by the device)
- On iOS, `securityLevel` is normalized by this library (`2` for Secure Enclave-backed keys, `1` for Keychain fallback), not a native Apple numeric level API.
- `htm` is normalized to uppercase in proof generation.
- `ath` is derived from `accessToken` (`SHA-256`, base64url) when provided.
- `jti` and `iat` are auto-generated when omitted.

## Contributing

- [Development workflow](CONTRIBUTING.md#development-workflow)
- [Sending a pull request](CONTRIBUTING.md#sending-a-pull-request)
- [Code of conduct](CODE_OF_CONDUCT.md)

## License

MIT
