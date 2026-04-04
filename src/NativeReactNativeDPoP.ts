import type { TurboModule } from 'react-native';
import { NativeModules, TurboModuleRegistry } from 'react-native';
import type { UnsafeObject } from 'react-native/Libraries/Types/CodegenTypes';

export interface Spec extends TurboModule {
  assertHardwareBacked(alias: string | null): Promise<void>;
  deleteKeyPair(alias: string | null): Promise<void>;
  generateProof(
    htu: string,
    htm: string,
    nonce: string | null,
    accessToken: string | null,
    additional: UnsafeObject | null,
    kid: string | null,
    jti: string | null,
    iat: number | null,
    alias: string | null,
    requireHardwareBacked: boolean
  ): Promise<UnsafeObject>;
  getKeyInfo(alias: string | null): Promise<UnsafeObject>;
  getPublicKeyDer(alias: string | null): Promise<string>;
  getPublicKeyJwk(alias: string | null): Promise<UnsafeObject>;
  getPublicKeyRaw(alias: string | null): Promise<string>;
  getPublicKeyThumbprint(alias: string | null): Promise<string>;
  hasKeyPair(alias: string | null): Promise<boolean>;
  isBoundToAlias(proof: string, alias: string | null): Promise<boolean>;
  rotateKeyPair(alias: string | null): Promise<void>;
  signWithDPoPPrivateKey(payload: string, alias: string | null): Promise<string>;
}

const nativeDPoPModule =
  // eslint-disable-next-line dot-notation -- required by noPropertyAccessFromIndexSignature from @tsconfig/strictest
  TurboModuleRegistry.get<Spec>('ReactNativeDPoP') ?? (NativeModules['ReactNativeDPoP'] as Spec | undefined);

export default nativeDPoPModule as Spec;
