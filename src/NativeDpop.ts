import type { TurboModule } from 'react-native';
import { NativeModules, TurboModuleRegistry } from 'react-native';
import type { UnsafeObject } from 'react-native/Libraries/Types/CodegenTypes';

export interface Spec extends TurboModule {
  assertHardwareBacked(alias: string | null): Promise<void>;
  calculateThumbprint(alias: string | null): Promise<string>;
  deleteKeyPair(alias: string | null): Promise<void>;
  getKeyInfo(alias: string | null): Promise<UnsafeObject>;
  getPublicKeyDer(alias: string | null): Promise<string>;
  getPublicKeyJwk(alias: string | null): Promise<UnsafeObject>;
  getPublicKeyRaw(alias: string | null): Promise<string>;
  hasKeyPair(alias: string | null): Promise<boolean>;
  isBoundToAlias(proof: string, alias: string | null): Promise<boolean>;
  rotateKeyPair(alias: string | null): Promise<void>;
  signWithDpopPrivateKey(payload: string, alias: string | null): Promise<string>;
  generateProof(
    htu: string,
    htm: string,
    nonce: string | null,
    accessToken: string | null,
    additional: UnsafeObject | null,
    kid: string | null,
    jti: string | null,
    iat: number | null,
    alias: string | null
  ): Promise<UnsafeObject>;
}

const nativeDpopModule = TurboModuleRegistry.get<Spec>('Dpop') ?? (NativeModules.Dpop as Spec | undefined);

export default nativeDpopModule as Spec;
