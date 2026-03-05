import { Platform } from 'react-native';
import Dpop from './NativeDpop';

type AdditionalClaims = Record<string, unknown>;

export type PublicJwk = {
  kty: 'EC';
  crv: 'P-256';
  x: string;
  y: string;
};

export type PublicKeyFormat = 'JWK' | 'DER' | 'RAW';

export type DPoPKeyInfo = {
  alias: string;
  hasKeyPair: boolean;
  algorithm?: string;
  curve?: string;
  insideSecureHardware?: boolean;
  securityLevel?: number;
  strongBoxAvailable?: boolean;
  strongBoxBacked?: boolean;
};

export type GenerateProofInput = {
  htu: string;
  htm: string;
  nonce?: string;
  accessToken?: string;
  additional?: AdditionalClaims;
  kid?: string;
  jti?: string;
  iat?: number;
  alias?: string;
};

export type DPoPProofContext = {
  htu: string;
  htm: string;
  nonce: string | null;
  ath: string | null;
  additional: AdditionalClaims | null;
  kid: string | null;
  jti: string;
  iat: number;
};

type GenerateProofResult = {
  proof: string;
  proofContext: DPoPProofContext;
};

const LINKING_ERROR =
  'Dpop module nao encontrado. Verifique se o app Android foi recompilado apos adicionar o modulo nativo.';

function requireAndroid() {
  if (Platform.OS !== 'android') {
    throw new Error('react-native-dpop (MVP atual) suporta somente Android.');
  }
  if (!Dpop) {
    throw new Error(LINKING_ERROR);
  }
}

export class DPoP {
  public readonly proof: string;
  public readonly alias?: string;
  public readonly proofContext: DPoPProofContext;

  private constructor(proof: string, proofContext: DPoPProofContext, alias?: string) {
    this.proof = proof;
    this.proofContext = proofContext;
    this.alias = alias;
  }

  public async calculateThumbprint(): Promise<string> {
    requireAndroid();
    return Dpop.calculateThumbprint(this.alias ?? null);
  }

  public async getPublicKey(format: PublicKeyFormat): Promise<PublicJwk | string> {
    requireAndroid();
    if (format === 'DER') {
      return Dpop.getPublicKeyDer(this.alias ?? null);
    }
    if (format === 'RAW') {
      return Dpop.getPublicKeyRaw(this.alias ?? null);
    }

    return Dpop.getPublicKeyJwk(this.alias ?? null) as Promise<PublicJwk>;
  }

  public async signWithDpopPrivateKey(payload: string): Promise<string> {
    requireAndroid();
    return Dpop.signWithDpopPrivateKey(payload, this.alias ?? null);
  }

  public async isBoundToAlias(alias?: string): Promise<boolean> {
    requireAndroid();
    return Dpop.isBoundToAlias(this.proof, alias ?? this.alias ?? null);
  }

  public static async generateProof(input: GenerateProofInput): Promise<DPoP> {
    requireAndroid();
    const result = (await Dpop.generateProof(
      input.htu,
      input.htm,
      input.nonce ?? null,
      input.accessToken ?? null,
      input.additional ?? null,
      input.kid ?? null,
      input.jti ?? null,
      input.iat ?? null,
      input.alias ?? null
    )) as GenerateProofResult;

    return new DPoP(result.proof, result.proofContext, input.alias);
  }

  public static async assertHardwareBacked(alias?: string): Promise<void> {
    requireAndroid();
    await Dpop.assertHardwareBacked(alias ?? null);
  }

  public static async deleteKeyPair(alias?: string): Promise<void> {
    requireAndroid();
    await Dpop.deleteKeyPair(alias ?? null);
  }

  public static async getKeyInfo(alias?: string): Promise<DPoPKeyInfo> {
    requireAndroid();
    return Dpop.getKeyInfo(alias ?? null) as Promise<DPoPKeyInfo>;
  }

  public static async hasKeyPair(alias?: string): Promise<boolean> {
    requireAndroid();
    return Dpop.hasKeyPair(alias ?? null);
  }

  public static async rotateKeyPair(alias?: string): Promise<void> {
    requireAndroid();
    await Dpop.rotateKeyPair(alias ?? null);
  }
}
