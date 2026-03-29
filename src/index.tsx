import NativeReactNativeDPoP from './NativeReactNativeDPoP';

type AdditionalClaims = Record<string, unknown>;

export type PublicJwk = {
  kty: 'EC';
  crv: 'P-256';
  x: string;
  y: string;
};

export type PublicKeyFormat = 'JWK' | 'DER' | 'RAW';

export type SecureHardwareFallbackReason = 'UNAVAILABLE' | 'PROVIDER_ERROR' | 'POLICY_REJECTED' | 'UNKNOWN';

export type DPoPKeyInfo = {
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
      strongBoxFallbackReason?: SecureHardwareFallbackReason | null;
    };
    ios?: {
      secureEnclaveAvailable: boolean;
      secureEnclaveBacked: boolean;
      securityLevel?: number | null;
      secureEnclaveFallbackReason?: SecureHardwareFallbackReason | null;
    };
  };
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

export class DPoP {
  public readonly proof: string;
  public readonly alias: string | undefined;
  public readonly proofContext: DPoPProofContext;

  private constructor(proof: string, proofContext: DPoPProofContext, alias?: string) {
    this.proof = proof;
    this.proofContext = proofContext;
    this.alias = alias;
  }

  public async calculateThumbprint(): Promise<string> {
    return NativeReactNativeDPoP.calculateThumbprint(this.alias ?? null);
  }

  public async getPublicKey(format: PublicKeyFormat): Promise<PublicJwk | string> {
    if (format === 'DER') {
      return NativeReactNativeDPoP.getPublicKeyDer(this.alias ?? null);
    }
    if (format === 'RAW') {
      return NativeReactNativeDPoP.getPublicKeyRaw(this.alias ?? null);
    }

    return NativeReactNativeDPoP.getPublicKeyJwk(this.alias ?? null) as Promise<PublicJwk>;
  }

  public async signWithDpopPrivateKey(payload: string): Promise<string> {
    return NativeReactNativeDPoP.signWithDpopPrivateKey(payload, this.alias ?? null);
  }

  public async isBoundToAlias(alias?: string): Promise<boolean> {
    return NativeReactNativeDPoP.isBoundToAlias(this.proof, alias ?? this.alias ?? null);
  }

  public static async generateProof(input: GenerateProofInput): Promise<DPoP> {
    const result = (await NativeReactNativeDPoP.generateProof(
      input.htu,
      input.htm,
      input.nonce ?? null,
      input.accessToken ?? null,
      input.additional ?? null,
      input.kid ?? null,
      input.jti ?? null,
      // RN 0.75 Android bridge can crash when a nullable Double arrives as null.
      input.iat ?? Math.floor(Date.now() / 1000),
      input.alias ?? null
    )) as GenerateProofResult;

    return new DPoP(result.proof, result.proofContext, input.alias);
  }

  public static async assertHardwareBacked(alias?: string): Promise<void> {
    await NativeReactNativeDPoP.assertHardwareBacked(alias ?? null);
  }

  public static async deleteKeyPair(alias?: string): Promise<void> {
    await NativeReactNativeDPoP.deleteKeyPair(alias ?? null);
  }

  public static async getKeyInfo(alias?: string): Promise<DPoPKeyInfo> {
    return NativeReactNativeDPoP.getKeyInfo(alias ?? null) as Promise<DPoPKeyInfo>;
  }

  public static async hasKeyPair(alias?: string): Promise<boolean> {
    return NativeReactNativeDPoP.hasKeyPair(alias ?? null);
  }

  public static async rotateKeyPair(alias?: string): Promise<void> {
    await NativeReactNativeDPoP.rotateKeyPair(alias ?? null);
  }
}
