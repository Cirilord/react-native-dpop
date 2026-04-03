import NativeReactNativeDPoP from './NativeReactNativeDPoP';

type AdditionalClaims = Record<string, unknown>;

export type PublicJwk = {
  crv: 'P-256';
  kty: 'EC';
  x: string;
  y: string;
};

export type PublicKeyFormat = 'JWK' | 'DER' | 'RAW';

export type SecureHardwareFallbackReason = 'UNAVAILABLE' | 'PROVIDER_ERROR' | 'POLICY_REJECTED' | 'UNKNOWN';
export type AndroidSecurityLevelName = 'SOFTWARE' | 'TRUSTED_ENVIRONMENT' | 'STRONGBOX';
export type IOSSecurityLevelName = 'SOFTWARE' | 'SECURE_ENCLAVE';

export type DPoPKeyInfo = {
  algorithm?: string;
  alias: string;
  curve?: string;
  hardware?: {
    android?: {
      securityLevel?: number;
      securityLevelName?: AndroidSecurityLevelName;
      strongBoxAvailable: boolean;
      strongBoxBacked: boolean;
      strongBoxFallbackReason?: SecureHardwareFallbackReason | null;
    };
    ios?: {
      secureEnclaveAvailable: boolean;
      secureEnclaveBacked: boolean;
      secureEnclaveFallbackReason?: SecureHardwareFallbackReason | null;
      securityLevel?: number | null;
      securityLevelName?: IOSSecurityLevelName;
    };
  };
  hasKeyPair: boolean;
  insideSecureHardware?: boolean;
};

export type GenerateProofInput = {
  accessToken?: string;
  additional?: AdditionalClaims;
  alias?: string;
  htm: string;
  htu: string;
  iat?: number;
  jti?: string;
  kid?: string;
  nonce?: string;
};

export type DPoPHeaders = {
  Authorization?: string;
  DPoP: string;
};

export type DPoPProofContext = {
  additional: AdditionalClaims | null;
  ath: string | null;
  htm: string;
  htu: string;
  iat: number;
  jti: string;
  kid: string | null;
  nonce: string | null;
};

type GenerateProofResult = {
  proof: string;
  proofContext: DPoPProofContext;
};

export class DPoP {
  public readonly alias: string | undefined;
  public readonly proof: string;
  public readonly proofContext: DPoPProofContext;

  private constructor(proof: string, proofContext: DPoPProofContext, alias?: string) {
    this.proof = proof;
    this.proofContext = proofContext;
    this.alias = alias;
  }

  public static async assertHardwareBacked(alias?: string): Promise<void> {
    await NativeReactNativeDPoP.assertHardwareBacked(alias ?? null);
  }

  public static async buildDPoPHeaders(input: GenerateProofInput): Promise<DPoPHeaders> {
    const dPoP = await DPoP.generateProof(input);

    return {
      DPoP: dPoP.proof,
      ...(input.accessToken ? { Authorization: `DPoP ${input.accessToken}` } : {}),
    };
  }

  public static async deleteKeyPair(alias?: string): Promise<void> {
    await NativeReactNativeDPoP.deleteKeyPair(alias ?? null);
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

  public static async getKeyInfo(alias?: string): Promise<DPoPKeyInfo> {
    return NativeReactNativeDPoP.getKeyInfo(alias ?? null) as Promise<DPoPKeyInfo>;
  }

  public static async hasKeyPair(alias?: string): Promise<boolean> {
    return NativeReactNativeDPoP.hasKeyPair(alias ?? null);
  }

  public static async rotateKeyPair(alias?: string): Promise<void> {
    await NativeReactNativeDPoP.rotateKeyPair(alias ?? null);
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

  public async getPublicKeyThumbprint(): Promise<string> {
    return NativeReactNativeDPoP.getPublicKeyThumbprint(this.alias ?? null);
  }

  public async isBoundToAlias(alias?: string): Promise<boolean> {
    return NativeReactNativeDPoP.isBoundToAlias(this.proof, alias ?? this.alias ?? null);
  }

  public async signWithDPoPPrivateKey(payload: string): Promise<string> {
    return NativeReactNativeDPoP.signWithDPoPPrivateKey(payload, this.alias ?? null);
  }
}
