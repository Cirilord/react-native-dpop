jest.mock('../NativeReactNativeDPoP', () => ({
  __esModule: true,
  default: {
    assertHardwareBacked: jest.fn(),
    calculateThumbprint: jest.fn(),
    deleteKeyPair: jest.fn(),
    generateProof: jest.fn(),
    getKeyInfo: jest.fn(),
    getPublicKeyDer: jest.fn(),
    getPublicKeyJwk: jest.fn(),
    getPublicKeyRaw: jest.fn(),
    hasKeyPair: jest.fn(),
    isBoundToAlias: jest.fn(),
    rotateKeyPair: jest.fn(),
    signWithDpopPrivateKey: jest.fn(),
  },
}));

import { DPoP } from '../index';
import NativeReactNativeDPoP from '../NativeReactNativeDPoP';

describe('DPoP', () => {
  const mockNativeReactNativeDPoP = NativeReactNativeDPoP as jest.Mocked<typeof NativeReactNativeDPoP>;
  const proofContext = {
    htu: 'https://api.example.com/token',
    htm: 'POST',
    nonce: 'nonce',
    ath: 'ath',
    additional: null,
    kid: null,
    jti: 'jti',
    iat: 1_700_000_000,
  };

  beforeEach(() => {
    jest.clearAllMocks();
  });

  it('generates proof and exposes proof data', async () => {
    mockNativeReactNativeDPoP.generateProof.mockResolvedValue({
      proof: 'proof.jwt',
      proofContext,
    });

    const dpop = await DPoP.generateProof({
      htu: proofContext.htu,
      htm: 'post',
      alias: 'alias-1',
    });

    expect(mockNativeReactNativeDPoP.generateProof).toHaveBeenCalledWith(
      proofContext.htu,
      'post',
      null,
      null,
      null,
      null,
      null,
      expect.any(Number),
      'alias-1'
    );
    expect(dpop.proof).toBe('proof.jwt');
    expect(dpop.proofContext).toEqual(proofContext);
    expect(dpop.alias).toBe('alias-1');
  });

  it('routes getPublicKey by format', async () => {
    mockNativeReactNativeDPoP.generateProof.mockResolvedValue({
      proof: 'proof.jwt',
      proofContext,
    });
    mockNativeReactNativeDPoP.getPublicKeyJwk.mockResolvedValue({ kty: 'EC', crv: 'P-256', x: 'x', y: 'y' });
    mockNativeReactNativeDPoP.getPublicKeyDer.mockResolvedValue('der');
    mockNativeReactNativeDPoP.getPublicKeyRaw.mockResolvedValue('raw');

    const dpop = await DPoP.generateProof({ htu: proofContext.htu, htm: 'POST', alias: 'a1' });

    expect(await dpop.getPublicKey('JWK')).toEqual({ kty: 'EC', crv: 'P-256', x: 'x', y: 'y' });
    expect(await dpop.getPublicKey('DER')).toBe('der');
    expect(await dpop.getPublicKey('RAW')).toBe('raw');

    expect(mockNativeReactNativeDPoP.getPublicKeyJwk).toHaveBeenCalledWith('a1');
    expect(mockNativeReactNativeDPoP.getPublicKeyDer).toHaveBeenCalledWith('a1');
    expect(mockNativeReactNativeDPoP.getPublicKeyRaw).toHaveBeenCalledWith('a1');
  });

  it('calls instance methods with alias fallback', async () => {
    mockNativeReactNativeDPoP.generateProof.mockResolvedValue({
      proof: 'proof.jwt',
      proofContext,
    });
    mockNativeReactNativeDPoP.calculateThumbprint.mockResolvedValue('thumb');
    mockNativeReactNativeDPoP.signWithDpopPrivateKey.mockResolvedValue('sig');
    mockNativeReactNativeDPoP.isBoundToAlias.mockResolvedValue(true);

    const dpop = await DPoP.generateProof({ htu: proofContext.htu, htm: 'POST' });

    expect(await dpop.calculateThumbprint()).toBe('thumb');
    expect(await dpop.signWithDpopPrivateKey('payload')).toBe('sig');
    expect(await dpop.isBoundToAlias()).toBe(true);

    expect(mockNativeReactNativeDPoP.calculateThumbprint).toHaveBeenCalledWith(null);
    expect(mockNativeReactNativeDPoP.signWithDpopPrivateKey).toHaveBeenCalledWith('payload', null);
    expect(mockNativeReactNativeDPoP.isBoundToAlias).toHaveBeenCalledWith('proof.jwt', null);
  });

  it('calls static key management methods', async () => {
    mockNativeReactNativeDPoP.getKeyInfo.mockResolvedValue({ alias: 'a1', hasKeyPair: true });
    mockNativeReactNativeDPoP.hasKeyPair.mockResolvedValue(true);

    await DPoP.assertHardwareBacked('a1');
    await DPoP.deleteKeyPair('a1');
    await DPoP.rotateKeyPair('a1');

    expect(await DPoP.getKeyInfo('a1')).toEqual({ alias: 'a1', hasKeyPair: true });
    expect(await DPoP.hasKeyPair('a1')).toBe(true);

    expect(mockNativeReactNativeDPoP.assertHardwareBacked).toHaveBeenCalledWith('a1');
    expect(mockNativeReactNativeDPoP.deleteKeyPair).toHaveBeenCalledWith('a1');
    expect(mockNativeReactNativeDPoP.rotateKeyPair).toHaveBeenCalledWith('a1');
    expect(mockNativeReactNativeDPoP.getKeyInfo).toHaveBeenCalledWith('a1');
    expect(mockNativeReactNativeDPoP.hasKeyPair).toHaveBeenCalledWith('a1');
  });
});
