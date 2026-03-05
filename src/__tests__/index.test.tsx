jest.mock('../NativeDpop', () => ({
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

jest.mock('react-native', () => ({
  Platform: { OS: 'android' },
}));

import { Platform } from 'react-native';
import NativeDpop from '../NativeDpop';
import { DPoP } from '../index';

describe('DPoP', () => {
  const mockNativeDpop = NativeDpop as jest.Mocked<typeof NativeDpop>;
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
    Platform.OS = 'android';
  });

  it('generates proof and exposes proof data', async () => {
    mockNativeDpop.generateProof.mockResolvedValue({
      proof: 'proof.jwt',
      proofContext,
    });

    const dpop = await DPoP.generateProof({
      htu: proofContext.htu,
      htm: 'post',
      alias: 'alias-1',
    });

    expect(mockNativeDpop.generateProof).toHaveBeenCalledWith(
      proofContext.htu,
      'post',
      null,
      null,
      null,
      null,
      null,
      null,
      'alias-1'
    );
    expect(dpop.proof).toBe('proof.jwt');
    expect(dpop.proofContext).toEqual(proofContext);
    expect(dpop.alias).toBe('alias-1');
  });

  it('routes getPublicKey by format', async () => {
    mockNativeDpop.generateProof.mockResolvedValue({
      proof: 'proof.jwt',
      proofContext,
    });
    mockNativeDpop.getPublicKeyJwk.mockResolvedValue({ kty: 'EC', crv: 'P-256', x: 'x', y: 'y' });
    mockNativeDpop.getPublicKeyDer.mockResolvedValue('der');
    mockNativeDpop.getPublicKeyRaw.mockResolvedValue('raw');

    const dpop = await DPoP.generateProof({ htu: proofContext.htu, htm: 'POST', alias: 'a1' });

    expect(await dpop.getPublicKey('JWK')).toEqual({ kty: 'EC', crv: 'P-256', x: 'x', y: 'y' });
    expect(await dpop.getPublicKey('DER')).toBe('der');
    expect(await dpop.getPublicKey('RAW')).toBe('raw');

    expect(mockNativeDpop.getPublicKeyJwk).toHaveBeenCalledWith('a1');
    expect(mockNativeDpop.getPublicKeyDer).toHaveBeenCalledWith('a1');
    expect(mockNativeDpop.getPublicKeyRaw).toHaveBeenCalledWith('a1');
  });

  it('calls instance methods with alias fallback', async () => {
    mockNativeDpop.generateProof.mockResolvedValue({
      proof: 'proof.jwt',
      proofContext,
    });
    mockNativeDpop.calculateThumbprint.mockResolvedValue('thumb');
    mockNativeDpop.signWithDpopPrivateKey.mockResolvedValue('sig');
    mockNativeDpop.isBoundToAlias.mockResolvedValue(true);

    const dpop = await DPoP.generateProof({ htu: proofContext.htu, htm: 'POST' });

    expect(await dpop.calculateThumbprint()).toBe('thumb');
    expect(await dpop.signWithDpopPrivateKey('payload')).toBe('sig');
    expect(await dpop.isBoundToAlias()).toBe(true);

    expect(mockNativeDpop.calculateThumbprint).toHaveBeenCalledWith(null);
    expect(mockNativeDpop.signWithDpopPrivateKey).toHaveBeenCalledWith('payload', null);
    expect(mockNativeDpop.isBoundToAlias).toHaveBeenCalledWith('proof.jwt', null);
  });

  it('calls static key management methods', async () => {
    mockNativeDpop.getKeyInfo.mockResolvedValue({ alias: 'a1', hasKeyPair: true });
    mockNativeDpop.hasKeyPair.mockResolvedValue(true);

    await DPoP.assertHardwareBacked('a1');
    await DPoP.deleteKeyPair('a1');
    await DPoP.rotateKeyPair('a1');

    expect(await DPoP.getKeyInfo('a1')).toEqual({ alias: 'a1', hasKeyPair: true });
    expect(await DPoP.hasKeyPair('a1')).toBe(true);

    expect(mockNativeDpop.assertHardwareBacked).toHaveBeenCalledWith('a1');
    expect(mockNativeDpop.deleteKeyPair).toHaveBeenCalledWith('a1');
    expect(mockNativeDpop.rotateKeyPair).toHaveBeenCalledWith('a1');
    expect(mockNativeDpop.getKeyInfo).toHaveBeenCalledWith('a1');
    expect(mockNativeDpop.hasKeyPair).toHaveBeenCalledWith('a1');
  });

  it('throws on non-android platform', async () => {
    Platform.OS = 'ios';

    await expect(
      DPoP.generateProof({
        htu: 'https://api.example.com/token',
        htm: 'POST',
      })
    ).rejects.toThrow('react-native-dpop (MVP atual) suporta somente Android.');
  });
});
