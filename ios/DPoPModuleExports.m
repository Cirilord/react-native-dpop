#import <React/RCTBridgeModule.h>

@interface RCT_EXTERN_MODULE(Dpop, NSObject)

RCT_EXTERN_METHOD(assertHardwareBacked:(NSString * _Nullable)alias
                  resolve:(RCTPromiseResolveBlock)resolve
                  reject:(RCTPromiseRejectBlock)reject)

RCT_EXTERN_METHOD(calculateThumbprint:(NSString * _Nullable)alias
                  resolve:(RCTPromiseResolveBlock)resolve
                  reject:(RCTPromiseRejectBlock)reject)

RCT_EXTERN_METHOD(deleteKeyPair:(NSString * _Nullable)alias
                  resolve:(RCTPromiseResolveBlock)resolve
                  reject:(RCTPromiseRejectBlock)reject)

RCT_EXTERN_METHOD(getKeyInfo:(NSString * _Nullable)alias
                  resolve:(RCTPromiseResolveBlock)resolve
                  reject:(RCTPromiseRejectBlock)reject)

RCT_EXTERN_METHOD(getPublicKeyDer:(NSString * _Nullable)alias
                  resolve:(RCTPromiseResolveBlock)resolve
                  reject:(RCTPromiseRejectBlock)reject)

RCT_EXTERN_METHOD(getPublicKeyJwk:(NSString * _Nullable)alias
                  resolve:(RCTPromiseResolveBlock)resolve
                  reject:(RCTPromiseRejectBlock)reject)

RCT_EXTERN_METHOD(getPublicKeyRaw:(NSString * _Nullable)alias
                  resolve:(RCTPromiseResolveBlock)resolve
                  reject:(RCTPromiseRejectBlock)reject)

RCT_EXTERN_METHOD(hasKeyPair:(NSString * _Nullable)alias
                  resolve:(RCTPromiseResolveBlock)resolve
                  reject:(RCTPromiseRejectBlock)reject)

RCT_EXTERN_METHOD(isBoundToAlias:(NSString *)proof
                  alias:(NSString * _Nullable)alias
                  resolve:(RCTPromiseResolveBlock)resolve
                  reject:(RCTPromiseRejectBlock)reject)

RCT_EXTERN_METHOD(rotateKeyPair:(NSString * _Nullable)alias
                  resolve:(RCTPromiseResolveBlock)resolve
                  reject:(RCTPromiseRejectBlock)reject)

RCT_EXTERN_METHOD(signWithDpopPrivateKey:(NSString *)payload
                  alias:(NSString * _Nullable)alias
                  resolve:(RCTPromiseResolveBlock)resolve
                  reject:(RCTPromiseRejectBlock)reject)

RCT_EXTERN_METHOD(generateProof:(NSString *)htu
                  htm:(NSString *)htm
                  nonce:(NSString * _Nullable)nonce
                  accessToken:(NSString * _Nullable)accessToken
                  additional:(NSDictionary * _Nullable)additional
                  kid:(NSString * _Nullable)kid
                  jti:(NSString * _Nullable)jti
                  iat:(NSNumber * _Nullable)iat
                  alias:(NSString * _Nullable)alias
                  resolve:(RCTPromiseResolveBlock)resolve
                  reject:(RCTPromiseRejectBlock)reject)

@end
