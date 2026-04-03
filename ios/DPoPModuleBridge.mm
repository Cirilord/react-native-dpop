#import <React/RCTBridgeModule.h>
#import <React/RCTUtils.h>

#ifdef RCT_NEW_ARCH_ENABLED
#if __has_include(<ReactNativeDPoPSpec/ReactNativeDPoPSpec.h>)
#import <ReactNativeDPoPSpec/ReactNativeDPoPSpec.h>
#else
#import "ReactNativeDPoPSpec.h"
#endif
#endif

#if __has_include(<ReactNativeDPoP/ReactNativeDPoP-Swift.h>)
#import <ReactNativeDPoP/ReactNativeDPoP-Swift.h>
#else
#import "ReactNativeDPoP-Swift.h"
#endif

@interface RCT_EXTERN_MODULE(ReactNativeDPoP, NSObject)

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

RCT_EXTERN_METHOD(signWithDPoPPrivateKey:(NSString *)payload
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
                  iat:(id _Nullable)iat
                  alias:(NSString * _Nullable)alias
                  resolve:(RCTPromiseResolveBlock)resolve
                  reject:(RCTPromiseRejectBlock)reject)

@end

@implementation ReactNativeDPoP
@end

#if RCT_NEW_ARCH_ENABLED
@implementation ReactNativeDPoP (TurboModule)

- (std::shared_ptr<facebook::react::TurboModule>)getTurboModule:
    (const facebook::react::ObjCTurboModule::InitParams &)params
{
    return std::make_shared<facebook::react::NativeReactNativeDPoPSpecJSI>(params);
}

@end
#endif
