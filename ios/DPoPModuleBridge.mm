#import "DPoPModule.h"

@implementation Dpop

RCT_EXPORT_MODULE(Dpop)

@end

#if RCT_NEW_ARCH_ENABLED
#import <DpopSpec/DpopSpec.h>

@implementation Dpop (TurboModule)

- (std::shared_ptr<facebook::react::TurboModule>)getTurboModule:
    (const facebook::react::ObjCTurboModule::InitParams &)params
{
    return std::make_shared<facebook::react::NativeDpopSpecJSI>(params);
}

@end
#endif
