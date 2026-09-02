#ifndef shadow_hook_configuration_h
#define shadow_hook_configuration_h

// HookConfiguration.h is now a compatibility shim — canonical declarations
// live in SHDWPlugin.h (renamed InstallUnit → Plugin). This header re-exports
// that interface so existing imports (ShadowCore, Settings, tests) keep
// compiling without churn. New code should import <Shadow/SHDWPlugin.h>.
#import "SHDWPlugin.h"

#endif // shadow_hook_configuration_h
