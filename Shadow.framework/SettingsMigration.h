#import <Foundation/Foundation.h>

// Applies the one-time Hook_* -> Universal_/Adapter_ preference rename.
// Canonical values win and legacy keys are omitted from the result.
FOUNDATION_EXPORT NSDictionary<NSString*, id>* SHDWMigratedHookSettings(NSDictionary<NSString*, id>* settings);
