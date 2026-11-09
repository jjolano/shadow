#import <Foundation/Foundation.h>

// Normalizes a stored preferences dictionary: legacy App_Disabled becomes
// App_Enabled, and obsolete scalar keys are pruned to the live surface.
FOUNDATION_EXPORT NSDictionary<NSString *, id> *
SHDWMigratedHookSettings(NSDictionary<NSString *, id> *settings);
