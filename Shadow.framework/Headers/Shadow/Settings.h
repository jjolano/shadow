#ifndef shadow_settings_h
#define shadow_settings_h

#import <Foundation/Foundation.h>

@interface ShadowSettings : NSObject
@property (nonatomic, readonly) NSDictionary<NSString *, id>* defaultSettings;
@property (nonatomic, readonly) NSUserDefaults* userDefaults;

+ (instancetype)sharedInstance;

- (NSDictionary<NSString *, id> *)getPreferencesForIdentifier:(NSString *)bundleIdentifier;
@end
#endif
