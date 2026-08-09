#import "hooks.h"

%group shadowhook_UIApplication
%hook UIApplication
- (BOOL)canOpenURL:(NSURL *)url {
    if(isCallerExternal() && [_shadow isURLRestricted:url]) {
        NSLog(@"canOpenURL restricted: %@", url);
        return NO;
    }

    return %orig;
}

- (BOOL)openURL:(NSURL *)url {
    if(isCallerExternal() && [_shadow isURLRestricted:url]) {
        NSLog(@"openURL restricted: %@", url);
        return NO;
    }

    return %orig;
}

// NOTE: declared void on iOS 10+ (UIApplication.h) — never contact
// LaunchServices for a restricted URL; the completion is delivered
// asynchronously with NO, matching the async contract of the real API.
- (void)openURL:(NSURL *)url options:(NSDictionary<UIApplicationOpenExternalURLOptionsKey, id> *)options completionHandler:(void (^)(BOOL success))completion {
    if(isCallerExternal() && [_shadow isURLRestricted:url]) {
        NSLog(@"openURL:options: restricted: %@", url);

        if(completion) {
            dispatch_async(dispatch_get_global_queue(QOS_CLASS_USER_INITIATED, 0), ^{
                completion(NO);
            });
        }

        return;
    }

    %orig;
}
%end
%end

void shadowhook_UIApplication(HKSubstitutor* hooks) {
    %init(shadowhook_UIApplication);
}
