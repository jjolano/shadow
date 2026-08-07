#import "hooks.h"

#import <MobileCoreServices/LSApplicationWorkspace.h>
#import <MobileCoreServices/LSApplicationProxy.h>
#import <MobileCoreServices/LSBundleProxy.h>

// use of LSApplicationWorkspace seems to be known for getting App Store rejected, but you never know...

// TODO: LaunchServices/MobileInstallation payload content filtering —
// restricted app IDs inside allowed install plists (LSApplicationProxy
// reads of /var/mobile/Library/MobileInstallation or LS install records)
// are not yet filtered; needs the NSFileManager/NSString read paths to
// post-filter plist payloads by bundle ID.

// C0-3: hidden-app predicate — restricted bundle URL OR case-insensitive
// restricted bundle ID. Applied to every proxy-returning surface so a proxy
// can't leak through a variant that only checks one of the two signals.
static NSArray* shdw_filter_application_proxies(NSArray* proxies) {
    NSMutableArray* result_filtered = [NSMutableArray arrayWithCapacity:proxies.count];

    for(LSApplicationProxy* ap in proxies) {
        if(![_shadow isURLRestricted:[ap bundleURL]] && ![_shadow isBundleIDRestricted:[ap bundleIdentifier]]) {
            [result_filtered addObject:ap];
        }
    }

    return [result_filtered copy];
}

%group shadowhook_LSApplicationWorkspace
%hook LSApplicationWorkspace
- (NSArray<LSApplicationProxy *> *)allApplications {
    NSArray<LSApplicationProxy *>* result = %orig;

    if(!isCallerExternal() && result) {
        result = shdw_filter_application_proxies(result);
    }

    return result;
}

- (NSArray<LSApplicationProxy *> *)allInstalledApplications {
    NSArray<LSApplicationProxy *>* result = %orig;

    if(!isCallerExternal() && result) {
        result = shdw_filter_application_proxies(result);
    }

    return result;
}

- (NSArray<LSApplicationProxy *> *)directionsApplications {
    NSArray<LSApplicationProxy *>* result = %orig;

    if(!isCallerExternal() && result) {
        result = shdw_filter_application_proxies(result);
    }

    return result;
}

- (NSArray<LSApplicationProxy *> *)unrestrictedApplications {
    NSArray<LSApplicationProxy *>* result = %orig;

    if(!isCallerExternal() && result) {
        result = shdw_filter_application_proxies(result);
    }

    return result;
}

- (NSArray<NSString *> *)installedApplications {
    NSArray<NSString *>* result = %orig;

    if(!isCallerExternal() && result) {
        NSMutableArray<NSString *>* result_filtered = [NSMutableArray arrayWithCapacity:result.count];

        for(NSString* app_bundleId in result) {
            // The ID is checked directly (case-insensitive predicate); the
            // resolved proxy URL is checked as well, and a nil proxy is
            // dropped when the ID itself is restricted.
            if([_shadow isBundleIDRestricted:app_bundleId]) {
                continue;
            }

            LSBundleProxy* app_bundle = [LSBundleProxy bundleProxyForIdentifier:app_bundleId];
            BOOL restricted = app_bundle && [_shadow isURLRestricted:[app_bundle bundleURL]];

            if(!restricted) {
                [result_filtered addObject:app_bundleId];
            }
        }

        result = [result_filtered copy];
    }

    return result;
}

- (NSArray<LSApplicationProxy *> *)applicationsAvailableForHandlingURLScheme:(NSString *)urlScheme {
    if(!isCallerExternal() && [_shadow isSchemeRestricted:urlScheme]) {
        return @[];
    }

    NSArray<LSApplicationProxy *>* result = %orig;

    if(!isCallerExternal() && result) {
        result = shdw_filter_application_proxies(result);
    }

    return result;
}

- (NSArray<LSApplicationProxy *> *)applicationsAvailableForOpeningURL:(NSURL *)url {
    if(!isCallerExternal() && [_shadow isURLRestricted:url]) {
        return @[];
    }

    NSArray<LSApplicationProxy *>* result = %orig;

    if(!isCallerExternal() && result) {
        result = shdw_filter_application_proxies(result);
    }

    return result;
}

- (NSArray<LSApplicationProxy *> *)applicationsAvailableForOpeningURL:(NSURL *)url legacySPI:(BOOL)legacySPI {
    if(!isCallerExternal() && [_shadow isURLRestricted:url]) {
        return @[];
    }

    NSArray<LSApplicationProxy *>* result = %orig;

    if(!isCallerExternal() && result) {
        result = shdw_filter_application_proxies(result);
    }

    return result;
}

- (NSArray<NSString *> *)publicURLSchemes {
    NSArray<NSString *>* result = %orig;

    if(!isCallerExternal() && result) {
        NSMutableArray<NSString *>* result_filtered = [NSMutableArray arrayWithCapacity:result.count];

        for(NSString* scheme in result) {
            if(![_shadow isSchemeRestricted:scheme]) {
                [result_filtered addObject:scheme];
            }
        }

        result = [result_filtered copy];
    }

    return result;
}

- (NSArray<NSString *> *)privateURLSchemes {
    NSArray<NSString *>* result = %orig;

    if(!isCallerExternal() && result) {
        NSMutableArray<NSString *>* result_filtered = [NSMutableArray arrayWithCapacity:result.count];

        for(NSString* scheme in result) {
            if(![_shadow isSchemeRestricted:scheme]) {
                [result_filtered addObject:scheme];
            }
        }

        result = [result_filtered copy];
    }

    return result;
}
%end
%end

void shadowhook_LSApplicationWorkspace(HKSubstitutor* hooks) {
    %init(shadowhook_LSApplicationWorkspace);
}
