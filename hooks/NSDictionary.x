#import "hooks.h"

%group shadowhook_NSDictionary
%hook NSDictionary
- (id)initWithContentsOfFile:(NSString *)path {
    if([_shadow isPathRestricted:path]) {
        return nil;
    }

    return %orig;
}

- (id)initWithContentsOfURL:(NSURL *)url {
    if([_shadow isURLRestricted:url]) {
        return nil;
    }

    return %orig;
}

- (id)initWithContentsOfURL:(NSURL *)url error:(NSError * _Nullable *)error {
    if([_shadow isURLRestricted:url]) {
        return nil;
    }

    return %orig;
}

+ (id)dictionaryWithContentsOfFile:(NSString *)path {
    if([_shadow isPathRestricted:path]) {
        return nil;
    }

    return %orig;
}

+ (id)dictionaryWithContentsOfURL:(NSURL *)url error:(NSError * _Nullable *)error {
    if([_shadow isURLRestricted:url]) {
        return nil;
    }

    return %orig;
}

+ (id)dictionaryWithContentsOfURL:(NSURL *)url {
    if([_shadow isURLRestricted:url]) {
        return nil;
    }

    return %orig;
}
%end

%hook NSMutableDictionary
- (id)initWithContentsOfFile:(NSString *)path {
    if([_shadow isPathRestricted:path]) {
        return nil;
    }

    return %orig;
}

- (id)initWithContentsOfURL:(NSURL *)url {
    if([_shadow isURLRestricted:url]) {
        return nil;
    }

    return %orig;
}
%end
%end

void shadowhook_NSDictionary(void) {
    %init(shadowhook_NSDictionary);
}
