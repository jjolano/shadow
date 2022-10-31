#import "hooks.h"

%group shadowhook_NSArray
%hook NSArray
- (id)initWithContentsOfFile:(NSString *)path {
    if([_shadow isPathRestricted:path]) {
        return nil;
    }

    return %orig;
}

+ (id)arrayWithContentsOfFile:(NSString *)path {
    if([_shadow isPathRestricted:path]) {
        return nil;
    }

    return %orig;
}

+ (id)arrayWithContentsOfURL:(NSURL *)url {
    if([_shadow isURLRestricted:url]) {
        return nil;
    }

    return %orig;
}
%end

%hook NSMutableArray
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

+ (id)arrayWithContentsOfFile:(NSString *)path {
    if([_shadow isPathRestricted:path]) {
        return nil;
    }

    return %orig;
}

+ (id)arrayWithContentsOfURL:(NSURL *)url {
    if([_shadow isURLRestricted:url]) {
        return nil;
    }

    return %orig;
}
%end
%end

void shadowhook_NSArray(void) {
    %init(shadowhook_NSArray);
}
