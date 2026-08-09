#import "hooks.h"

// C0-3 protected-name policy for assets: an image whose basename exactly
// matches one of Shadow's own artifact names (case-insensitive, with or
// without the file extension) is refused. Exact-name only — never substring
// matching. The list mirrors Shadow.framework/Core.m isProtectedImagePath.
static BOOL shdw_imageNameProtected(NSString* name) {
    if(!name || name.length == 0) {
        return NO;
    }

    static NSSet* protectedNames = nil;
    static dispatch_once_t onceToken = 0;

    dispatch_once(&onceToken, ^{
        protectedNames = [NSSet setWithArray:@[
            @"shadow.dylib",
            @"shadow.framework",
            @"libsandy.dylib",
            @"hookkit.framework",
            @"rootbridge.framework",
            @"substrate",
            @"libsubstrate",
            @"substitute",
            @"libsubstitute",
            @"ellekit",
            @"libellekit"
        ]];
    });

    // No-allocation matching (the old code built lowercaseString /
    // stringByDeletingPathExtension copies per call): an anchored,
    // pattern-length-bounded range search is exact case-insensitive
    // equality, and the extension-stripped variant is name == pattern + "."
    // + extension where the pattern is the LAST dot's prefix — no further
    // dots in the tail and at least one char after the dot (a trailing dot
    // is not an extension, matching stringByDeletingPathExtension).
    for(NSString* protectedName in protectedNames) {
        if(name.length == protectedName.length
        && [name rangeOfString:protectedName options:NSCaseInsensitiveSearch|NSAnchoredSearch].location == 0) {
            return YES;
        }

        if(name.length >= protectedName.length + 2
        && [name rangeOfString:protectedName options:NSCaseInsensitiveSearch|NSAnchoredSearch range:NSMakeRange(0, protectedName.length)].location == 0
        && [name characterAtIndex:protectedName.length] == '.'
        && [name rangeOfString:@"." options:NSLiteralSearch range:NSMakeRange(protectedName.length + 1, name.length - protectedName.length - 1)].location == NSNotFound) {
            return YES;
        }
    }

    return NO;
}

static BOOL shdw_assetRestricted(NSString* name, NSBundle* bundle) {
    if(bundle && [_shadow isProtectedImagePath:[bundle bundlePath]]) {
        return YES;
    }

    return shdw_imageNameProtected(name);
}

%group shadowhook_UIImage
%hook UIImage
- (instancetype)initWithContentsOfFile:(NSString *)path {
    SHADOW_RETURN_NIL_IF_PATH_RESTRICTED(path);

    return %orig;
}

+ (UIImage *)imageWithContentsOfFile:(NSString *)path {
    SHADOW_RETURN_NIL_IF_PATH_RESTRICTED(path);

    return %orig;
}

+ (UIImage *)imageNamed:(NSString *)name {
    if(isCallerExternal() && shdw_imageNameProtected(name)) {
        return nil;
    }

    return %orig;
}

+ (UIImage *)imageNamed:(NSString *)name inBundle:(NSBundle *)bundle {
    if(isCallerExternal() && shdw_assetRestricted(name, bundle)) {
        return nil;
    }

    return %orig;
}

+ (UIImage *)imageNamed:(NSString *)name inBundle:(NSBundle *)bundle compatibleWithTraitCollection:(UITraitCollection *)traitCollection {
    if(isCallerExternal() && shdw_assetRestricted(name, bundle)) {
        return nil;
    }

    return %orig;
}

// id instead of UIImageConfiguration: the type is iOS 13+ and the tweak
// targets iOS 9; selector dispatch only needs the pointer ABI.
+ (UIImage *)imageNamed:(NSString *)name inBundle:(NSBundle *)bundle withConfiguration:(id)configuration {
    if(isCallerExternal() && shdw_assetRestricted(name, bundle)) {
        return nil;
    }

    return %orig;
}

+ (UIImage *)imageNamed:(NSString *)name inBundle:(NSBundle *)bundle variableValue:(double)value withConfiguration:(id)configuration {
    if(isCallerExternal() && shdw_assetRestricted(name, bundle)) {
        return nil;
    }

    return %orig;
}
%end
%end

void shadowhook_UIImage(HKSubstitutor* hooks) {
    %init(shadowhook_UIImage);
}
