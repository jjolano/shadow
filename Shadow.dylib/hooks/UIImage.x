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

    if([protectedNames containsObject:[name lowercaseString]]) {
        return YES;
    }

    return [protectedNames containsObject:[[name stringByDeletingPathExtension] lowercaseString]];
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
    if(!isCallerExternal() && [_shadow isPathRestricted:path]) {
        return nil;
    }

    return %orig;
}

+ (UIImage *)imageWithContentsOfFile:(NSString *)path {
    if(!isCallerExternal() && [_shadow isPathRestricted:path]) {
        return nil;
    }

    return %orig;
}

+ (UIImage *)imageNamed:(NSString *)name {
    if(!isCallerExternal() && shdw_imageNameProtected(name)) {
        return nil;
    }

    return %orig;
}

+ (UIImage *)imageNamed:(NSString *)name inBundle:(NSBundle *)bundle {
    if(!isCallerExternal() && shdw_assetRestricted(name, bundle)) {
        return nil;
    }

    return %orig;
}

+ (UIImage *)imageNamed:(NSString *)name inBundle:(NSBundle *)bundle compatibleWithTraitCollection:(UITraitCollection *)traitCollection {
    if(!isCallerExternal() && shdw_assetRestricted(name, bundle)) {
        return nil;
    }

    return %orig;
}

// id instead of UIImageConfiguration: the type is iOS 13+ and the tweak
// targets iOS 9; selector dispatch only needs the pointer ABI.
+ (UIImage *)imageNamed:(NSString *)name inBundle:(NSBundle *)bundle withConfiguration:(id)configuration {
    if(!isCallerExternal() && shdw_assetRestricted(name, bundle)) {
        return nil;
    }

    return %orig;
}

+ (UIImage *)imageNamed:(NSString *)name inBundle:(NSBundle *)bundle variableValue:(double)value withConfiguration:(id)configuration {
    if(!isCallerExternal() && shdw_assetRestricted(name, bundle)) {
        return nil;
    }

    return %orig;
}
%end
%end

void shadowhook_UIImage(HKSubstitutor* hooks) {
    %init(shadowhook_UIImage);
}
