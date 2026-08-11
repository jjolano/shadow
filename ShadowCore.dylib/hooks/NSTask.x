#import "hooks.h"

// The toolchain's SDK Foundation headers ship no NSTask.h (and the cached
// Foundation module declares no NSTask), so the vendored Apple header is the
// only class declaration in this TU. It carries no availability guards, so
// all selectors below hook unconditionally.
#import "../../vendor/apple/NSTask.h"

// The vendored header predates the designated initializer (macOS 10.13 /
// iOS 11 era); declare it here so the hook and its %orig compile against a
// real signature.
@interface NSTask (ShadowInitWithLaunchPath)
- (nullable instancetype)initWithLaunchPath:(NSString *)path arguments:(NSArray<NSString *> *)arguments;
@end

%group shadowhook_NSTask
%hook NSTask

- (instancetype)initWithLaunchPath:(NSString *)path arguments:(NSArray<NSString *> *)arguments {
    // Construction only records the path and arguments — no I/O, nothing to
    // leak (same reasoning as NSFileWrapper's
    // initSymbolicLinkWithDestinationURL:, which is deliberately unhooked).
    // The denial happens at -launch, where stock performs the exec.
    return %orig;
}

- (void)launch {
    if(isCallerExternal() && self.launchPath && [_shadow isPathRestricted:self.launchPath options:shdw_restriction_write_options()]) {
        // Stock raises exactly this exception when the launch path is
        // invalid ("Couldn't posix_spawn: No such file or directory"); a
        // denied spawn therefore looks like a missing binary —
        // fingerprint-plausible, exercises the caller's normal error path,
        // and never hangs.
        [NSException raise:NSInternalInconsistencyException format:@"Couldn't posix_spawn: No such file or directory"];
    }

    %orig;
}

+ (instancetype)launchedTaskWithLaunchPath:(NSString *)path arguments:(NSArray<NSString *> *)arguments {
    if(isCallerExternal() && path && [_shadow isPathRestricted:path options:shdw_restriction_write_options()]) {
        // The convenience raises NSInvalidArgumentException for an unusable
        // launch path; mirror it so a denied task fails the same way stock
        // fails on a bad path.
        [NSException raise:NSInvalidArgumentException format:@"launch path not accessible"];
    }

    return %orig;
}

// -launchPath intentionally NOT hooked: it only reports the configured path,
// and filtering it would corrupt the task's own configuration (the path is
// what -launch executes); the denial lives in -launch.

%end
%end

void shadowhook_NSTask(HKSubstitutor* hooks) {
    %init(shadowhook_NSTask);
}
