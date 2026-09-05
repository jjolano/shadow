#!/usr/bin/env bash
set -euo pipefail
ROOT=$(cd "$(dirname "$0")/.." && pwd)
: "${THEOS:?THEOS must point to Theos}"
export PATH=/tmp/swift-5.8.1-RELEASE-ubuntu22.04/usr/bin:$PATH
ABI_ARGS=()
RUNNER_ARGS=()
if [ "$(uname -s)" = Linux ]; then
    tc=${NEWABI_TOOLCHAIN:-$THEOS/toolchain/modern/linux/iphone}
    [ -x "$tc/bin/clang" ] || { echo "missing new-ABI toolchain: $tc" >&2; exit 1; }
    ABI_ARGS=("SDKBINPATH=$tc/bin" "IS_NEW_ABI=1")
    RUNNER_ARGS=("TARGET_CC=$THEOS/toolchain/linux/iphone/bin/clang" "TARGET_CXX=$THEOS/toolchain/linux/iphone/bin/clang++" "SWIFTBINPATH=$THEOS/toolchain/linux/iphone/bin")
fi
m() { make "$@" ${ABI_ARGS[@]+"${ABI_ARGS[@]}"}; }
"$ROOT/scripts/fetch-detector-sdks.sh" all
# BATJailbreakGuard's DynamicLib service uses String(validatingCString:), a
# Swift 5.9+ stdlib init absent from the 14.5 SDK's stdlib; validatingUTF8 is
# equivalent for the dylib names it reads from the image list (idempotent).
sed -i 's/String(validatingCString: cName)/String(validatingUTF8: cName)/' \
    "$ROOT/.detector-deps/BATJailbreakGuard/Sources/BATJailbreakGuard/Service/Sub/DynamicLib/JailbreakDetectionDynamicLibraryCheckService.swift"
# JailMonkey's RN isDebuggedMode bridge stores a BOOL into a BOOL* (compiles
# under RN without -Werror); fix the type (idempotent).
sed -i 's/BOOL \*isDebuggedModeActived = \[self isDebugged\];/BOOL isDebuggedModeActived = [self isDebugged];/' \
    "$ROOT/.detector-deps/JailMonkey/JailMonkey/JailMonkey.m"
# isJailbroken's tuyul() stores its own const char* return in a char* (an error
# under this toolchain's -Werror); the pointer is only read, so const-qualify
# it (idempotent).
sed -i 's/^\(\s*\)char\* ptr = tuyul/\1const char* ptr = tuyul/' \
    "$ROOT/.detector-deps/isJailbroken/isJailbroken/JB.m"
# isJailbroken's isDebugged() aborts the runner via assert() when its sysctl
# fails; a crash yields no callback and stalls Run All on the 90s timeout.
# Return NO instead — identical on the success path (idempotent).
sed -i 's/^\(\s*\)assert(junk == 0);/\1if(junk != 0) return NO;/' \
    "$ROOT/.detector-deps/isJailbroken/isJailbroken/JB.m"
# isJailbroken logs every probe hit to syslog (DEBUGGING); silence it — the
# runner already records each verdict in its report checks (idempotent).
sed -i 's/^BOOL DEBUGGING = YES;/BOOL DEBUGGING = NO;/' \
    "$ROOT/.detector-deps/isJailbroken/isJailbroken/JB.m"
# SwiftyJBD's JailBreak.swift is a bare two-method fragment (no enclosing type,
# no imports) that cannot compile as-is. Wrap it into `struct SwiftyJBD` with
# Foundation/UIKit imports so the SwiftyJBD runner can call
# SwiftyJBD.isJailbroken() (idempotent).
python3 - "$ROOT/.detector-deps/SwiftyJBD/JailBreak.swift" <<'PY'
import sys
p = sys.argv[1]
s = open(p).read()
if 'struct SwiftyJBD' not in s:
    s = 'import Foundation\nimport UIKit\n\nstruct SwiftyJBD {\n' + s + '\n}\n'
    open(p, 'w').write(s)
PY
# This Linux Theos Swift toolchain has no iOS _Concurrency module. SafetyNet's
# jailbreak detector only awaits its main-thread URL-scheme call, so make that
# one-shot path synchronous; the runner invokes the same underlying checks.
sed -i \
    -e 's/static func detect() async -> Result/static func detect() -> Result/' \
    -e 's/result.urlScheme = await checkURLSchemes()/result.urlScheme = checkURLSchemes()/' \
    -e '/^[[:space:]]*@MainActor$/d' \
    "$ROOT/.detector-deps/SafetyNet/Sources/SafetyNet/Detectors/JailbreakDetector.swift"
# SafetyNet's Swift `import SafetyNetObjC` names an SPM C target that does not
# exist in Theos' single-module build; the two C symbols it needs come through
# the runner's bridging header instead (SafetyNetRunner-Bridging.h). Drop the
# import (idempotent).
sed -i '/^import SafetyNetObjC$/d' \
    "$ROOT/.detector-deps/SafetyNet/Sources/SafetyNet/Detectors/DebuggerDetector.swift" \
    "$ROOT/.detector-deps/SafetyNet/Sources/SafetyNet/Detectors/IntegrityValidator.swift"
# The real Roothider repo is a single main.m app whose detect_* functions only
# LOG findings; the harness compiles it in-process. Filter it (idempotent):
# redirect LOG to the recorder header, drop the app-scaffolding (NSObject
# category + AppDelegate + main), remove Roothider's side-effecting openURL
# probe, and fix an int-passed-as-%s bug in detect_jailbreak_port.
python3 - "$ROOT/.detector-deps/JailbreakDetector/main.m" <<'PY'
import sys, re
p = sys.argv[1]
s = open(p).read()
s = re.sub(r'#define LOG\(\.\.\.\) NSLog\(@__VA_ARGS__\)', '#include "RoothiderLog.h"', s)
s = re.sub(
    r'^#include <xpc_private.h>\n',
    '#include <xpc/xpc.h>\n'
    'extern int xpc_pipe_routine(xpc_object_t pipe, xpc_object_t message, xpc_object_t *reply);\n'
    'extern int xpc_pipe_routine_with_flags(xpc_object_t pipe, xpc_object_t message, xpc_object_t *reply, uint32_t flags);\n',
    s, flags=re.M)
s = s.replace('xpc_dictionary_create_empty()', 'xpc_dictionary_create(NULL, NULL, 0)')
s = re.sub(r'/\* bypass all jb-bypass.*\Z', '', s, flags=re.S)
s = re.sub(
    r'(?m)^[ \t]*canOpen = \[\[UIApplication sharedApplication\] openURL:.*\n'
    r'[ \t]*if\(canOpen\) LOG\("URLScheme opened:.*\n',
    '', s)
s = s.replace('LOG("jailbreak port %s unknown err: %s,%s\\n", ports[i], kr, mach_error_string(kr))',
               'LOG("jailbreak port %s unknown err: %d,%s\\n", ports[i], kr, mach_error_string(kr))')
s = s.replace('snprintf(path,sizeof(path),"%s/tmp/%lx",getenv("HOME"), arc4random());',
              'snprintf(path,sizeof(path),"%s/tmp/%lx",getenv("HOME"), (unsigned long)arc4random());')
s = s.replace('int fd = open(path, O_RDWR|O_CREAT, 0755);\n        assert(fd >= 0);',
              'int fd = open(path, O_RDWR|O_CREAT, 0755);\n        if(fd < 0) return;')
s = s.replace('assert(fcntl(fd, F_GETSIGSINFO, &siginfo)==0);',
              'if(fcntl(fd, F_GETSIGSINFO, &siginfo)!=0) { close(fd); unlink(path); return; }')
s = s.replace('LOG("jailbreak actived! %s : %d\\n", jbsigs[i].tag, siginfo.fg_sig_is_platform)',
              'LOG("jailbreak actived! %s : %lu\\n", jbsigs[i].tag, (unsigned long)siginfo.fg_sig_is_platform)')
s = s.replace('kern_return_t kr = bootstrap_look_up(bootstrap_port, (char *)name, &port);',
              'bootstrap_look_up(bootstrap_port, (char *)name, &port);')
s = s.replace('        NSString* appIdentifier = [appBundle performSelector:@selector(bundleIdentifier)];',
               '        // NSString* appIdentifier = [appBundle performSelector:@selector(bundleIdentifier)];')
s = s.replace('NSLog(@"detect jbapp plugin: %@ %lx", pluginIdentifier, pluginIdentifier.hash);',
              'LOG("detect jbapp plugin: %s %lx\\n", pluginIdentifier.UTF8String, pluginIdentifier.hash);')
s = s.replace('(__bridge id)kSecAttrIsPermanent: @YES,',
              '(__bridge id)kSecAttrIsPermanent: @NO,')
s = re.sub(r'#define JBSIGS\(l,h,x\) assert\(l==sizeof\(x\)\); static uint8_t sig_##h\[\] = x;\n(#undef JBSIGS\n)?#include "jbsigs.h"\n',
              '#define JBSIGS(l,h,x) assert(l==sizeof(x)); static uint8_t sig_##h[] = x;\n#include "jbsigs.h"\n#undef JBSIGS\n',
              s, count=1)
open(p, 'w').write(s)
PY

# TalsecRuntime interfaces ship built with a newer Swift than the theos 5.8
# toolchain can read: they import _Concurrency/_StringProcessing/_SwiftConcurrencyShims
# (vestigial — the interface bodies use none) and carry a newer compiler-version
# stamp. Patch the fetched copies in place (idempotent) so the harness can build
# against the current (7.1.2) and fallback (6.4.0) frameworks.
patch_talsec() {
    local m="$1/Modules/TalsecRuntime.swiftmodule"
    for f in "$m"/*.swiftinterface; do
        sed -i \
            -e 's|^// swift-compiler-version: .*|// swift-compiler-version: Apple Swift version 5.8 (swift-5.8-RELEASE)|' \
            -e '/^import _Concurrency$/d' \
            -e '/^import _StringProcessing$/d' \
            -e '/^import _SwiftConcurrencyShims$/d' \
            "$f"
    done
    # 7.1.2 bundles libcurl headers with a deliberate re-inclusion design that
    # breaks the clang module build ("macro redefined"); the Swift API does not
    # use them, so move them out of the umbrella scan and slim the umbrella +
    # module map to the Swift-facing surface (idempotent).
    local fw="$1"
    mkdir -p "$fw/Headers/curl-internal"
    for h in stdcheaders.h mprintf.h curl.h curlver.h easy.h header.h multi.h options.h system.h typecheck-gcc.h urlapi.h websockets.h CryptoBridgingHeader.h CurlWrapper.h; do
        [ -f "$fw/Headers/$h" ] && mv "$fw/Headers/$h" "$fw/Headers/curl-internal/"
    done
    printf '#import <UIKit/UIKit.h>\n\n//! Project version number for TalsecRuntime_iOS.\nFOUNDATION_EXPORT double TalsecRuntime_iOSVersionNumber;\n\n//! Project version string for TalsecRuntime.\nFOUNDATION_EXPORT const unsigned char TalsecRuntime_iOSVersionString[];\n' > "$fw/Headers/TalsecRuntime_iOS.h"
    printf 'framework module TalsecRuntime {\n    umbrella header "TalsecRuntime_iOS.h"\n\n    export *\n    module * { export * }\n\n    explicit module Private {\n        export *\n    }\n}\n\nmodule TalsecRuntime.Swift {\n  header "TalsecRuntime-Swift.h"\n  requires objc\n}\n' > "$fw/Modules/module.modulemap"
}
patch_talsec "$ROOT/.detector-deps/Free-RASP-iOS-7.1.2/Talsec/TalsecRuntime.xcframework/ios-arm64/TalsecRuntime.framework"
patch_talsec "$ROOT/.detector-deps/Free-RASP-iOS-6.4.0/Talsec/TalsecRuntime.xcframework/ios-arm64/TalsecRuntime.framework"
m -C "$ROOT/src/Shadow.framework" THEOS_PACKAGE_SCHEME=rootless TARGET=iphone:clang:16.5:15.0 ARCHS="arm64 arm64e" \
    ADDITIONAL_CFLAGS=-fmodules-cache-path=/tmp/shadow-detector-framework-module-cache \
    ADDITIONAL_OBJCFLAGS=-fmodules-cache-path=/tmp/shadow-detector-framework-module-cache
m -C "$ROOT/src/Shadow.framework" stage THEOS_PACKAGE_SCHEME=rootless TARGET=iphone:clang:16.5:15.0 ARCHS="arm64 arm64e" \
    ADDITIONAL_CFLAGS=-fmodules-cache-path=/tmp/shadow-detector-framework-module-cache \
    ADDITIONAL_OBJCFLAGS=-fmodules-cache-path=/tmp/shadow-detector-framework-module-cache
m -C "$ROOT/tests/ShadowHarness/detector-frameworks" stage FINALPACKAGE=1 THEOS_PACKAGE_SCHEME=rootless \
    TARGET=iphone:clang:14.5:14.0 ARCHS="arm64" \
    "${RUNNER_ARGS[@]}" \
    ADDITIONAL_CFLAGS=-fmodules-cache-path=/tmp/shadow-detector-framework-module-cache \
    ADDITIONAL_OBJCFLAGS=-fmodules-cache-path=/tmp/shadow-detector-framework-module-cache
m -C "$ROOT/tests/tools/dyldprobe" stage FINALPACKAGE=1 THEOS_PACKAGE_SCHEME=rootless \
    TARGET=iphone:clang:16.5:15.0 ARCHS="arm64 arm64e" \
    THEOS_LIBRARY_PATH=/tmp/shadow-dyldprobe-lib \
    ADDITIONAL_CFLAGS=-fmodules-cache-path=/tmp/shadow-dyldprobe-module-cache \
    ADDITIONAL_OBJCFLAGS=-fmodules-cache-path=/tmp/shadow-dyldprobe-module-cache
for runner in \
    IOSSecuritySuite JailbreakDetector SecurityToolkit DTTJailbreakDetection \
    FreeRASP Roothider BATJailbreakGuard SafetyNet DeviceSecurityKit JailMonkey \
    isJailbroken SwiftyJBD; do
    m -C "$ROOT/tests/DetectorRunners/$runner" stage FINALPACKAGE=1 THEOS_PACKAGE_SCHEME=rootless \
        TARGET=iphone:clang:14.5:14.0 ARCHS="arm64" \
        "${RUNNER_ARGS[@]}" \
        ADDITIONAL_CFLAGS=-fmodules-cache-path=/tmp/shadow-detector-runner-module-cache \
        ADDITIONAL_OBJCFLAGS=-fmodules-cache-path=/tmp/shadow-detector-runner-module-cache
done
m -C "$ROOT/tests/ShadowHarness" package FINALPACKAGE=1 THEOS_PACKAGE_SCHEME=rootless \
    TARGET=iphone:clang:14.5:14.0 ARCHS="arm64" \
    THEOS_LIBRARY_PATH="$ROOT/src/Shadow.framework/.theos/obj/debug" INCLUDE_DETECTOR_RUNNERS=1
