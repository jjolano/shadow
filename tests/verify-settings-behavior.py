"""Execute settings helper and release-parser source with host Foundation.

macOS: python3 tests/verify-settings-behavior.py
Linux: python3 tests/verify-settings-behavior.py --docker <GNUstep image>
The Docker image must already contain clang, libobjc2 and gnustep-config.
"""
import argparse
import platform
from pathlib import Path
import re
import shlex
import subprocess
import tempfile

root = Path(__file__).resolve().parents[1]
settings = root / "src/ShadowSettings.bundle"
prefs = (settings / "SHDWPrefs.m").read_text()
about = (settings / "SHDWAboutListController.m").read_text()
keys = (root / "src/Shadow.framework/Headers/Shadow/SHDWPlugin.h").read_text()

# Compile the original bodies, not Python translations of their behavior.
helpers = prefs[prefs.index("BOOL SHDWAppFollowsGlobal("):
                prefs.index("UIImage *SHDWSettingsSymbol(")]
parser = about[about.index("NSString* version = nil;"):
               about.index("// Always reload:")]
source = '#import <Foundation/Foundation.h>\n#import <objc/runtime.h>\n#include <assert.h>\n'
source += "\n".join(re.findall(
    r'^#define SHDW(?:AppEnabled|AppDisabled|DetectorAggressive)ID\s+@"[^"]+"',
    keys, re.M))
source += '\nBOOL SHDWAppIsCustomized(id appPrefs);\n' + helpers
source += '''
enum { UIImageRenderingModeAlwaysTemplate = 2 };
@interface UIImage : NSObject
@property(nonatomic) NSInteger renderingMode;
- (UIImage *)imageWithRenderingMode:(NSInteger)mode;
@end
@interface UIImage (ModernSymbols)
+ (UIImage *)systemImageNamed:(NSString *)name;
@end
@implementation UIImage
- (UIImage *)imageWithRenderingMode:(NSInteger)mode { self.renderingMode = mode; return self; }
@end
static id testSymbol(id cls, SEL selector, NSString *name) {
    return [name isEqualToString:@"missing"] ? nil : [UIImage new];
}
'''
source += prefs[prefs.index("UIImage *SHDWSettingsSymbol("):
                prefs.index("void SHDWClearAppEnabled(")]
source += '''
// In-memory defaults double: no test keys can reach a user's persistent domain.
@interface TestDefaults : NSUserDefaults
@property(nonatomic, strong) NSMutableDictionary *storage;
@property(nonatomic) BOOL failSynchronize;
@end
@implementation TestDefaults
- (instancetype)init { if((self = [super init])) _storage = [NSMutableDictionary new]; return self; }
- (id)objectForKey:(NSString *)key { return _storage[key]; }
- (NSDictionary *)dictionaryForKey:(NSString *)key { return _storage[key]; }
- (NSDictionary *)dictionaryRepresentation { return [_storage copy]; }
- (void)setObject:(id)value forKey:(NSString *)key { _storage[key] = value; }
- (void)setBool:(BOOL)value forKey:(NSString *)key { _storage[key] = @(value); }
- (void)removeObjectForKey:(NSString *)key { [_storage removeObjectForKey:key]; }
- (BOOL)synchronize { return !self.failSynchronize; }
@end
static NSDictionary *parse(NSData *data, NSInteger status, NSError *error) {
    NSURLResponse *response = [[NSHTTPURLResponse alloc]
        initWithURL:[NSURL URLWithString:@"https://example.invalid/releases"]
        statusCode:status HTTPVersion:@"HTTP/1.1" headerFields:nil];
'''
source += parser
source += '''
    return @{@"version": version ?: @"", @"title": title ?: @"",
             @"body": body ?: @"", @"failed": @(failed)};
}
static NSDictionary *parseJSON(id json) {
    return parse([NSJSONSerialization dataWithJSONObject:json options:0 error:NULL], 200, nil);
}
int main(void) { @autoreleasepool {
    assert(![UIImage respondsToSelector:@selector(systemImageNamed:)]);
    assert(SHDWSettingsSymbol(@"info.circle") == nil);
    class_addMethod(object_getClass([UIImage class]), @selector(systemImageNamed:), (IMP)testSymbol, "@@:@");
    assert(SHDWSettingsSymbol(@"info.circle").renderingMode == UIImageRenderingModeAlwaysTemplate);
    assert(SHDWSettingsSymbol(@"missing") == nil);
    TestDefaults *prefs = [TestDefaults new];
    NSString *app = @"example.selected", *other = @"example.other";
    [prefs setBool:YES forKey:@"Global_Enabled"];
    [prefs setBool:NO forKey:SHDWDetectorAggressiveID];
    [prefs setObject:@{SHDWAppEnabledID: @NO} forKey:other];
    assert(SHDWAppFollowsGlobal(prefs, app));
    assert(!SHDWAppIsCustomized(@YES));
    assert(!SHDWAppIsCustomized(@{}));
    for(NSString *key in @[SHDWAppEnabledID, SHDWAppDisabledID, SHDWDetectorAggressiveID]) {
        for(NSNumber *value in @[@NO, @YES]) {
            NSDictionary *override = @{key: value, @"obsolete": @YES};
            [prefs setObject:override forKey:app];
            NSDictionary *before = [prefs dictionaryRepresentation];
            assert(!SHDWAppFollowsGlobal(prefs, app));
            assert(SHDWAppIsCustomized([prefs dictionaryForKey:app]));
            assert([[prefs dictionaryRepresentation] isEqual:before]);
            prefs.failSynchronize = YES;
            assert(!SHDWResetApp(prefs, app));
            NSMutableDictionary *expected = [before mutableCopy];
            [expected removeObjectForKey:app];
            // Failed persistence leaves current memory visible, without clobbering other keys.
            assert([[prefs dictionaryRepresentation] isEqual:expected]);
            prefs.failSynchronize = NO;
            assert(SHDWResetApp(prefs, app));
            [prefs setObject:override forKey:app];
            assert(SHDWResetApp(prefs, app));
            assert([[prefs dictionaryRepresentation] isEqual:expected]);
            assert([prefs objectForKey:app] == nil);
            assert(SHDWAppFollowsGlobal(prefs, app));
        }
    }
    NSDictionary *before = [prefs dictionaryRepresentation];
    assert(!SHDWResetApp(prefs, nil));
    assert(!SHDWResetApp(prefs, @""));
    assert(SHDWResetApp(prefs, app));
    assert([[prefs dictionaryRepresentation] isEqual:before]);

    NSString *longBody = [@"## Actual notes\\n- Fix with `code` and https://example.invalid\\n"
        stringByPaddingToLength:100000 withString:@"More release notes.\\n" startingAtIndex:0];
    NSDictionary *release = @{@"tag_name": @"v4.2.0", @"prerelease": @NO,
        @"name": @"Actual release title", @"body": longBody};
    NSDictionary *result = parseJSON(@[
        @{@"tag_name": @"artifacts", @"prerelease": @NO},
        @{@"tag_name": @"v5.0.0", @"prerelease": @YES},
        @{@"tag_name": @42, @"prerelease": @NO},
        @{@"tag_name": @"v8.0", @"prerelease": [NSNull null]},
        [NSNull null], release,
        @{@"tag_name": @"v4.1.0", @"prerelease": @NO}]);
    assert(![result[@"failed"] boolValue]);
    assert([result[@"version"] isEqual:@"4.2.0"]);
    assert([result[@"title"] isEqual:release[@"name"]]);
    assert([result[@"body"] isEqual:longBody]);
    result = parseJSON(@[@{@"tag_name": @"4.0", @"prerelease": @NO,
        @"name": [NSNull null], @"body": @42}]);
    assert([result[@"title"] isEqual:@"4.0"]);
    assert([result[@"body"] isEqual:@""]);
    assert(![parseJSON(@[])[@"failed"] boolValue]);
    assert([parseJSON(@{})[@"failed"] boolValue]);
    assert([parse([@"broken" dataUsingEncoding:NSUTF8StringEncoding], 200, nil)[@"failed"] boolValue]);
    assert([parse(nil, 200, nil)[@"failed"] boolValue]);
    assert([parse([NSData data], 403, nil)[@"failed"] boolValue]);
    assert([parse([NSData data], 200, [NSError errorWithDomain:@"network" code:1 userInfo:nil])[@"failed"] boolValue]);
    puts("PASS: actual settings helpers, symbol availability guard, and release parser (Foundation with UI doubles, no device)");
} return 0; }
'''

args = argparse.ArgumentParser(description=__doc__)
args.add_argument("--docker", metavar="IMAGE")
options = args.parse_args()
with tempfile.TemporaryDirectory(prefix="shadow-settings-") as directory:
    temporary = Path(directory)
    (temporary / "test.m").write_text(source)
    if options.docker:
        subprocess.run([
            "docker", "run", "--rm", "--network=none", "-v", f"{temporary}:/test",
            "-w", "/test", options.docker, "sh", "-ec",
            "clang -fobjc-arc -fobjc-runtime=gnustep-2.0 $(gnustep-config --objc-flags) "
            "-UNDEBUG test.m -o test $(gnustep-config --base-libs) && ./test",
        ], check=True)
    else:
        flags = ["-framework", "Foundation"] if platform.system() == "Darwin" else (
            ["-fobjc-runtime=gnustep-2.0"] + shlex.split(subprocess.check_output(
                ["gnustep-config", "--objc-flags"], text=True)) + shlex.split(
                subprocess.check_output(["gnustep-config", "--base-libs"], text=True)))
        subprocess.run(["clang", "-fobjc-arc", *flags, "-UNDEBUG", "test.m", "-o", "test"],
                       cwd=temporary, check=True)
        subprocess.run([str(temporary / "test")], check=True)
