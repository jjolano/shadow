#import <UIKit/UIKit.h>
#import <mach-o/dyld.h>
#import <mach-o/dyld_images.h>
#import <dlfcn.h>

// dyldprobe — W5 on-device verification probe for Shadow v5.
// Shows the jailbreak the way detectors see it, from four angles:
//   1. dyld_all_image_infos read DIRECTLY from memory (W2's target)
//   2. the dyld API view (_dyld_image_count / _dyld_get_image_name)
//   3. file-existence probes of known jailbreak paths
//   4. URL scheme probes (canOpenURL)
// Run it with Shadow disabled for this app (baseline), then with Shadow
// enabled and all hooks on — the two reports are the test.

static NSString* ProbeReport(void) {
    NSMutableString* out = [NSMutableString string];
    NSString* appPath = [[NSBundle mainBundle] bundlePath];
    NSFileManager* fm = [NSFileManager defaultManager];

    [out appendString:@"== 1. dyld_all_image_infos (direct memory read) ==\n"];
    struct dyld_all_image_infos* infos = dlsym(RTLD_DEFAULT, "dyld_all_image_infos");

    if(infos && infos->infoArray) {
        [out appendFormat:@"infoArrayCount = %lu\n", (unsigned long)infos->infoArrayCount];
        [out appendFormat:@"uuidArrayCount = %lu\n", (unsigned long)infos->uuidArrayCount];
        [out appendString:@"non-system entries:\n"];

        for(uint32_t i = 0; i < infos->infoArrayCount; i++) {
            struct dyld_image_info info = infos->infoArray[i];
            NSString* p = info.imageFilePath ? @(info.imageFilePath) : @"?";

            if(![p hasPrefix:@"/System"] && ![p hasPrefix:appPath]) {
                [out appendFormat:@"  %@\n", p];
            }
        }
    } else {
        [out appendString:@"  (dyld_all_image_infos unavailable)\n"];
    }

    [out appendString:@"\n== 2. dyld API view ==\n"];
    uint32_t count = _dyld_image_count();
    [out appendFormat:@"_dyld_image_count = %u\n", count];

    for(uint32_t i = 0; i < count; i++) {
        const char* n = _dyld_get_image_name(i);
        NSString* p = n ? @(n) : @"?";

        if(![p hasPrefix:@"/System"] && ![p hasPrefix:appPath]) {
            [out appendFormat:@"  %@\n", p];
        }
    }

    [out appendString:@"\n== 3. jailbreak path probes (fileExistsAtPath) ==\n"];
    NSArray* jbPaths = @[
        @"/var/jb",
        @"/var/jb/usr/lib/libhooker.dylib",
        @"/var/jb/usr/lib/libsubstitute.0.dylib",
        @"/var/jb/usr/lib/libellekit.dylib",
        @"/var/jb/Library/MobileSubstrate/DynamicLibraries",
        @"/var/jb/bin/sbreload",
        @"/usr/lib/libhooker.dylib",
        @"/usr/lib/libsubstitute.0.dylib",
        @"/usr/lib/libsubstrate.dylib",
        @"/usr/lib/libellekit.dylib",
        @"/usr/lib/pspawn_payload-stg2.dylib",
        @"/usr/lib/tweakloader.dylib",
        @"/Library/MobileSubstrate/MobileSubstrate.dylib",
        @"/usr/bin/sbreload",
        @"/bin/bash",
        @"/Applications/Cydia.app",
        @"/cores",
        @"/usr/libexec/cydia"
    ];

    for(NSString* p in jbPaths) {
        [out appendFormat:@"  %@ %@\n", p, [fm fileExistsAtPath:p] ? @"EXISTS" : @"no"];
    }

    NSArray* preboot = [fm contentsOfDirectoryAtPath:@"/private/preboot" error:nil];
    NSMutableArray* jbdirs = [NSMutableArray new];

    for(NSString* d in preboot) {
        if([d hasPrefix:@"jb-"] || [d hasPrefix:@"procursus"]) {
            [jbdirs addObject:d];
        }
    }

    [out appendFormat:@"  /private/preboot jailbreak dirs: %@\n", jbdirs];

    [out appendString:@"\n== 4. URL scheme probes ==\n"];

    for(NSString* s in @[@"cydia://", @"sileo://", @"zbra://", @"xina://", @"filza://"]) {
        BOOL openable = [[UIApplication sharedApplication] canOpenURL:[NSURL URLWithString:s]];
        [out appendFormat:@"  %-12@ %@\n", s, openable ? @"OPENABLE" : @"no"];
    }

    [out appendString:@"\n== done ==\n"];
    return out;
}

@interface AppDelegate : UIResponder <UIApplicationDelegate>
@property (strong, nonatomic) UIWindow* window;
@end

@implementation AppDelegate {
    UITextView* _textView;
}

- (void)_refresh {
    _textView.text = ProbeReport();
}

- (BOOL)application:(UIApplication*)application didFinishLaunchingWithOptions:(NSDictionary*)launchOptions {
    CGRect frame = [[UIScreen mainScreen] bounds];
    self.window = [[UIWindow alloc] initWithFrame:frame];

    UIViewController* vc = [UIViewController new];
    vc.view = [[UIView alloc] initWithFrame:frame];

    UIButton* refresh = [UIButton buttonWithType:UIButtonTypeSystem];
    refresh.frame = CGRectMake(0, 20, frame.size.width, 44);
    [refresh setTitle:@"Refresh" forState:UIControlStateNormal];
    [refresh addTarget:self action:@selector(_refresh) forControlEvents:UIControlEventTouchUpInside];
    [vc.view addSubview:refresh];

    _textView = [[UITextView alloc] initWithFrame:CGRectMake(0, 64, frame.size.width, frame.size.height - 64)];
    _textView.editable = NO;
    _textView.font = [UIFont systemFontOfSize:11];
    [vc.view addSubview:_textView];

    self.window.rootViewController = vc;
    [self.window makeKeyAndVisible];
    [self _refresh];
    return YES;
}

@end

int main(int argc, char* argv[]) {
    @autoreleasepool {
        return UIApplicationMain(argc, argv, nil, NSStringFromClass([AppDelegate class]));
    }
}
