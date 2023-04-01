#import <HookKit/Core.h>
#import <Modulous/Loader.h>
#import <RootBridge.h>

@implementation HookKitCore {
    ModulousLoader* loader;
    NSMutableDictionary<NSString *, __kindof HookKitModule *>* registeredModules;
}

+ (instancetype)sharedInstance {
    static HookKitCore* sharedInstance = nil;
    static dispatch_once_t onceToken = 0;

    dispatch_once(&onceToken, ^{
        sharedInstance = [self new];
    });

    return sharedInstance;
}

- (__kindof HookKitModule *)defaultModule {
    static __kindof HookKitModule* defaultModule = nil;
    static dispatch_once_t onceToken = 0;

    dispatch_once(&onceToken, ^{
        // load the highest priority module
        NSArray<NSDictionary *>* modulous_infos = [[loader getModuleInfo] sortedArrayUsingComparator:^NSComparisonResult(NSDictionary* a, NSDictionary* b) {
            NSDictionary* info_a = [a objectForKey:@"ModuleInfo"];
            NSDictionary* info_b = [b objectForKey:@"ModuleInfo"];
            NSNumber* prio_a = [info_a objectForKey:@"Priority"];
            NSNumber* prio_b = [info_b objectForKey:@"Priority"];

            if(!prio_a) {
                prio_a = @(100);
            }

            if(!prio_b) {
                prio_b = @(100);
            }

            return [prio_a compare:prio_b];
        }];

        if(modulous_infos) {
            for(NSDictionary* modulous_info in modulous_infos) {
                NSString* modulous_identifier = [modulous_info objectForKey:@"CFBundleIdentifier"];
                NSDictionary* info = [modulous_info objectForKey:@"ModuleInfo"];

                if(info) {
                    NSString* module_identifier = [info objectForKey:@"Identifier"];
                    
                    [loader loadModulesWithIdentifiers:@[modulous_identifier]];
                    defaultModule = [self getModuleWithIdentifier:module_identifier];
                }

                if(defaultModule) {
                    break;
                }
            }
        }
    });

    return defaultModule;
}

- (NSArray<NSDictionary *> *)getModuleInfo {
    NSMutableArray<NSDictionary *>* infos = [NSMutableArray new];
    NSArray<NSDictionary *>* modulous_infos = [loader getModuleInfo];

    if(modulous_infos) {
        for(NSDictionary* modulous_info in modulous_infos) {
            NSDictionary* info = [modulous_info objectForKey:@"ModuleInfo"];

            if(info) {
                [infos addObject:info];
            }
        }
    }

    return [infos copy];
}

- (NSDictionary *)getModuleInfoWithIdentifier:(NSString *)identifier {
    NSArray<NSDictionary *>* modulous_infos = [loader getModuleInfo];

    if(modulous_infos) {
        for(NSDictionary* modulous_info in modulous_infos) {
            NSDictionary* info = [modulous_info objectForKey:@"ModuleInfo"];

            if(info && [[info objectForKey:@"Identifier"] isEqualToString:identifier]) {
                return info;
            }
        }
    }

    return nil;
}

- (__kindof HookKitModule *)getModuleWithIdentifier:(NSString *)identifier {
    __kindof HookKitModule* result = nil;

    @synchronized(registeredModules) {
        result = [registeredModules objectForKey:identifier];
    }

    if(!result) {
        NSArray<NSDictionary *>* modulous_infos = [loader getModuleInfo];

        if(modulous_infos) {
            for(NSDictionary* modulous_info in modulous_infos) {
                NSString* modulous_identifier = [modulous_info objectForKey:@"CFBundleIdentifier"];
                NSDictionary* info = [modulous_info objectForKey:@"ModuleInfo"];

                if(info && [[info objectForKey:@"Identifier"] isEqualToString:identifier]) {
                    // load module with modulous
                    [loader loadModulesWithIdentifiers:@[modulous_identifier]];
                }
            }
        }

        @synchronized(registeredModules) {
            result = [registeredModules objectForKey:identifier];
        }
    }

    return result;
}

- (void)registerModule:(__kindof HookKitModule *)module withIdentifier:(NSString *)identifier {
    if(module && identifier) {
        @synchronized(registeredModules) {
            [registeredModules setObject:module forKey:identifier];
        }
    }
}

- (instancetype)init {
    if((self = [super init])) {
        loader = [ModulousLoader loaderWithPath:[RootBridge getJBPath:@"/Library/Modulous/HookKit"]];
        registeredModules = [NSMutableDictionary new];
    }

    return self;
}
@end