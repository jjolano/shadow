#import <HookKit/Core.h>
#import <Modulous/Loader.h>

@implementation HookKitCore {
    ModulousLoader* loader;
    __kindof HookKitModule* _default;
    NSDictionary<NSString *, __kindof HookKitModule *>* registeredModules;
}

+ (instancetype)sharedInstance {
    static HookKitCore* sharedInstance = nil;
    static dispatch_once_t onceToken = 0;

    dispatch_once(&onceToken, ^{
        sharedInstance = [HookKitCore new];
    });

    return sharedInstance;
}

- (__kindof HookKitModule *)defaultModule {
    if(!_default) {
        // load the highest priority module
        NSNumber* module_priority = nil;
        NSString* module_identifier = nil;
        NSString* module_load_identifier = nil;

        NSArray<NSDictionary *>* modulous_infos = [loader getModuleInfo];

        if(modulous_infos) {
            for(NSDictionary* modulous_info in modulous_infos) {
                NSString* modulous_identifier = [modulous_info objectForKey:@"CFBundleIdentifier"];
                NSDictionary* info = [modulous_info objectForKey:@"ModuleInfo"];

                if(info) {
                    NSNumber* priority = [info objectForKey:@"Priority"];

                    if(!priority) {
                        priority = @(0);
                    }

                    if(!module_priority || [module_priority compare:priority] == NSOrderedDescending) {
                        module_priority = priority;
                        module_identifier = [info objectForKey:@"Identifier"];
                        module_load_identifier = modulous_identifier;
                    }
                }
            }
        }

        if(module_load_identifier) {
            [loader loadModulesWithIdentifiers:@[module_load_identifier]];
            _default = [self getModuleWithIdentifier:module_identifier];
        }
    }

    return _default;
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
    __kindof HookKitModule* result = [registeredModules objectForKey:identifier];

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

        result = [registeredModules objectForKey:identifier];
    }

    return result;
}

- (void)registerModule:(__kindof HookKitModule *)module withIdentifier:(NSString *)identifier {
    if(module && identifier) {
        NSMutableDictionary* modules = [registeredModules mutableCopy];
        [modules setObject:module forKey:identifier];
        registeredModules = [modules copy];
    }
}

- (instancetype)init {
    if((self = [super init])) {
        loader = [ModulousLoader loaderWithPath:@"/Library/Modulous/HookKit"];
        registeredModules = @{};
        _default = nil;
    }

    return self;
}
@end