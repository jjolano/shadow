#include <mach-o/dyld.h>
#include <stdlib.h>

#import "../Includes/Shadow.h"

@implementation Shadow
- (id)init {
    self = [super init];

    if(self) {
        link_map = [NSMutableDictionary new];
        path_map = [NSMutableDictionary new];
        image_set = [NSMutableArray new];
        url_set = [NSMutableArray new];

        _useTweakCompatibilityMode = NO;
        _useInjectCompatibilityMode = NO;
        _usePathStandardization = NO;
        _passthrough = NO;
    }

    return self;
}

- (NSArray *)generateDyldArray {
    NSMutableArray *dyldArray = [NSMutableArray new];

    uint32_t i;
    uint32_t count = _dyld_image_count();

    for(i = 0; i < count; i++) {
        const char *image_name = _dyld_get_image_name(i);

        if(image_name) {
            NSString *image_name_ns = [NSString stringWithUTF8String:image_name];

            if([self isImageRestricted:image_name_ns]) {
                // Skip restricted image name.
                continue;
            }

            // [dyldArray addObject:[NSNumber numberWithUnsignedInt:i]];
            [dyldArray addObject:[NSNumber numberWithUnsignedInt:i]];
        }
    }

    return [dyldArray copy];
}

+ (NSArray *)generateFileMap {
    // Generate file map.
    NSMutableArray *blacklist = [NSMutableArray new];

    NSString *dpkg_info_path = DPKG_INFO_PATH;
    NSArray *dpkg_info = [[NSFileManager defaultManager] contentsOfDirectoryAtPath:dpkg_info_path error:nil];

    if(dpkg_info) {
        for(NSString *dpkg_info_file in dpkg_info) {
            // Read only .list files.
            if([[dpkg_info_file pathExtension] isEqualToString:@"list"]) {
                // Skip some packages.
                if([dpkg_info_file isEqualToString:@"firmware-sbin.list"]
                || [dpkg_info_file hasPrefix:@"gsc."]
                || [dpkg_info_file hasPrefix:@"cy+"]) {
                    continue;
                }

                NSString *dpkg_info_file_a = [dpkg_info_path stringByAppendingPathComponent:dpkg_info_file];
                NSString *dpkg_info_contents = [NSString stringWithContentsOfFile:dpkg_info_file_a encoding:NSUTF8StringEncoding error:NULL];

                // Read file paths line by line.
                if(dpkg_info_contents) {
                    NSArray *dpkg_info_contents_files = [dpkg_info_contents componentsSeparatedByCharactersInSet:[NSCharacterSet newlineCharacterSet]];

                    for(NSString *dpkg_file in dpkg_info_contents_files) {
                        BOOL isDir;

                        if([[NSFileManager defaultManager] fileExistsAtPath:dpkg_file isDirectory:&isDir]) {
                            if(!isDir
                            /*|| [[dpkg_file pathExtension] isEqualToString:@"app"]
                            || [[dpkg_file pathExtension] isEqualToString:@"framework"]
                            || [[dpkg_file pathExtension] isEqualToString:@"bundle"]
                            || [[dpkg_file pathExtension] isEqualToString:@"theme"]*/) {
                                [blacklist addObject:dpkg_file];
                            }
                        }
                    }
                }
            }
        }
    }

    return [blacklist copy];
}

+ (NSArray *)generateSchemeArray {
    // Generate URL scheme set from installed packages.
    NSMutableArray *blacklist = [NSMutableArray new];

    NSString *dpkg_info_path = DPKG_INFO_PATH;
    NSArray *dpkg_info = [[NSFileManager defaultManager] contentsOfDirectoryAtPath:dpkg_info_path error:nil];

    if(dpkg_info) {
        for(NSString *dpkg_info_file in dpkg_info) {
            // Read only .list files.
            if([[dpkg_info_file pathExtension] isEqualToString:@"list"]) {
                // Skip some packages.
                if([dpkg_info_file isEqualToString:@"firmware-sbin.list"]
                || [dpkg_info_file hasPrefix:@"gsc."]
                || [dpkg_info_file hasPrefix:@"cy+"]) {
                    continue;
                }
                
                NSString *dpkg_info_file_a = [dpkg_info_path stringByAppendingPathComponent:dpkg_info_file];
                NSString *dpkg_info_contents = [NSString stringWithContentsOfFile:dpkg_info_file_a encoding:NSUTF8StringEncoding error:NULL];

                // Read file paths line by line.
                if(dpkg_info_contents) {
                    NSArray *dpkg_info_contents_files = [dpkg_info_contents componentsSeparatedByCharactersInSet:[NSCharacterSet newlineCharacterSet]];

                    for(NSString *dpkg_file in dpkg_info_contents_files) {
                        if([dpkg_file hasPrefix:@"/Applications"]) {
                            BOOL isDir;

                            if([[NSFileManager defaultManager] fileExistsAtPath:dpkg_file isDirectory:&isDir]) {
                                if(isDir && [[dpkg_file pathExtension] isEqualToString:@"app"]) {
                                    // Open Info.plist
                                    NSMutableDictionary *plist_info = [NSMutableDictionary dictionaryWithContentsOfFile:[dpkg_file stringByAppendingPathComponent:@"Info.plist"]];

                                    if(plist_info) {
                                        for(NSDictionary *type in plist_info[@"CFBundleURLTypes"]) {
                                            for(NSString *scheme in type[@"CFBundleURLSchemes"]) {
                                                [blacklist addObject:scheme];
                                            }
                                        }
                                    }
                                }
                            }
                        }
                    }
                }
            }
        }
    }

    return [blacklist copy];
}

+ (NSError *)generateFileNotFoundError {
    NSDictionary *userInfo = @{
        NSLocalizedDescriptionKey: NSLocalizedString(@"Operation was unsuccessful.", nil),
        NSLocalizedFailureReasonErrorKey: NSLocalizedString(@"Object does not exist.", nil),
        NSLocalizedRecoverySuggestionErrorKey: NSLocalizedString(@"Don't access this again :)", nil)
    };

    NSError *error = [NSError errorWithDomain:NSCocoaErrorDomain code:NSFileNoSuchFileError userInfo:userInfo];
    return error;
}

- (BOOL)isImageRestricted:(NSString *)name {
    if(!name || _passthrough) {
        return NO;
    }

    // Match some known dylib paths/names.
    if([name hasPrefix:@"/Library/Frameworks"]
    || [name hasPrefix:@"/Library/Caches/cy-"]
    || [name hasPrefix:@"/Library/MobileSubstrate"]
    || [name hasPrefix:@"/Library/TweakInject"]
    || [name hasPrefix:@"/usr/lib/tweaks"]
    || [name hasPrefix:@"/usr/lib/TweakInject"]
    || [name hasPrefix:@"/var/containers/Bundle/tweaksupport"]
    || [name hasPrefix:@"/var/containers/Bundle/dylibs"]
    || [name containsString:@"Substrate"]
    || [name containsString:@"substrate"]
    || [name containsString:@"substitute"]
    || [name containsString:@"Substitrate"]
    || [name containsString:@"TweakInject"]
    || [name containsString:@"jailbreak"]
    || [name containsString:@"cycript"]
    || [name containsString:@"SBInject"]
    || [name containsString:@"pspawn"]
    || [name containsString:@"rocketbootstrap"]
    || [name containsString:@"bfdecrypt"]) {
        return YES;
    }

    // Find exact match.
    if(![name isAbsolutePath]) {
        name = [NSString stringWithFormat:@"/usr/lib/lib%@.dylib", name];
    }

    if([image_set containsObject:name]) {
        return YES;
    }
    
    if([self isPathRestricted:name partial:NO]) {
        return YES;
    }

    return NO;
}

- (BOOL)isPathRestricted:(NSString *)path {
    return [self isPathRestricted:path manager:[NSFileManager defaultManager] partial:YES];
}

- (BOOL)isPathRestricted:(NSString *)path partial:(BOOL)partial {
    return [self isPathRestricted:path manager:[NSFileManager defaultManager] partial:partial];
}

- (BOOL)isPathRestricted:(NSString *)path manager:(NSFileManager *)fm {
    return [self isPathRestricted:path manager:fm partial:YES];
}

- (BOOL)isPathRestricted:(NSString *)path manager:(NSFileManager *)fm partial:(BOOL)partial {
    if(!path || _passthrough || !path_map || [path containsString:@"file:"]) {
        return NO;
    }

    if(!fm) {
        fm = [NSFileManager defaultManager];
    }

    BOOL ret = NO;

    // Change symlink path to real path if in link map.
    NSString *path_resolved = [self resolveLinkInPath:path];
    path = path_resolved;

    // Standardize path if enabled.
    if(_usePathStandardization) {
        path = [path stringByStandardizingPath];
    }

    // Ensure we are working with absolute path.
    if(![path isAbsolutePath]) {
        NSString *path_abs = [[fm currentDirectoryPath] stringByAppendingPathComponent:path];
        // NSString *path_abs = [NSString stringWithFormat:@"%@/%@", [fm currentDirectoryPath], path];
        path = path_abs;
    }

    // Remove extra path names.
    if([path hasPrefix:@"/private/var"]
    || [path hasPrefix:@"/private/etc"]) {
        NSMutableArray *pathComponents = [NSMutableArray arrayWithArray:[path pathComponents]];
        [pathComponents removeObjectAtIndex:1];
        path = [NSString pathWithComponents:pathComponents];
    }

    if([path hasPrefix:@"/var/tmp"]) {
        NSMutableArray *pathComponents = [NSMutableArray arrayWithArray:[path pathComponents]];
        [pathComponents removeObjectAtIndex:1];
        path = [NSString pathWithComponents:pathComponents];
    }

    // Exclude some paths under tweak compatibility mode.
    if(_useTweakCompatibilityMode) {
        if([path hasPrefix:@"/Library/Application Support"]
        || [path hasPrefix:@"/Library/Frameworks"]
        || [path hasPrefix:@"/Library/Themes"]
        || [path hasPrefix:@"/Library/SnowBoard"]
        || [path hasPrefix:@"/Library/PreferenceBundles"]
        || [path hasPrefix:@"/var/mobile/Library/Preferences"]
        || [path hasPrefix:@"/User/Library/Preferences"]) {
            NSLog(@"unrestricted path (tweak compatibility): %@", path);
            return NO;
        }
    }

    // Check path components with path map.
    if(!ret) {
        NSArray *pathComponents = [path pathComponents];
        NSDictionary *current_path_map = [path_map copy];

        for(NSString *value in pathComponents) {
            NSDictionary *next = [current_path_map[value] copy];

            if(!next) {
                if(partial) {
                    // Attempt partial match.
                    for(NSString *value_match in current_path_map) {
                        if([value hasPrefix:value_match]) {
                            next = [current_path_map[value_match] copy];
                            break;
                        }
                    }

                    if(!next) {
                        break;
                    }
                } else {
                    // Did not exact match.
                    return NO;
                }
            }

            current_path_map = next;
        }

        if(current_path_map[@"restricted"]) {
            ret = [current_path_map[@"restricted"] boolValue];
        }

        if(ret && current_path_map[@"hidden"] && [[pathComponents lastObject] isEqualToString:current_path_map[@"name"]]) {
            ret = [current_path_map[@"hidden"] boolValue];
        }
    }

    if(ret) {
        NSLog(@"restricted path: %@", path);
    }

    return ret;
}

- (BOOL)isURLRestricted:(NSURL *)url {
    return [self isURLRestricted:url manager:[NSFileManager defaultManager] partial:YES];
}

- (BOOL)isURLRestricted:(NSURL *)url partial:(BOOL)partial {
    return [self isURLRestricted:url manager:[NSFileManager defaultManager] partial:partial];
}

- (BOOL)isURLRestricted:(NSURL *)url manager:(NSFileManager *)fm {
    return [self isURLRestricted:url manager:fm partial:YES];
}

- (BOOL)isURLRestricted:(NSURL *)url manager:(NSFileManager *)fm partial:(BOOL)partial {
    if(!url || _passthrough) {
        return NO;
    }

    // Package manager URL scheme checks
    if([[url scheme] isEqualToString:@"cydia"]
    || [[url scheme] isEqualToString:@"sileo"]
    || [[url scheme] isEqualToString:@"zbra"]) {
        return YES;
    }

    // File URL checks
    if([url isFileURL]) {
        NSString *path = [url path];

        // Handle File Reference URLs
        if([url isFileReferenceURL]) {
            NSURL *surl = [url standardizedURL];

            if(surl) {
                path = [surl path];
            }
        }

        return [self isPathRestricted:path manager:fm partial:partial];
    }

    // URL set checks
    if([url_set containsObject:[url scheme]]) {
        return YES;
    }

    return NO;
}

- (void)addPath:(NSString *)path restricted:(BOOL)restricted {
    [self addPath:path restricted:restricted hidden:YES prestricted:NO phidden:NO];
}

- (void)addPath:(NSString *)path restricted:(BOOL)restricted hidden:(BOOL)hidden {
    [self addPath:path restricted:restricted hidden:hidden prestricted:NO phidden:NO];
}

- (void)addPath:(NSString *)path restricted:(BOOL)restricted hidden:(BOOL)hidden prestricted:(BOOL)prestricted phidden:(BOOL)phidden {
    if(path) {
        NSArray *pathComponents = [path pathComponents];
        NSMutableDictionary *current_path_map = path_map;

        for(NSString *value in pathComponents) {
            if(!current_path_map[value]) {
                current_path_map[value] = [NSMutableDictionary new];
                [current_path_map[value] setValue:value forKey:@"name"];
                [current_path_map[value] setValue:[NSNumber numberWithBool:prestricted] forKey:@"restricted"];
                [current_path_map[value] setValue:[NSNumber numberWithBool:phidden] forKey:@"hidden"];
            }

            current_path_map = current_path_map[value];
        }

        [current_path_map setValue:[NSNumber numberWithBool:restricted] forKey:@"restricted"];
        [current_path_map setValue:[NSNumber numberWithBool:hidden] forKey:@"hidden"];
    }
}

- (void)addRestrictedPath:(NSString *)path {
    [self addPath:path restricted:YES hidden:YES prestricted:YES phidden:YES];
}

- (void)addPathsFromFileMap:(NSArray *)file_map {
    if(file_map) {
        for(NSString *path in file_map) {
            if([path hasPrefix:@"/System"]) {
                // Don't restrict paths along the way for /System
                [self addPath:path restricted:YES];
            } else {
                if([path hasPrefix:@"/usr/lib"]
                || [path hasPrefix:@"/Library/MobileSubstrate"]) {
                    [image_set addObject:path];

                    if(_useTweakCompatibilityMode) {
                        continue;
                    }
                }

                [self addRestrictedPath:path];
            }
        }
    }
}

- (void)addSchemesFromURLSet:(NSArray *)set {
    if(set) {
        [url_set addObjectsFromArray:set];
    }
}

- (void)addLinkFromPath:(NSString *)from toPath:(NSString *)to {
    if(from && to) {
        // Exclude some paths under tweak compatibility mode.
        if(_useTweakCompatibilityMode) {
            if([from hasPrefix:@"/Library/Application Support"]
            || [from hasPrefix:@"/Library/Frameworks"]
            || [from hasPrefix:@"/Library/Themes"]
            || [from hasPrefix:@"/Library/SnowBoard"]
            || [from hasPrefix:@"/Library/PreferenceBundles"]
            || [from hasPrefix:@"/var/mobile/Library/Preferences"]
            || [from hasPrefix:@"/User/Library/Preferences"]) {
                return;
            }
        }

        // Exception for relative destination paths.
        if(![to isAbsolutePath]) {
            return;
        }

        NSLog(@"tracking link %@ -> %@", from, to);
        [link_map setValue:to forKey:from];
    }
}

- (NSString *)resolveLinkInPath:(NSString *)path {
    if(path) {
        NSDictionary *links = [link_map copy];

        for(NSString *key in links) {
            if([path hasPrefix:key]) {
                NSString *value = links[key];
                
                if([key isEqualToString:@"/"]) {
                    path = [value stringByAppendingPathComponent:path];
                } else {
                    path = [path stringByReplacingOccurrencesOfString:key withString:value];
                }

                break;
            }
        }
    }

    return path;
}
@end
