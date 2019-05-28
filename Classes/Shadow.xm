#import "../Includes/Shadow.h"

#include <mach-o/dyld.h>

@implementation Shadow
- (instancetype)init {
    self = [super init];

    if(self) {
        file_map = nil;
        link_map = [NSMutableDictionary new];
        path_map = [NSMutableDictionary new];
        dyld_array = [NSMutableArray new];

        [path_map setValue:@NO forKey:@"restricted"];

        _isDyldArrayGenerated = NO;
        _useTweakCompatibilityMode = NO;
        _useInjectCompatibilityMode = NO;

        passthrough = YES;

        const char *image_name = _dyld_get_image_name(0);

        if(image_name) {
            _dyldSelfImageName = [NSString stringWithUTF8String:image_name];
        } else {
            _dyldSelfImageName = @"";
        }

        passthrough = NO;
    }

    return self;
}

- (void)generateDyldArray {
    passthrough = YES;

    if(_isDyldArrayGenerated) {
        [dyld_array removeAllObjects];
        _isDyldArrayGenerated = NO;
        _dyldArrayCount = 0;
    }

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

            [dyld_array addObject:image_name_ns];
            _dyldArrayCount++;
        }
    }

    passthrough = NO;
    _isDyldArrayGenerated = YES;
}

- (void)generateFileMap {
    passthrough = YES;

    // Generate file map.
    NSString *dpkg_info_path = DPKG_INFO_PATH;
    NSArray *dpkg_info = [[NSFileManager defaultManager] contentsOfDirectoryAtPath:dpkg_info_path error:nil];

    if(dpkg_info) {
        NSMutableArray *blacklist = [NSMutableArray new];

        for(NSString *dpkg_info_file in dpkg_info) {
            // Read only .list files.
            if([[dpkg_info_file pathExtension] isEqualToString:@"list"]) {
                NSString *dpkg_info_file_a = [dpkg_info_path stringByAppendingPathComponent:dpkg_info_file];
                NSString *dpkg_info_contents = [NSString stringWithContentsOfFile:dpkg_info_file_a encoding:NSUTF8StringEncoding error:NULL];

                // Read file paths line by line.
                if(dpkg_info_contents) {
                    NSArray *dpkg_info_contents_files = [dpkg_info_contents componentsSeparatedByCharactersInSet:[NSCharacterSet newlineCharacterSet]];

                    for(NSString *dpkg_file in dpkg_info_contents_files) {
                        BOOL isDir;
                        NSString *dpkg_file_std = [dpkg_file stringByStandardizingPath];

                        if([[NSFileManager defaultManager] fileExistsAtPath:dpkg_file_std isDirectory:&isDir]) {
                            if(!isDir
                            || [[dpkg_file pathExtension] isEqualToString:@"app"]
                            || [[dpkg_file pathExtension] isEqualToString:@"framework"]
                            || [[dpkg_file pathExtension] isEqualToString:@"bundle"]
                            || [[dpkg_file pathExtension] isEqualToString:@"theme"]) {
                                [blacklist addObject:dpkg_file_std];
                            }
                        }
                    }
                }
            }
        }

        NSMutableDictionary *prefs = [[NSMutableDictionary alloc] initWithContentsOfFile:PREFS_PATH];

        if(prefs) {
            [prefs setValue:blacklist forKey:@"file_map"];

            if([prefs writeToFile:PREFS_PATH atomically:YES]) {
                NSLog(@"wrote file map to preferences");
            }
        }

        // Set internal file map to this newly generated one.
        [self generateFileMapWithArray:blacklist];
    }

    passthrough = NO;
}

- (void)generateFileMapWithArray:(NSArray *)file_map_array {
    file_map = [NSSet setWithArray:file_map_array];
}

- (BOOL)isImageRestricted:(NSString *)name {
    if(passthrough) {
        return NO;
    }

    BOOL ret = NO;

    passthrough = YES;

    // Use file map if available.
    if(file_map) {
        if([file_map containsObject:name]) {
            ret = YES;
        }
    }

    // Match some known dylib paths/names.
    if(!ret) {
        if([name hasPrefix:@"/Library/Frameworks"]
        || [name hasPrefix:@"/Library/Caches"]
        || [name containsString:@"Substrate"]
        || [name containsString:@"substrate"]
        || [name containsString:@"substitute"]
        || [name containsString:@"Substitrate"]
        || [name containsString:@"TweakInject"]
        || [name containsString:@"libjailbreak"]
        || [name containsString:@"cycript"]
        || [name containsString:@"SBInject"]
        || [name containsString:@"pspawn"]
        || [name containsString:@"librocketbootstrap"]
        || [name containsString:@"libcolorpicker"]
        || [name containsString:@"libCS"]
        || [name containsString:@"bfdecrypt"]) {
            ret = YES;
        }
    }

    passthrough = NO;

    return ret;
}

- (BOOL)isPathRestricted:(NSString *)path {
    return [self isPathRestricted:path manager:[NSFileManager defaultManager]];
}

- (BOOL)isPathRestricted:(NSString *)path manager:(NSFileManager *)fm {
    if(passthrough) {
        return NO;
    }

    // Root itself is never restricted
    if([path isEqualToString:@"/"]) {
        return NO;
    }

    BOOL ret = NO;

    passthrough = YES;

    // Change symlink path to real path if in link map.
    path = [self resolveLinkInPath:path];

    // Ensure we are working with absolute path.
    if(![path isAbsolutePath]) {
        path = [[fm currentDirectoryPath] stringByAppendingPathComponent:path];
    }

    // Change symlink path to real path if in link map (again).
    path = [self resolveLinkInPath:path];

    // Remove extra path names.
    if([path hasPrefix:@"/private"]) {
        NSMutableArray *pathComponents = [NSMutableArray arrayWithArray:[path pathComponents]];
        [pathComponents removeObjectAtIndex:1];
        path = [NSString pathWithComponents:pathComponents];
    }

    if([path hasPrefix:@"/var/tmp"]) {
        NSMutableArray *pathComponents = [NSMutableArray arrayWithArray:[path pathComponents]];
        [pathComponents removeObjectAtIndex:1];
        path = [NSString pathWithComponents:pathComponents];
    }

    if([path hasPrefix:@"/var/mobile"]) {
        NSMutableArray *pathComponents = [NSMutableArray arrayWithArray:[path pathComponents]];
        [pathComponents removeObjectAtIndex:1];
        pathComponents[1] = @"User";
        path = [NSString pathWithComponents:pathComponents];
    }

    // Use file map if available.
    if(file_map) {
        if([file_map containsObject:path]) {
            ret = YES;
        }
    }

    // Check path components with path map.
    if(!ret) {
        NSArray *pathComponents = [path pathComponents];
        NSMutableDictionary *current_path_map = path_map;

        for(NSString *value in pathComponents) {
            if(!current_path_map[value]) {
                BOOL match = NO;

                // Attempt partial match
                for(NSString *value_match in current_path_map) {
                    if([value hasPrefix:value_match]) {
                        match = YES;
                        break;
                    }
                }

                if(!match) {
                    break;
                }
            }

            current_path_map = current_path_map[value];
        }

        ret = [current_path_map[@"restricted"] boolValue];
    }

    // Exclude some paths under tweak compatibility mode.
    if(_useTweakCompatibilityMode) {
        if([path hasPrefix:@"/Library/Application Support"]
        || [path hasPrefix:@"/Library/Frameworks"]
        || [path hasPrefix:@"/Library/Themes"]) {
            ret = NO;
        }
    }

    if(ret) {
        NSLog(@"restricted path: %@", path);
    }

    passthrough = NO;

    return ret;
}

- (BOOL)isURLRestricted:(NSURL *)url {
    if(passthrough) {
        return NO;
    }

    BOOL ret = NO;

    passthrough = YES;

    // Package manager URL scheme checks
    if([[url scheme] isEqualToString:@"cydia"]
    || [[url scheme] isEqualToString:@"sileo"]
    || [[url scheme] isEqualToString:@"zbra"]) {
        ret = YES;
    }

    passthrough = NO;

    // File URL checks
    if(!ret && [url isFileURL]) {
        ret = [self isPathRestricted:[url path]];
    }

    return ret;
}

- (void)addPath:(NSString *)path restricted:(BOOL)restricted {
    NSArray *pathComponents = [path pathComponents];
    NSMutableDictionary *current_path_map = path_map;

    for(NSString *value in pathComponents) {
        if(!current_path_map[value]) {
            current_path_map[value] = [NSMutableDictionary new];
            [current_path_map[value] setValue:@NO forKey:@"restricted"];
        }

        current_path_map = current_path_map[value];
    }

    [current_path_map setValue:[NSNumber numberWithBool:restricted] forKey:@"restricted"];
}

- (void)addLinkFromPath:(NSString *)from toPath:(NSString *)to {
    [link_map setValue:to forKey:from];
}

- (NSString *)resolveLinkInPath:(NSString *)path {
    for(NSString *key in link_map) {
        if([path hasPrefix:key]) {
            NSString *value = link_map[key];
            path = [value stringByAppendingPathComponent:[path substringFromIndex:[key length]]];
        }
    }

    return path;
}

- (const char *)getDyldImageName:(uint32_t)image_index {
    if(image_index > _dyldArrayCount) {
        return NULL;
    }

    return [dyld_array[image_index] UTF8String];
}
@end
