#include <mach-o/dyld.h>
#include <stdlib.h>

#import "../Includes/Shadow.h"

@implementation Shadow
- (id)init {
    self = [super init];

    if(self) {
        link_map = nil;
        path_map = nil;

        _useTweakCompatibilityMode = NO;
        _useInjectCompatibilityMode = NO;
    }

    return self;
}

- (NSMutableArray *)generateDyldNameArray {
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
            [dyldArray addObject:image_name_ns];
        }
    }

    return dyldArray;
}

- (struct mach_header *)generateDyldHeaderArray {
    uint32_t i;
    uint32_t j = 0;
    uint32_t count = _dyld_image_count();

    struct mach_header *headers = (struct mach_header *) malloc(count * sizeof(struct mach_header));

    if(!headers) {
        return NULL;
    }

    for(i = 0; i < count; i++) {
        const char *image_name = _dyld_get_image_name(i);

        if(image_name) {
            NSString *image_name_ns = [NSString stringWithUTF8String:image_name];

            if([self isImageRestricted:image_name_ns]) {
                // Skip restricted image name.
                continue;
            }

            const struct mach_header *header = _dyld_get_image_header(i);

            headers[j].magic = header->magic;
            headers[j].cputype = header->cputype;
            headers[j].cpusubtype = header->cpusubtype;
            headers[j].filetype = header->filetype;
            headers[j].ncmds = header->ncmds;
            headers[j].sizeofcmds = header->sizeofcmds;
            headers[j].flags = header->flags;

            j++;
        }
    }

    struct mach_header *ret = (struct mach_header *) realloc(headers, j * sizeof(struct mach_header));
    return ret ? ret : headers;
}

- (intptr_t *)generateDyldSlideArray {
    uint32_t i;
    uint32_t j = 0;
    uint32_t count = _dyld_image_count();

    intptr_t *slides = (intptr_t *) malloc(count * sizeof(intptr_t));

    if(!slides) {
        return NULL;
    }

    for(i = 0; i < count; i++) {
        const char *image_name = _dyld_get_image_name(i);

        if(image_name) {
            NSString *image_name_ns = [NSString stringWithUTF8String:image_name];

            if([self isImageRestricted:image_name_ns]) {
                // Skip restricted image name.
                continue;
            }

            intptr_t slide = _dyld_get_image_vmaddr_slide(i);
            slides[j++] = slide;
        }
    }

    intptr_t *ret = (intptr_t *) realloc(slides, j * sizeof(intptr_t));
    return ret ? ret : slides;
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
                            /*|| [[dpkg_file pathExtension] isEqualToString:@"app"]
                            || [[dpkg_file pathExtension] isEqualToString:@"framework"]
                            || [[dpkg_file pathExtension] isEqualToString:@"bundle"]
                            || [[dpkg_file pathExtension] isEqualToString:@"theme"]*/) {
                                [blacklist addObject:dpkg_file_std];
                            }
                        }
                    }
                }
            }
        }
    }

    return [blacklist copy];
}

- (BOOL)isImageRestricted:(NSString *)name {
    if(passthrough) {
        return NO;
    }

    BOOL ret = NO;

    // Match some known dylib paths/names.
    if([name hasPrefix:@"/Library/Frameworks"]
    || [name hasPrefix:@"/Library/Caches/cy-"]
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

    // Find exact match.
    if(!ret) {
        if(![name isAbsolutePath]) {
            NSString *libdir = @"/usr/lib";
            name = [libdir stringByAppendingPathComponent:name];
        }
        
        if([self isPathRestricted:name partial:NO]) {
            ret = YES;
        }
    }

    return ret;
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
    if(passthrough || !path_map) {
        return NO;
    }

    BOOL ret = NO;

    // Change symlink path to real path if in link map.
    NSString *path_resolved = [self resolveLinkInPath:path];
    path = path_resolved;

    // Ensure we are working with absolute path.
    if(![path isAbsolutePath]) {
        NSString *path_abs = [[fm currentDirectoryPath] stringByAppendingPathComponent:path];
        path = path_abs;

        // Change symlink path to real path if in link map (again).
        path_resolved = [self resolveLinkInPath:path];
        path = path_resolved;
    }

    // Remove extra path names.
    if([path hasPrefix:@"/private/var"]
    || [path hasPrefix:@"/private/etc"]) {
        NSMutableArray *pathComponents = [NSMutableArray arrayWithArray:[path pathComponents]];
        [pathComponents removeObjectAtIndex:1];
        path = [NSString pathWithComponents:[pathComponents copy]];
    }

    if([path hasPrefix:@"/var/tmp"]) {
        NSMutableArray *pathComponents = [NSMutableArray arrayWithArray:[path pathComponents]];
        [pathComponents removeObjectAtIndex:1];
        path = [NSString pathWithComponents:[pathComponents copy]];
    }

    if([path hasPrefix:@"/var/mobile"]) {
        NSMutableArray *pathComponents = [NSMutableArray arrayWithArray:[path pathComponents]];
        [pathComponents removeObjectAtIndex:1];
        pathComponents[1] = @"User";
        path = [NSString pathWithComponents:[pathComponents copy]];
    }

    // Check path components with path map.
    if(!ret) {
        NSArray *pathComponents = [path pathComponents];
        NSMutableDictionary *current_path_map = path_map;

        for(NSString *value in pathComponents) {
            if(!current_path_map[value]) {
                if(partial) {
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
                } else {
                    return NO;
                }
            }

            current_path_map = current_path_map[value];
        }

        if(current_path_map[@"restricted"]) {
            ret = [current_path_map[@"restricted"] boolValue];
        }

        if(ret && current_path_map[@"hidden"] && [[pathComponents lastObject] isEqualToString:current_path_map[@"name"]]) {
            ret = [current_path_map[@"hidden"] boolValue];
        }
    }

    // Exclude some paths under tweak compatibility mode.
    if(ret && _useTweakCompatibilityMode) {
        if([path hasPrefix:@"/Library/Application Support"]
        || [path hasPrefix:@"/Library/Frameworks"]
        || [path hasPrefix:@"/Library/Themes"]
        || [path hasPrefix:@"/User/Library/Preferences"]) {
            NSLog(@"unrestricted path (tweak compatibility): %@", path);
            ret = NO;
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
    if(passthrough) {
        return NO;
    }

    BOOL ret = NO;

    // Package manager URL scheme checks
    if([[url scheme] isEqualToString:@"cydia"]
    || [[url scheme] isEqualToString:@"sileo"]
    || [[url scheme] isEqualToString:@"zbra"]) {
        ret = YES;
    }

    // File URL checks
    if(!ret && [url isFileURL]) {
        ret = [self isPathRestricted:[url path] manager:fm partial:partial];
    }

    return ret;
}

- (void)addPath:(NSString *)path restricted:(BOOL)restricted {
    return [self addPath:path restricted:restricted hidden:YES];
}

- (void)addPath:(NSString *)path restricted:(BOOL)restricted hidden:(BOOL)hidden {
    if(!path_map) {
        path_map = [NSMutableDictionary new];
    }

    NSArray *pathComponents = [path pathComponents];
    NSMutableDictionary *current_path_map = path_map;

    for(NSString *value in pathComponents) {
        if(!current_path_map[value]) {
            current_path_map[value] = [NSMutableDictionary new];
            [current_path_map[value] setValue:value forKey:@"name"];
            [current_path_map[value] setValue:@NO forKey:@"restricted"];
            [current_path_map[value] setValue:@NO forKey:@"hidden"];
        }

        current_path_map = current_path_map[value];
    }

    [current_path_map setValue:[NSNumber numberWithBool:restricted] forKey:@"restricted"];
    [current_path_map setValue:[NSNumber numberWithBool:hidden] forKey:@"hidden"];
}

- (void)addRestrictedPath:(NSString *)path {
    if(!path_map) {
        path_map = [NSMutableDictionary new];
    }

    NSArray *pathComponents = [path pathComponents];
    NSMutableDictionary *current_path_map = path_map;

    for(NSString *value in pathComponents) {
        if(!current_path_map[value]) {
            current_path_map[value] = [NSMutableDictionary new];
            [current_path_map[value] setValue:value forKey:@"name"];
            [current_path_map[value] setValue:@YES forKey:@"restricted"];
            [current_path_map[value] setValue:@YES forKey:@"hidden"];
        }

        current_path_map = current_path_map[value];
    }

    [current_path_map setValue:@YES forKey:@"restricted"];
    [current_path_map setValue:@YES forKey:@"hidden"];
}

- (void)addPathsFromFileMap:(NSArray *)file_map {
    for(NSString *path in file_map) {
        [self addRestrictedPath:path];
    }
}

- (void)addLinkFromPath:(NSString *)from toPath:(NSString *)to {
    if(!link_map) {
        link_map = [NSMutableDictionary new];
    }

    NSLog(@"tracking link %@ -> %@", from, to);
    [link_map setValue:to forKey:from];
}

- (NSString *)resolveLinkInPath:(NSString *)path {
    if(!link_map) {
        return path;
    }

    for(NSString *key in link_map) {
        if([path hasPrefix:key]) {
            NSString *value = link_map[key];
            NSString *new_path = [value stringByAppendingPathComponent:[path substringFromIndex:[key length]]];
            path = new_path;
            break;
        }
    }

    return path;
}
@end
