#import "ShadowService+Database.h"
#import "ShadowService+Restriction.h"

@implementation ShadowService (Database)
+ (NSDictionary *)generateDatabase {
    // Determine dpkg info database path.
	NSString* dpkgInfoPath = @"/Library/dpkg/info";

	if(![[NSFileManager defaultManager] fileExistsAtPath:dpkgInfoPath]) {
		dpkgInfoPath = @"/var/jb/Library/dpkg/info";
	}

	if(![[NSFileManager defaultManager] fileExistsAtPath:dpkgInfoPath]) {
		return nil;
	}

	NSMutableDictionary* db = [NSMutableDictionary new];
	NSMutableSet* db_installed = [NSMutableSet new];
    NSMutableSet* db_exception = [NSMutableSet new];

	// Iterate all list files in database.
	NSArray* db_files = [[NSFileManager defaultManager] contentsOfDirectoryAtURL:[NSURL fileURLWithPath:dpkgInfoPath] includingPropertiesForKeys:@[] options:0 error:nil];

	for(NSURL* db_file in db_files) {
		if([db_file pathExtension] && [[db_file pathExtension] isEqualToString:@"list"]) {
			NSString* content = [NSString stringWithContentsOfURL:db_file encoding:NSUTF8StringEncoding error:nil];

			if(content) {
				// Read all lines
				NSArray* lines = [content componentsSeparatedByCharactersInSet:[NSCharacterSet newlineCharacterSet]];

                if([[db_file lastPathComponent] isEqualToString:@"base.list"] || [[db_file lastPathComponent] isEqualToString:@"firmware-sbin.list"]) {
                    // exception
                    for(NSString* line in lines) {
                        if(![line isEqualToString:@""]) {
                            [db_exception addObject:line];
                        }
                    }
                } else {
                    // installed
                    for(NSString* line in lines) {
                        if(![line isEqualToString:@""]) {
                            [db_installed addObject:line];
                        }
                    }
                }
			}
		}
	}

	// Filter some unneeded filenames.
	NSArray* filter_names = @[
		@"/."
	];

	for(NSString* name in filter_names) {
		[db_installed removeObject:name];
		[db_exception removeObject:name];
	}

    NSArray* filter_exception = [db_exception allObjects];

    for(NSString* name in filter_exception) {
        [db_installed removeObject:name];
    }

    NSSet* schemes = [NSSet setWithArray:[[self class] getURLSchemes_db:db_installed]];

	[db setObject:[db_installed allObjects] forKey:@"installed"];
    [db setObject:[schemes allObjects] forKey:@"schemes"];
	return [db copy];
}
@end
