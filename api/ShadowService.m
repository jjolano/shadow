#import "ShadowService.h"
#import "ShadowService+Restriction.h"
#import "ShadowSettings.h"
#import "common.h"

#import <AppSupport/CPDistributedMessagingCenter.h>

@implementation ShadowService {
	NSCache* responseCache;
	NSDictionary* db;
	NSString* dpkgPath;
	CPDistributedMessagingCenter* center;
}

- (NSDictionary *)handleMessageNamed:(NSString *)name withUserInfo:(NSDictionary *)userInfo {
	if(!name) {
		return nil;
	}

	NSDictionary* response = nil;

	if([name isEqualToString:@"resolvePath"]) {
		if(!userInfo) {
			return nil;
		}

		NSString* rawPath = userInfo[@"path"];

		if(!rawPath) {
			return nil;
		}

		// Resolve and standardize path.
		if(dpkgPath) {
			// Unsandboxed and unhooked - safe to resolve
			NSString* path = [[rawPath stringByExpandingTildeInPath] stringByStandardizingPath];

			if([path hasPrefix:@"/private/var"] || [path hasPrefix:@"/private/etc"]) {
				NSMutableArray* pathComponents = [[path pathComponents] mutableCopy];
				[pathComponents removeObjectAtIndex:1];
				path = [NSString pathWithComponents:pathComponents];
			}

			if([path hasPrefix:@"/var/tmp"]) {
				NSMutableArray* pathComponents = [[path pathComponents] mutableCopy];
				[pathComponents removeObjectAtIndex:1];
				path = [NSString pathWithComponents:pathComponents];
			}

			response = @{
				@"path" : path
			};
		} else {
			// Sandboxed and hooked
			return nil;
		}
	} else if([name isEqualToString:@"isPathRestricted"]) {
		if(!userInfo) {
			return nil;
		}
		
		NSString* path = userInfo[@"path"];

		if(!path || ![path isAbsolutePath] || [path isEqualToString:@"/"] || [path isEqualToString:@""]) {
			return nil;
		}

		if(dpkgPath && ![[NSFileManager defaultManager] fileExistsAtPath:path]) {
			return nil;
		}

		NSLog(@"%@: %@", name, path);
		
		// Check if path is restricted.
		BOOL restricted = NO;

		if(db && db[@"installed"]) {
			restricted = [[self class] isPathRestricted_db:db[@"installed"] withPath:path];
		} else if(dpkgPath) {
			restricted = [[self class] isPathRestricted_dpkg:dpkgPath withPath:path];
		}

		response = @{
			@"restricted" : @(restricted)
		};
	} else if([name isEqualToString:@"getURLSchemes"]) {
		NSArray* schemes = nil;

		if(db && db[@"schemes"]) {
			schemes = db[@"schemes"];
		} else if(dpkgPath) {
			schemes = [[self class] getURLSchemes_dpkg:dpkgPath];
		}

		response = @{
			@"schemes" : schemes
		};
	} else if([name isEqualToString:@"getPreferences"]) {
		if(!userInfo) {
			return nil;
		}

		NSString* bundleIdentifier = userInfo[@"bundleIdentifier"];

		if(!bundleIdentifier) {
			return nil;
		}

		response = [ShadowSettings getPreferences:bundleIdentifier];
	}

	return response;
}

- (void)startService {
	dpkgPath = @"/usr/bin/dpkg-query";

	if(![[NSFileManager defaultManager] fileExistsAtPath:dpkgPath]) {
		dpkgPath = @"/var/jb/usr/bin/dpkg-query";
	}

	if(![[NSFileManager defaultManager] fileExistsAtPath:dpkgPath]) {
		dpkgPath = nil;
	}

	[self connectService];

	if(center) {
		[center runServerOnCurrentThread];

		// Register messages.
		SEL handler = @selector(handleMessageNamed:withUserInfo:);

		[center registerForMessageName:@"isPathRestricted" target:self selector:handler];
		[center registerForMessageName:@"resolvePath" target:self selector:handler];
		[center registerForMessageName:@"getURLSchemes" target:self selector:handler];
		[center registerForMessageName:@"getPreferences" target:self selector:handler];
	}
}

- (void)startLocalService {
	// Load precompiled data from filesystem.
	db = [NSDictionary dictionaryWithContentsOfFile:@SHADOW_DB_PLIST];

	if(!db) {
		db = [NSDictionary dictionaryWithContentsOfFile:@("/var/jb" SHADOW_DB_PLIST)];
	}

	if(!db) {
		NSLog(@"%@", @"could not load db");
	} else {
		NSLog(@"%@", @"successfully loaded db");
	}
}

- (void)connectService {
	center = [CPDistributedMessagingCenter centerNamed:@MACH_SERVICE_NAME];
}

- (NSDictionary *)sendIPC:(NSString *)messageName withArgs:(NSDictionary *)args useService:(BOOL)service {
	if(service) {
		if(center) {
			NSError* error = nil;
			NSDictionary* result = [center sendMessageAndReceiveReplyName:messageName userInfo:args error:&error];
			return error ? nil : result;
		}

		return nil;
	}

	return [self handleMessageNamed:messageName withUserInfo:args];
}

- (NSDictionary *)sendIPC:(NSString *)messageName withArgs:(NSDictionary *)args {
	return [self sendIPC:messageName withArgs:args useService:(center != nil)];
}

- (NSString *)resolvePath:(NSString *)path {
	if(!path) {
		return nil;
	}

	NSDictionary* response = [self sendIPC:@"resolvePath" withArgs:@{@"path" : path} useService:(center != nil)];

	if(response) {
		path = response[@"path"];
	}

	return path;
}

- (BOOL)isPathRestricted:(NSString *)path {
	if(!path || [path isEqualToString:@"/"] || [path isEqualToString:@""]) {
		return NO;
	}

	// Rootless
    if([path isEqualToString:@"/var/jb"]
    || ([path hasPrefix:@"/private/preboot"]
    && [[path pathComponents] count] >= 5
    && [[[path pathComponents] objectAtIndex:4] isEqualToString:@"procursus"])) {
		return YES;
	}

	NSNumber* response_cached = [responseCache objectForKey:path];

	if(response_cached) {
		return [response_cached boolValue];
	}

	NSDictionary* response = [self sendIPC:@"isPathRestricted" withArgs:@{@"path" : path} useService:(db == nil)];

	if(response) {
		BOOL restricted = [response[@"restricted"] boolValue];

		if(!restricted) {
			BOOL responseParent = [self isPathRestricted:[path stringByDeletingLastPathComponent]];

			if(responseParent) {
				restricted = YES;
			}
		}

		[responseCache setObject:@(restricted) forKey:path];
		return restricted;
	}

	return NO;
}

- (NSArray *)getURLSchemes {
	NSDictionary* response = [self sendIPC:@"getURLSchemes" withArgs:nil useService:(db == nil)];

	if(response && response[@"schemes"] && [response[@"schemes"] count] > 0) {
		return response[@"schemes"];
	}

	return @[@"cydia", @"sileo", @"zbra", @"filza", @"undecimus", @"xina"];
}

- (NSDictionary *)getVersions {
	return @{
		@"build_date" : [NSString stringWithFormat:@"%@ %@", @__DATE__, @__TIME__],
		@"bypass_version" : @BYPASS_VERSION,
		@"api_version" : @API_VERSION
	};
}

- (instancetype)init {
	if((self = [super init])) {
		responseCache = [NSCache new];
		center = nil;
		db = nil;
		dpkgPath = nil;
	}

	return self;
}
@end
