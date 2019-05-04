// In modern jailbreaks, the sandbox is intact so there is no need for restricting access...
// This is more for compatibility in case this tweak actually works on old iOS versions.
bool is_path_sb_readonly(NSString *path) {
	if(path == nil) {
		return false;
	}

	if([path hasPrefix:@"/private"]) {
		if(![path hasPrefix:@"/private/var/MobileDevice/ProvisioningProfiles"]
		&& ![path hasPrefix:@"/private/var/mobile"]) {
			return true;
		}
	}

	if([path hasPrefix:@"/var"]) {
		if(![path hasPrefix:@"/var/MobileDevice/ProvisioningProfiles"]
		&& ![path hasPrefix:@"/var/mobile"]) {
			return true;
		}
	}

	return false;
}

/*
%hook NSData
- (BOOL)writeToFile:(NSString *)path
	atomically:(BOOL)useAuxiliaryFile {
	
	if(is_path_sb_readonly(path)) {
		NSLog(@"[shadow] blocked writeToFile with path %@", path);
		return NO;
	}

	return %orig;
}

- (BOOL)writeToFile:(NSString *)path
	options:(NSDataWritingOptions)writeOptionsMask
	error:(NSError * _Nullable *)errorPtr {
	
	if(is_path_sb_readonly(path)) {
		NSLog(@"[shadow] blocked writeToFile with path %@", path);

		if(errorPtr != NULL) {
			*errorPtr = [NSError errorWithDomain:@"NSCocoaErrorDomain" code:NSFileNoSuchFileError userInfo:nil];
		}

		return NO;
	}

	return %orig;
}

- (BOOL)writeToURL:(NSURL *)url
	atomically:(BOOL)useAuxiliaryFile {
	
	if(is_path_sb_readonly([url path])) {
		NSLog(@"[shadow] blocked writeToFile with path %@", [url path]);
		return NO;
	}

	return %orig;
}

- (BOOL)writeToURL:(NSURL *)url
	options:(NSDataWritingOptions)writeOptionsMask
	error:(NSError * _Nullable *)errorPtr {
	
	if(is_path_sb_readonly([url path])) {
		NSLog(@"[shadow] blocked writeToFile with path %@", [url path]);

		if(errorPtr != nil) {
			*errorPtr = [NSError errorWithDomain:@"NSCocoaErrorDomain" code:NSFileNoSuchFileError userInfo:nil];
		}

		return NO;
	}

	return %orig;
}
%end

%hook NSString
- (BOOL)writeToFile:(NSString *)path
	atomically:(BOOL)useAuxiliaryFile
	encoding:(NSStringEncoding)enc
	error:(NSError * _Nullable *)error {
	
	if(is_path_sb_readonly(path)) {
		NSLog(@"[shadow] blocked writeToFile with path %@", path);

		if(error != nil) {
			*error = [NSError errorWithDomain:@"NSCocoaErrorDomain" code:NSFileNoSuchFileError userInfo:nil];
		}

		return NO;
	}

	return %orig;
}

- (BOOL)writeToURL:(NSURL *)url
	atomically:(BOOL)useAuxiliaryFile
	encoding:(NSStringEncoding)enc
	error:(NSError * _Nullable *)error {
	
	if(is_path_sb_readonly([url path])) {
		NSLog(@"[shadow] blocked writeToURL with path %@", [url path]);

		if(error != nil) {
			*error = [NSError errorWithDomain:@"NSCocoaErrorDomain" code:NSFileNoSuchFileError userInfo:nil];
		}

		return NO;
	}

	return %orig;
}
%end


%hook NSURL
- (BOOL)checkResourceIsReachableAndReturnError:(NSError * _Nullable *)error {
	if(is_jb_path([self path])) {
		NSLog(@"[shadow] blocked checkResourceIsReachableAndReturnError with path %@", [self path]);

		if(error != nil) {
			*error = [NSError errorWithDomain:@"NSCocoaErrorDomain" code:NSFileNoSuchFileError userInfo:nil];
		}

		return NO;
	}

	return %orig;
}
%end
*/

// Seems to be disabled in the SDK (12.2). Probably no point hooking this.
%hookf(int, "system", const char *command) {
	if(command == NULL) {
		return 0;
	}

	//return %orig;
	return 127;
}

%hookf(pid_t, fork) {
	NSLog(@"[shadow] blocked fork");
	return -1;
}

%hookf(FILE *, popen, const char *command, const char *type) {
	NSLog(@"[shadow] blocked popen");
	return NULL;
}

%hookf(int, posix_spawn, pid_t *pid, const char *path, const posix_spawn_file_actions_t *file_actions, const posix_spawnattr_t *attrp, char *const argv[], char *const envp[]) {
	NSLog(@"[shadow] blocked posix_spawn");
	return -1;
}

%hookf(int, posix_spawnp, pid_t *pid, const char *path, const posix_spawn_file_actions_t *file_actions, const posix_spawnattr_t *attrp, char *const argv[], char *const envp[]) {
	NSLog(@"[shadow] blocked posix_spawnp");
	return -1;
}

%hookf(int, setgid, gid_t gid) {
	// Block setgid for root.
	if(gid == 0) {
		NSLog(@"[shadow] blocked setgid(0)");
		return -1;
	}

	return %orig;
}

%hookf(int, setuid, uid_t uid) {
	// Block setuid for root.
	if(uid == 0) {
		NSLog(@"[shadow] blocked setuid(0)");
		return -1;
	}

	return %orig;
}

%hookf(int, setegid, gid_t gid) {
	// Block setegid for root.
	if(gid == 0) {
		NSLog(@"[shadow] blocked setegid(0)");
		return -1;
	}

	return %orig;
}

%hookf(int, seteuid, uid_t uid) {
	// Block seteuid for root.
	if(uid == 0) {
		NSLog(@"[shadow] blocked seteuid(0)");
		return -1;
	}

	return %orig;
}

%hookf(uid_t, getuid) {
	// Return uid for mobile.
	return 501;
}

%hookf(gid_t, getgid) {
	// Return gid for mobile.
	return 501;
}

%hookf(uid_t, geteuid) {
	// Return uid for mobile.
	return 501;
}

%hookf(uid_t, getegid) {
	// Return gid for mobile.
	return 501;
}

%hookf(int, setreuid, uid_t ruid, uid_t euid) {
	// Block for root.
	if(ruid == 0 || euid == 0) {
		return -1;
	}

	return %orig;
}

%hookf(int, setregid, gid_t rgid, gid_t egid) {
	// Block for root.
	if(rgid == 0 || egid == 0) {
		return -1;
	}

	return %orig;
}
