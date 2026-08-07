#import "SHDWHookLibs.h"
#import <HookKit.h>

NSArray<NSDictionary *> *SHDWAvailableHookLibs(void) {
	NSMutableArray* hooklibs_info = [[HKSubstitutor getSubstitutorTypeInfo:[HKSubstitutor getAvailableSubstitutorTypes]] mutableCopy];

	for(NSDictionary* hooklib_info in [hooklibs_info copy]) {
		NSString* hooklib_id = hooklib_info[@"id"];

		// substrate/substitute are legacy selection ids; swift is a vtable-only
	// opt-in API with no message/function hooks — selecting it as the
	// general hooking engine would leave every hook group unsupported.
	if([hooklib_id isEqualToString:@"substrate"] || [hooklib_id isEqualToString:@"substitute"] || [hooklib_id isEqualToString:@"swift"]) {
			[hooklibs_info removeObject:hooklib_info];
		}
	}

	return hooklibs_info;
}
