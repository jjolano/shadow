#import "SHDWHookLibs.h"

NSArray<NSDictionary *> *SHDWAvailableHookLibs(void) {
	NSMutableArray* hooklibs_info = [[HKSubstitutor getSubstitutorTypeInfo:[HKSubstitutor getAvailableSubstitutorTypes]] mutableCopy];

	for(NSDictionary* hooklib_info in [hooklibs_info copy]) {
		NSString* hooklib_id = hooklib_info[@"id"];

		if([hooklib_id isEqualToString:@"substrate"] || [hooklib_id isEqualToString:@"substitute"]) {
			[hooklibs_info removeObject:hooklib_info];
		}
	}

	return hooklibs_info;
}
