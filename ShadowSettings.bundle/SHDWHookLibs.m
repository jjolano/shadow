#import "SHDWHookLibs.h"
#import <HookKit.h>

NSArray<NSDictionary *> *SHDWAvailableHookLibs(void) {
	NSMutableArray* hooklibs_info = [[HKSubstitutor getSubstitutorTypeInfo:[HKSubstitutor getAvailableSubstitutorTypes]] mutableCopy];

	for(NSDictionary* hooklib_info in [hooklibs_info copy]) {
		// Legacy/opt-in backends (substrate, substitute, swift) are marked
		// selectable=NO by the registry — they exist for compatibility/opt-in
		// but must not be user-selectable. Only filter when the key is
		// explicitly NO: a missing key (older framework) means selectable.
		// ponytail: key-existence-and-NO, not boolValue==NO alone
		if([hooklib_info objectForKey:@"selectable"] && ![[hooklib_info objectForKey:@"selectable"] boolValue]) {
			[hooklibs_info removeObject:hooklib_info];
		}
	}

	return hooklibs_info;
}
