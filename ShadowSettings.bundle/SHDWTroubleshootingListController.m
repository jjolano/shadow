#import "SHDWAppListController.h"
#import "SHDWPrefs.h"

#import <Preferences/PSListController.h>
#import <Shadow/Settings.h>
#import <Shadow/HookConfiguration.h>
// The HK3 native runtime, not the HKSubstitutor 2.x facade: hooking already
// runs on this path, and hk_runtime_enumerate_backends is its exported,
// side-effect-free backend discovery. The umbrella is ObjC-only, so import the
// runtime header directly.
#import <HookKit/HookKitRuntime.h>

@interface SHDWTroubleshootingListController : PSListController
@end

// hk_runtime_enumerate_backends callback context: the picker's value/title
// arrays. Unretained — both live on the stack across the synchronous enumerate.
typedef struct {
	__unsafe_unretained NSMutableArray* values;
	__unsafe_unretained NSMutableArray* titles;
} SHDWBackendCollector;

// One row per selectable backend group: backend_id is the stored value (passed
// verbatim to the override), display_name is the human title. Both views are
// borrowed for the call only, so copy by length (not NUL-terminated). Returning
// YES keeps enumerating.
static bool SHDWCollectBackend(void* context, hk_string_view_t backendID,
                               hk_string_view_t displayName) {
	SHDWBackendCollector* collector = context;

	if(!backendID.data || !backendID.length) {
		return true;
	}

	NSString* identifier = [[NSString alloc] initWithBytes:backendID.data
													length:backendID.length
												  encoding:NSUTF8StringEncoding];

	if(!identifier.length) {
		return true;
	}

	NSString* title = (displayName.data && displayName.length)
		? [[NSString alloc] initWithBytes:displayName.data
								   length:displayName.length
								 encoding:NSUTF8StringEncoding]
		: nil;

	[collector->values addObject:identifier];
	[collector->titles addObject:title.length ? title : identifier];

	return true;
}

@implementation SHDWTroubleshootingListController {
	NSUserDefaults* prefs;
	NSArray* hookLibraryValues;
	NSArray* hookLibraryTitles;
}

- (NSArray *)specifiers {
	if(!_specifiers) {
		_specifiers = [self loadSpecifiersFromPlistName:@"Troubleshooting" target:self];
	}

	return _specifiers;
}

- (NSString *)applicationIDInContext {
	for(UIViewController* controller in self.navigationController.viewControllers) {
		if([controller isKindOfClass:[SHDWAppListController class]]) {
			return [(SHDWAppListController *)controller applicationID];
		}
	}

	return nil;
}

- (id)readPreferenceValue:(PSSpecifier *)specifier {
	id value = SHDWReadAppPref(prefs, [self applicationIDInContext], [specifier identifier]);

	// The override defaults to auto, and a stored id that a HookKit update no
	// longer offers falls back to auto rather than showing a stale row.
	if([[specifier identifier] isEqualToString:SHDWHookLibraryID]) {
		return [hookLibraryValues containsObject:value] ? value : @"auto";
	}

	return value;
}

- (void)setPreferenceValue:(id)value forSpecifier:(PSSpecifier *)specifier {
	SHDWToggleHaptic();
	SHDWWriteAppPref(prefs, [self applicationIDInContext], [specifier identifier], value);
}

- (NSArray *)getValues:(PSSpecifier *)specifier {
	return hookLibraryValues;
}

- (NSArray *)getTitles:(PSSpecifier *)specifier {
	return hookLibraryTitles;
}

- (instancetype)init {
	if((self = [super init])) {
		prefs = [[ShadowSettings sharedInstance] userDefaults];

		NSMutableArray* values = [NSMutableArray arrayWithObject:@"auto"];
		NSBundle* bundle = [NSBundle bundleForClass:[self class]];
		NSMutableArray* titles = [NSMutableArray arrayWithObject:
			[bundle localizedStringForKey:@"AUTOMATIC" value:@"Automatic (Recommended)" table:@"Troubleshooting"]];

		// The picker lists whatever backends the running HookKit reports, in
		// routing order; the engine IDs (e.g. "provider-ellekit", "native") are
		// self-describing, so they double as titles. Enumeration is discovery
		// only — it activates no provider and mutates nothing. A HookKit too old
		// to export the entry point leaves just the auto row.
		hk_runtime_config_t config;
		memset(&config, 0, sizeof(config));
		config.struct_size = sizeof(config);
		config.struct_version = HK_ABI_VERSION_3_0;
		config.install_context = HK_INSTALL_CONTEXT_EARLY_PROCESS;

		hk_runtime_t* runtime = NULL;
		if(hk_runtime_create(&config, &runtime) == HK_STATUS_OK && runtime) {
			SHDWBackendCollector collector = { values, titles };
			hk_runtime_enumerate_backends(runtime, SHDWCollectBackend, &collector);
			hk_runtime_release(runtime);
		}

		hookLibraryValues = [values copy];
		hookLibraryTitles = [titles copy];
	}

	return self;
}
@end
