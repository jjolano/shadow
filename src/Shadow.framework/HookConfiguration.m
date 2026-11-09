#import <Shadow/SHDWPlugin.h>

// Canonical metadata for the hook lifecycle/configuration registry. The same
// ordered rows become the dylib's installer table in shadowcore.x, so IDs and
// order cannot drift.

#pragma mark - Plugin registry

#define SHDW_PLUGIN(id, pref, phase, cap, ctor, installer)                     \
  {id, pref, phase, cap, ctor},
static const SHDWPlugin kSHDWPlugins[] = {
#include <Shadow/SHDWPlugins.def>
};
#undef SHDW_PLUGIN

const SHDWPlugin *SHDWPluginRegistry(NSUInteger *outCount) {
  if (outCount) {
    *outCount = sizeof(kSHDWPlugins) / sizeof(kSHDWPlugins[0]);
  }
  return kSHDWPlugins;
}

const SHDWInstallUnit *SHDWInstallUnits(NSUInteger *outCount) {
  // Compat shim — same storage, new name
  if (outCount) {
    *outCount = sizeof(kSHDWPlugins) / sizeof(kSHDWPlugins[0]);
  }
  return (const SHDWInstallUnit *)kSHDWPlugins;
}

#pragma mark - Built-in profile

NSDictionary<NSString *, id> *SHDWDefaultHookSettings(void) {
  NSMutableDictionary<NSString *, id> *settings = [NSMutableDictionary new];
  NSUInteger count = 0;
  const SHDWPlugin *plugins = SHDWPluginRegistry(&count);

  for (NSUInteger i = 0; i < count; i++) {
    const SHDWPlugin *plugin = &plugins[i];
    if (plugin->prefKey) {
      settings[plugin->prefKey] = @YES;
    }
  }

  // Modes, not hook toggles: both are resolved from userDefaults/per-app
  // state, so they stay out of the installer rows.
  settings[SHDWUniversalPseudoSandboxModeID] = @(0);
  // Off by default: the natural, stock-shaped bypasses run for every enabled
  // app; disable-style neutralizers only activate when the user opts into
  // aggressive mode (globally or per app).
  settings[SHDWDetectorAggressiveID] = @(NO);

  return [settings copy];
}

#pragma mark - Capability metadata

// Registry capability -> group kind: PrivateSym is the private-symbol (inline)
// lane; rows with no prefKey (None/Symlookup) never contribute a group.
static NSString *SHDWCapabilityKindName(SHDWCapabilityKind capability) {
  switch (capability) {
  case SHDWCapabilityFunction:
    return @"function";
  case SHDWCapabilityMessage:
    return @"message";
  case SHDWCapabilityPrivateSym:
    return @"inline";
  default:
    return @"none";
  }
}

NSString *SHDWHookGroupCapabilityKind(NSString *groupID) {
  static NSDictionary<NSString *, NSString *> *kinds = nil;
  static dispatch_once_t onceToken;
  dispatch_once(&onceToken, ^{
    NSMutableDictionary<NSString *, NSString *> *map =
        [NSMutableDictionary new];
    NSUInteger count = 0;
    const SHDWPlugin *plugins = SHDWPluginRegistry(&count);
    // FIRST registry row per prefKey wins — load-bearing for composite
    // groups: Universal_Filesystem is the C lane's "function", never the
    // later Universal_Filesystem_ObjC's "message".
    for (const SHDWPlugin *plugin = plugins; plugin < plugins + count;
         plugin++) {
      if (plugin->prefKey && !map[plugin->prefKey]) {
        map[plugin->prefKey] = SHDWCapabilityKindName(plugin->capability);
      }
    }
    // Pseudo-sandbox is a mode, not an installer row, so its key is the one
    // capability entry the registry cannot derive.
    map[SHDWUniversalPseudoSandboxModeID] = @"none";
    kinds = map;
  });
  return kinds[groupID];
}

#pragma mark - Planner

static BOOL SHDWPluginEnabled(const SHDWPlugin *plugin,
                              NSDictionary<NSString *, id> *prefs,
                              SHDWLifecycleEvent event) {
  // Harness frameworks load per detector. The Harness profile key defers
  // target-dependent adapters until that first pass has loaded every target;
  // production apps have no such key and retain their early adapter
  // behavior.
  if (plugin->phase == SHDWPhaseSDKFallback && event == SHDWEventCtor &&
      prefs[SHDWUniversalHarnessBaselineID] != nil) {
    return NO;
  }
  if (!plugin->prefKey) {
    return YES;
  }
  if (event == SHDWEventDetectorEscalation &&
      plugin->phase == SHDWPhaseEscalation) {
    return YES;
  }
  return [prefs[plugin->prefKey] boolValue];
}

static BOOL SHDWPluginCapable(const SHDWPlugin *plugin, SHDWCapabilities caps) {
  if (plugin->phase == SHDWPhaseEscalation) {
    return YES;
  }
  if (plugin->capability != SHDWCapabilityMessage) {
    return YES;
  }
  return (caps & SHDWCapMessage) != 0;
}

NSArray<NSString *> *SHDWPluginPlan(NSDictionary<NSString *, id> *prefs,
                                    SHDWCapabilities caps,
                                    SHDWLifecycleEvent event) {
  NSDictionary<NSString *, id> *effective = prefs ?: SHDWDefaultHookSettings();
  NSMutableArray<NSString *> *plan = [NSMutableArray new];
  NSUInteger count = 0;
  const SHDWPlugin *plugins = SHDWPluginRegistry(&count);
  for (NSUInteger i = 0; i < count; i++) {
    const SHDWPlugin *plugin = &plugins[i];
    BOOL include = NO;
    switch (event) {
    case SHDWEventCtor:
      include = plugin->ctorInstall != 0;
      break;
    case SHDWEventUIKitLoaded:
      include = plugin->phase == SHDWPhaseUIKit;
      break;
    case SHDWEventDetectorEscalation:
      include = plugin->phase == SHDWPhaseTier2 ||
                plugin->phase == SHDWPhaseEscalation;
      break;
    case SHDWEventSDKFallback:
      include = plugin->phase == SHDWPhaseSDKFallback;
      break;
    }
    if (!include)
      continue;
    if (!SHDWPluginEnabled(plugin, effective, event))
      continue;
    if (!SHDWPluginCapable(plugin, caps))
      continue;
    [plan addObject:[NSString stringWithUTF8String:plugin->pluginID]];
  }
  return plan;
}

// Compat shims — forward to new planner
NSArray<NSString *> *SHDWHookPlan(NSDictionary<NSString *, id> *prefs,
                                  SHDWCapabilities caps,
                                  SHDWLifecycleEvent event) {
  return SHDWPluginPlan(prefs, caps, event);
}
