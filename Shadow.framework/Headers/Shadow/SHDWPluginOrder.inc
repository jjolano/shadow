// SHDWPluginOrder.inc — canonical plugin order (Hybrid seam)
// Single source of truth for drift checks. Hybrid: HookConfiguration.m and
// shadowcore.x keep their tables but verify count/order against this list.
// Edit order HERE, not in the two tables — the tables must match this order.
// ponytail: verification-only; X-macro generation if tables ever diverge.

// Canonical ordered IDs — must stay in SHDWPluginRegistry order.
#define SHDW_PLUGIN_ORDER \
    "dyld", \
    "Hook_Filesystem@c", \
    "Hook_EnvVars@c", \
    "Hook_EnvVars@objc", \
    "Hook_DeviceCheck", \
    "Hook_MachBootstrap", \
    "Hook_IOKit", \
    "Hook_LowLevelC", \
    "Hook_AntiDebugging", \
    "Hook_CodeSigning", \
    "objc", \
    "objc@methodimpl", \
    "Hook_Syscall", \
    "Hook_Memory", \
    "Hook_Sandbox", \
    "classes", \
    "symlookup", \
    "Hook_DynamicLibrariesExtra", \
    "detector-integrity", \
    "Hook_Filesystem@objc", \
    "Hook_Foundation@objc", \
    "Hook_HideApps", \
    "Hook_URLScheme", \
    "Hook_Foundation@uikit", \
    "Hook_DeviceSecurityKit", \
    "IOSSecuritySuite", \
    "Policy_Path", \
    "Policy_Environment", \
    "Policy_Process", \
    "Policy_PseudoSandbox"

#define SHDW_PLUGIN_COUNT 30
