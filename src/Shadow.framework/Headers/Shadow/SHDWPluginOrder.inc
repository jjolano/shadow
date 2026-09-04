// SHDWPluginOrder.inc — canonical plugin order (Hybrid seam)
// Single source of truth for drift checks. Hybrid: HookConfiguration.m and
// shadowcore.x keep their tables but verify count/order against this list.
// Edit order HERE, not in the two tables — the tables must match this order.
// ponytail: verification-only; X-macro generation if tables ever diverge.

// Canonical ordered IDs — must stay in SHDWPluginRegistry order.
#define SHDW_PLUGIN_ORDER \
    "Universal_Dyld", \
    "Universal_Filesystem_C", \
    "Universal_EnvVars_C", \
    "Universal_EnvVars_ObjC", \
    "Adapter_DeviceCheck", \
    "Adapter_FreeRASP", \
    "Universal_MachBootstrap", \
    "Universal_IOKit", \
    "Universal_LowLevelC", \
    "Universal_AntiDebugging", \
    "Universal_CodeSigning", \
    "Universal_ObjC", \
    "Universal_ObjC_MethodImplementation", \
    "Universal_Syscall", \
    "Universal_Memory", \
    "Universal_Sandbox", \
    "Universal_HideClasses", \
    "Universal_SymbolLookup", \
    "Universal_DynamicLibrariesExtra", \
    "Universal_DetectorIntegrity", \
    "Universal_Filesystem_ObjC", \
    "Universal_Foundation_ObjC", \
    "Universal_HideApps", \
    "Universal_URLScheme", \
    "Universal_Foundation_UIKit", \
    "Universal_PasscodeStatus", \
    "Adapter_DeviceSecurityKit", \
    "Adapter_IOSSecuritySuite", \
    "Adapter_BATJailbreakGuard", \
    "Policy_Path", \
    "Policy_Environment", \
    "Policy_Process", \
    "Policy_PseudoSandbox"

#define SHDW_PLUGIN_COUNT 33
