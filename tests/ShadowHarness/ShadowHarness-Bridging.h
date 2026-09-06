// Bridging header for the ShadowHarness app target: exposes the C symbols
// the embedded Swift drivers need:
//   - SHDWFreeRASPGenericProbeJSON (DetectorRunners/FreeRASP/Probe.m)
//   - safetynet_install_anti_debug + csops (SafetyNetObjC; the .m itself is
//     deliberately NOT linked — its PT_DENY_ATTACH constructor would fire
//     on the harness — but DebuggerDetector.swift references the symbols).
// Keep it C-only: importing Foundation from a Swift bridging header
// conflicts with the Linux Theos SDK's host Dispatch module.
#include <sys/types.h>
#include <unistd.h>

const char *SHDWFreeRASPGenericProbeJSON(void);

#include <stdbool.h>
bool SHDWEmbeddedFallbackInstalled(void);
void safetynet_install_anti_debug(void);
extern int csops(pid_t pid, unsigned int ops, void *useraddr, size_t usersize);
