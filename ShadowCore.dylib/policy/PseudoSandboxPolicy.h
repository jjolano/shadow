#ifndef shadow_pseudo_sandbox_policy_h
#define shadow_pseudo_sandbox_policy_h

// Plugin: Policy_PseudoSandbox — registered in SHDWPluginRegistry (HookConfiguration.m)
#define SHDWPolicyPseudoSandboxPluginID "Policy_PseudoSandbox"

#import <Foundation/Foundation.h>

// Pseudo-sandbox: a per-app fail-closed allowlist ("overlay") evaluated
// alongside the belt. Feature-flagged OFF by default. In audit mode
// (strict=NO) it only records divergence; in strict mode it denies paths
// outside the allowlist. The belt hooks (PathPolicy, sandbox.x) call
// shdw_pseudo_audit_log on every check when enabled; RestrictionEngine
// dlsym's shdw_pseudo_should_deny for central strict enforcement.
void shdw_pseudo_init(NSDictionary* prefs);
void shdw_pseudo_refresh(NSDictionary* prefs);
BOOL shdw_pseudo_enabled(void);
BOOL shdw_pseudo_strict(void);
BOOL shdw_pseudo_is_allowed(const char* path);
BOOL shdw_pseudo_should_deny(const char* path);
void shdw_pseudo_audit_log(const char* path, BOOL belt, const char* op);

#endif