#import "UniversalHooks.h"

// Code-signing self-validation concealment (Universal_CodeSigning).
//
// Commercial RASP validates the RUNNING process's own code signature
// (SecCodeCheckValidity / SecStaticCodeCheckValidity*) and treats failure as
// tampering evidence: on jailbroken devices the main executable is often
// re-signed (fake-root/ad-hoc), so a stock-passing validation fails and the
// detector infers a jailbreak.
//
// Policy: ONLY the process's own executable is concealed. When an external
// caller's validity check of our own code FAILS, report errSecSuccess.
// Everything else passes through untouched:
//   - other apps' code, embedded frameworks, downloaded content: real result
//     (faking those would silently defeat the app's legitimate integrity
//     decisions far beyond jailbreak hiding)
//   - successful validations: returned as-is
//   - internal Shadow callers: real result
//   - undecidable cases (signing info unavailable): real result (fail-open)
//
// Self-entitlement probes are not hooked.
//
// Lane: REBIND-only (hookRebindSymbol). Validity checks are cold one-shot
// calls, but they sit exactly on the byte-comparison surface this contract
// reserves for detection-facing APIs (see hooks.h lane contract).
//
// The theos SDK ships no Security framework headers; declare the stable
// public ABI surface locally (types are opaque; no layout dependence).

#import <string.h>
#import <limits.h>
#import <mach-o/dyld.h>

typedef int32_t shdw_osstatus_t;
#define SHDW_ERR_SEC_SUCCESS ((shdw_osstatus_t) 0)

typedef uint32_t shdw_sec_csflags_t;
#define SHDW_SEC_CS_DEFAULT_FLAGS ((shdw_sec_csflags_t) 0)

typedef struct __SecCode* shdw_sec_code_ref_t;
typedef struct __SecStaticCode* shdw_sec_static_code_ref_t;

static shdw_osstatus_t (*original_SecCodeCheckValidity)(shdw_sec_code_ref_t code, shdw_sec_csflags_t flags, const void* requirement);
static shdw_osstatus_t (*original_SecStaticCodeCheckValidity)(shdw_sec_static_code_ref_t code, shdw_sec_csflags_t flags, const void* requirement);
static shdw_osstatus_t (*original_SecStaticCodeCheckValidityWithErrors)(shdw_sec_static_code_ref_t code, shdw_sec_csflags_t flags, const void* requirement, void** errors);

static shdw_osstatus_t (*shdw_orig_SecCodeCopyPath)(const void* code, shdw_sec_csflags_t flags, CFURLRef* path);

// Canonical paths of our own executable and bundle, captured once at install.
static char shdw_own_exec_path[PATH_MAX] = {0};
static char shdw_own_bundle_path[PATH_MAX] = {0};

static void shdw_security_copy_canonical_path(char destination[PATH_MAX], const char* source) {
    if(!source || !source[0]) {
        return;
    }

    char resolved[PATH_MAX];
    snprintf(destination, PATH_MAX, "%s", realpath(source, resolved) ? resolved : source);
}

static void shdw_security_capture_own_paths(void) {
    char executable[PATH_MAX];
    uint32_t size = sizeof(executable);

    if(_NSGetExecutablePath(executable, &size) != 0) {
        shdw_own_exec_path[0] = '\0';
    } else {
        shdw_security_copy_canonical_path(shdw_own_exec_path, executable);
    }

    shdw_security_copy_canonical_path(shdw_own_bundle_path,
        [NSBundle mainBundle].bundlePath.fileSystemRepresentation);
}

// YES when the caller frame is inside Security.framework (see hooks.h).
// dladdr is hooked by the symlookup group, but that hook only alters
// answers for SHADOW-image addresses — a Security address forwards to the
// original untouched, so this stays a real lookup.
BOOL shdw_addr_in_security_framework(const void* return_address) {
    Dl_info info = {0};

    if(!return_address || dladdr(return_address, &info) == 0 || !info.dli_fname) {
        return NO;
    }

    const char* name = info.dli_fname;
    size_t len = strlen(name);
    const char* suffix = "/Security.framework/Security";
    size_t slen = strlen(suffix);

    return len > slen && strcmp(name + len - slen, suffix) == 0;
}

// YES when the code reference names our own executable. Resolution goes
// through the public SecCodeCopyPath API; any ambiguity answers NO — the hook
// then leaves the original result standing (fail-open).
static BOOL shdw_sec_code_is_own_executable(const void* code) {
    if(!code || !shdw_orig_SecCodeCopyPath) {
        return NO;
    }

    CFURLRef pathURL = NULL;

    if(shdw_orig_SecCodeCopyPath(code, SHDW_SEC_CS_DEFAULT_FLAGS, &pathURL) != SHDW_ERR_SEC_SUCCESS || !pathURL) {
        return NO;
    }

    char path[PATH_MAX];
    BOOL own = NO;

    if(CFURLGetFileSystemRepresentation(pathURL, true, (UInt8*) path, sizeof(path))) {
        char resolved[PATH_MAX];
        const char* queried = realpath(path, resolved) ? resolved : path;

        own = (shdw_own_exec_path[0] && strcmp(queried, shdw_own_exec_path) == 0) ||
              (shdw_own_bundle_path[0] && strcmp(queried, shdw_own_bundle_path) == 0);
    }

    CFRelease(pathURL);
    return own;
}

// Shared post-failure policy: fake success ONLY for an external caller's
// FAILED validation of our own executable.
static shdw_osstatus_t shdw_sec_validity_apply_after(shdw_osstatus_t ret, const void* code) {
    if(ret == SHDW_ERR_SEC_SUCCESS || !code) {
        return ret;
    }

    if(!isCallerExternal() || !shdw_sec_code_is_own_executable(code)) {
        return ret;
    }

    return SHDW_ERR_SEC_SUCCESS;
}

static shdw_osstatus_t replaced_sec_code_check_validity(shdw_sec_code_ref_t code, shdw_sec_csflags_t flags, const void* requirement) {
    return shdw_sec_validity_apply_after(original_SecCodeCheckValidity(code, flags, requirement), code);
}

static shdw_osstatus_t replaced_sec_static_code_check_validity(shdw_sec_static_code_ref_t code, shdw_sec_csflags_t flags, const void* requirement) {
    return shdw_sec_validity_apply_after(original_SecStaticCodeCheckValidity(code, flags, requirement), code);
}

static shdw_osstatus_t replaced_sec_static_code_check_validity_with_errors(shdw_sec_static_code_ref_t code, shdw_sec_csflags_t flags, const void* requirement, void** errors) {
    shdw_osstatus_t ret = original_SecStaticCodeCheckValidityWithErrors(code, flags, requirement, errors);

    if(ret != SHDW_ERR_SEC_SUCCESS && errors) {
        // A faked success must not leave stale error detail behind.
        shdw_osstatus_t applied = shdw_sec_validity_apply_after(ret, code);

        if(applied == SHDW_ERR_SEC_SUCCESS) {
            if(*errors) {
                CFRelease(*errors);
            }
            *errors = NULL;
            return applied;
        }
    }

    return ret;
}

void shdw_universal_codesigning(SHDWHookSession* hooks) {
    shdw_security_capture_own_paths();

    // Runtime-resolved, skipped cleanly when absent: an app that never
    // loaded Security.framework has nothing to hook and nothing to filter.
    void* sym = shdw_resolve_libsystem("SecCodeCheckValidity");

    if(sym) {
        [hooks hookRebindSymbol:@"SecCodeCheckValidity" withReplacement:replaced_sec_code_check_validity outOldPtr:(void **) &original_SecCodeCheckValidity];
    }

    sym = shdw_resolve_libsystem("SecStaticCodeCheckValidity");

    if(sym) {
        [hooks hookRebindSymbol:@"SecStaticCodeCheckValidity" withReplacement:replaced_sec_static_code_check_validity outOldPtr:(void **) &original_SecStaticCodeCheckValidity];
    }

    sym = shdw_resolve_libsystem("SecStaticCodeCheckValidityWithErrors");

    if(sym) {
        [hooks hookRebindSymbol:@"SecStaticCodeCheckValidityWithErrors" withReplacement:replaced_sec_static_code_check_validity_with_errors outOldPtr:(void **) &original_SecStaticCodeCheckValidityWithErrors];
    }

    // Path lookup runs through the ORIGINAL (unhooked dlsym resolve): it is
    // policy infrastructure, never filtered itself.
    shdw_orig_SecCodeCopyPath = (shdw_osstatus_t (*)(const void*, shdw_sec_csflags_t, CFURLRef*)) shdw_resolve_libsystem("SecCodeCopyPath");
}

void shdw_universal_codesigning_verify(void) {
    // SecCodeCheckValidity is the only export guaranteed present wherever
    // any of them are; the static twins are runtime-resolved siblings
    // (NULL expected when absent — same discipline as shadowhook_syscall_verify).
    shdw_hook_check_t checks[] = {
        { "SecCodeCheckValidity", original_SecCodeCheckValidity },
    };

    shdw_verify_hooks("security", checks, sizeof(checks) / sizeof(checks[0]));
}
