#import "hooks.h"
#import "../../policy/EnvironmentPolicy.h"

#import <string.h>

// getenv: hidden names answer NULL and PATH is sanitized — shared policy
// (policy/EnvironmentPolicy.m) so the getenv, *environ and NSProcessInfo
// channels agree.
char* (*original_getenv)(const char* name);
char* replaced_getenv(const char* name) {
    if(!isCallerExternal()) {
        return original_getenv(name);
    }

    char* result = original_getenv(name);

    if(!result || !name || !name[0]) {
        return result;
    }

    // Stock iOS never has these set; their presence is the jailbreak signal
    // a detector reads back from getenv.
    if(shdw_env_name_hidden(name)) {
        return NULL;
    }

    if(strcmp(name, "PATH") == 0) {
        return shdw_env_sanitized_path(result);
    }

    return result;
}

void shadowhook_libc_envvar(SHDWHookSession* hooks) {
    shdw_libc_install_group(hooks, SHADW_HOOK_GROUP_ENVVAR);
}

void shadowhook_libc_envvar_verify(void) {
    shdw_libc_verify_group("libc_envvar", SHADW_HOOK_GROUP_ENVVAR);
}
