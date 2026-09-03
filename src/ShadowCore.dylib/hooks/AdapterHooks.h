#ifndef shdw_adapter_hooks_h
#define shdw_adapter_hooks_h

#import "hooks.h"
#import "../HookAdapterBridge.h"

NSDictionary* shdw_adapter_resolve_preferences(NSDictionary* prefs);
void shdw_adapter_devicecheck_configure(NSDictionary* prefs);
void shdw_adapter_devicecheck(SHDWHookSession* hooks);
void shdw_adapter_freerasp_prepare_preferences(NSMutableDictionary* prefs);
void shdw_adapter_freerasp(SHDWHookSession* hooks);
void shdw_adapter_devicesecuritykit(SHDWHookSession* hooks);
void shdw_adapter_iossecuritysuite(SHDWHookSession* hooks);
void shdw_adapter_batjailbreakguard(SHDWHookSession* hooks);

#endif
