#!/bin/sh
set -eu

root=ShadowSettings.bundle/Resources/Root.plist
app=ShadowSettings.bundle/Resources/App.plist
runtime=ShadowCore.dylib/shadowcore.x
loader=Shadow.dylib/dylib.x
settings=Shadow.framework/Settings.m
profile=Shadow.framework/HookConfiguration.m

if grep -Rqs --exclude-dir=.theos 'SHDWPreset' Shadow.framework ShadowCore.dylib ShadowSettings.bundle; then
    echo 'SETTINGS DRIFT: preset API or UI returned'
    exit 1
fi

if grep -Eq 'Global_Enabled|SHDWHooksListController|BypassPreset' "$root"; then
    echo 'SETTINGS DRIFT: root pane exposes global or profile controls'
    exit 1
fi

if [ "$(grep -c '<string>PSSwitchCell</string>' "$app")" -ne 1 ] ||
   ! grep -q '<string>App_Enabled</string>' "$app" ||
   grep -Eq 'App_Disabled|App_FollowGlobal|BypassPreset|Universal_|Adapter_' "$app"; then
    echo 'SETTINGS DRIFT: app pane is not one App_Enabled switch'
    exit 1
fi

for obsolete in Hooks Individual Dangerous Adapters Troubleshooting; do
    if [ -e "ShadowSettings.bundle/Resources/$obsolete.plist" ]; then
        echo "SETTINGS DRIFT: obsolete $obsolete pane returned"
        exit 1
    fi
done

for key in SHDWUniversalFoundationID SHDWUniversalMachBootstrapID SHDWUniversalIOKitID SHDWUniversalSyscallID; do
    grep -q "$key : @(YES)" "$profile" || {
        echo "SETTINGS DRIFT: built-in profile does not enable $key"
        exit 1
    }
done

grep -q 'result\[SHDWAppEnabledID\] = @(enabled)' "$settings" &&
! grep -q 'addEntriesFromDictionary' "$settings" &&
grep -q 'SHDWApplicationEnabled' "$loader" &&
grep -q 'bundleIdentifier.length == 0' "$settings" || {
    echo 'SETTINGS DRIFT: runtime no longer uses the fixed profile with per-app activation'
    exit 1
}

grep -q 'kSHDWDetectorRunnerOverridesKey = @"Test_DetectorOverrides"' "$settings" &&
grep -q 'NSDictionary\* overrides = isDetectorRunner' "$settings" &&
grep -q 'SHDWAdapterDeviceCheckID, SHDWAdapterFreeRASPID' "$settings" &&
grep -q 'SHDWAdapterDeviceSecurityKitID, SHDWAdapterIOSSecuritySuiteID' "$settings" &&
grep -q 'me.jjolano.shadow.test.iossecuritysuite' "$settings" || {
    echo 'SETTINGS DRIFT: detector overrides must remain private to test runners'
    exit 1
}

grep -q 'SHDWSingleToggleMigrationID, @"DetectorLog"' ShadowSettings.bundle/SHDWRootListController.m || {
    echo 'SETTINGS DRIFT: exports no longer preserve single-toggle migration state'
    exit 1
}

grep -q 'sanitized\[SHDWSingleToggleMigrationID\] = @YES' ShadowSettings.bundle/SHDWRootListController.m &&
grep -q 'setBool:YES forKey:SHDWSingleToggleMigrationID' ShadowSettings.bundle/SHDWPrefs.m || {
    echo 'SETTINGS DRIFT: imported and edited app toggles must use explicit single-toggle semantics'
    exit 1
}

grep -q 'SHDWAppDisabledID.*SHDWAppEnabledID' Shadow.framework/SettingsMigration.m ||
grep -q 'migrated\[SHDWAppEnabledID\] = @NO' Shadow.framework/SettingsMigration.m || {
    echo 'SETTINGS DRIFT: legacy App_Disabled migration is missing'
    exit 1
}

for source in "$loader" "$settings"; do
    grep -q 'dictionaryWithContentsOfFile:@SHADOW_PREFS_PLIST' "$source" || {
        echo "SETTINGS DRIFT: $source lost the sandboxed per-app fallback"
        exit 1
    }
done

grep -q 'return "/var/mobile/Library/Preferences/me.jjolano.shadow.plist"' tests/stealth_device.py &&
grep -q '^PREFS_REMOTE=/var/mobile/Library/Preferences/me.jjolano.shadow.plist$' tests/bench/run-b.sh || {
    echo 'SETTINGS DRIFT: device tools must edit the canonical preference file'
    exit 1
}
