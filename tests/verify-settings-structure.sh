#!/bin/sh
set -eu

root=src/ShadowSettings.bundle/Resources/Root.plist
app=src/ShadowSettings.bundle/Resources/App.plist
runtime=src/ShadowCore.dylib/shadowcore.x
loader=src/Shadow.dylib/dylib.x
settings=src/Shadow.framework/Settings.m
profile=src/Shadow.framework/HookConfiguration.m

if grep -Rqs --exclude-dir=.theos 'SHDWPreset' src/Shadow.framework src/ShadowCore.dylib src/ShadowSettings.bundle; then
    echo 'SETTINGS DRIFT: preset API or UI returned'
    exit 1
fi

if grep -Eq 'SHDWHooksListController|BypassPreset' "$root"; then
    echo 'SETTINGS DRIFT: root pane exposes profile controls'
    exit 1
fi

# The root pane keeps the global activation switch, the applications list, and
# About — nothing else. The removed tools (respring/reset/import/export) and
# the detector log must stay gone.
grep -q '<string>Global_Enabled</string>' "$root" || {
    echo 'SETTINGS DRIFT: root pane lost the global activation switch'
    exit 1
}
if grep -Eq 'respring:|reset:|exportSettings:|importSettings:|DetectorLog' "$root"; then
    echo 'SETTINGS DRIFT: removed tools or detector log returned to the root pane'
    exit 1
fi

# The app pane is exactly the Follow Global + App_Enabled switch pair; no
# revived per-hook or profile controls, and no App_Disabled (the single-toggle
# backend never writes it).
if [ "$(grep -c '<string>PSSwitchCell</string>' "$app")" -ne 2 ] ||
   ! grep -q '<string>App_Enabled</string>' "$app" ||
   ! grep -q '<string>App_FollowGlobal</string>' "$app" ||
   grep -Eq 'App_Disabled|BypassPreset|Universal_|Adapter_' "$app"; then
    echo 'SETTINGS DRIFT: app pane is not the Follow Global + App_Enabled switch pair'
    exit 1
fi

for obsolete in Hooks Individual Dangerous Adapters Troubleshooting DetectorLog; do
    if [ -e "src/ShadowSettings.bundle/Resources/$obsolete.plist" ]; then
        echo "SETTINGS DRIFT: obsolete $obsolete pane returned"
        exit 1
    fi
done

# The detector log is gone entirely: no controller, no runtime recorder.
if [ -e src/ShadowSettings.bundle/SHDWDetectorLogListController.m ]; then
    echo 'SETTINGS DRIFT: detector log controller returned'
    exit 1
fi
if grep -q 'DetectorLog' src/Shadow.framework/RestrictionEngine.m; then
    echo 'SETTINGS DRIFT: detector log runtime recorder returned'
    exit 1
fi

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

# A per-app toggle edit takes the app off "follow global" by writing an
# explicit App_Enabled and stamping the single-toggle migration marker;
# clearing it (follow global) drops the override key.
grep -q 'setBool:YES forKey:SHDWSingleToggleMigrationID' src/ShadowSettings.bundle/SHDWPrefs.m &&
grep -q 'removeObjectForKey:SHDWAppEnabledID' src/ShadowSettings.bundle/SHDWPrefs.m || {
    echo 'SETTINGS DRIFT: per-app toggle must use explicit single-toggle semantics with follow-global clear'
    exit 1
}

grep -q 'SHDWAppDisabledID.*SHDWAppEnabledID' src/Shadow.framework/SettingsMigration.m ||
grep -q 'migrated\[SHDWAppEnabledID\] = @NO' src/Shadow.framework/SettingsMigration.m || {
    echo 'SETTINGS DRIFT: legacy App_Disabled migration is missing'
    exit 1
}

# Shadow runs the fixed full-capability profile when enabled, so migration must
# prune the plist to the live surface — obsolete hook toggles cannot linger as
# phantom switches. Enforce the allowlist-and-strip shape.
grep -q 'liveScalarKeys' src/Shadow.framework/SettingsMigration.m &&
grep -q 'removeObjectForKey:key' src/Shadow.framework/SettingsMigration.m || {
    echo 'SETTINGS DRIFT: migration no longer prunes obsolete keys to the live surface'
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
