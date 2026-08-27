#!/bin/sh
set -eu

hooks=ShadowSettings.bundle/Resources/Hooks.plist
troubleshooting=ShadowSettings.bundle/Resources/Troubleshooting.plist
controller=ShadowSettings.bundle/SHDWTroubleshootingListController.m
dangerous=ShadowSettings.bundle/Resources/Dangerous.plist
runtime=ShadowCore.dylib/shadowcore.x
loader=Shadow.dylib/dylib.x
settings=Shadow.framework/Settings.m

if grep -q '<string>HK_Library</string>' "$hooks"; then
    echo 'SETTINGS DRIFT: backend picker returned to the main Hooks page'
    exit 1
fi

grep -q '<string>SHDWTroubleshootingListController</string>' "$hooks" || {
    echo 'SETTINGS DRIFT: Hooks page no longer links to Troubleshooting'
    exit 1
}

grep -q '<string>HK_Library</string>' "$troubleshooting" || {
    echo 'SETTINGS DRIFT: Troubleshooting lost the backend override'
    exit 1
}

grep -q 'applicationIDInContext' "$controller" || {
    echo 'SETTINGS DRIFT: backend override no longer preserves per-app scope'
    exit 1
}

for key in DetectorPatch_DTTJailbreakDetection DetectorPatch_SafeDevice DetectorPatch_JailMonkey \
           DetectorPatch_IOSSecuritySuite DetectorPatch_FreeRASP; do
    grep -q "<string>$key</string>" "$dangerous" || {
        echo "SETTINGS DRIFT: Dangerous page lost $key"
        exit 1
    }
done

for key in SHDWDetectorPatchIOSSecuritySuiteID SHDWDetectorPatchFreeRASPID; do
    grep -q "$key" "$runtime" || {
        echo "SETTINGS DRIFT: $key no longer pre-arms behavioral coverage"
        exit 1
    }
done

for source in "$loader" "$settings"; do
    grep -q 'dictionaryWithContentsOfFile:@SHADOW_PREFS_PLIST' "$source" || {
        echo "SETTINGS DRIFT: $source lost the sandboxed per-app fallback"
        exit 1
    }
done
