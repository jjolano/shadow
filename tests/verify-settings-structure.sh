#!/bin/sh
set -eu

hooks=ShadowSettings.bundle/Resources/Hooks.plist
troubleshooting=ShadowSettings.bundle/Resources/Troubleshooting.plist
controller=ShadowSettings.bundle/SHDWTroubleshootingListController.m

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
