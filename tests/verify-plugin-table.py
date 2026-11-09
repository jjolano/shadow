"""Contract for the single ordered plugin registry.

The registry lives in SHDWPlugins.def and is expanded twice: metadata in
Shadow.framework and the aligned installer table in ShadowCore. A second
ordered table is exactly the drift this test exists to prevent.
"""
from pathlib import Path
import re
import sys

ROOT = Path(__file__).resolve().parents[1]
DEF = ROOT / "src/Shadow.framework/Headers/Shadow/SHDWPlugins.def"
FRAMEWORK = ROOT / "src/Shadow.framework/HookConfiguration.m"
DYLIB = ROOT / "src/ShadowCore.dylib/shadowcore.x"

text = DEF.read_text()
text = "\n".join(
    line for line in text.splitlines() if not line.lstrip().startswith("//")
)
rows = []
for block in re.findall(r"SHDW_PLUGIN\((.*?)\)", text, re.S):
    fields = [field.strip() for field in block.split(",")]
    assert len(fields) == 6, f"malformed registry row: {block!r}"
    rows.append(fields)

assert rows, "registry table is empty"
ids = [row[0] for row in rows]
assert len(ids) == len(set(ids)), "duplicate plugin ID in registry"

phases = {
    "SHDWPhaseAlways",
    "SHDWPhaseTier1",
    "SHDWPhaseTier2",
    "SHDWPhaseUIKit",
    "SHDWPhaseEscalation",
    "SHDWPhaseSDKFallback",
}
capabilities = {
    "SHDWCapabilityNone",
    "SHDWCapabilityMessage",
    "SHDWCapabilityFunction",
    "SHDWCapabilitySymlookup",
    "SHDWCapabilityPrivateSym",
}

plannable_phases = {
    "SHDWPhaseTier2",
    "SHDWPhaseUIKit",
    "SHDWPhaseEscalation",
    "SHDWPhaseSDKFallback",
}
installable = 0
for plugin_id, pref, phase, cap, ctor, installer in rows:
    assert plugin_id.startswith('"') and plugin_id.endswith('"'), plugin_id
    assert phase in phases, (plugin_id, phase)
    assert cap in capabilities, (plugin_id, cap)
    assert ctor in {"0", "1"}, (plugin_id, ctor)
    plannable = ctor == "1" or phase in plannable_phases
    assert plannable == (installer != "NULL"), (
        f"{plugin_id}: plannable row and installer disagree")
    if ctor == "1":
        installable += 1

assert installable > 0, "no ctor-installable rows"
assert len(rows) <= 64, "registry exceeds the coordinator's installed-state bitset"

required_profile_keys = {
    "SHDWUniversalFoundationID",
    "SHDWUniversalMachBootstrapID",
    "SHDWUniversalIOKitID",
    "SHDWUniversalSyscallID",
}
registry_keys = {row[1] for row in rows}
assert required_profile_keys <= registry_keys, (
    "a required default-enabled group is missing from the registry")

for source, label in ((FRAMEWORK, "framework"), (DYLIB, "dylib")):
    body = source.read_text()
    assert "#include <Shadow/SHDWPlugins.def>" in body, f"{label} does not expand the registry"
    assert "SHDWPluginOrder" not in body, f"{label} still references the deleted order file"

# The old hand-written rows must not come back.
assert not re.search(r'\{\s*"Universal_', FRAMEWORK.read_text())
assert not re.search(r'\{\s*"Universal_', DYLIB.read_text())

profile = FRAMEWORK.read_text()
assert "SHDWPluginRegistry" in profile, (
    "built-in profile is no longer derived from the registry")
assert "settings[plugin->prefKey] = @YES;" in profile
assert 'settings[SHDWUniversalPseudoSandboxModeID] = @(0);' in profile
assert 'settings[SHDWDetectorAggressiveID] = @(NO);' in profile

# DeviceCheck target mappings and registry preference rows must agree.
mapping_source = (
    ROOT / "src/ShadowCore.dylib/hooks/Adapters/DeviceCheckHooks.h"
).read_text()
mapping_keys = re.findall(r"\{SHDW(Adapter\w+ID), DCHTarget\w+\}", mapping_source)
assert mapping_keys, "DeviceCheck target mapping is empty"
for key in mapping_keys:
    assert f"SHDW{key}" in text, f"{key} has no registry row"

order_inc = ROOT / "src/Shadow.framework/Headers/Shadow/SHDWPluginOrder.inc"
assert not order_inc.exists(), "SHDWPluginOrder.inc returned"

print(f"verify-plugin-table: {len(rows)} registry rows, {installable} ctor installers, single source")
