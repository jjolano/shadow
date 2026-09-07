"""Static mount-query contract, not an Objective-C runtime or predicate sandbox test."""
from pathlib import Path
import re

root = Path(__file__).resolve().parents[1]
framework = root / "src/Shadow.framework"
engine = (framework / "RestrictionEngine.m").read_text()
core = (framework / "Core.m").read_text()
libc = (root / "src/ShadowCore.dylib/hooks/Universal/libc.x").read_text()
rules = (framework / "Ruleset.m").read_text()


def body(source, signature):
    start = source.index("{", source.index(signature))
    depth = 1
    end = start + 1
    while depth:
        depth += (source[end] == "{") - (source[end] == "}")
        end += 1
    return source[start:end]


def no_metadata(source):
    source = re.sub(r"//[^\n]*|/\*.*?\*/", "", source, flags=re.S)
    assert not re.search(
        r"NSURL|NSFileManager|NSLog|checkForChanges|_loadSnapshot|_reloadRulesets|"
        r"getStandardizedPath|StandardizingPath|ResolvingSymlinks|ExpandingTilde|"
        r"shdw_jbroot_prefix|shdw_probe_jbroot|\bjbroot\s*\(|"
        r"\b(?:realpath|access|stat|lstat|getcwd)\s*\(|"
        r"isCPathRestricted:|isPathRestricted:|_pathRestrictedQuery:|_rulesetDeniesPath:",
        source,
    ), source


query = body(engine, "- (BOOL)isMountPathRestricted:")
facade = body(core, "- (BOOL)isMountPathRestricted:")
no_metadata(query)
no_metadata(facade)
assert "[engine isMountPathRestricted:" in facade
assert "SHADOW_INTERNAL_SCOPE" in facade and "@catch" in facade
assert query.count("[store currentSnapshot]") == 1
assert query.index("[store currentSnapshot]") < query.index("while(path.length > 1)")
assert "shdwSnapshotDeniesPath(snapshot, path)" in query
assert "[path stringByDeletingLastPathComponent]" in query
assert "shdwPathIsWithin(path, mountRoot)" in query
assert "mountRoot = [[Shadow getStandardizedPath:shdw_jbroot_prefix()] copy]" in body(
    engine, "- (instancetype)initWithContext:"
)
startup = (root / "src/ShadowCore.dylib/shadowcore.x").read_text()
assert startup.index("Shadow* shadow = [Shadow sharedInstance]") < startup.index("shdw_coordinator_ctor(prefs)")

# Keep the real compliance -> whitelist -> blacklist evaluator and parent walk.
snapshot = body(engine, "static BOOL shdwSnapshotDeniesPath(")
assert snapshot.index("isPathCompliant:") < snapshot.index("isPathWhitelisted:") < snapshot.index("isPathBlacklisted:")
assert re.search(r"if\(\[ruleset isPathWhitelisted:path\]\)\s*\{\s*return NO;", snapshot)
assert re.search(r"if\(\[ruleset isPathBlacklisted:path\]\)\s*\{\s*return YES;", snapshot)
for method, table in (("isPathWhitelisted", "whitelist"), ("isPathBlacklisted", "blacklist")):
    matching = body(rules, f"- (BOOL){method}:")
    assert f"[set_{table} containsObject:path]" in matching
    assert f"matchesPrefixDict:dict_{table}" in matching
    assert f"[pred_{table} evaluateWithObject:path]" in matching
    no_metadata(matching)
no_metadata(snapshot)
for signature in ("- (BOOL)isPathCompliant:", "- (BOOL)_structureContains:",
                  "- (BOOL)_path:", "- (BOOL)path:"):
    no_metadata(body(rules, signature))
no_metadata(body((framework / "RulesetStore.m").read_text(),
                 "- (ShadowRulesetSnapshot *)currentSnapshot"))
for helper in ("shdwPathIsWithin", "shdwIsSandboxExempt", "shdwIsGroupContainerPath", "shdwPseudoWouldDeny"):
    no_metadata(body(engine, f"static BOOL {helper}("))
no_metadata(body((framework / "Headers/Shadow/JBPath.h").read_text(),
                 "static inline BOOL shdw_is_restricted_root_with_prefix("))

# Every mount hook and its path/fd helpers must avoid the ordinary engine.
mounts = libc[libc.index("static int shdw_filter_mounts("):libc.index("static int (*original_stat)(")]
assert "isCPathRestricted:" not in mounts
assert "isPathRestricted:" not in mounts
assert "shdw_fd_path_restricted(" not in mounts
for field in ("f_mntonname", "f_mntfromname"):
    assert f"[_shadow isMountPathRestricted:rec->{field}]" in mounts
for hook in ("getfsstat", "getmntinfo", "getmntinfo_r_np", "statfs", "fstatfs", "statvfs", "fstatvfs"):
    hook_body = body(mounts, f"replaced_{hook}(")
    assert "shdw_filter_mounts(" in hook_body or "shdw_getfsstat_filtered_snapshot(" in hook_body
    if hook in ("statfs", "statvfs"):
        assert "shdw_mount_argument_restricted(pathname)" in hook_body
    if hook in ("fstatfs", "fstatvfs"):
        assert "shdw_mount_fd_restricted(fd)" in hook_body
for helper in ("shdw_mount_argument_restricted", "shdw_mount_fd_restricted"):
    helper_body = body(mounts, f"static BOOL {helper}(")
    no_metadata(helper_body)
    assert "isMountPathRestricted:" in helper_body
    assert "SHADOW_INTERNAL_SCOPE" in helper_body
    assert "F_GETPATH" in helper_body

print("verify-mount-query: snapshot policy and no-refresh/resolve wiring passed (static)")
