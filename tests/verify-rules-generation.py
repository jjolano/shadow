"""Static contracts for generator cache ownership and unchanged-content writes."""
from pathlib import Path
import re


def anchor_pattern(needle):
    """Regex for `needle`, tolerant of reformat spacing.

    These gates locate real source snippets by text and pin them. A
    clang-format pass must not be able to break that, so the pattern matches
    identifier/punctuation tokens separated by any whitespace, while the
    token sequence itself stays exact.
    """
    return r"\s*".join(
        re.escape(tok) for tok in re.findall(r"[A-Za-z0-9_]+|[^\sA-Za-z0-9_]", needle)
    )


def anchor(text, needle, start=0):
    """Index of `needle` in `text`, tolerant of reformat spacing."""
    match = re.search(anchor_pattern(needle), text[start:])
    if match is None:
        raise ValueError(f"anchor not found: {needle!r}")
    return start + match.start()


def body(text, first, last):
    """Slice `text` between two anchors, tolerant of reformat spacing."""
    start = anchor(text, first)
    return text[start:anchor(text, last, start)]


root = Path(__file__).resolve().parents[1] / "src/Shadow.framework"
source = (root / "SystemRulesGenerator.m").read_text()
harvest = body(source, "+ (NSDictionary*)generateInstalledAppsRuleset {", "NSMutableSet* schemes")
assert 'IsGeneratedRulesetFilename' not in source
assert anchor(harvest, 'isEqualToString:@"shadow service"') < anchor(
    harvest, '[shdwCuratedRulesetEngines setObject:')
assert re.search(anchor_pattern('[seenPaths addObject:path];'), harvest)
assert re.search(anchor_pattern('if(![seenPaths containsObject:cachedPath])'), harvest)
assert re.search(anchor_pattern('[shdwCuratedRulesetEngines removeObjectForKey:cachedPath];'), harvest)

# Compiled-cache freshness stamp: the compile call site produces it and the
# reader compares it, and the two must use the same epoch. Inlining the epoch
# per site is exactly how the writer ends up stamping a value the reader can
# never match — the cache then stops being written or read, silently, and no
# host check drives the real reader/writer pair (that needs a device).
compiler = (root / "RulesetCompiler.m").read_text()
assert re.search(
    anchor_pattern("static NSNumber* shdw_compiledCacheStamp(NSDictionary* plistAttrs)"),
    compiler), "the cache stamp helper is gone"
assert len(re.findall(anchor_pattern("shdw_compiledCacheStamp("), compiler)) == 4, (
    "expected the helper definition plus the reader, the writer and the compile call site")
assert compiler.count("timeIntervalSince1970") == 2, (
    "the epoch choice must live only in shdw_compiledCacheStamp (comment + body)")

# The single-entry verdict fast path must have exactly ONE writer, and that
# writer must refuse working-directory-relative queries: a second publisher
# (the shared-cache hit path had one) stored a wd-scoped verdict under the raw
# leaf name, so a later nil-wd query for that leaf could take a verdict
# computed against a different directory.
engine = (root / "RestrictionEngine.m").read_text()
writers = engine.count("strlcpy(lastPathBuf")
assert writers == 1, (
    f"expected exactly one lastPathBuf writer, found {writers} — route new "
    f"publishers through publishTLS")
pub = body(engine, "void (^publishTLS)(BOOL)", "BOOL restricted = NO;")
assert re.search(anchor_pattern("query.workingDirectory != nil"), pub), (
    "publishTLS must refuse working-directory-relative verdicts")

dpkg = (root / "DpkgRulesGenerator.m").read_text()
for name in ("installed", "schemes"):
    assert re.search(anchor_pattern('[[%s allObjects] sortedArrayUsingSelector:@selector(compare:)]' % name), dpkg)
assert re.search(anchor_pattern('if(previous && [previous isEqual:ruleset]) { result = 1; } else {'), dpkg)
assert anchor(dpkg, 'if(previous &&') < anchor(dpkg, '[ruleset writeToFile:')
print("verify-rules-generation: cache ownership and stable-write contracts passed (static)")
