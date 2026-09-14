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

dpkg = (root / "DpkgRulesGenerator.m").read_text()
for name in ("installed", "schemes"):
    assert re.search(anchor_pattern('[[%s allObjects] sortedArrayUsingSelector:@selector(compare:)]' % name), dpkg)
assert re.search(anchor_pattern('if(previous && [previous isEqual:ruleset]) { result = 1; } else {'), dpkg)
assert anchor(dpkg, 'if(previous &&') < anchor(dpkg, '[ruleset writeToFile:')
print("verify-rules-generation: cache ownership and stable-write contracts passed (static)")
