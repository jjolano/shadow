"""Static contracts for generator cache ownership and unchanged-content writes."""
from pathlib import Path

root = Path(__file__).resolve().parents[1] / "src/Shadow.framework"
source = (root / "SystemRulesGenerator.m").read_text()
harvest = source.split("+ (NSDictionary*)generateInstalledAppsRuleset", 1)[1]
harvest = harvest.split("NSMutableSet* schemes", 1)[0]
assert 'IsGeneratedRulesetFilename' not in source
assert harvest.index('isEqualToString:@"shadow service"') < harvest.index(
    '[shdwCuratedRulesetEngines setObject:')
assert '[seenPaths addObject:path];' in harvest
assert 'if(![seenPaths containsObject:cachedPath])' in harvest
assert '[shdwCuratedRulesetEngines removeObjectForKey:cachedPath];' in harvest

dpkg = (root / "DpkgRulesGenerator.m").read_text()
for name in ("installed", "schemes"):
    assert '[[%s allObjects] sortedArrayUsingSelector:@selector(compare:)]' % name in dpkg
assert 'if(previous && [previous isEqual:ruleset]) {\n            result = 1;\n        } else {' in dpkg
assert dpkg.index('if(previous &&') < dpkg.index('[ruleset writeToFile:')
print("verify-rules-generation: cache ownership and stable-write contracts passed (static)")
