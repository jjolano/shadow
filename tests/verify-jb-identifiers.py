"""Compile the identifier arrays and check their data and consumer wiring."""
import hashlib
import os
from pathlib import Path
import subprocess
import tempfile

root = Path(__file__).resolve().parents[1]
header = root / "src/ShadowCore.dylib/hooks/Universal/jb-identifiers.h"
appenv = header.with_name("AppEnvironment.x").read_text()
symbols = ("shdw_jb_nsuserdefaults_suites", "shdw_jb_preference_domain_ids")
source = '#include <stdio.h>\n#include <assert.h>\n#include "%s"\nint main(void) {\n' % header
for prefix, symbol in zip(("S:", "P:"), symbols):
    source += """
    assert(%(symbol)s[sizeof(%(symbol)s) / sizeof(%(symbol)s[0]) - 1] == NULL);
    for(size_t i = 0; i + 1 < sizeof(%(symbol)s) / sizeof(%(symbol)s[0]); i++) {
        assert(%(symbol)s[i] && %(symbol)s[i][0]);
        printf("%(prefix)s%%s\\n", %(symbol)s[i]);
    }
""" % {"symbol": symbol, "prefix": prefix}
source += "return 0; }\n"
with tempfile.TemporaryDirectory() as tmp:
    driver, binary = Path(tmp) / "driver.c", Path(tmp) / "driver"
    driver.write_text(source)
    subprocess.run([os.environ.get("CC", "cc"), "-std=c99", "-Wall", "-Wextra",
                    "-Werror", str(driver), "-o", str(binary)], check=True)
    output = subprocess.check_output([str(binary)])
assert hashlib.sha256(output).hexdigest() == "6c5d2b391886540703dcbc607858cdaa0028018112074514ed7779bbc9254e28", "identifier data changed"
assert '#import "jb-identifiers.h"' in appenv
for symbol in symbols:
    assert 'for(const char* const* p = %s; *p; p++)' % symbol in appenv
assert "[restrictedSuites containsObject:suitename]" in appenv
assert "suitename.lastPathComponent" in appenv
assert "[leaf isEqualToString:pref]" in appenv
print("verify-jb-identifiers: compiled data and consumer wiring passed")
