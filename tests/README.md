# Shadow test harness

Host-side test harness for Shadow's decision engine — no device, no theos,
no simulator. Builds the real `Shadow.framework` decision sources
(`Core.m`, `Backend.m`, `Ruleset.m`, `Core+Utilities.m`) against a host
Foundation with a stubbed `RootBridge`, then runs the engine against staged
fixture rulesets and a fixture jailbreak tree.

## Build & run

**Linux (this repo's dev box):** the harness runs inside a Docker image with
an ARC-capable GNUstep toolchain (clang + libobjc2 + GNUstep base, built in
`tests/Dockerfile` — first `make` builds the image, ~10 min once):

```sh
make -C tests test        # unit assertions, rooted + rootless modes
make -C tests detect      # detector-probe battery against the shipped rulesets
make -C tests adversary   # adversarial evasion battery (rooted + rootless)
make -C tests detector    # real-detector vs Shadow: raw vs filtered passes
make -C tests benign      # benign app session: filter OFF vs ON must match
make -C tests coverage    # gcov report: engine methods vs hooked API groups
```

**CI:** `.github/workflows/tests.yml` runs all three on every push/PR
(ubuntu-latest, docker in the loop).

**macOS:** `make -C tests test` builds and runs natively with the system
Foundation (same assertions; the fsinterpose shims compile to no-ops).

`harness` stages a temp working dir shaped like an app on a jailbroken
device:

```
<work>/Harness.app/harness                        running binary — bundlePath
                                                  ends in .app, so
                                                  hasAppSandbox == YES and the
                                                  resolve-before-exempt branch
                                                  of isPathRestricted: runs
<work>/fs/jb/...                                  fixture jbroot tree backing
                                                  the virtual filesystem
<work>/<jb|root>/Library/Shadow/Rulesets/         staged rulesets
<work>/shdw-app/restricted-target                 real file the rooted
                                                  sandbox symlink resolves to
```

The parent process forks one child per mode (fresh singleton/backend per
mode) and each child execs itself from the staged `.app` dir.

## How the device semantics are faked on a host

- **RootBridge stub** (`RootBridgeStub.m`): rooted/rootless switchable;
  the rulesets dir redirects to the staged dir in both modes.
- **Virtual filesystem** (`fsinterpose.c`, Linux only): the engine's
  rootless existence gates call real `access()`/`realpath()` on literal
  `/var/jb`-prefixed paths. The harness links with
  `-Wl,--wrap=access -Wl,--wrap=realpath`, so those calls rewrite
  `/var/jb...` into the fixture tree (`<work>/fs/jb/...`) — rootless gates
  behave exactly as on a device: file present → gate passes → engine
  decides; absent → gate blocks. Also provides `_NSGetArgv` (GNUstep
  doesn't export it) and stubs the unused `dyld_image_path_containing_address`.
- **GNUstep patches** (applied in `tests/Dockerfile`): two real bugs that
  would break the engine on this stack —
  - `-contentsOfDirectoryAtURL:` built child URLs from the enumerator's
    relative names with plain `+fileURLWithPath:` (resolved against the
    process CWD) — every ruleset URL was garbage.
  - `NSPredicate` NSCoding was `subclassResponsibility` FIXMEs: Shadow's
    compiled-cache write (`Ruleset.m _writeCompiledCacheForRuleset`) hit the
    throw mid-encode, and GNUstep's NSKeyedArchiver over-releases in dealloc
    after a throw — heap corruption. The patch encodes predicates as a plain
    marker string: the cache-restore type check rejects the entry and the
    caller recompiles. The cache is a pure speedup, so correctness wins.
  - `dispatch_once` and the two `CFBundle*` functions used by
    Core+Utilities are provided as harness-side shims (Linux only), since
    this stack has no libdispatch/CoreFoundation.

## What's covered

- Ruleset semantics: exact/prefix blacklist, whitelist-overrides-blacklist,
  whitelist mid-filename prefix, predicate rules, FileSystemStructure
  compliance vetoes, parent-path recursion, whitelisted-parent vs
  deeper-blacklisted child.
- Engine subtleties surfaced by the harness (device-identical code):
  - a whitelist only beats an exact blacklist when the parent chain is
    clean — parent-dir recursion restricts a whitelisted child of a
    blacklisted dir (e.g. the shipped `/tmp/com.apple` whitelist does not
    rescue `/tmp/com.apple.installer` from the `/tmp/` blacklist);
  - prefix rules match the prefix and its direct children only.
- C0-1 write probes: absent-but-restricted targets are denied for writes
  even though reads are existence-gate-allowed.
- Rootless vs rooted decision paths: `/var/jb`/`/cores`/`/private/preboot`
  restricted-root fast paths, rootless existence gates (virtual FS), the
  rootless `/var/jb`-gated reads vs rooted host-`/usr/lib` reads.
- Scheme, bundle-ID (static list + ruleset extension) and protected-image
  name checks, case-variant probes included.
- Ruleset reload via mtime detection, decision-cache invalidation on
  ruleset-generation bump, and last-known-good serving after a malformed
  ruleset rewrite (reload test).
- Resolve-before-exempt: a symlink inside the sandbox-exempt bundle dir
  resolving to a restricted target is caught; `kShadowRestrictionNoFollow`
  link-location queries are exempt.
- `getStandardizedPath`, `filterPathArray`, file-error factories.
- Detector battery (`--detect`): classic jailbreak-detection probes
  (`fopen`/`access` on JB paths, `openURL` schemes, bundle IDs, image names)
  against the real shipped `StandardRules.plist` + `JailbreakMisc.plist`,
  plus the 3-byte placeholder `dpkgInstalled.plist` as a tolerance check.
- Real-detector battery (`--detector`): an independent ObjC implementation
  of the classic jailbreak-detection checks (suspicious-file existence and
  readability across ~80 well-known JB artifact paths, restricted-dir
  writability, jailbreak URL schemes), run twice against the engine:
  **raw** — Shadow off (rulesets emptied, filter disabled): the detector
  must find the simulated jailbreak (proves the detector works and the
  fixture simulates a jailbroken device); **shadow** — shipped rulesets
  restored and the shadow filter enabled: the engine must hide every probe
  (ENOENT for reads, EACCES for writes — exactly the device hook layer's
  semantics), and any firing check is reported as a LEAK. Note: this is an
  independent implementation of publicly documented detection techniques,
  NOT a vendored port — IOSSecuritySuite is distributed under a restrictive
  EULA that forbids modification/redistribution (see
  `tests/detectors/ShadowDetector.m` for the full licensing note).
- Adversary battery (`--adversary`): evasion attempts against the engine —
  normalization attacks (`//`, `/./`, `..`, trailing slash, tilde escapes,
  `file://` and `/private/var` URL forms), case variants, mode-divergent
  `/var/jb`-sibling paths, C0-1 creatable-file probes — each with an
  expectation encoding the engine's true per-mode semantics (a deviation
  fails the run as a LEAK), plus a report-only mutation sweep. Findings so
  far: the FileSystemStructure veto catches case variants the rules don't
  (`/USR/SBIN/FSTAB`), GNUstep evaluates `CONTAINS` case-insensitively
  (Cocoa is case-sensitive — documented divergence), and a leading `//`
  parses as a protocol-relative URL (faithful to the engine's
  standardization on any platform).

- Benign-app battery (`--benign`): the other half of the contract — a
  normal, detector-free app must be UNAFFECTED by Shadow. A scripted app
  session (read/stat/list/write its own container files, access its
  prefs/tmp dirs, hit an absent file, open http/cydia schemes, query stock
  bundle IDs and frameworks) runs twice — shadow filter OFF (baseline) and
  ON — and every outcome, including errno, must be identical; any
  divergence is reported as AFFECTED. Also guards the subtle false
  positive: an app file *named* like a JB artifact (e.g. `ssh`) inside its
  own container stays readable.

## Hooked-API coverage

The hook layer itself (HookKit interposition in `ShadowCore.dylib`) is
device-only, but every hooked API funnels into a small set of engine entry
points — that surface is what the harness covers. `make -C tests coverage`
builds the harness with gcov instrumentation, runs every battery, and
reports per-method line coverage of each entry point cross-referenced with
the hooked-API groups that dispatch into it (from the actual call sites in
`ShadowCore.dylib/hooks/*.x`):

```
isPathRestricted:options: 89.61%  [libc, dyld, sandbox, syscall, NSFileManager, ...]
isURLRestricted:options:  64.71%  [NSFileManager, NSURL, NSString, ...]
isCPathRestricted:       100.00%  [libc, dyld, sandbox, syscall]
isSchemeRestricted:      100.00%  [LSApplicationWorkspace]
isBundleIDRestricted:    100.00%  [LSApplicationWorkspace]
isProtectedImagePath:    100.00%  [dyld, objc, NSBundle, UIImage]
isAddrRestricted:        100.00%  [dyld, objc, mem, sandbox, NSThread, NSBundle]
filterPathArray:         100.00%  [NSFileManager]
generateDatabase:         98.33%  [SystemRules/shadowd]
...
```

A method listed as `unexecuted` would mean the engine behavior behind some
hooked API group is never exercised by any battery — a gap to fill.

## Known host limitations (deliberate)

- The hook layer (HookKit/substrate interposition, dylib ctor, image-span
  collection, jailbreakd probes) is device-only and not exercised here —
  the harness covers the decision engine those hooks dispatch into.
- Rooted `/usr/lib` read probes are gated against the host's `/usr/lib`
  (absent files → allowed); write probes (C0-1) and rootless read probes
  (virtual FS) are device-accurate.
- Ruleset reloads are throttled by the engine's 1-second scan gate, so the
  reload test sleeps ~1.3s per mutation (adds ~3s to the rooted run).
- SystemRules/dpkg-database generation (`shadowd`) is device-only.

## Layout

- `main.m` — staging, fork/exec, assertions, detector battery
- `RootBridgeStub.m`/`.h` — host `RootBridge` implementation
- `fsinterpose.c`/`.h` — virtual filesystem + dyld/dispatch/CF shims
- `Dockerfile`, `build-linux.sh` — Linux toolchain image + build
- `fixtures/rulesets/` — synthetic rulesets (base, overrides, structure,
  malformed, reload)
- `fixtures/fs/jb/` — fake rootless jailbreak tree backing the virtual FS
- `hdr/` — Linux-only stubs (Availability/TargetConditionals/mach-o,
  dispatch/once, CoreFoundation/CFBundle)
