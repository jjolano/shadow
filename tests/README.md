# Shadow test harness

Host-side tests for Shadow's real decision engine. Linux runs the full suite in
Docker with GNUstep; macOS runs selected checks with system Foundation. No iOS
device, simulator, or Theos installation is required.

## Run

The first Linux run builds the toolchain image and takes about ten minutes.

| Command | Coverage |
| --- | --- |
| `make -C tests test` | Unit and policy assertions |
| `make -C tests detect` | Classic detection probes |
| `make -C tests detector` | Independent detector, raw versus filtered |
| `make -C tests shipped` | Shipped product rulesets |
| `make -C tests benign` | Benign-app regression battery |
| `make -C tests adversary` | Path-evasion battery |
| `make -C tests fuzz` | Seeded invariant fuzzer |
| `make -C tests afuzz` | Seeded adversarial fuzzer |
| `make -C tests coverage` | gcov report mapped to hook groups |

The table is the Linux suite. The native macOS checks used in CI are:

```sh
make -C tests test-rooted
make -C tests adversary-rooted
make -C tests fuzz
```

CI runs the Linux suite plus rooted macOS unit, adversary, and fuzz checks. The
scheduled deep-fuzz workflow raises the iteration counts for both fuzzers.

## What is covered

- Ruleset parsing, compilation, reloads, caching, and last-known-good behavior.
- Rooted and rootless path, URL, scheme, bundle-ID, image, and write policies.
- Symlink resolution, path normalization, directory filtering, and error shapes.
- Independent detector and benign-app differential batteries.
- Mutation fuzzing and semantic-equivalence evasion fuzzing.
- Hook-configuration and coordinator planning through the real framework code.

The harness builds the production decision sources listed in `tests/Makefile`
against host Foundation. Linux shims map `/var/jb` into `tests/fixtures/fs/jb`
so rootless existence gates exercise a controlled filesystem.

## Reproduce fuzz failures

Both fuzzers print their seed and iteration. Override them with:

```sh
SHADW_FUZZ_SEED=123 SHADW_FUZZ_ITERS=200000 make -C tests fuzz
SHADW_AFUZZ_SEED=123 SHADW_AFUZZ_ITERS=20000 make -C tests afuzz
```

## Host limits

- HookKit interposition, Darwin-only APIs, and injected-process behavior require
  on-device probes.
- Rooted `/usr/lib` reads use the host filesystem; rootless reads use fixtures.

Use `tests/tools/dyldprobe`, `tests/tools/hookprobe`, `tests/ShadowHarness`, and
`tests/stealth-device.sh` for device validation.

`tests/stealth-device.sh run-all` executes Harness Run All headlessly and
captures its thirteen detector reports as device evidence.

`tests/harness-regression.py` is the opt-in on-device regression check: it
deploys the harness, runs all thirteen detectors under aggressive mode via a
real SpringBoard launch (not headless — so `freerasp.debug`, which only fires
on the orphaned nohup environment, stays clean), and asserts each detector's
outcome and its `notChecked` check-ids against `tests/harness-expected.json`. A
new `notChecked` id (a real check quietly downgraded to a pass) or a flipped
row fails; known artifacts stay green. It mutates and restores device prefs, so
it is NOT part of `make` or CI — run it when touching anti-detection code:

```sh
make -C tests harness-regression DEVICE=mobile@10.0.1.160
make -C tests harness-regression DEVICE=mobile@10.0.1.160 DEB=../build/me.jjolano.shadow.harness_1.0.0_iphoneos-arm64.deb
python3 tests/harness-regression.py --device mobile@10.0.1.160 --update   # rebaseline after a verified change
```

Its pure-logic checks run in CI via `make -C tests verify-device-driver`.

## Layout

- `main.m`, `*Tests.m`, `Fuzz.m` — runner and batteries
- `fixtures/` — rulesets and fake jailbreak filesystem
- `ShdwPathShim.*`, `fsinterpose.*`, `ShadowFilter.m` — host/device seams
- `detectors/` — independent detector implementation
- `Dockerfile`, `build-linux.sh` — Linux toolchain
- `coverage-report.sh`, `verify-hook-matrix.sh` — coverage and drift checks
