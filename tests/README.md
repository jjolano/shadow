# Shadow public tests

Public tests are pure-C checks plus static contract scripts. They need make, Bash,
a host C compiler, Python 3.7+, and standard shell tools; no device, Docker, iOS SDK, or engine
build is required. The lane/package contract also requires `THEOS` to point to a
directory containing `bin/lane.sh`; a full Theos installation is not required.

| Check | Command |
| --- | --- |
| svc path-rewrite (pure C) | `make -C tests verify-path-rewrite` |
| fresh fd/DIR path policy (host doubles) | `make -C tests verify-fd-path-freshness` |
| mount filtering (pure C + static query contract) | `make -C tests verify-mount-filter` |
| rebind journal/repair (pure C) | `make -C tests verify-rebind-repair` |
| lane/package contract | `sh tests/verify-lane-contract.sh` |
| hook→engine matrix drift | `sh tests/verify-hook-matrix.sh` |
| raw syscall metadata | `sh tests/verify-syscall-meta.sh` |
| settings structure | `sh tests/verify-settings-structure.sh` |
| JB-identifier generation contract | `make -C tests jb-identifiers` |
| package maintainer scripts | `sh tests/MaintainerScriptTests.sh` |

Run the public checks from the repository root:

```sh
make -C tests test
sh tests/MaintainerScriptTests.sh
```

The Makefile's `test` target does not include the maintainer-script checks.

The optional `make -C tests settings-behavior` compiles and executes the actual
settings customization/reset helpers, local version reader, symbol guard, release
parser, About getters, and Updates controller with Foundation and UI/network doubles.
It checks zero requests during pane construction/lifecycle, explicit checks and
retries, duplicate-click suppression, cancellation/stale callbacks, inline notes,
and release URL validation. The companion structure check covers all four locales
and removal of the old popup/action.
It requires macOS Foundation or a host GNUstep/libobjc2 toolchain. On Linux,
`make -C tests settings-behavior GNUSTEP_IMAGE=<image>` uses an existing Docker
image containing clang and GNUstep/libobjc2, with networking disabled. Tests use
an in-memory defaults double, not Shadow's domain. This check is not in `test`
or CI and does not exercise UIKit rendering, accessibility, or live networking.

`verify-device-driver` is a private-only placeholder that prints a skip message;
it does not execute a selftest.

CI's `.github/workflows/tests.yml` runs individual checks, including maintainer
scripts, rather than the aggregate target. It currently omits mount filtering
and JB-identifier generation. Consult that workflow for the actual CI selection.

Mount checks cover record verdict handling and static wiring to the existing
snapshot matcher, including rule precedence and absence of refresh/resolution
in the query. They do not execute Foundation predicates or test device locking;
custom predicates that perform I/O are outside the mount-query contract.

The full engine/detector/adversary/fuzz/device harness is private and
not part of this repo (no URL). The engine-linked batteries were removed
from `tests/Makefile`. For local harness discovery, follow `AGENTS.md`; neither
host checks nor an old harness executable verify the installed iOS harness UI.
