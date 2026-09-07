# Shadow public tests

Public tests are pure-C checks plus static contract scripts — no device,
no Theos, no Docker, no engine build.

| Check | Command |
| --- | --- |
| svc path-rewrite (pure C) | `make -C tests verify-path-rewrite` |
| rebind journal/repair (pure C) | `make -C tests verify-rebind-repair` |
| device-driver selftest | `make -C tests verify-device-driver` |
| lane/package contract | `sh tests/verify-lane-contract.sh` |
| hook→engine matrix drift | `sh tests/verify-hook-matrix.sh` |
| raw syscall metadata | `sh tests/verify-syscall-meta.sh` |
| settings structure | `sh tests/verify-settings-structure.sh` |

`make -C tests test` runs everything public.

The full engine/detector/adversary/fuzz/device harness is private and
not part of this repo (no URL). The engine-linked batteries were removed
from `tests/Makefile`; only the checks above remain.
