# Shadow public tests

Public tests are pure-C checks plus static contract scripts — no device,
no Theos, no Docker, no engine build.

| Check | Command |
| --- | --- |
| svc path-rewrite (pure C) | `make -C tests verify-path-rewrite` |
| mount filtering (pure C + static query contract) | `make -C tests verify-mount-filter` |
| rebind journal/repair (pure C) | `make -C tests verify-rebind-repair` |
| device-driver selftest | `make -C tests verify-device-driver` |
| lane/package contract | `sh tests/verify-lane-contract.sh` |
| hook→engine matrix drift | `sh tests/verify-hook-matrix.sh` |
| raw syscall metadata | `sh tests/verify-syscall-meta.sh` |
| settings structure | `sh tests/verify-settings-structure.sh` |

`make -C tests test` runs everything public.

Mount checks cover record verdict handling and static wiring to the existing
snapshot matcher, including rule precedence and absence of refresh/resolution
in the query. They do not execute Foundation predicates or test device locking;
custom predicates that perform I/O are outside the mount-query contract.

The full engine/detector/adversary/fuzz/device harness is private and
not part of this repo (no URL). The engine-linked batteries were removed
from `tests/Makefile`; only the checks above remain.
