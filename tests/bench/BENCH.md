# Shadow performance benchmarks

Measurement rig and results for per-call hook overhead (arm A), launch cost
(arm B), and detector response (arm C). Re-run instructions per arm below.

## Baseline pin

| Field | Value |
|---|---|
| Device | iPhone 7 (iPhone9,3), arm64 |
| iOS | 15.8.3 (19H386), rootless (Dopamine, /var/jb) |
| Shadow build | d142425 (commit at baseline), package me.jjolano.shadow |
| Hook prefs | all hook groups ENABLED on this device (non-default; shipped defaults ship several OFF) |
| Method | mach_absolute_time, per-call sampling, median of medians across runs |
| Runs / iters | 3 runs x 10000 iters per arm (arm A) |

## Arm A — per-call hook microbench (median of medians, ns)

| group | path class | injected | stock | delta |
|---|---|---:|---:|---:|
| devicecheck | allowed | 333 | 523791 | -523458 |
| libc.open | allowed | 7208 | 2041 | +5167 |
| libc.open | fast-allowed | 9542 | 9375 | +167 |
| libc.open | restricted | 542 | 12791 | -12249 |
| libc.stat | allowed | 6500 | 1458 | +5042 |
| libc.stat | fast-allowed | 10959 | 8833 | +2126 |
| libc.stat | restricted | 12542 | 12166 | +376 |
| mach.bootstrap | allowed | 55208 | 54916 | +292 |
| mach.bootstrap | restricted | 83125 | 82583 | +542 |
| mem.vmregion | allowed | 2542 | 2542 | +0 |
| nsbundle | allowed | 542 | 583 | -41 |
| nsbundle | restricted | 59334 | 14209 | +45125 |
| nsdata | allowed | 13292 | 13167 | +125 |
| nsdata | restricted | 417 | 197541 | -197124 |
| nsdictionary | allowed | 113375 | 112625 | +750 |
| nsdictionary | restricted | 1625 | 150084 | -148459 |
| nsfilehandle | allowed | 24333 | 23750 | +583 |
| nsfilehandle | restricted | 16209 | 30584 | -14375 |
| nsfilemanager | allowed | 6416 | 1208 | +5208 |
| nsfilemanager | fast-allowed | 8375 | 8375 | +0 |
| nsfilemanager | restricted | 11959 | 11583 | +376 |
| nsprocessinfo | allowed | 28791 | 8834 | +19957 |
| nsstring | allowed | 14167 | 13958 | +209 |
| nsstring | restricted | 458 | 23458 | -23000 |
| nsthread | allowed | 250 | 250 | +0 |
| nsurl | allowed | 12875 | 7416 | +5459 |
| nsurl | fast-allowed | 15250 | 15000 | +250 |
| nsurl | restricted | 18791 | 18209 | +582 |
| nsuserdefaults | allowed | 1958 | 1959 | -1 |
| objc.classlookup | allowed | 333 | 250 | +83 |
| objc.classlookup | restricted | 250 | 833 | -583 |
| sandbox | allowed | 2458 | 2458 | +0 |
| sandbox | fast-allowed | 8792 | 8583 | +209 |
| sandbox | restricted | 12125 | 11958 | +167 |
| syscall.csops | allowed | 1250 | 541 | +709 |
| uikit.imagenamed | allowed | 138250 | 133125 | +5125 |
