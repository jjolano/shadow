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

## Arm B — app launch CPU (median of 5 runs)

Target: Bitwarden (`com.8bit.bitwarden`), process `Bitwarden`. CPU time is the
primary measure; wall time is coarse one-second device sampling.

| arm | median CPU | median wall |
|---|---:|---:|
| injected | 0:05.83 | 7 s |
| uninjected | 0:01.04 | 3 s |
| delta | +0:04.79 | +4 s |

## Arm C - detector response timing (median of medians, ms)

`first` is the first invocation in a process; `latest` is the latest report after the harness scene re-run. `framework load` is the cold SDK framework load measured by the harness.

| detector | injected first | injected latest | uninjected first | uninjected latest | latest delta | framework load |
|---|---:|---:|---:|---:|---:|---:|
| batjailbreakguard | 22.423 | 20.886 | 8.622 | 6.144 | 14.742 | 39.823 |
| devicesecuritykit | 59.178 | 50.591 | 242.218 | 205.873 | -155.282 | 39.823 |
| dttjailbreakdetection | 0.015 | 0.008 | 1.027 | 1.038 | -1.030 | 39.823 |
| freerasp | 115.144 | 0.043 | 194.723 | 0.071 | -0.028 | 39.823 |
| iossecuritysuite | 33.169 | 30.384 | 30.300 | 26.542 | 3.842 | 39.823 |
| jailbreakdetector | 0.735 | 1.363 | 1.216 | 0.857 | 0.505 | 39.823 |
| jailmonkey | 28.230 | 18.571 | 28.099 | 24.138 | -5.567 | 39.823 |
| roothider | 165.009 | 175.016 | 108.810 | 76.084 | 98.932 | 39.823 |
| safetynet | 1617.430 | 147.648 | 1828.776 | 320.777 | -173.129 | 39.823 |
| securitytoolkit | 3.238 | 4.151 | 2.537 | 2.133 | 2.017 | 39.823 |
