# SDK audit inventory

These SDKs are for header/symbol comparisons only. They do not change
Shadow's shipping `TARGET` values in `lanes.sh`.

| SDK | Audit boundary | Source |
| --- | --- | --- |
| iPhoneOS 15.6 | Closest audited headers for the rootless iOS 15 floor | Theos `master-146e41f` release; archive SHA-256 `c4a02f5cac1101d1e5e506a1d117de38fd23714a6f535d50c64265bc7351f623` |
| iPhoneOS 16.5 | Current shipping build SDK | existing Theos SDK |
| iPhoneOS 17.5 | RootHide-supported iOS 17 range | `xybp888/iOS-SDKs` commit `1b92ff4a8928f582876e1d388d1381c6a0c59eb9` |
| iPhoneOS 18.6 | First post-RootHide range | same pinned commit |
| iPhoneOS 26.5 | Forward-compatibility canary | same pinned commit |

Promote a newer SDK to a shipping lane only after every lane builds, its
package passes `scripts/check-compat.sh`, and device probes pass on the
relevant jailbreak scheme.

## Detector-facing API gate

Run `THEOS=/path/to/theos scripts/audit-sdk-compat.sh` before accepting a
newer SDK. It compares the iPhoneOS 15.6 baseline with 16.5, 17.5, 18.6, and
26.5 for public Objective-C runtime, dyld, dlfcn, and DeviceCheck selectors.
It fails if an added API has no explicit review. The existing
`objc_enumerateClasses` delta is reviewed because Shadow resolves and hooks it
only when the symbol exists.

The rootless lane still deploys to iOS 15.0; 15.6 is a header-audit baseline,
not a change to that package floor. Runtime-only/private symbols such as
`dlopen_from` and `openat_authenticated_np` are intentionally resolved at
runtime and need device probes in addition to this SDK-header audit.

For a new DeviceCheck or App Attest selector, choose a policy before adding it
to the allowlist: ordinary local signals can be handled normally, but
server-verifiable tokens, attestations, and assertions must not be forged.
