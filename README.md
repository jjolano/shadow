# Shadow

A modern jailbreak detection bypass.

## Install

Add `https://ios.jjolano.me` to your package manager and install `me.jjolano.shadow`. Or grab the [latest release](https://github.com/jjolano/shadow/releases/latest).

Needs `AltList` + `libSandy` (opa334) and `HookKit >= 3.0.0` (jjolano). `Injection Foundation` (PoomSmart) recommended.

## Use

Settings app → Shadow → global defaults or per-app config. `shdw -d` keeps the app ruleset in sync.

## Compatibility

| Package | iOS |
| --- | --- |
| Rootful legacy (`iphoneos-arm`) | 9–13 |
| Rootful modern (`iphoneos-arm`) | 14+ |
| Rootless (`iphoneos-arm64`) | 15+ |
| RootHide (`iphoneos-arm64e`) | 15–17 |

No guarantee every app/detection SDK works everywhere.

## Troubleshooting

* Disable other tweaks per-app (Choicy).
* Downgrade the app; don't stack multiple bypass tweaks.
* Rootless/semi-untethered: test in stock jailed state to isolate.

## Building

Requires [Theos](https://theos.dev). One lane at a time:

```sh
.github/scripts/build-deps.sh rootful-modern
./build.sh rootful-modern
```

Lanes: `rootful-legacy`, `rootful-modern`, `rootless`, `roothide`. See `build-support/lanes.sh` for the matrix. Tests: `make -C tests test` ([details](tests/README.md)).

## Legal

*Copyright Act*, RSC 1985, c C-42, s 41.12.
