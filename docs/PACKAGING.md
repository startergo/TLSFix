# Building the installer

How the shipped `AquaTransport.pkg` and the DMG around it are produced. The pkg is
**not** committed: generated installers are kept out of version control, and the
build reproduces it from source. (`packaging/DMG Image/AquaTransport.pkg` may exist
locally as a build output; `.gitignore` covers it.)

## What the artifacts are

```
packaging/DMG Image/          the DMG's source folder
├── AquaTransport.pkg         the installer (build output; see below)
├── Readme.rtf                end-user notes shown in the DMG
└── Uninstall.command         receipt-driven uninstaller

packaging/Package/AquaTransport.pkgproj   Packages-app project (the format authority)
packaging/Default Configuration/          default rule files shipped into config/
packaging/Modern Roots/                   root certificates + their post-install script
packaging/insert_dylib, preinstall.sh, postinstall.sh   the pkg's Scripts archive
packaging/tap.pkg           optional tuntaposx tap kext (AirDrop radio dependency)
```

`AquaTransport.pkg` is a distribution-format installer (an xar archive) with three
parts: the `AquaTransport.pkg` component (Payload + Bom + Scripts + PackageInfo),
the `Modern_Root_Certificates.pkg` component (empty payload; its post-install
installs the pem roots and edits `EVRoots.plist`), and the `Distribution` +
`Resources` installer UI.

## Prerequisites

```
./build-macos.sh
```

Everything the pkg can carry is staged under `build/stage/`:

| payload | staged when |
| --- | --- |
| `aquatransport.dylib`, `aquatransport_engine.dylib`, config defaults | always |
| `aquatransport_gsa.dylib`, `aquatransport_maps.dylib` | a GC-capable compiler is available (see [ICLOUD.md](ICLOUD.md)) |
| `aquatransport_airdrop.dylib`, `aquatransport-bootstrap`, `airdrop/` helpers, the bootstrap LaunchDaemon | `tools/build-airdrop.sh` ran (invoked automatically by `build-macos.sh`) |

Each optional image rides along only when present, the same way
`install-macos.sh` stages whatever exists — a build without the GC toolchain
ships an installer without those modules, cleanly.

## Building the pkg

**Rebuild the shipped pkg: `./tools/make-pkg.sh`** (needs sudo, prompted on the
terminal or piped on stdin: `printf '%s\n' password | ./tools/make-pkg.sh`).

The script unpacks the existing `packaging/DMG Image/AquaTransport.pkg` as a
template, replaces Payload/Bom/Scripts/PackageInfo from `build/stage/`, and
re-archives — replicating the original Packages-app output byte-format: odc-cpio
("070707") payloads, gzip, root:wheel ownership, entry modes, and
`xar --compression none` (load-bearing: Leopard-era installers fail on
double-compressed Payload with `BOMCopierFatalError`). The shipped pkg is
replaced atomically, so a reported success is never a half-written file.

Because it needs a template, the first build on a fresh clone has to come from
the Packages app (below), or from a previously built pkg — the file is not in
git. If the template is missing after a fresh clone, recover it from any
machine that built one, or rebuild via the Packages project once.

**Build from scratch: the Packages app.** Open
`packaging/Package/AquaTransport.pkgproj` in [Packages](https://github.com/packagesdev/packages)
and build. The project references `../../build/stage/...` paths directly and is
the authority for layout and file modes; `make-pkg.sh` replicates its output so
the two stay interchangeable. After changing payload layout or modes, change
the pkgproj first, then mirror it in `make-pkg.sh`.

## Verifying a built pkg

```
xar -tf "packaging/DMG Image/AquaTransport.pkg"      # the distribution entries
d=$(mktemp -d) && xar -x -f "packaging/DMG Image/AquaTransport.pkg" -C "$d" AquaTransport.pkg/Payload
gunzip -c "$d/AquaTransport.pkg/Payload" | cpio -it  # the payload listing
```

or after a test install, `sudo lsbom -p fM /var/db/receipts/Wowfunhappy.AquaTransport.bom`
shows every payload path with its mode. The pkg is intentionally unsigned (it
patches `/System`; see [TECHNICAL.md](TECHNICAL.md) for why and what that means
on each OS version).

## The DMG

There is no DMG script; assemble it by hand from the folder:

```
hdiutil create -volname AquaTransport -srcfolder "packaging/DMG Image" \
    -ov -format UDZO AquaTransport.dmg
```

Old target systems (10.6–10.9) read UDZO fine; keep the source folder's layout
(readme visible, `Uninstall.command` beside the pkg) as it ships.

## Install and uninstall (test machines)

```
sudo installer -pkg "packaging/DMG Image/AquaTransport.pkg" -target /
bash "packaging/DMG Image/Uninstall.command"
```

The uninstaller is receipt-BOM-driven: it removes exactly what the pkg laid
down (keeping the admin's rule files) and restores `Security.framework` from
its backup. An install that never wrote a receipt (files copied by hand, or an
interrupted pkg install) leaves the uninstaller nothing to enumerate — remove
`/usr/share/aquatransport` and any `/Library/LaunchDaemons/org.aquatransport.*`
by hand in that case.
