#!/bin/sh
# Rebuilds packaging/DMG Image/AquaTransport.pkg on a 10.6 machine from the freshly built
# dylibs, replicating the original Packages-app output format exactly:
#   - Payload: odc-cpio ("070707"), gzip, uid/gid 0, entry modes as the shipped pkg carries
#   - Scripts: odc-cpio, gzip: insert_dylib + postinstall + preinstall, all 0755 root:wheel
#   - Bom: regenerated with mkbom from the staged tree
#   - PackageInfo: gains the <preinstall> reference; installKBytes recomputed
# Everything else (Distribution, Modern_Root_Certificates.pkg, Resources) is carried over
# from the existing pkg untouched. On success the shipped pkg is replaced atomically, so
# there is no way for the committed artifact to go stale while this reports success.
#
# Root is needed for the staging ownership (chown, mkbom, pax's archive headers). Credentials
# are taken once by sudo itself -- prompted on the terminal when interactive, read from
# stdin when piped (`printf '%s\n' secret | ./tools/make-pkg.sh`) -- and never as an
# argument, where ps(1) and shell history would keep a copy.
set -e
REPO="$(cd "$(dirname "$0")/.." && pwd)"
OLDPKG="$REPO/packaging/DMG Image/AquaTransport.pkg"
W="$(mktemp -d /tmp/aqpkg.XXXXXX)"     # private and unpredictable: root consumes this tree
NEW=""                                 # the beside-the-pkg staging copy, once there is one
# Cleanup on any exit. Nothing in $W is root-owned until the first run_root chown, so the
# plain rm covers the early error paths -- including a rejected password, where sudo cannot
# be re-asked -- and the sudo fallback covers the root-owned case. Each stage is non-fatal:
# under set -e a failed command aborts the trap itself, and the stages after it -- NEW, so a
# failed replace cannot leave a stray .new beside the real pkg for git to pick up -- would
# never run. Verified on 10.6's /bin/sh: a failing command mid-trap skips the rest of it.
trap 'rm -rf "$W" 2>/dev/null || sudo rm -rf "$W" || :; [ -n "$NEW" ] && rm -f "$NEW" || :; :' EXIT

if [ -t 0 ]; then sudo -v; else sudo -S -v; fi
run_root() { sudo "$@"; }              # failures print their reason and stop the build

STAGE="$REPO/build/stage/usr/share/aquatransport"
[ -f "$STAGE/aquatransport.dylib" ] || { echo "no built dylibs at $STAGE -- run build-macos.sh first"; exit 1; }
[ -f "$OLDPKG" ] || { echo "no existing pkg to carry the distribution from: $OLDPKG"; exit 1; }

# Unpack the existing distribution as the template.
mkdir -p "$W/x"
(cd "$W/x" && xar -xf "$OLDPKG")

# Stage the AquaTransport payload: new dylibs, current default rule files.
R="$W/root/usr/share/aquatransport"
mkdir -p "$R/config"
cp "$STAGE/aquatransport.dylib" "$STAGE/aquatransport_engine.dylib" "$R/"
cp "$REPO/packaging/Default Configuration/disabled.txt" \
   "$REPO/packaging/Default Configuration/headers.txt" \
   "$REPO/packaging/Default Configuration/redirects.txt" "$R/config/"
chmod 0755 "$W/root" "$R"
chmod 0775 "$W/root/usr" "$W/root/usr/share" "$R/config"
chmod 0644 "$R/aquatransport.dylib" "$R/aquatransport_engine.dylib"
chmod 0664 "$R/config/"*.txt
run_root chown -R root:wheel "$W/root"
run_root chgrp admin "$R/config" "$R/config/"*.txt

# Payload: pax writes odc-cpio; as root so the headers say root:wheel.
KB=$(( $(cd "$W/root" && du -sk . | cut -f1) ))
(cd "$W/root" && sudo pax -w -x cpio . > "$W/payload.cpio")
gzip -9 < "$W/payload.cpio" > "$W/x/AquaTransport.pkg/Payload"
[ "$(gunzip -c "$W/x/AquaTransport.pkg/Payload" | wc -c)" -eq "$(wc -c < "$W/payload.cpio")" ] \
    || { echo "payload gzip round-trip mismatch"; exit 1; }

# Bom from the same tree.
run_root mkbom "$W/root" "$W/x/AquaTransport.pkg/Bom"

# Scripts archive: the two install scripts plus the helper binary. PackageInfo names the
# scripts without their .sh, the way the Packages app laid them down, so stage them renamed.
mkdir -p "$W/scripts"
cp "$REPO/packaging/insert_dylib" "$W/scripts/"
cp "$REPO/packaging/postinstall.sh" "$W/scripts/postinstall"
cp "$REPO/packaging/preinstall.sh" "$W/scripts/preinstall"
chmod 0755 "$W/scripts/"*
run_root chown -R root:wheel "$W/scripts"
(cd "$W/scripts" && sudo pax -w -x cpio . > "$W/scripts.cpio")
gzip -9 < "$W/scripts.cpio" > "$W/x/AquaTransport.pkg/Scripts"

# PackageInfo: add the preinstall reference, refresh the size estimate. The newline in the
# replacement is a literal backslash-line-continuation, which is how BSD sed spells it.
sed -e 's|<postinstall file="./postinstall"/>|<postinstall file="./postinstall"/>\
    <preinstall file="./preinstall"/>|' \
    -e "s|installKBytes=\"[0-9]*\"|installKBytes=\"$KB\"|" \
    "$W/x/AquaTransport.pkg/PackageInfo" > "$W/PackageInfo.new"
grep -q "preinstall file" "$W/PackageInfo.new" || { echo "PackageInfo preinstall patch failed"; exit 1; }
grep -q "installKBytes=\"$KB\"" "$W/PackageInfo.new" || { echo "PackageInfo installKBytes patch failed"; exit 1; }
cp "$W/PackageInfo.new" "$W/x/AquaTransport.pkg/PackageInfo"

# Re-archive the distribution, then put it where the repo ships it from -- beside the old
# one first, renamed into place, so no state ever sees a half-written pkg. The staging name
# carries the pid: a fixed name is shared by concurrent rebuilds, and one run's rename can
# then hand the other's still-writing cp the live pkg as its destination.
(cd "$W/x" && xar -cf "$W/AquaTransport-new.pkg" Distribution AquaTransport.pkg Modern_Root_Certificates.pkg Resources)
NEW="$OLDPKG.new.$$"
cp "$W/AquaTransport-new.pkg" "$NEW"
mv -f "$NEW" "$OLDPKG"
NEW=                                   # installed: nothing left for the trap to clean
echo "rebuilt and installed: $OLDPKG ($(stat -f%z "$OLDPKG") bytes)"
