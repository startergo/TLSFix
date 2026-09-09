#!/bin/bash
# Offline. Synthetic credentials only; a catch-all NSURLProtocol prevents socket I/O.
set -eu
DIR="$(cd "$(dirname "$0")/.." && pwd)"
cd "$DIR"
GSA_CC="${AQUATRANSPORT_GSA_CC:-$DIR/build/gsa-toolchain/bin/clang}"
[ -x "$GSA_CC" ] || GSA_CC="${AQUATRANSPORT_GSA_CC:-clang}"
# The probes build fat, and the i386 slice cannot link against the default SDK; the same
# 10.7-era SDK the GSA module itself uses (see build-macos.sh) supplies it.
GSA_SDKROOT="${AQUATRANSPORT_GSA_SDK:-}"
[ -z "$GSA_SDKROOT" ] && for cand in "$HOME/leopard-webkit-build/sdk/MacOSX-SDKs/MacOSX10.9.sdk" \
                                          "$HOME/Downloads/MacOSX10.9.sdk"; do
  [ -d "$cand/usr/lib" ] && GSA_SDKROOT="$cand" && break
done
[ -n "$GSA_SDKROOT" ] || { echo 'no 10.7-era SDK found: set AQUATRANSPORT_GSA_SDK'; exit 1; }

# Every probe is an executable, and linking one needs crt1.10.6.o, which 10.7-era SDKs no
# longer carry (it moved into the toolchain, and this machine's /usr/lib does not have it
# either -- modern clang errors with "library 'crt1.10.6.o' not found", clang 3.4.2 the
# same). The 10.6 SDK still ships the crt objects, so a one-time overlay gives every build
# a sysroot with both: everything of the 10.9 SDK by symlink, plus the crt files copied in.
OLD_SDK="${AQUATRANSPORT_SDK:-${SDKROOT:-$HOME/Downloads/MacOSX10.6.sdk}}"
GSA_LINKROOT="$DIR/build/gsa-sysroot"
if [ ! -f "$GSA_LINKROOT/usr/lib/crt1.10.6.o" ]; then
  [ -f "$OLD_SDK/usr/lib/crt1.10.6.o" ] || { echo "no crt1.10.6.o under $OLD_SDK: set AQUATRANSPORT_SDK"; exit 1; }
  rm -rf "$GSA_LINKROOT"; mkdir -p "$GSA_LINKROOT/usr/lib"
  for f in "$GSA_SDKROOT"/*; do ln -s "$f" "$GSA_LINKROOT/$(basename "$f")"; done
  for f in "$GSA_SDKROOT"/usr/*; do [ "$(basename "$f")" = lib ] || ln -s "$f" "$GSA_LINKROOT/usr/$(basename "$f")"; done
  for f in "$GSA_SDKROOT"/usr/lib/*; do ln -s "$f" "$GSA_LINKROOT/usr/lib/$(basename "$f")"; done
  for f in "$OLD_SDK"/usr/lib/crt*.o "$OLD_SDK"/usr/lib/bundle1.o "$OLD_SDK"/usr/lib/dylib1*.o; do
    [ -f "$f" ] && cp "$f" "$GSA_LINKROOT/usr/lib/"
  done
fi
GSA_SDK="-isysroot $GSA_LINKROOT"
LIB="$DIR/build/stage/usr/share/aquatransport/aquatransport.dylib"
[ -f "$LIB" ] || { echo 'Run ./build-macos.sh first'; exit 1; }
CONF=$(mktemp -d /tmp/aquatransport-gsa-test.XXXXXX)
trap 'rm -rf "$CONF"' EXIT
: > "$CONF/flags.txt"
printf 'http://127.0.0.1:9/anisette\n' > "$CONF/gsa-anisette-url.txt"
# These would break the exchange if authentication were subject to generic rules.
printf '*\nhttps://gsa.apple.com/\nhttps://example.invalid/\n' > "$CONF/redirects.txt"
printf '*\nhttps://setup.icloud.com/\nAuthorization: must-not-replace-token\n\n*\nhttps://profile.ess.apple.com/\nAuthorization: must-not-replace-token\n' > "$CONF/headers.txt"
python tools/gsa-vectors.py > build/gsa-vectors.h
clang -arch x86_64 -arch i386 -mmacosx-version-min=10.7 $GSA_SDK -Wno-deprecated-declarations \
    -Ibuild -Ibuild/openssl/include tools/gsacrypto.c build/openssl/lib/libcrypto.a -o build/gsacrypto
clang -arch x86_64 -arch i386 -mmacosx-version-min=10.7 $GSA_SDK -Wno-deprecated-declarations \
    -Ibuild/openssl/include tools/gsaprobe.m build/openssl/lib/libcrypto.a -lz -framework Foundation -o build/gsaprobe
clang -arch x86_64 -arch i386 -mmacosx-version-min=10.7 $GSA_SDK -Wno-deprecated-declarations \
    -Ibuild/openssl/include tools/gsa-diagnose.m src/mac/aquatransport_gsa_crypto.c \
    src/mac/aquatransport_config.c build/openssl/lib/libcrypto.a \
    -framework Foundation -framework IOKit -lz -o build/gsa-diagnose
clang -arch x86_64 -arch i386 -mmacosx-version-min=10.7 $GSA_SDK tools/davprobe.m -framework Foundation -o build/davprobe
clang -arch x86_64 -mmacosx-version-min=10.7 $GSA_SDK tools/mailprobe.m -framework Foundation -framework Security -o build/mailprobe
# The Mail adapter tests need Mavericks' own MailCore framework (see docs/ICLOUD.md);
# a host without it -- any non-10.9 build machine -- sets AQUATRANSPORT_SKIP_MAIL=1 to
# run the rest of the suite. The first probe run below loads the engine, which is what
# the rewrite-side tests exercise even without the Mail part.
if [ "${AQUATRANSPORT_SKIP_MAIL:-0}" != 1 ]; then
  for mode in success missing; do
    # Mavericks MailCore is x86_64 and cannot load into a GC process.
    AQUATRANSPORT_DIR="$CONF" DYLD_INSERT_LIBRARIES="$LIB" build/mailprobe "$mode"
  done
fi
"$GSA_CC" -arch x86_64 -mmacosx-version-min=10.7 $GSA_SDK -fobjc-gc tools/davprobe.m -framework Foundation -o build/davprobe-gc
for a in x86_64 i386; do
    for mode in success auth missing native-calendar native-contacts; do
        AQUATRANSPORT_DIR="$CONF" DYLD_INSERT_LIBRARIES="$LIB" arch -"$a" build/davprobe "$mode"
    done
done
for mode in success auth missing native-calendar native-contacts; do
    AQUATRANSPORT_DIR="$CONF" DYLD_INSERT_LIBRARIES="$LIB" build/davprobe-gc "$mode"
done
for a in x86_64 i386; do
    arch -"$a" build/gsacrypto
    arch -"$a" build/gsa-diagnose --request-vector
    for mode in success bad-proof short-proof malformed redirect missing-anisette 2fa aos aos-basic aos-mixed settings settings-missing settings-redirect aos-settings ids-success ids-gzip ids-2fa ids-rejected ids-bad-gzip ids-gzip-limit ids-gzip-trailing ids-bad-proof ids-missing-anisette ids-redirect ids-bad-delegate ids-missing-token ids-missing-profile ids-bad-status-type; do
        AQUATRANSPORT_DIR="$CONF" DYLD_INSERT_LIBRARIES="$LIB" arch -"$a" build/gsaprobe "$mode"
    done
done
"$GSA_CC" -arch x86_64 -mmacosx-version-min=10.7 $GSA_SDK -fobjc-gc -Wno-deprecated-declarations \
    -Ibuild/openssl/include tools/gsaprobe.m build/openssl/lib/libcrypto.a -lz -framework Foundation -o build/gsaprobe-gc
for mode in success 2fa aos aos-basic aos-mixed settings aos-settings ids-gzip ids-2fa ids-rejected ids-bad-gzip; do
    AQUATRANSPORT_DIR="$CONF" DYLD_INSERT_LIBRARIES="$LIB" build/gsaprobe-gc "$mode"
done
printf 'disable-icloud-gsa\n' > "$CONF/flags.txt"
[ "${AQUATRANSPORT_SKIP_MAIL:-0}" = 1 ] || \
    AQUATRANSPORT_DIR="$CONF" DYLD_INSERT_LIBRARIES="$LIB" build/mailprobe disabled
# Remove intentionally conflicting rules to test the ordinary native request.
: > "$CONF/redirects.txt"
: > "$CONF/headers.txt"
for a in x86_64 i386; do
    AQUATRANSPORT_DIR="$CONF" DYLD_INSERT_LIBRARIES="$LIB" arch -"$a" build/gsaprobe disabled
    AQUATRANSPORT_DIR="$CONF" DYLD_INSERT_LIBRARIES="$LIB" arch -"$a" build/gsaprobe ids-disabled
done
AQUATRANSPORT_DIR="$CONF" DYLD_INSERT_LIBRARIES="$LIB" build/gsaprobe-gc disabled
AQUATRANSPORT_DIR="$CONF" DYLD_INSERT_LIBRARIES="$LIB" build/gsaprobe-gc ids-disabled
for a in x86_64 i386; do
    AQUATRANSPORT_DIR="$CONF" DYLD_INSERT_LIBRARIES="$LIB" arch -"$a" build/davprobe disabled
done
AQUATRANSPORT_DIR="$CONF" DYLD_INSERT_LIBRARIES="$LIB" build/davprobe-gc disabled
