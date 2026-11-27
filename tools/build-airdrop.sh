#!/bin/bash
# Optional Mavericks-only payload; the universal engine never links these frameworks.
set -euo pipefail
export LC_ALL=C
DIR="$(cd "$(dirname "$0")/.." && pwd)"
BUILD="$DIR/build/airdrop"
ST="$DIR/build/stage/usr/share/aquatransport"
BOOT_ST="$DIR/build/stage/Library/LaunchDaemons"
mkdir -p "$BUILD" "$ST" "$BOOT_ST"
rm -rf "$ST/airdrop"
rm -f "$ST/org.aquatransport.bootstrap.plist"
find "$DIR/build/stage" -name .DS_Store -delete
mkdir -p "$ST/airdrop"
ARCHIVE="$DIR/deps/libev-4.33.tar.gz"
[ "$(shasum -a 256 "$ARCHIVE" | awk '{print $1}')" = 507eb7b8d1015fbec5b935f34ebed15bf346bed04a11ab82b8eee848c4205aea ]
if [ ! -f "$BUILD/libev-4.33/.libs/libev.a" ]; then
  tar xzf "$ARCHIVE" -C "$BUILD"
  (cd "$BUILD/libev-4.33"; CFLAGS='-arch x86_64 -mmacosx-version-min=10.9 -O2' ./configure --disable-shared --enable-static > configure.log; make -j4 > build.log)
fi
make -C "$DIR/deps/owl" BUILD="$BUILD/owl" \
  CFLAGS='-arch x86_64 -mmacosx-version-min=10.9 -Wall -Wextra -O2 -MMD -MP' \
  LDFLAGS='-arch x86_64 -mmacosx-version-min=10.9' \
  INCLUDES="-I$DIR/deps/owl/src -I$DIR/deps/owl/radiotap -I$DIR/deps/owl/daemon -I$BUILD/libev-4.33" \
  LIBS="-lpcap $BUILD/libev-4.33/.libs/libev.a -framework Foundation -framework CoreWLAN -framework SystemConfiguration"
SOURCES="$DIR/src/mac/airdrop"
rm -rf "$ST/airdrop/AirDropUI.bundle"
ditto "$SOURCES/AirDropUI.bundle" "$ST/airdrop/AirDropUI.bundle"
printf '_AQAirDropInstalled\n' > "$BUILD/exports.txt"
printf '_AQAirDropModernActive\n' >> "$BUILD/exports.txt"
printf '_AQAirDropNativePeer\n' >> "$BUILD/exports.txt"
# ARC is a compile-time flag here only. On a link line it makes the compiler driver add
# libarclite, and current Xcodes ship none of its macOS variant for targets this old ("SDK
# does not contain 'libarclite'"). Nothing in this payload needs it: every ARC entry point
# these images import is exported by 10.9's own libobjc. So the sources carry the flag and
# the links are driven without it.
CFLAGS=(-arch x86_64 -mmacosx-version-min=10.9 -O2 -fobjc-arc -fblocks -fvisibility=hidden -Wall -Wextra)
LFLAGS=(-arch x86_64 -mmacosx-version-min=10.9 -fblocks -fvisibility=hidden)
objc() { # objc <source>: compile one ARC source to build/airdrop/<basename>.o
  clang "${CFLAGS[@]}" -c "$1" -o "$BUILD/$(basename "${1%.*}").o"
}
objc "$SOURCES/AQAirDrop.m"
objc "$SOURCES/AQUI.m"
clang -arch x86_64 -mmacosx-version-min=10.9 -O2 -fblocks -fvisibility=hidden -Wall -Wextra \
  -c "$DIR/deps/fishhook/fishhook.c" -o "$BUILD/fishhook.o"
clang "${LFLAGS[@]}" -dynamiclib "$BUILD/AQAirDrop.o" "$BUILD/AQUI.o" "$BUILD/fishhook.o" \
  -framework Foundation -framework CFNetwork -framework AppKit -framework IOBluetooth -framework CoreWLAN -Wl,-exported_symbols_list,"$BUILD/exports.txt" \
  -install_name /usr/share/aquatransport/aquatransport_airdrop.dylib -o "$ST/aquatransport_airdrop.dylib"
objc "$SOURCES/AQHelper.m"
objc "$SOURCES/AQWiFiLease.m"
clang "${LFLAGS[@]}" "$BUILD/AQHelper.o" "$BUILD/AQWiFiLease.o" \
  -framework Foundation -framework CoreWLAN -framework IOBluetooth -framework SystemConfiguration -framework IOKit -o "$ST/airdrop/org.aquatransport.airdrop"
bootstrap_slices=()
for arch in x86_64 i386; do
  bootstrap="$BUILD/aquatransport-bootstrap-$arch"
  BFLAGS=(-arch "$arch" -mmacosx-version-min=10.6 -O2 -fblocks -Wall -Wextra)
  # Compiled against the default SDK's headers, which is where xpc/xpc.h exists (from 10.7's),
  # and linked against the SDK build-macos.sh settled on when it passes one down in
  # AQUATRANSPORT_SDK: the current default SDK carries no i386 stubs at all. The engine is
  # built with the same split.
  clang "${BFLAGS[@]}" -c "$DIR/src/mac/aquatransport_bootstrap.m" -o "$BUILD/aquatransport_bootstrap-$arch.o"
  clang "${BFLAGS[@]}" -c "$DIR/src/mac/aquatransport_config.c" -o "$BUILD/aquatransport_config-bootstrap-$arch.o"
  ISYS=()
  [ -n "${AQUATRANSPORT_SDK:-}" ] && ISYS=(-isysroot "$AQUATRANSPORT_SDK")
  clang "${BFLAGS[@]}" ${ISYS[@]+"${ISYS[@]}"} "$BUILD/aquatransport_bootstrap-$arch.o" "$BUILD/aquatransport_config-bootstrap-$arch.o" \
    -framework Foundation -o "$bootstrap"
  bootstrap_slices+=("$bootstrap")
done
lipo -create "${bootstrap_slices[@]}" -output "$ST/aquatransport-bootstrap"
objc "$SOURCES/ad_ble_wake.m"
clang "${LFLAGS[@]}" "$BUILD/ad_ble_wake.o" -framework Foundation -framework IOBluetooth -o "$ST/airdrop/ad_ble_wake"
cp "$BUILD/owl/owl" "$ST/airdrop/owl"
cp "$SOURCES/org.aquatransport.airdrop.plist" "$ST/airdrop/"
cp "$DIR/src/mac/org.aquatransport.bootstrap.plist" "$BOOT_ST/"
for image in "$ST/aquatransport_airdrop.dylib" "$ST/airdrop/org.aquatransport.airdrop" "$ST/airdrop/ad_ble_wake" "$ST/airdrop/owl"; do
  lipo -info "$image" | grep -q "is architecture: x86_64$"
  if otool -L "$image" | tail -n +2 | grep -E '/Users/|/usr/local/|SIMBL|ModernAirDrop'; then
    echo "AirDrop payload has an external development dependency: $image"; exit 1
  fi
done
lipo -info "$ST/aquatransport-bootstrap" | grep -q 'Architectures in the fat file: .* are: x86_64 i386[[:space:]]*$'
find "$DIR/build/stage" -name .DS_Store -delete
echo 'Built standalone Mavericks AirDrop payload.'
