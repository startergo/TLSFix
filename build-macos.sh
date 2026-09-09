#!/bin/bash
# Builds AquaTransport for Mac OS X 10.6 - 10.9.
#
# OpenSSL is vendored. The GSA module also needs a GC-capable compiler;
# see docs/ICLOUD.md. Once the toolchain is present, builds need no network access.
#
# Output: build/stage/usr/share/aquatransport/aquatransport.dylib (fat i386 + x86_64)
#
# install-macos.sh adds a load command naming that dylib to Security.framework, so it is loaded
# into every process that loads Security. Two requirements the build verifies before finishing:
#   * both architectures present -- so it loads in i386 and x86_64 processes alike
#   * no symbols exported -- OpenSSL defines the whole SSL_*/EVP_* namespace, which must
#     not be visible to any process it is loaded into

set -e
DIR="$(cd "$(dirname "$0")" && pwd)"
OPENSSL_VERSION="${OPENSSL_VERSION:-3.5.7}"
MIN="${AQUATRANSPORT_MIN_OS:-10.6}"
ARCHS=(x86_64 i386)

BUILD="$DIR/build"
mkdir -p "$BUILD"
GSA_CC="${AQUATRANSPORT_GSA_CC:-$BUILD/gsa-toolchain/bin/clang}"
[ -x "$GSA_CC" ] || GSA_CC="${AQUATRANSPORT_GSA_CC:-clang}"
# Clang 3.4 still emits GC write barriers; newer Apple clang cannot. See docs/ICLOUD.md.
# The GSA module is optional: without its toolchain or SDK the build still produces the
# loader and engine, and install-macos.sh and make-pkg.sh stage whatever exists. A
# compiler named by AQUATRANSPORT_GSA_CC is held to strictly, though -- a setting that
# silently falls back to no module at all is worse than the error.
GSA_OK=1
if ! printf '@interface AQGC @end\n@implementation AQGC @end\n' | \
    "$GSA_CC" -x objective-c -fobjc-gc -c -o "$BUILD/gsa-gc-check.o" - 2>/dev/null; then
  if [ -n "${AQUATRANSPORT_GSA_CC:-}" ]; then
    echo "AQUATRANSPORT_GSA_CC is set but cannot compile Objective-C GC (see docs/ICLOUD.md)."
    exit 1
  fi
  echo "==> no GC-capable compiler; building without the GSA module (docs/ICLOUD.md)"
  GSA_OK=0
fi
rm -f "$BUILD/gsa-gc-check.o"
LS_SRC="$BUILD/src/openssl-$OPENSSL_VERSION"
LS_OUT="$BUILD/openssl"
TARBALL="$DIR/deps/openssl-$OPENSSL_VERSION.tar.gz"

# The i386 slice cannot link against the default SDK: its libSystem.tbd has no i386 members,
# and the link dies on plain libc ("symbol(s) not found for architecture i386" -- _time,
# _vfprintf, _vm_protect). A 10.6-era SDK supplies every slice the deployment target names,
# so the dylib links name one explicitly; compilation keeps the default SDK's headers, which
# sit above the deployment floor. AQUATRANSPORT_SDK overrides, then SDKROOT, then the usual
# place the SDK is kept on the machines that build this.
#
# The choice is validated, not trusted: SDKROOT is often set by Xcode build environments to
# the current SDK, which does not carry i386, and a nonexistent directory would otherwise
# surface later as an opaque clang error. An unusable setting falls back to the known-good
# location, and only when that is unusable too does the build stop. The probe requires both
# of the architectures the build links -- an i386-only SDK would pass an i386-only check and
# then fail the x86_64 link -- and it scrubs the environment because lipo itself honours
# SDKROOT: a stale exported value makes lipo error out looking for tooling inside it, which
# would fail the check on a perfectly good SDK. For the same reason SDKROOT is dropped once
# the choice is made: the build's later lipo/clang calls must not be steered by it either.
sdk_usable() {
  [ -d "$1" ] || return 1
  local archs
  archs="$(env -u SDKROOT -u DEVELOPER_DIR /usr/bin/lipo -info "$1/usr/lib/libSystem.dylib" 2>/dev/null)" || return 1
  grep -qw x86_64 <<<"$archs" && grep -qw i386 <<<"$archs"
}

SDK="${AQUATRANSPORT_SDK:-${SDKROOT:-}}"
[ -z "$SDK" ] && [ -d "$HOME/Downloads/MacOSX10.6.sdk" ] && SDK="$HOME/Downloads/MacOSX10.6.sdk"
if ! sdk_usable "$SDK"; then
  [ -n "$SDK" ] && echo "SDK libSystem lacks i386 or x86_64, not using it: $SDK" >&2
  SDK="$HOME/Downloads/MacOSX10.6.sdk"
fi
sdk_usable "$SDK" || { echo "no 10.6-era SDK with an i386+x86_64 libSystem found: set AQUATRANSPORT_SDK to one"; exit 1; }
unset SDKROOT DEVELOPER_DIR

# The GSA module is Foundation code for 10.7+ -- NSURLConnectionDelegate and friends
# postdate the 10.6 SDK -- so it compiles and links against a newer one: 10.9, the era
# its account flows were validated on. Same validation rules as the engine's SDK, and
# the same optional/strict split as the GC compiler above.
if [ "$GSA_OK" = 1 ]; then
  GSA_SDK="${AQUATRANSPORT_GSA_SDK:-}"
  [ -z "$GSA_SDK" ] && for cand in "$HOME/leopard-webkit-build/sdk/MacOSX-SDKs/MacOSX10.9.sdk" \
                                     "$HOME/Downloads/MacOSX10.9.sdk"; do
    sdk_usable "$cand" && GSA_SDK="$cand" && break
  done
  if ! sdk_usable "$GSA_SDK"; then
    if [ -n "${AQUATRANSPORT_GSA_SDK:-}" ]; then
      echo "AQUATRANSPORT_GSA_SDK is set but has no i386+x86_64 libSystem."
      exit 1
    fi
    echo "==> no 10.7-era SDK; building without the GSA module (docs/ICLOUD.md)"
    GSA_OK=0
  fi
fi

[ -f "$TARBALL" ] || { echo "missing vendored dependency: $TARBALL"; exit 1; }

# ---- 1. OpenSSL (cached; delete build/openssl to force a rebuild) ----------
#
# 3.5 is the current LTS, supported to 2030-04. The engine needs a TLS library that still
# negotiates TLS 1.0, so that a legacy server stock Secure Transport can reach stays
# reachable through the engine; OpenSSL does at security level 0.
if [ ! -f "$LS_OUT/lib/libssl.a" ] || [ ! -f "$LS_OUT/lib/libcrypto.a" ]; then
  echo "==> building OpenSSL $OPENSSL_VERSION (min $MIN)"
  mkdir -p "$BUILD/src"
  [ -d "$LS_SRC" ] || tar xzf "$TARBALL" -C "$BUILD/src"
  for a in "${ARCHS[@]}"; do
    if [ ! -f "$BUILD/ossl-$a/libssl.a" ]; then
      echo "    configure $a"
      mkdir -p "$BUILD/ossl-$a"
      case "$a" in
        x86_64) target=darwin64-x86_64-cc; extra="" ;;
        # i386 has no inline 8-byte atomic, and this era's clang cannot emit the libatomic
        # call either ("cannot compile this atomic library call yet" in threads_pthread.c).
        # BROKEN_CLANG_ATOMICS is OpenSSL's own escape for exactly this; it selects the
        # mutex-backed paths instead.
        i386)   target=darwin-i386-cc;    extra="-DBROKEN_CLANG_ATOMICS" ;;
      esac
      # --with-rand-seed=devrandom keeps the seeding off getentropy(), which is 10.12+ and
      # would bind lazily then kill the process on first use (see the import check below).
      # AR/RANLIB are pinned to Apple's tools: a homebrew binutils install shadows /usr/bin/ar
      # in PATH, and GNU ar writes archives with even-byte member padding that the Apple
      # linker then rejects for 64-bit members ("64-bit mach-o member not 8-byte aligned").
      ( cd "$BUILD/ossl-$a" && perl "$LS_SRC/Configure" "$target" \
          no-shared no-tests no-docs no-apps no-legacy no-engine \
          AR=/usr/bin/ar RANLIB=/usr/bin/ranlib \
          --with-rand-seed=devrandom \
          -mmacosx-version-min="$MIN" -O2 -fPIC $extra > configure.log 2>&1 )
      echo "    compile $a"
      ( cd "$BUILD/ossl-$a" && make -j4 AR=/usr/bin/ar RANLIB=/usr/bin/ranlib build_libs > build.log 2>&1 )
    fi
  done
  mkdir -p "$LS_OUT/lib" "$LS_OUT/include"
  crypto=(); ssl=()
  for a in "${ARCHS[@]}"; do crypto+=("$BUILD/ossl-$a/libcrypto.a"); ssl+=("$BUILD/ossl-$a/libssl.a"); done
  # lipo, not libtool: libtool -static merges the inputs' member lists and drops the
  # second appearance of every same-named member (both architectures use identical .o
  # names), leaving slices that are missing half their objects. lipo keeps each thin
  # archive intact as a slice.
  lipo -create "${crypto[@]}" -output "$LS_OUT/lib/libcrypto.a"
  lipo -create "${ssl[@]}"    -output "$LS_OUT/lib/libssl.a"
  # Headers: the shipped tree plus the per-arch generated ones (opensslconf.h and friends).
  # They agree across our two targets, so either arch's generated set will do.
  cp -R "$LS_SRC/include/"* "$LS_OUT/include/"
  cp -R "$BUILD/ossl-${ARCHS[0]}/include/"* "$LS_OUT/include/"
  echo "    OpenSSL ready"
else
  echo "==> OpenSSL $OPENSSL_VERSION already built (cached)"
fi

# ---- 2. the dylib ----------------------------------------------------------
echo "==> building aquatransport.dylib (min $MIN)"
SRCS=("$DIR/src/aquatransport_engine.c" "$DIR/src/mac/aquatransport_hooks_mac.c" "$DIR/src/mac/aquatransport_config.c"
      "$DIR/src/mac/aquatransport_rewrite.c" "$DIR/src/mac/aquatransport_trust_mac.c" "$DIR/deps/fishhook/fishhook.c")
OBJDIR="$BUILD/obj"; rm -rf "$OBJDIR"; mkdir -p "$OBJDIR"
: > "$BUILD/nothing.exp"

slices=()
loader_slices=()
gsa_slices=()
for a in "${ARCHS[@]}"; do
  objs=()
  for src in "${SRCS[@]}"; do
    o="$OBJDIR/$(basename "${src%.c}")-$a.o"
    clang -arch "$a" -mmacosx-version-min="$MIN" -O2 -fPIC -fvisibility=hidden \
      -Wall -Wno-deprecated-declarations -I"$LS_OUT/include" \
      -c "$src" -o "$o"
    objs+=("$o")
  done
  out="$OBJDIR/aquatransport_engine-$a.dylib"
  # Plain -framework, not -lazy_framework: against the 10.6 SDK's stubs the linker actually
  # engages the lazy-load machinery, which wants __dyld_lazy_load -- a dyld feature the 10.6
  # deployment target predates -- and the link dies. Function bindings are lazily resolved
  # by default anyway, so nothing is lost. Nothing is lost off the 10.6 floor either: the
  # current linker ignores -lazy_framework at EVERY deployment target from 10.6 through
  # 15.0 (measured; it warns "deployment target version is too low" even for 15.0) -- the
  # lazy-dylib feature only ever lived in a narrow 10.11-era toolchain/OS window, and dyld
  # has since dropped it. This also matches the previously shipped engine exactly: the
  # linker ignored -lazy_framework for it too and emitted plain load commands -- verified
  # by dlopening both engines in a CoreFoundation-free process on 10.6 and diffing what
  # dyld maps: identical sets. Making the engine resolve Sec*/CF* through dlsym instead
  # would avoid mapping those frameworks until first use, but the loader only dlopens the
  # engine at a process's first Secure Transport call, by which point CoreFoundation is
  # present by construction, so the rework buys nothing observed.
  clang -arch "$a" -mmacosx-version-min="$MIN" -isysroot "$SDK" -dynamiclib -o "$out" \
    -install_name /usr/share/aquatransport/aquatransport_engine.dylib \
    "${objs[@]}" "$LS_OUT/lib/libssl.a" "$LS_OUT/lib/libcrypto.a" \
    -Wl,-framework,Security -Wl,-framework,CoreFoundation \
    -Wl,-exported_symbols_list,"$BUILD/nothing.exp"
  slices+=("$out")

  # The loader is what Security.framework's load command names, so it is mapped into every
  # process on the system. It links nothing but libc: see the header of the source for why
  # the engine must not be reachable through a load command.
  lout="$OBJDIR/aquatransport-$a.dylib"
  clang -arch "$a" -mmacosx-version-min="$MIN" -isysroot "$SDK" -O2 -fPIC -fvisibility=hidden \
    -Wall -Wno-deprecated-declarations -dynamiclib -o "$lout" \
    -install_name /usr/share/aquatransport/aquatransport.dylib \
    "$DIR/src/mac/aquatransport_loader.c" \
    -Wl,-exported_symbols_list,"$BUILD/nothing.exp"
  loader_slices+=("$lout")

  # iCloud begins at 10.7. This separate image supports GC for System Preferences;
  # the engine stays pure C and the loader never maps it during process startup.
  if [ "$GSA_OK" = 1 ]; then
    gobj="$OBJDIR/aquatransport_gsa-$a.o"
    # -isysroot names the 10.7-era SDK for both compilers: the GC toolchain is a stock LLVM
    # drop with no macOS headers of its own, and the modern clang linking the dylib needs the
    # SDK's i386 Foundation, which the default SDK does not carry.
    "$GSA_CC" -arch "$a" -mmacosx-version-min=10.7 -isysroot "$GSA_SDK" -O2 -fPIC -fvisibility=hidden \
      -fobjc-gc -Wall -Wno-deprecated-declarations -I"$LS_OUT/include" \
      -c "$DIR/src/mac/aquatransport_gsa.m" -o "$gobj"
    cobj="$OBJDIR/aquatransport_gsa_crypto-$a.o"
    clang -arch "$a" -mmacosx-version-min=10.7 -isysroot "$GSA_SDK" -O2 -fPIC -fvisibility=hidden \
      -Wall -Wno-deprecated-declarations -I"$LS_OUT/include" \
      -c "$DIR/src/mac/aquatransport_gsa_crypto.c" -o "$cobj"
    gout="$OBJDIR/aquatransport_gsa-$a.dylib"
    clang -arch "$a" -mmacosx-version-min=10.7 -isysroot "$GSA_SDK" -dynamiclib -o "$gout" \
      -install_name /usr/share/aquatransport/aquatransport_gsa.dylib \
      "$gobj" "$cobj" "$OBJDIR/aquatransport_config-$a.o" "$LS_OUT/lib/libcrypto.a" \
      -framework Foundation -framework IOKit -lz -Wl,-exported_symbols_list,"$BUILD/nothing.exp"
    gsa_slices+=("$gout")
  fi
  echo "    $a ok"
done

# The stage holds the build's output -- the loader and engine dylibs -- alongside the rule-file
# fixtures selftest.sh reads through AQUATRANSPORT_DIR. install-macos.sh copies the dylibs from
# here; the installer package is assembled separately under packaging/.
ST="$BUILD/stage/usr/share/aquatransport"

# Clear the regenerated files first, keeping only the rule files. Anything left at a path this
# build no longer writes would linger in the stage install-macos.sh copies from, so a binary
# from a retired layout could ship alongside the real one. Clearing everything the build
# regenerates -- rather than a list of names it knows about -- is what keeps that true through a
# rename: a name dropped from the list is exactly the file that would survive.
#
# The rule files are the exception: they are hand-maintained fixtures that selftest.sh reads
# through AQUATRANSPORT_DIR, and nothing regenerates them.
if [ -d "$BUILD/stage" ]; then
  find "$BUILD/stage" -type f ! -name '*.txt' -delete
fi

mkdir -p "$ST"

lipo -create "${slices[@]}" -output "$ST/aquatransport_engine.dylib"
lipo -create "${loader_slices[@]}" -output "$ST/aquatransport.dylib"
if [ ${#gsa_slices[@]} -gt 0 ]; then
  lipo -create "${gsa_slices[@]}" -output "$ST/aquatransport_gsa.dylib"

  # Restore the Objective-C GC bit the linker drops. The compile emits __objc_imageinfo
  # flags 0x2 (OBJC_IMAGE_SUPPORTS_GC -- loadable by GC and non-GC processes alike), but
  # modern ld64 writes the section back as zero, and ld-classic rewrites it to 0x40. A GC
  # process such as Mavericks' System Preferences refuses a library without the bit, so it
  # is written straight into the x86_64 slice at the section's file offset: the fat header
  # gives the slice's base, the section header the offset within it, and byte 4 of the
  # 8-byte section is the low flag byte. The i386 slice is left alone -- 32-bit processes
  # use retain/release, and the verifier below only demands the bit of x86_64.
  GSADY="$ST/aquatransport_gsa.dylib"
  gsa_base=$(lipo -detailed_info "$GSADY" | awk '/^architecture x86_64$/{f=1;next} f && /offset /{print $2; exit}')
  gsa_off=$(otool -arch x86_64 -l "$GSADY" | awk '/sectname __objc_imageinfo/{f=1} f && /^ *offset /{print $2; exit}')
  [ -n "$gsa_base" ] && [ -n "$gsa_off" ] || { echo "FATAL: cannot locate __objc_imageinfo in $GSADY"; exit 1; }
  printf '\x02' | dd of="$GSADY" bs=1 seek=$((gsa_base + gsa_off + 4)) conv=notrunc status=none
else
  echo "==> GSA module skipped: no GC toolchain or no 10.7-era SDK (docs/ICLOUD.md)"
fi

# The URL rewriter is pure C compiled into the dylib above (src/mac/aquatransport_rewrite.c),
# and has no Objective-C dependency. The GSA image is loaded at request time.

# ---- 3. verify the invariants ----------------------------------------------
# Per slice: the architecture is present; nothing is exported (OpenSSL's whole SSL_*/EVP_*
# namespace must not leak into host processes); and
# nothing is imported that postdates the deployment target. Post-10.6 imports bind lazily, so
# the dylib would load and then crash the process on first use -- checked per slice because
# i386 legitimately imports $UNIX2003 variants x86_64 never has.
#   Added in 10.7:  strndup strnlen getline getdelim memmem arc4random_buf
#   Added in 10.12: getentropy clock_gettime clock_gettime_nsec_np
echo "==> verifying"
for img in aquatransport.dylib aquatransport_engine.dylib aquatransport_gsa.dylib; do
# A build without the GC toolchain stages no GSA image at all; verify what exists.
[ -f "$ST/$img" ] || continue
have=$(lipo -info "$ST/$img" | sed 's/.*://')
echo "    $img architectures:$have"
POST106='^_(strndup|strnlen|getline|getdelim|memmem|getentropy|clock_gettime|clock_gettime_nsec_np|arc4random_buf|dispatch_activate|os_unfair_lock_lock)$'
# The engine and loader floor at $MIN; the GSA module floors at 10.7 -- its loader gates
# on Darwin 11+, so what Lion added (strndup, strnlen, getline, getdelim, memmem,
# arc4random_buf) is legal there, and only the newer set is banned.
floor="$MIN"; banned="$POST106"
[ "$img" = aquatransport_gsa.dylib ] && {
  floor=10.7
  banned='^_(getentropy|clock_gettime|clock_gettime_nsec_np|dispatch_activate|os_unfair_lock_lock)$'
}
for a in "${ARCHS[@]}"; do
  echo "$have" | grep -qw "$a" || { echo "FATAL: $img missing $a slice; $a processes would go unpatched"; exit 1; }
  n=$(nm -arch "$a" -g "$ST/$img" 2>/dev/null | grep -cE " (T|D|B|S) _" || true)
  [ "$n" = "0" ] || { echo "FATAL: $img $a exports $n symbols (OpenSSL namespace would leak)"; exit 1; }
  bad=$(nm -arch "$a" -u "$ST/$img" 2>/dev/null | tr -d ' ' | grep -E "$banned" || true)
  [ -z "$bad" ] || { echo "FATAL: $img $a imports symbols absent on $floor (would crash on first use):"
                     echo "$bad" | sed 's/^/      /'; exit 1; }
done
done
echo "    per slice: present, 0 exports, no post-floor imports"
if [ -f "$ST/aquatransport_gsa.dylib" ]; then
  # OS X's Objective-C collector is x86_64 only; i386 uses retain/release.
  otool -arch x86_64 -ov "$ST/aquatransport_gsa.dylib" | grep -q 'OBJC_IMAGE_SUPPORTS_GC' ||
    { echo "FATAL: GSA x86_64 does not support Objective-C garbage collection"; exit 1; }
  echo "    GSA: GC-compatible, deployment target 10.7"
fi

ls -lh "$ST/aquatransport.dylib" "$ST/aquatransport_engine.dylib" | awk '{print "    "$9": "$5}'
# The loader must stay small: its whole purpose is to be harmless to map.
lsz=$(stat -f%z "$ST/aquatransport.dylib")
[ "$lsz" -lt 200000 ] || { echo "FATAL: loader is $lsz bytes; it is meant to be a stub"; exit 1; }
if [ -f "$ST/aquatransport_gsa.dylib" ]; then
  echo "built: loader + TLS engine + iCloud GSA module in $ST"
else
  echo "built: loader + TLS engine in $ST (no GSA module this build)"
fi
