#!/bin/bash
set -e

DEST="/usr/share/aquatransport"
SECURITY_BIN="/System/Library/Frameworks/Security.framework/Versions/A/Security"

# Lay the admin's rule files back over the defaults the payload just extracted; preinstall.sh
# lifted them out beforehand. Files the admin never had keep the fresh default. cp -p keeps
# their ownership and permissions, which is the editable-in-place arrangement the package
# ships them with. Runs before the already-installed early exit below, so a reinstall over an
# existing install restores too -- that is the case where it matters most.
CONF="$DEST/config"
KEEP="$DEST/.config-keep"
if [ -d "$KEEP" ]; then
	mkdir -p "$CONF"
	if cp -p "$KEEP"/* "$CONF"/; then
		rm -rf "$KEEP"
	else
		# The backup is the only remaining copy of the admin's files, so it stays: nothing is
		# lost by failing here, and preinstall.sh merges a stranded backup back in on the next
		# install, which is exactly the retry. A restore that failed must not be reported as
		# success -- the system would be running on default rules the admin never chose, and
		# nobody would know until traffic behaved wrong.
		echo "could not restore rule files from $KEEP -- install failed" >&2
		exit 1
	fi
fi

if [[ -e "$SECURITY_BIN.original" ]]
then
	# Already installed
	exit 0
fi

# Write the load command into a copy of Security.
./insert_dylib --weak --all-yes --strip-codesig "$DEST/aquatransport.dylib" "$SECURITY_BIN" "$SECURITY_BIN.new"
chown root:wheel "$SECURITY_BIN.new"
chmod 0755 "$SECURITY_BIN.new"

# Save the original (hard link), then swap atomically.
ln "$SECURITY_BIN" "$SECURITY_BIN.original"
mv -f "$SECURITY_BIN.new" "$SECURITY_BIN"

update_dyld_shared_cache