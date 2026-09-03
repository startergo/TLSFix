#!/bin/bash
# Runs before the payload extracts, which is the only point at which the admin's rule files
# can still be reached: the payload carries config/headers.txt, redirects.txt and disabled.txt
# as editable defaults, and payload extraction overwrites whatever is on disk. Lift the whole
# config directory out here and postinstall lays it back down over the fresh defaults.
set -e

CONF="/usr/share/aquatransport/config"
KEEP="/usr/share/aquatransport/.config-keep"

# A stranded backup means an earlier install's postinstall never ran its restore; those files
# are the admin's real ones, while config/ is most likely the defaults that install laid down.
# Prefer the backup, then take the merged directory out again as this install's backup.
if [ -d "$KEEP" ]; then
	rm -rf "$CONF"
	mv "$KEEP" "$CONF"
fi

[ -d "$CONF" ] && mv "$CONF" "$KEEP"
exit 0
