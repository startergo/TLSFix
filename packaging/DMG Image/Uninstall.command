#!/bin/bash

clear
printf "You are about to remove AquaTransport from your computer. Your computer will restart automatically once the process is complete. Continue? (yes/no) "
read -r confirmation
if [ "$confirmation" != "y" ] && [ "$confirmation" != "yes" ]
then
	echo "Exiting. No changes have been made."
	exit 1
fi

echo "Please type in your password and press return. No characters will appear as you type."
sudo true || exit 1

SECURITY_BIN="/System/Library/Frameworks/Security.framework/Versions/A/Security"
sudo mv -f "$SECURITY_BIN.original" "$SECURITY_BIN"

# Keep the admin's rule files: remove what the package owns, then the directories only if
# they are empty. Reinstalling preserves them too -- the package's preinstall lifts the
# config directory out before its payload extracts, and its postinstall lays it back over
# the fresh defaults.
sudo rm -f /usr/share/aquatransport/aquatransport.dylib \
           /usr/share/aquatransport/aquatransport_engine.dylib \
           /usr/share/aquatransport/insert_dylib \
           /usr/share/aquatransport/aquatransport.sh \
           /usr/share/aquatransport/uninstall.sh
sudo rmdir /usr/share/aquatransport/config 2>/dev/null || true
sudo rmdir /usr/share/aquatransport 2>/dev/null || true
if [ -d /usr/share/aquatransport/config ]; then
	echo "Rule files kept at /usr/share/aquatransport/config; delete that directory to discard them."
fi

sudo update_dyld_shared_cache

sudo pkgutil --forget Wowfunhappy.AquaTransport
sudo shutdown -r now