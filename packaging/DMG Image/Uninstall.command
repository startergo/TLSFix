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

# The receipt BOM is the authority on what the package installed, so the removal
# list can never go stale the way a hand-written one did (it once missed the GSA
# module). Two things the BOM cannot describe remain explicit below: the
# Security.framework patch, which the postinstall performed rather than shipped,
# and the config directory, whose contents belong to the admin.
PKGID="Wowfunhappy.AquaTransport"
BOM="/var/db/receipts/$PKGID.bom"
if [ ! -f "$BOM" ]
then
	echo "No AquaTransport receipt found. Nothing to uninstall."
	exit 1
fi

SECURITY_BIN="/System/Library/Frameworks/Security.framework/Versions/A/Security"
if [ -e "$SECURITY_BIN.original" ]
then
	sudo mv -f "$SECURITY_BIN.original" "$SECURITY_BIN"
else
	echo "Note: no Security.framework backup was present; leaving the framework as it is."
fi

# Remove every payload file the BOM records, except the admin's rule files.
# -f filters to file entries: the unfiltered listing includes directories, and
# feeding those to rm would ask it to remove /usr and the like.
sudo lsbom -f -p f "$BOM" | while read -r path
do
	case "$path" in
		./usr/share/aquatransport/config/*) continue ;;
	esac
	sudo rm -f "/${path#./}"
done
# The rule files are the admin's, not the package's: a reinstall seeds defaults
# only where a file is missing, so deleting them here would quietly revert that
# tuning. Remove the directories only when they are empty.
sudo rmdir /usr/share/aquatransport/config 2>/dev/null || true
sudo rmdir /usr/share/aquatransport 2>/dev/null || true
if [ -d /usr/share/aquatransport/config ]
then
	echo "Rule files kept at /usr/share/aquatransport/config; delete that directory to discard them."
fi

sudo update_dyld_shared_cache

# The Modern Root Certificates package installed no files (its BOM is empty);
# its certificates live in the system keychain and are left in place. Removing
# trusted roots by script is a decision an admin should make in Keychain Access,
# not have made for them by an uninstaller.
sudo pkgutil --forget "$PKGID"
sudo pkgutil --forget "Wowfunhappy.AquaTransport.ModernRootCertificates" 2>/dev/null

sudo shutdown -r now
