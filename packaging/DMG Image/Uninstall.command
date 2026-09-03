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
sudo rm -rf "/usr/share/aquatransport"

sudo update_dyld_shared_cache

sudo pkgutil --forget Wowfunhappy.AquaTransport
sudo shutdown -r now