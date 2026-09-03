#!/bin/bash

cd "$(dirname "$0")"

for cert in trust/*.pem
do
	fingerprint="$(openssl x509 -in "$cert" -noout -fingerprint -sha1 2>/dev/null | sed 's/^.*=//' | tr -d ':')"

	if ! security find-certificate -a -Z \
		/System/Library/Keychains/SystemRootCertificates.keychain \
		/Library/Keychains/System.keychain 2>/dev/null | \
		grep -Fq "SHA-1 hash: $fingerprint"
	then
		security -v add-trusted-cert -d -r trustRoot -k /Library/Keychains/System.keychain "$cert"
	fi
done

for cert in distrust/*.pem
do
	security -v add-trusted-cert -d -r deny -k /Library/Keychains/System.keychain "$cert"
done
