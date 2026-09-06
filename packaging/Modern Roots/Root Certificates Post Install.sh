#!/bin/bash
# Installs the modern root set a 10.6-10.9 machine needs to authenticate today's servers.
#
# A root that only exists as an admin trust record is not enough on 10.6. Three pieces:
#
#   1. the trustRoot record in System.keychain (admin domain) -- what ordinary chain
#      building consults;
#   2. the same certificate imported into SystemRootCertificates.keychain -- the system
#      anchor set. CDSA refuses to anchor an EV chain at a root that is not a system
#      anchor, answering CSSMERR_TP_INVALID_ANCHOR_CERT (measured on 10.6.8: every
#      apple.com host failed until the roots landed there, because Apple's leaves are
#      EV-only);
#   3. an entry under the CA's EV policy OID in /System/Library/Keychains/EVRoots.plist,
#      which maps each CA's EV OID to the SHA-1 digests of the roots allowed to carry it.
#      The 10.6-era list predates every root in this bundle, so the EV-capable ones are
#      appended below. That file exists on 10.6 only; later systems keep their EV list
#      elsewhere, and its absence makes step 3 a no-op.
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
		# The system anchor set, not just an admin trust record -- piece 2 above. Failure is
		# tolerated: on systems where this keychain is not importable the EV plist will not
		# exist either, and piece 1 remains what carries ordinary chains.
		security import "$cert" -k /System/Library/Keychains/SystemRootCertificates.keychain 2>/dev/null || true
	fi
done

for cert in distrust/*.pem
do
	security -v add-trusted-cert -d -r deny -k /Library/Keychains/System.keychain "$cert"
done

# ---- EV digest list (piece 3) -------------------------------------------------
if [ -f /System/Library/Keychains/EVRoots.plist ]; then
/usr/bin/python - <<'PYEOF'
import base64, hashlib, os, plistlib, shutil, tempfile

# The roots in this bundle that anchor EV CAs today, keyed by the CA EV policy OID their
# leaves assert -- the same OIDs the plist already keys on for that CA. A root absent from
# this map is simply not EV-enabled: its DV/OV chains verify through pieces 1-2 alone.
EV = {
    "DigiCert Global Root G2.pem":                        "2.16.840.1.114412.2.1",
    "DigiCert Global Root G3.pem":                        "2.16.840.1.114412.2.1",
    "USERTrust ECC Certification Authority.pem":          "1.3.6.1.4.1.6449.1.2.1.5.1",
    "USERTrust RSA Certification Authority.pem":          "1.3.6.1.4.1.6449.1.2.1.5.1",
    "SSL.com EV Root Certification Authority RSA R2.pem": "1.3.6.1.4.1.23223.1.1.1",
}

path = "/System/Library/Keychains/EVRoots.plist"
pl = plistlib.readPlist(path)

def der_sha1(pem):
    b64 = "".join(l for l in open(pem).read().splitlines() if not l.startswith("-----"))
    return hashlib.sha1(base64.b64decode(b64)).digest()

changed = False
for name in sorted(EV):
    if not os.path.exists(name):
        continue
    lst = pl.setdefault(EV[name], [])
    dg = der_sha1(name)
    if dg not in lst:
        lst.append(dg)
        changed = True

if changed:
    if not os.path.exists(path + ".aquatransport-original"):
        shutil.copy2(path, path + ".aquatransport-original")
    fd, tmp = tempfile.mkstemp(dir=os.path.dirname(path))
    os.close(fd)
    plistlib.writePlist(pl, tmp)
    os.chmod(tmp, 0644)
    os.rename(tmp, path)
    print "EVRoots.plist: added modern EV roots"
else:
    print "EVRoots.plist: already current"
PYEOF
fi
