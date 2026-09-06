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

	in_keychain() { security find-certificate -a -Z "$1" 2>/dev/null | grep -Fq "SHA-1 hash: $fingerprint"; }

	# The two keychains are checked independently. An upgrade from the earlier
	# admin-only install has every root in System.keychain and none in the system
	# anchor set, and one combined check would skip the import the upgrade needs --
	# the exact state the first EV failures were debugged in.
	if ! in_keychain /System/Library/Keychains/SystemRootCertificates.keychain; then
		# The system anchor set (piece 2). Failure is tolerated: where this keychain
		# is not importable the EV plist will not exist either, and piece 1 remains
		# what carries ordinary chains.
		security import "$cert" -k /System/Library/Keychains/SystemRootCertificates.keychain 2>/dev/null || true
	fi
	if ! in_keychain /Library/Keychains/System.keychain; then
		security -v add-trusted-cert -d -r trustRoot -k /Library/Keychains/System.keychain "$cert"
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
# Paths are relative to this script's directory, where the payload places trust/.
EV = {
    "trust/DigiCert Global Root G2.pem":                        "2.16.840.1.114412.2.1",
    "trust/DigiCert Global Root G3.pem":                        "2.16.840.1.114412.2.1",
    "trust/USERTrust ECC Certification Authority.pem":          "1.3.6.1.4.1.6449.1.2.1.5.1",
    "trust/USERTrust RSA Certification Authority.pem":          "1.3.6.1.4.1.6449.1.2.1.5.1",
    "trust/SSL.com EV Root Certification Authority RSA R2.pem": "1.3.6.1.4.1.23223.1.1.1",
}

path = "/System/Library/Keychains/EVRoots.plist"
pl = plistlib.readPlist(path)

# Python 2's plistlib hands <data> values back as plistlib.Data and will only write
# <data> for Data instances -- a plain str becomes a <string>, which is not the format
# the trust engine reads. Python 3 uses bytes both ways.
try:
    Data = plistlib.Data
except AttributeError:
    Data = None

def as_bytes(v):
    return v.data if Data is not None and isinstance(v, Data) else v

def der_sha1(pem):
    b64 = "".join(l for l in open(pem).read().splitlines() if not l.startswith("-----"))
    return hashlib.sha1(base64.b64decode(b64)).digest()

changed = False
for name in sorted(EV):
    if not os.path.exists(name):
        continue
    lst = pl.setdefault(EV[name], [])
    dg = der_sha1(name)
    if not any(as_bytes(x) == dg for x in lst):
        lst.append(Data(dg) if Data is not None else dg)
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
