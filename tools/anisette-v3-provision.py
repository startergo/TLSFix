#!/usr/bin/env python3
"""One-time anisette V3 provisioning against an anisette-v3-server.

Replicates the client side of the provisioning WebSocket: the server relays
Apple's mid-start/mid-finish provisioning while THIS machine holds the
identity being provisioned. The resulting identifier + adi_pb stay local and
are all Apple ever ties this "device" to; the server only ever derives
one-time passwords from them, on demand, statelessly.

Usage (requires python3 with `websockets`; run from anywhere that can reach
the server -- the box itself, a Mac, or the server host):

    ANISERVER=http://server:port python3 anisette-v3-provision.py

Environment:
  ANISERVER   anisette-v3-server base URL (default http://127.0.0.1:6969)
  ANISTATE    where to write the identity JSON (default ./anisette-identity.json)
  ANICI       client info to provision under. MUST be an akd-flavor identity:
              Apple's edge refuses identities provisioned in other contexts
              (the Xcode AuthKit flavor is refused outright; verified
              2026-09-14). Default is a Mac akd identity.
  ANIUA       akd User-Agent used for the provisioning requests.
  ANIEXTRA    JSON object of extra headers (e.g. hardware headers).

The output file feeds the adapter as gsa-anisette-v3.json (see
docs/ICLOUD.md): adi_identifier and adi_pb are base64, client-info is the
provisioning identity.
"""
import asyncio, base64, hashlib, json, os, plistlib, urllib.request, urllib.error, uuid
from datetime import datetime, timezone

SERVER = os.environ.get("ANISERVER", "http://127.0.0.1:6969")
STATE = os.environ.get("ANISTATE", "anisette-identity.json")
CLIENT_INFO = os.environ.get("ANICI",
    "<Mac16,8> <macOS;26.5;25F71> <com.apple.AuthKit/1 (com.apple.akd/1.0)>")
USER_AGENT = os.environ.get("ANIUA", "akd/1.0 CFNetwork/1568.200.51 Darwin/25.5.0")
EXTRA = json.loads(os.environ["ANIEXTRA"]) if os.environ.get("ANIEXTRA") else {}

IDENT = bytes.fromhex(json.load(open(STATE))["identifier"]) if os.path.exists(STATE) else os.urandom(16)

def lu(): return hashlib.sha256(IDENT).hexdigest()
def devid(): return str(uuid.UUID(bytes=IDENT)).upper()
def b64(b): return base64.b64encode(b).decode()

def apple_headers():
    now = datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")
    return {
        "User-Agent": USER_AGENT,
        "X-Apple-Baa-E": "-10000",
        "X-Apple-I-MD-LU": lu(),
        "X-Mme-Device-Id": devid(),
        "X-Apple-Baa-Avail": "2",
        "X-Mme-Client-Info": CLIENT_INFO,
        "X-Apple-I-Client-Time": now,
        "Accept-Language": "en-US,en;q=0.9",
        "X-Apple-Client-App-Name": "akd",
        "Accept": "*/*",
        # The plist body travels under this content type verbatim; Apple's
        # provisioning endpoints expect the pair, not a plist content type.
        "Content-Type": "application/x-www-form-urlencoded",
        "X-Apple-Baa-UE": "AKAuthenticationError:-7066|com.apple.devicecheck.error.baa:-10000",
        "X-Apple-Host-Baa-E": "-7066",
        **EXTRA,
    }

def http(method, url, body=None, hdrs=None, js=None):
    data = json.dumps(js).encode() if js is not None else body
    req = urllib.request.Request(url, data=data, method=method)
    for k, v in (hdrs or {}).items(): req.add_header(k, v)
    if js is not None: req.add_header("Content-Type", "application/json")
    try:
        with urllib.request.urlopen(req, timeout=30) as r: return r.status, r.read()
    except urllib.error.HTTPError as e: return e.code, e.read()

def plist_post(url, obj):
    body = plistlib.dumps(obj, fmt=plistlib.FMT_XML)
    status, data = http("POST", url, body, apple_headers())
    if status != 200: raise RuntimeError(f"apple {status}: {data[:200]}")
    return plistlib.loads(data)

async def main():
    status, data = http("GET", "https://gsa.apple.com/grandslam/GsService2/lookup", None, apple_headers())
    if status != 200: raise RuntimeError(f"lookup {status}: {data[:200]}")
    urls = plistlib.loads(data)["urls"]
    start_url, end_url = urls["midStartProvisioning"], urls["midFinishProvisioning"]
    print("provisioning urls ok")

    import websockets
    adi_pb = None
    async with websockets.connect(SERVER.replace("http", "ws") + "/v3/provisioning_session") as ws:
        while True:
            msg = json.loads(await ws.recv())
            tag = msg.get("result")
            if tag == "GiveIdentifier":
                await ws.send(json.dumps({"identifier": b64(IDENT)}))
            elif tag == "GiveStartProvisioningData":
                r = plist_post(start_url, {"Header": {}, "Request": {}})
                await ws.send(json.dumps({"spim": r["Response"]["spim"]}))
                print("start ok")
            elif tag == "GiveEndProvisioningData":
                r = plist_post(end_url, {"Header": {}, "Request": {"cpim": msg["cpim"]}})
                resp = r["Response"]
                await ws.send(json.dumps({"ptm": resp["ptm"], "tk": resp["tk"],
                                          "rinfo": resp["X-Apple-I-MD-RINFO"]}))
                print("end ok")
            elif tag == "ProvisioningSuccess":
                adi_pb = base64.b64decode(msg["adi_pb"])
                break
            else:
                raise RuntimeError(f"provisioning failed: {msg}")
    if not adi_pb: raise RuntimeError("no adi_pb")

    json.dump({"identifier": IDENT.hex(), "adi_pb": b64(adi_pb)}, open(STATE, "w"))
    os.chmod(STATE, 0o600)
    print(f"identity saved to {STATE}: identifier={IDENT.hex()} adi_pb={len(adi_pb)} bytes")
    print(f"adapter file fields: adi_identifier={b64(IDENT)} client-info={CLIENT_INFO!r}")

    status, data = http("POST", SERVER + "/v3/get_headers",
                        js={"identifier": b64(IDENT), "adi_pb": b64(adi_pb)})
    print(f"get_headers: HTTP {status} {data[:160].decode(errors='replace')}")

asyncio.run(main())
