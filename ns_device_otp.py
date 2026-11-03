#!/usr/bin/env python3
"""Look up a Netskope Client device by user + hostname and fetch its one-time password (OTP).

Flow (REST API v2):
  1. GET /api/v2/events/datasearch/clientstatus  -> find the device (nsdeviceuid + userkey)
  2. GET /api/v2/devices/otp                     -> fetch the OTP(s) for that device

Credentials come from the environment, never the command line or disk:
  NETSKOPE_TENANT     e.g. mytenant  or  mytenant.goskope.com
  NETSKOPE_API_TOKEN  REST API v2 token (needs access to the clientstatus and devices endpoints)
Optional:
  NETSKOPE_CA_BUNDLE  CA file to trust (needed when the Netskope Client does SSL inspection)

Usage:
#Set Variables
export NETSKOPE_TENANT=tenant
export NETSKOPE_API_TOKEN='token'
##Optional
export NETSKOPE_CA_BUNDLE="/Library/Application Support/Netskope/STAgent/data/nscacert.pem"
#Run script
  ns_device_otp.py alice@example.com MACBOOK-123
  ns_device_otp.py                      # prompts for user and hostname
"""
import argparse
import json
import os
import ssl
import sys
import time
import urllib.error
import urllib.parse
import urllib.request

CLIENTSTATUS_PATH = "/api/v2/events/datasearch/clientstatus"
OTP_PATH = "/api/v2/devices/otp"


def die(msg, code=1):
    print(f"error: {msg}", file=sys.stderr)
    sys.exit(code)


def require_env(name):
    value = os.environ.get(name, "").strip()
    if not value:
        die(f"{name} is not set")
    return value


def ssl_context():
    # Add the Netskope CA on top of the system trust store (the tenant may or may not be inspected).
    ctx = ssl.create_default_context()
    ca = os.environ.get("NETSKOPE_CA_BUNDLE")
    if ca:
        ctx.load_verify_locations(cafile=ca)
        ctx.verify_flags &= ~ssl.VERIFY_X509_STRICT  # Python 3.13+ rejects many inspection CAs otherwise
    return ctx


def api_get(base, token, ctx, path, params):
    """GET a Netskope API path and return parsed JSON; exit with an explanation on any failure."""
    url = f"{base}{path}?{urllib.parse.urlencode(params)}"
    # Official v2 header first; fall back to Bearer if the tenant rejects it.
    for auth in ({"Netskope-Api-Token": token}, {"Authorization": f"Bearer {token}"}):
        req = urllib.request.Request(url, headers={**auth, "Accept": "application/json"})
        try:
            with urllib.request.urlopen(req, context=ctx, timeout=30) as r:
                return json.load(r)
        except urllib.error.HTTPError as e:
            body = e.read().decode(errors="replace").strip()[:500]
            if e.code in (401, 403) and "Netskope-Api-Token" in auth:
                continue
            if e.code in (401, 403):
                die(f"HTTP {e.code}: token rejected for {path}. Check it is valid, not expired, and "
                    f"allowed to call this endpoint (REST API v2 > token privileges). {body}")
            if e.code == 404 and "agent needs to request OTP" in body:
                die("Netskope has no OTP for this user/device yet: the client must generate one. Check "
                    "'Allow One-Time Disable with password' is enabled in the user's client configuration, "
                    "then restart the client or re-establish its tunnel and retry.", 4)
            if e.code == 404 and "no Route matched" in body:
                die(f"{path} does not exist on this tenant (the OTP route is undocumented and may have "
                    f"changed). Check Swagger under Settings > Tools > REST API v2.")
            if e.code == 429:
                die(f"rate limited by {path}; wait a minute and retry. {body}")
            die(f"HTTP {e.code} from {path}: {body}")
        except urllib.error.URLError as e:
            if isinstance(e.reason, ssl.SSLCertVerificationError):
                die(f"TLS verification failed ({e.reason.verify_message}). If the Netskope Client inspects "
                    "traffic, set NETSKOPE_CA_BUNDLE to its CA file.")
            die(f"cannot reach {base}: {e.reason}")
        except TimeoutError:
            die(f"timed out calling {path}")
        except json.JSONDecodeError:
            die(f"{path} returned a non-JSON response")


def find_device(base, token, ctx, user, hostname, hours):
    """Return (device_id, userkey, hostname, os) for the most recently seen matching device."""
    now = int(time.time())
    data = api_get(base, token, ctx, CLIENTSTATUS_PATH, {
        "query": "username eq '%s'" % user.replace("'", "\\'"),
        "starttime": now - hours * 3600, "endtime": now, "limit": 500,
    })
    status = data.get("status")
    if isinstance(status, dict) and status.get("status_code", 200) >= 400:
        die(f"client-status query rejected: {status.get('message')}")
    records = data.get("result") or []
    want = hostname.lower()
    best = None
    for r in records:
        hi, ui = r.get("host_info") or {}, r.get("user_info") or {}
        names = {str(n).lower() for n in (r.get("hostname"), hi.get("hostname")) if n}
        if want in names and hi.get("nsdeviceuid") and ui.get("userkey"):
            if best is None or r.get("timestamp", 0) > best[0]:
                best = (r.get("timestamp", 0), hi["nsdeviceuid"], ui["userkey"],
                        r.get("hostname") or hi.get("hostname"), hi.get("os") or r.get("os"))
    if best is None:
        die(f"no device '{hostname}' for user '{user}' among {len(records)} client-status records in the "
            f"last {hours}h. Check the exact username/hostname, or widen the window with --hours.", 2)
    return best[1:]


def main():
    ap = argparse.ArgumentParser(description=__doc__.split("\n\n")[0])
    ap.add_argument("user", nargs="?", help="user email / username")
    ap.add_argument("hostname", nargs="?", help="device hostname (case-insensitive, exact match)")
    ap.add_argument("--hours", type=int, default=168, help="client-status lookback in hours (default 168)")
    args = ap.parse_args()

    tenant = require_env("NETSKOPE_TENANT").removeprefix("https://").rstrip("/")
    base = f"https://{tenant if '.' in tenant else tenant + '.goskope.com'}"
    token = require_env("NETSKOPE_API_TOKEN")
    user = args.user or input("User (email): ").strip()
    hostname = args.hostname or input("Hostname: ").strip()
    if not user or not hostname:
        die("both user and hostname are required")

    ctx = ssl_context()
    device_id, userkey, name, os_name = find_device(base, token, ctx, user, hostname, args.hours)
    print(f"Device: {name} ({os_name})  id={device_id}", file=sys.stderr)

    resp = api_get(base, token, ctx, OTP_PATH, {"deviceID": device_id, "userkey": userkey, "type": "all"})
    if resp.get("status") != "success":
        die(f"unexpected OTP response: {json.dumps(resp)[:300]}")
    for key, value in resp.items():
        if key != "status" and isinstance(value, (str, int)) and value != "":
            print(f"{key}: {value}")


if __name__ == "__main__":
    main()
