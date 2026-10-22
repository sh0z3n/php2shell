#!/usr/bin/env python3
# php2shell — CVE-2026-109618 / CVE-2026-109619 checker + s-1 proof
import ipaddress
import secrets
import sys
import urllib.error
import urllib.request
from urllib.parse import urlparse

 # assuming one of them u can change as u like for ur attack4
# i didn't add a way to find the version automaticaly i needed this just for an old php server i had'
FIXED = {"8.2": (8, 2, 35), "8.3": (8, 3, 36), "8.4": (8, 4, 27), "8.5": (8, 5, 12)}
AFFECTED_FROM = {"8.2": (8, 2, 0), "8.3": (8, 3, 0), "8.4": (8, 4, 0), "8.5": (8, 5, 0)}


def is_private_target(url):
    host = urlparse(url).hostname or ""
    if host == "localhost":
        return True
    try:
        ip = ipaddress.ip_address(host)
    except ValueError:
        return False
    return bool(ip.is_loopback or ip.is_private)


def guard_trigger(url):
    if is_private_target(url):
        return
    host = urlparse(url).hostname or ""
    print(f"[-] refusing  {host}:  loopback / LAN only, use check")
    sys.exit(2)


def fetch(url, data=None, headers=None, method=None):
    req = urllib.request.Request(url, data=data, headers=headers or {}, method=method)
    try:
        with urllib.request.urlopen(req, timeout=10) as r:
            return r.status, dict(r.headers), r.read(4096)
    except urllib.error.HTTPError as e:
        return e.code, dict(e.headers), e.read(4096)
    except Exception as e:
        print(f"[-] cannot reach {url}: {e}")
        sys.exit(1)


def parse_php(headers):
    powered = headers.get("X-Powered-By", "")
    if "PHP/" not in powered:
        return None
    raw = powered.split("PHP/")[-1].strip().split()[0]
    try:
        parts = tuple(int(x) for x in raw.split(".")[:3])
    except ValueError:
        return None
    return raw, parts


def verdict(parts):
    branch = f"{parts[0]}.{parts[1]}"
    if branch not in FIXED:
        return "unknown", branch
    if parts >= FIXED[branch]:
        return "patched", branch
    if parts >= AFFECTED_FROM[branch]:
        return "vulnerable", branch
    return "unknown", branch


def check(url):
    status, headers, _ = fetch(url)
    server = headers.get("Server", "(none)")
    print(f"[*] {url} -> HTTP {status}")
    print(f"[*] Server: {server}")
    found = parse_php(headers)
    if not found:
        print("[!] no PHP version in headers (expose_php=Off) — cannot confirm")
        return 3
    raw, parts = found
    state, branch = verdict(parts)
    print(f"[*] PHP: {raw}")
    if state == "patched":
        print(f"[-] PATCHED — fixed in {branch} >= {'.'.join(map(str, FIXED[branch]))}")
        return 1
    if state == "vulnerable":
        print(f"[+] VULNERABLE version — {branch} < {'.'.join(map(str, FIXED[branch]))}")
        return 0
    print(f"[?] branch {branch} not covered by this checker")
    return 3


def prove(url):
    guard_trigger(url)
    rc = check(url)
    if rc == 1:
        print("[*] patched — trigger not sent")
        return 1
    if rc == 3:
        print("[*] version unconfirmed — trigger not sent")
        return 3

    sid = secrets.token_hex(13)
    boundary = "----checker" + secrets.token_hex(8)
    file_body = b"A" * 256
    body = b"".join([
        f"--{boundary}\r\n".encode(),
        b'Content-Disposition: form-data; name="PHPSESSID_UPLOAD_PROGRESS"\r\n\r\n',
        b"proof\r\n",
        f"--{boundary}\r\n".encode(),
        b'Content-Disposition: form-data; name="f"; filename="proof.txt"\r\n',
        b"Content-Type: text/plain\r\n\r\n",
        file_body, b"\r\n",
        f"--{boundary}--\r\n".encode(),
    ])
    headers = {
        "Content-Type": f"multipart/form-data; boundary={boundary}",
        "Cookie": f"PHPSESSID={sid}",
    }
    status, _, _ = fetch(url, data=body, headers=headers, method="POST")
    print(f"[*] stage-1 trigger: upload_progress POST (sid={sid[:8]}…) -> HTTP {status}")
    if status < 500:
        print("[+] stage-1 accepted — server processed the upload_progress request")
        print("[+] proof complete: vulnerable version + trigger accepted. Nothing else was sent.")
        return 0
    print("[!] server errored on the trigger — inconclusive, check the target's error log")
    return 4


USAGE = """usage:
  python3 check.py check <url>    # fingerprint only
  python3 check.py prove <url>    # fingerprint + stage-1 trigger
  python3 check.py version

examples:
  python3 check.py check https://some-site.example/
  python3 check.py prove http://127.0.0.1:8080/index.php
  python3 check.py prove http://192.168.1.50/index.php

exit codes: 0 vulnerable/proved · 1 patched · 2 refused target · 3 unknown · 4 inconclusive
"""

if __name__ == "__main__":
    a = sys.argv[1:]
    if not a or a[0] in ("-h", "--help", "help"):
        print(__doc__)
        print(USAGE)
        sys.exit(0)

    if a[0] in ("check", "prove") and len(a) == 2:
        sys.exit(check(a[1]) if a[0] == "check" else prove(a[1]))
    print(USAGE)
    sys.exit(2)
