#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
detect_redirect.py — robust single-domain redirect detector (v1.2)

Usage:
  python3 detect_redirect.py example.com

Enhancements in v1.2:
- Realistic Chrome UA + browsery headers (Accept, Accept-Language).
- GET-first probing (then HEAD) for each candidate.
- Tries extra "trigger" paths that commonly emit cross-domain redirects on CDNs:
  /, /login, /signin, /sign-in, /account, /cart, /checkout
- Manual 30x walker captures every hop; meta-refresh & simple JS fallback.
- verify=False and http2=False for CDN parity.

If any hop changes host away from the starting apex (not subdomain), it's a redirect.
"""

import sys
import re
from urllib.parse import urlparse, urljoin
from typing import List, Optional, Tuple
import httpx

# A modern Chrome UA (desktop)
CHROME_UA = (
    "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) "
    "AppleWebKit/537.36 (KHTML, like Gecko) "
    "Chrome/127.0.0.0 Safari/537.36"
)

BROWSER_HEADERS = {
    "User-Agent": CHROME_UA,
    "Accept": "text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8",
    "Accept-Language": "en-US,en;q=0.9",
    "Cache-Control": "no-cache",
    "Pragma": "no-cache",
}

TIMEOUT = httpx.Timeout(8.0, connect=6.0)
HOP_LIMIT = 8

SCHEMES = ("https://", "http://")
HOST_FORMS = ("{h}", "www.{h}")

# Paths that frequently yield the same redirects a human sees
TRIGGER_PATHS = ("/", "/login", "/signin", "/sign-in", "/account", "/cart", "/checkout")

META_REFRESH_RE = re.compile(
    r'<meta[^>]*http-equiv=["\']refresh["\'][^>]*content=["\']\s*\d+\s*;\s*url=([^"\']+)["\']',
    re.IGNORECASE
)
JS_LOCATION_RE = re.compile(
    r'location(?:\.href)?\s*=\s*["\']([^"\']+)["\']|location\.replace\(\s*["\']([^"\']+)["\']\s*\)',
    re.IGNORECASE
)
CANONICAL_RE = re.compile(
    r'<link[^>]+rel=["\']canonical["\'][^>]+href=["\']([^"\']+)["\']',
    re.IGNORECASE
)
OGURL_RE = re.compile(
    r'<meta[^>]+property=["\']og:url["\'][^>]+content=["\']([^"\']+)["\']',
    re.IGNORECASE
)

def host_of(u: str) -> str:
    try:
        return urlparse(u).hostname or ""
    except Exception:
        return ""

def same_or_sub(host: str, base: str) -> bool:
    host = (host or "").lower().strip(".")
    base = (base or "").lower().strip(".")
    return host == base or host.endswith("." + base)

def req(client: httpx.Client, method: str, url: str) -> Optional[httpx.Response]:
    try:
        return client.request(method, url, follow_redirects=False)
    except Exception:
        return None

def manual_redirect_walk(start: str, client: httpx.Client) -> Tuple[List[str], Optional[httpx.Response]]:
    """Return URL chain (including start + each Location hop) and the final Response (if any)."""
    chain = [start]
    current = start
    for _ in range(HOP_LIMIT):
        # Try GET first (some edges 403 HEAD), then HEAD as fallback
        r = req(client, "GET", current) or req(client, "HEAD", current)
        if not r:
            return chain, None
        if r.status_code in (301, 302, 303, 307, 308):
            loc = r.headers.get("Location")
            if not loc:
                return chain, r
            try:
                nxt = urljoin(current, loc)
            except Exception:
                return chain, r
            if nxt == current or nxt in chain:
                return chain, r
            chain.append(nxt)
            current = nxt
            continue
        return chain, r
    return chain, None

def html_redirect_target(base_url: str, html: str) -> Optional[str]:
    if not html:
        return None
    m = META_REFRESH_RE.search(html)
    if m:
        return urljoin(base_url, m.group(1).strip())
    m2 = JS_LOCATION_RE.search(html)
    if m2:
        t = m2.group(1) or m2.group(2)
        if t:
            return urljoin(base_url, t.strip())
    # weak hints
    m3 = CANONICAL_RE.search(html)
    if m3:
        return urljoin(base_url, m3.group(1).strip())
    m4 = OGURL_RE.search(html)
    if m4:
        return urljoin(base_url, m4.group(1).strip())
    return None

def main():
    if len(sys.argv) != 2:
        print("Usage: python3 detect_redirect.py <domain>")
        sys.exit(2)

    root = sys.argv[1].strip().lower().strip(".")
    candidates = []
    for scheme in SCHEMES:
        for hostf in HOST_FORMS:
            host = hostf.format(h=root)
            for path in TRIGGER_PATHS:
                candidates.append(f"{scheme}{host}{path}")

    with httpx.Client(
        headers=BROWSER_HEADERS,
        verify=False,     # permissive for quirky CDN/TLS chains
        http2=False,      # avoid HTTP/2 protocol errors
        timeout=TIMEOUT,
    ) as client:

        for start in candidates:
            chain, final_resp = manual_redirect_walk(start, client)

            if len(chain) > 1:
                start_host = host_of(chain[0])
                for hop in chain[1:]:
                    h = host_of(hop)
                    if h and not same_or_sub(h, start_host):
                        print(f"REDIRECT: {root} → {h}")
                        print("Chain:")
                        for u in chain:
                            print(f"  {u}")
                        sys.exit(0)

            if final_resp and "text/html" in (final_resp.headers.get("content-type", "").lower()):
                target = html_redirect_target(str(final_resp.url), final_resp.text or "")
                if target:
                    th = host_of(target)
                    sh = host_of(chain[0])
                    if th and not same_or_sub(th, sh):
                        print(f"HTML-REDIRECT: {root} → {th}")
                        print("From:", final_resp.url)
                        print("Via: ", target)
                        sys.exit(0)

        print(f"NO REDIRECT: {root}")
        sys.exit(0)

if __name__ == "__main__":
    main()
