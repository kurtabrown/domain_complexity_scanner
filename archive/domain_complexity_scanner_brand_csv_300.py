#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
domain_complexity_scanner_brand_csv.py — v3.0.0

What it does (based on your approved checks):
  1 MX present
  2 SPF policy
  3 DKIM discovered (heuristic)
  4 DMARC policy (record only; reject doesn't raise priority)
  5 DNSSEC (DS at parent)
  6 Mail security vendors (Proofpoint/Mimecast/Microsoft/Google/etc)
  7 General SaaS CNAMEs (Shopify/Salesforce/HubSpot/Marketo/Cloudflare/Akamai/Fastly/etc)
  8 Risky CNAMEs (parking/misconfig patterns)
  9 HTTP presence & status; "inactive" penalty applied
 10 Portal signals via path probes (/login,/signin,/account,/cart,/checkout)
 11 robots.txt hints for portal/admin
 12 Static HTML clues (Sign in / Cart / Checkout tokens)
 13 Sitemap presence
 14 TLS error notes (light)
 15 Included via subdomain (coverage)
 16 Included via redirect (30x/meta/JS) to covered apex
 17 Alias chain capture for explainability
 21 CT names count (optional --with-ct)
 22 OSINT breach footprint (optional --with-breach; safe stub)
 23 Custom search term guard
 24 Primary brand boost
 25 Explain mode (reason strings)
 26 Flexible CLI: --with-http --with-ct --check-redirects --with-breach --insecure --vertical --debug --explain
 27 Auto output name: <input>_results.csv
 28 Robust CSV sniffer + optional header handling

Usage (examples):
  python3 domain_complexity_scanner_brand_csv.py --in domains.csv --with-http --check-redirects --with-ct --vertical retail --debug
  python3 domain_complexity_scanner_brand_csv.py --in domains.csv --explain example.com

CSV input:
  domain[,primary_flag]
  - primary_flag: "Y" or "N" (defaults to N). If the CSV has only one column for any row, "N" is assumed.

Output CSV columns:
  host, apex, included_via_subdomain(Y/N), redirect_target, included_via_redirect(Y/N),
  signal_priority (Included/High/Medium/Low), score, reason, details_json

Dependencies:
  pip3 install httpx dnspython tldextract
  (Optional) pip3 install aiohttp  # if you want async CT queries
"""

import os
import re
import csv
import sys
import ssl
import json
import time
import asyncio
from dataclasses import dataclass, asdict
from typing import List, Optional, Tuple, Set, Dict, Any
from urllib.parse import urlparse, urljoin

import httpx
import dns.resolver
import dns.dnssec
import dns.name
import dns.rdatatype
import tldextract

VERSION = "v3.0.0"

# ------------------------------------------------------------
# Config / constants
# ------------------------------------------------------------

TIMEOUT = httpx.Timeout(8.0, connect=6.0)
HOP_LIMIT = 8
PATH_PROBES = ["/", "/login", "/signin", "/sign-in", "/account", "/cart", "/checkout", "/basket"]
ROBOTS_PATH = "/robots.txt"
SITEMAP_NAMES = ["/sitemap.xml", "/sitemap_index.xml"]

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

PORTAL_HTML_TOKENS = [
    "sign in", "signin", "log in", "login",
    "my account", "account", "checkout", "cart", "basket"
]

MAIL_VENDOR_HINTS = {
    "proofpoint": ["pphosted.com", "pphosted.com."],
    "mimecast": ["mimecast.com", "mimecast.com."],
    "microsoft": ["outlook.com", "protection.outlook.com", "microsoft.com"],
    "google": ["google.com", "aspmx.l.google.com", "alt1.aspmx.l.google.com"],
    "barracuda": ["barracudanetworks.com"],
    "ironport": ["iphmx.com", "secureexch.net", "protection.office.com"],
}

SAAS_CNAME_HINTS = {
    "shopify": ["shops.myshopify.com", "cdn.shopify.com"],
    "salesforce": ["salesforce.com", "force.com", "live.siteforce.com"],
    "hubspot": ["hubspot.com", "hs-sites.com", "hs-analytics.net"],
    "marketo": ["marketo.net", "mktoweb.com"],
    "zendesk": ["zendesk.com", "zdusercontent.com"],
    "cloudflare": ["cdn.cloudflare.net", "cloudflare.net"],
    "akamai": ["akamai.net", "akamaihd.net", "edgekey.net", "edgesuite.net"],
    "fastly": ["fastly.net", "edgekey.net"],
    "netsuite": ["netsuite.com"],
    "square": ["squareup.com"],
    "bigcommerce": ["bigcommerce.com"],
    "wordpress": ["wordpress.com", "wpengine.com", "wordpress.org"],
}

RISKY_CNAME_HINTS = [
    "parkingcrew.net",
    "sedoparking.com",
    "bodis.com",
    "domaincontrol.com",  # not inherently risky, but often misconfigs
    "unbouncepages.com",  # takeover scenarios
    "ghs.googlehosted.com",  # if dangling
]

# We use PSL snapshot to avoid network
TLDX = tldextract.TLDExtract(suffix_list_urls=None)

# ------------------------------------------------------------
# Data models
# ------------------------------------------------------------

@dataclass
class Row:
    host: str
    primary: bool

@dataclass
class Result:
    host: str
    apex: str
    included_via_subdomain: bool
    redirect_target: str
    included_via_redirect: bool
    signal_priority: str
    score: int
    reason: str
    details_json: str

# ------------------------------------------------------------
# Utility: apex & validation
# ------------------------------------------------------------

def apex_of(host: str) -> str:
    s = (host or "").strip().lower().strip(".")
    if not s:
        return ""
    ext = TLDX(s)
    apex = getattr(ext, "top_domain_under_public_suffix", None)
    if apex:
        return apex.lower()
    return (ext.registered_domain or s).lower()

def is_valid_domain(token: str) -> bool:
    s = (token or "").strip().lower()
    if not s or " " in s:
        return False
    if "." not in s:
        return False
    label = re.compile(r"^[a-z0-9-]{1,63}$", re.IGNORECASE)
    parts = s.strip(".").split(".")
    if any(p == "" for p in parts):
        return False
    if not all(label.match(p) and not (p.startswith("-") or p.endswith("-")) for p in parts):
        return False
    if len(parts[-1]) < 2:
        return False
    return True

def same_or_sub(host: str, base_apex: str) -> bool:
    host = (host or "").lower().strip(".")
    base_apex = (base_apex or "").lower().strip(".")
    return host == base_apex or host.endswith("." + base_apex)

def host_of_url(u: str) -> str:
    try:
        return urlparse(u).hostname or ""
    except Exception:
        return ""

# ------------------------------------------------------------
# CSV I/O
# ------------------------------------------------------------

def load_input_csv(path: str) -> List[Row]:
    rows: List[Row] = []
    with open(path, "r", newline="", encoding="utf-8") as f:
        sample = f.read(2048)
        f.seek(0)
        try:
            dialect = csv.Sniffer().sniff(sample, delimiters=",;\t|")
        except Exception:
            dialect = csv.get_dialect("excel")
        reader = csv.reader(f, dialect)
        first = next(reader, None)
        if first is None:
            return rows

        def looks_like_header(cols):
            j = ",".join(c.lower() for c in cols)
            return ("domain" in j) or ("primary" in j)

        def parse(cols) -> Optional[Row]:
            if not cols:
                return None
            host = (cols[0] or "").strip()
            flag = (cols[1] if len(cols) > 1 else "").strip().upper()
            primary = (flag == "Y")
            if not host:
                return None
            return Row(host=host, primary=primary)

        if looks_like_header(first):
            for cols in reader:
                r = parse(cols)
                if r:
                    rows.append(r)
        else:
            r0 = parse(first)
            if r0:
                rows.append(r0)
            for cols in reader:
                r = parse(cols)
                if r:
                    rows.append(r)
    return rows

def write_output_csv(path: str, results: List[Result]) -> None:
    with open(path, "w", newline="", encoding="utf-8") as f:
        w = csv.writer(f)
        w.writerow([
            "host","apex","included_via_subdomain","redirect_target","included_via_redirect",
            "signal_priority","score","reason","details_json"
        ])
        for r in results:
            w.writerow([
                r.host, r.apex,
                "Y" if r.included_via_subdomain else "N",
                r.redirect_target or "",
                "Y" if r.included_via_redirect else "N",
                r.signal_priority, r.score, r.reason, r.details_json
            ])

# ------------------------------------------------------------
# DNS helpers (MX/SPF/DKIM/DMARC/DNSSEC + vendors/SaaS)
# ------------------------------------------------------------

def dns_query(name: str, rtype: str, debug: bool=False) -> List[dns.rrset.RRset]:
    resolver = dns.resolver.Resolver()
    resolver.timeout = 3.0
    resolver.lifetime = 5.0
    try:
        ans = resolver.resolve(name, rtype)
        return list(ans.rrset.items) if ans.rrset else []
    except Exception as e:
        if debug:
            print(f"DEBUG: DNS {rtype} {name} -> {e}")
        return []

def get_mx(apex: str, debug: bool=False) -> List[str]:
    rcds = dns_query(apex, "MX", debug)
    vals = []
    for r in rcds:
        try:
            vals.append(str(r.exchange).rstrip(".").lower())
        except Exception:
            pass
    return vals

def get_txt(apex: str, debug: bool=False) -> List[str]:
    vals = []
    rcds = dns_query(apex, "TXT", debug)
    for r in rcds:
        try:
            text = b"".join([b for b in r.strings]).decode("utf-8", "ignore")
            vals.append(text)
        except Exception:
            pass
    return vals

def parse_spf(txts: List[str]) -> Optional[str]:
    for t in txts:
        if t.lower().startswith("v=spf1"):
            if " -all" in t or t.endswith("-all"):
                return "-all"
            if "~all" in t:
                return "~all"
            if "?all" in t:
                return "?all"
            if "+all" in t:
                return "+all"
            return "present"
    return None

def parse_dmarc(apex: str, debug: bool=False) -> Dict[str, Any]:
    name = f"_dmarc.{apex}"
    txts = get_txt(name, debug)
    res = {"present": False, "policy": None, "rua": None, "ruf": None}
    for t in txts:
        low = t.lower()
        if low.startswith("v=dmarc1"):
            res["present"] = True
            m = re.search(r"\bp=([a-z]+)", low)
            if m:
                res["policy"] = m.group(1)
            m = re.search(r"\brua=([^; ]+)", low)
            if m:
                res["rua"] = m.group(1)
            m = re.search(r"\bruf=([^; ]+)", low)
            if m:
                res["ruf"] = m.group(1)
    return res

def detect_dkim_selectors(apex: str, debug: bool=False) -> List[str]:
    # Heuristic: try common selectors (k=rsa presence). Not exhaustive.
    common = ["default", "selector1", "selector2", "google", "k1", "s1", "s2", "mail"]
    found = []
    for sel in common:
        name = f"{sel}._domainkey.{apex}"
        txts = get_txt(name, debug)
        for t in txts:
            if "v=DKIM1" in t or "p=" in t:
                found.append(sel)
                break
    return list(sorted(set(found)))

def has_dnssec(apex: str, debug: bool=False) -> bool:
    try:
        # Check DS at parent as a quick signal
        parent = ".".join(apex.split(".")[1:])
        if not parent:
            return False
        ds = dns_query(apex, "DS", debug)
        return len(ds) > 0
    except Exception as e:
        if debug:
            print(f"DEBUG: DNSSEC {apex} -> {e}")
        return False

def map_mail_vendors(mx_hosts: List[str]) -> List[str]:
    vendors = set()
    for vendor, needles in MAIL_VENDOR_HINTS.items():
        for mxh in mx_hosts:
            if any(n in mxh for n in needles):
                vendors.add(vendor)
    return sorted(vendors)

def query_cname(host: str, debug: bool=False) -> Optional[str]:
    resolver = dns.resolver.Resolver()
    resolver.timeout = 3.0
    resolver.lifetime = 5.0
    try:
        ans = resolver.resolve(host, "CNAME")
        if ans and ans.rrset:
            for r in ans.rrset.items:
                return str(r.target).rstrip(".").lower()
    except Exception as e:
        if debug:
            print(f"DEBUG: DNS CNAME {host} -> {e}")
    return None

def gather_saas_cnames(host: str, debug: bool=False) -> Dict[str, List[str]]:
    hits: Dict[str, List[str]] = {}
    # check host and www
    for h in [host, f"www.{host}"]:
        cn = query_cname(h, debug)
        if not cn:
            continue
        for platform, needles in SAAS_CNAME_HINTS.items():
            if any(n in cn for n in needles):
                hits.setdefault(platform, []).append(cn)
        # risky?
        for risky in RISKY_CNAME_HINTS:
            if risky in cn:
                hits.setdefault("risky", []).append(cn)
    return hits

# ------------------------------------------------------------
# HTTP probing (no browser): presence/portal/robots/sitemap/TLS
# ------------------------------------------------------------

def _req(client: httpx.Client, method: str, url: str) -> Optional[httpx.Response]:
    try:
        return client.request(method, url, follow_redirects=False)
    except Exception:
        return None

def manual_redirect_walk(start: str, client: httpx.Client) -> Tuple[List[str], Optional[httpx.Response]]:
    chain = [start]
    current = start
    for _ in range(HOP_LIMIT):
        r = _req(client, "GET", current) or _req(client, "HEAD", current)
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
    # weak hints give *possible* destination when 30x blocked
    m3 = CANONICAL_RE.search(html)
    if m3:
        return urljoin(base_url, m3.group(1).strip())
    m4 = OGURL_RE.search(html)
    if m4:
        return urljoin(base_url, m4.group(1).strip())
    return None

def detect_cross_domain_redirect(host: str, insecure: bool, debug: bool=False) -> Tuple[Optional[str], List[str], Optional[str]]:
    """
    Returns (target_host, chain, via_html_url)
    """
    root = (host or "").strip().lower().strip(".")
    if not root:
        return None, [], None

    schemes = ("https://", "http://")
    host_forms = ("{h}", "www.{h}")
    trigger_paths = ["/", "/login", "/signin", "/sign-in", "/account", "/cart", "/checkout"]

    ctx_verify = False if insecure else True
    tls = os.environ.get("PYTHONHTTPSVERIFY", "")
    if insecure:
        os.environ["PYTHONHTTPSVERIFY"] = "0"
    try:
        with httpx.Client(headers=BROWSER_HEADERS, verify=ctx_verify, timeout=TIMEOUT, http2=False) as client:
            for scheme in schemes:
                for hform in host_forms:
                    h = hform.format(h=root)
                    for p in trigger_paths:
                        start = f"{scheme}{h}{p}"
                        chain, final = manual_redirect_walk(start, client)
                        # if any hop crosses apex boundary => redirect
                        if len(chain) > 1:
                            start_host = host_of_url(chain[0])
                            start_apex = apex_of(start_host)
                            for hop in chain[1:]:
                                th = host_of_url(hop)
                                if th and not same_or_sub(th, start_apex):
                                    return th, chain, None
                        # try HTML hints
                        if final and "text/html" in (final.headers.get("content-type","").lower()):
                            tgt = html_redirect_target(str(final.url), final.text or "")
                            if tgt:
                                th = host_of_url(tgt)
                                sh = host_of_url(chain[0])
                                if th and not same_or_sub(th, apex_of(sh)):
                                    return th, chain, tgt
    finally:
        if insecure is True and tls == "":
            # restore default if we changed it
            os.environ.pop("PYTHONHTTPSVERIFY", None)

    return None, [], None

def http_probe_bundle(host: str, insecure: bool, debug: bool=False) -> Dict[str, Any]:
    """
    Probes http/https + www host roots and portal paths.
    Returns dict with:
      present, statuses, tls_errors, portal_hits (list of (method,url,status)),
      robots_hints (bool), sitemap_present (bool), html_tokens (bool)
    """
    res = {
        "present": False,
        "statuses": {},
        "tls_errors": [],
        "portal_hits": [],
        "robots_hints": False,
        "sitemap_present": False,
        "html_tokens": False,
        "inactive": True,
    }
    verify = False if insecure else True
    targets = []
    for scheme in ("https://", "http://"):
        for h in (host, f"www.{host}"):
            for p in PATH_PROBES:
                targets.append((scheme, h, p))

    seen_root_ok = False
    try:
        with httpx.Client(headers=BROWSER_HEADERS, verify=verify, timeout=TIMEOUT, http2=False) as client:
            # Root hits & statuses
            for scheme in ("https://", "http://"):
                for h in (host, f"www.{host}"):
                    url = f"{scheme}{h}/"
                    try:
                        r = client.request("GET", url, follow_redirects=False)
                        res["statuses"][url] = r.status_code
                        if 200 <= r.status_code < 600:
                            seen_root_ok = True
                        # HTML tokens
                        if "text/html" in (r.headers.get("content-type","").lower()):
                            html = r.text or ""
                            if any(tok in html.lower() for tok in PORTAL_HTML_TOKENS):
                                res["html_tokens"] = True
                    except ssl.SSLError as e:
                        res["tls_errors"].append(f"{url}: {e.__class__.__name__}")
                    except httpx.HTTPError as e:
                        if debug:
                            print(f"DEBUG: HTTP {url} -> {e}")
            # Portal paths (HEAD then GET)
            for scheme,h,p in targets:
                url = f"{scheme}{h}{p}"
                for method in ("HEAD", "GET"):
                    try:
                        r = client.request(method, url, follow_redirects=False)
                        sc = r.status_code
                        if sc in (200,301,302,303,307,308,401,403,404):
                            # treat 30x to auth or 401/403 as portal-ish if on auth/cart-ish paths
                            if p != "/" and (sc in (200,301,302,303,307,308,401,403)):
                                res["portal_hits"].append((method, url, sc))
                        # robots/sitemap detection
                        if p == "/" and method == "GET":
                            rb = client.request("GET", f"{scheme}{h}{ROBOTS_PATH}", follow_redirects=False)
                            if rb is not None and rb.status_code == 200:
                                rb_txt = rb.text or ""
                                if any(tok in rb_txt.lower() for tok in ["account", "checkout", "cart", "admin", "signin", "login"]):
                                    res["robots_hints"] = True
                                # sitemap lines inside robots
                                if "sitemap:" in rb_txt.lower():
                                    res["sitemap_present"] = True
                            # direct sitemap names
                            for sm in SITEMAP_NAMES:
                                smu = f"{scheme}{h}{sm}"
                                sm_r = client.request("HEAD", smu, follow_redirects=False)
                                if sm_r.status_code in (200, 301, 302):
                                    res["sitemap_present"] = True
                    except ssl.SSLError as e:
                        res["tls_errors"].append(f"{url}: {e.__class__.__name__}")
                    except httpx.HTTPError as e:
                        if debug:
                            print(f"DEBUG: HTTP {url} -> {e}")
    except Exception as e:
        if debug:
            print(f"DEBUG: http_probe_bundle error for {host}: {e}")

    res["present"] = seen_root_ok or bool(res["portal_hits"]) or res["html_tokens"]
    res["inactive"] = not res["present"]
    return res

# ------------------------------------------------------------
# CT & OSINT (light)
# ------------------------------------------------------------

async def ct_count_async(apex: str, debug: bool=False) -> int:
    """
    Very lightweight CT name count. If aiohttp is available, query crt.sh JSON.
    Otherwise returns -1 (unknown).
    """
    try:
        import aiohttp
    except Exception:
        return -1
    url = f"https://crt.sh/?q=%25.{apex}&output=json"
    try:
        async with aiohttp.ClientSession(timeout=aiohttp.ClientTimeout(total=8)) as sess:
            async with sess.get(url) as resp:
                if resp.status != 200:
                    return -1
                data = await resp.json(content_type=None)
                # Unique names
                names = set()
                for row in data:
                    cn = row.get("common_name") or ""
                    na = row.get("name_value") or ""
                    for part in (cn, na):
                        for n in str(part).split("\n"):
                            n = n.strip().lower()
                            if n and n.endswith(apex):
                                names.add(n)
                return len(names)
    except Exception as e:
        if debug:
            print(f"DEBUG: CT query failed for {apex}: {e}")
        return -1

def breach_footprint_stub(apex: str, debug: bool=False) -> int:
    """
    OSINT breach footprint (count). Safe stub unless you wire an API:
    - If env HIBP_API_KEY is provided, you could integrate there.
    For now, return -1 (unknown). Score only applied if >=0 and > threshold.
    """
    # Placeholder: return -1 for "not checked"
    return -1

# ------------------------------------------------------------
# Scoring
# ------------------------------------------------------------

def score_host(
    host: str,
    primary: bool,
    with_http: bool,
    with_ct: bool,
    with_breach: bool,
    insecure: bool,
    vertical: str,
    debug: bool,
) -> Tuple[int, List[str], Dict[str, Any]]:
    """
    Returns (score, reasons, details)
    """
    reasons = []
    details: Dict[str, Any] = {}
    apex = apex_of(host)

    # (1) MX
    mx_hosts = get_mx(apex, debug)
    details["mx_hosts"] = mx_hosts
    if mx_hosts:
        reasons.append("+4 MX present")
        score = 4
    else:
        score = 0

    # (2) SPF
    spf_txts = get_txt(apex, debug)
    details["spf_txts"] = [t for t in spf_txts if t.lower().startswith("v=spf1")]
    spf = parse_spf(spf_txts)
    details["spf_policy"] = spf
    if spf is None:
        reasons.append("+2 No SPF")
        score += 2
    elif spf == "+all":
        reasons.append("+3 SPF +all (overly permissive)")
        score += 3
    elif spf == "?all":
        reasons.append("+1 SPF ?all (permissive)")
        score += 1
    elif spf == "~all":
        reasons.append("+1 SPF ~all (soft fail)")
        score += 1
    elif spf == "-all":
        reasons.append("+0 SPF -all (strict)")
    else:
        reasons.append("+0 SPF present")

    # (3) DKIM selectors (heuristic)
    dkim_selectors = detect_dkim_selectors(apex, debug)
    details["dkim_selectors"] = dkim_selectors
    if dkim_selectors:
        reasons.append("+2 DKIM discovered")
        score += 2
    else:
        reasons.append("+1 No DKIM discovered (heuristic)")
        score += 1

    # (4) DMARC
    dmarc = parse_dmarc(apex, debug)
    details["dmarc"] = dmarc
    if not dmarc["present"]:
        reasons.append("+3 No DMARC")
        score += 3
    else:
        pol = dmarc["policy"] or "none"
        if pol == "none":
            reasons.append("+3 DMARC p=none")
            score += 3
        elif pol == "quarantine":
            reasons.append("+1 DMARC p=quarantine")
            score += 1
        elif pol == "reject":
            # DO NOT add to signal per your rule
            reasons.append("+0 DMARC p=reject (no increase)")
        else:
            reasons.append("+0 DMARC present")

    # (5) DNSSEC
    if has_dnssec(apex, debug):
        reasons.append("+0 DNSSEC present")
    else:
        reasons.append("+1 DNSSEC absent")
        score += 1

    # (6) Mail vendors
    vendors = map_mail_vendors(mx_hosts)
    details["mail_vendors"] = vendors
    if vendors:
        reasons.append(f"+1 Mail vendors {vendors}")
        score += 1

    # (7)+(8) SaaS / Risky CNAMEs
    saas = gather_saas_cnames(host, debug)
    details["saas_cnames"] = saas
    if saas:
        # +1 for any SaaS, +1 extra for risky
        if any(k for k in saas.keys() if k != "risky"):
            reasons.append("+1 SaaS CNAMEs detected")
            score += 1
        if "risky" in saas:
            n = len(saas["risky"])
            reasons.append(f"+2 Risky CNAMEs ({n})")
            score += 2

    # (9-14) HTTP/Web surface bundle
    httpd = {}
    if with_http:
        httpd = http_probe_bundle(host, insecure=insecure, debug=debug)
        details["http"] = httpd
        if not httpd.get("inactive"):
            reasons.append("+3 Active HTTP endpoint")
            score += 3
        else:
            reasons.append("−5 Inactive site")
            score -= 5  # Inactive penalty

        # (10) Portal paths
        if httpd.get("portal_hits"):
            reasons.append("+5 Portal paths responded")
            score += 5

        # (11) robots.txt hints
        if httpd.get("robots_hints"):
            reasons.append("+1 robots.txt portal/admin hints")
            score += 1

        # (12) Static HTML tokens
        if httpd.get("html_tokens"):
            reasons.append("+2 HTML portal/cart tokens")
            score += 2

        # (13) Sitemap
        if httpd.get("sitemap_present"):
            reasons.append("+1 Sitemap present")
            score += 1

        # (14) TLS errors (just a tiny nudge)
        tls_errs = httpd.get("tls_errors", [])
        if tls_errs:
            reasons.append("+1 TLS issues observed")
            score += 1

    # (21) CT names count
    if with_ct:
        try:
            ct_n = asyncio.run(ct_count_async(apex, debug))
        except RuntimeError:
            # running inside event loop (e.g. Jupyter)
            ct_n = -1
        details["ct_count"] = ct_n
        if ct_n >= 0:
            if ct_n >= 200:
                reasons.append("+2 Large CT subdomain set (>=200)")
                score += 2
            elif ct_n >= 50:
                reasons.append("+1 Moderate CT subdomain set (>=50)")
                score += 1

    # (22) OSINT breach footprint (stub)
    if with_breach:
        bf = breach_footprint_stub(apex, debug)
        details["breach_footprint"] = bf
        if bf >= 50:
            reasons.append("+2 Notable breach footprint (>=50 mentions)")
            score += 2
        elif bf >= 10:
            reasons.append("+1 Some breach footprint (>=10)")
            score += 1
        else:
            reasons.append("+0 Breach footprint not elevated / unknown")

    # (24) Primary brand
    if primary:
        reasons.append("+6 Primary brand domain")
        score += 6

    # Vertical nudges (retail/finance/other)
    v = (vertical or "other").lower()
    if v == "retail":
        # retail cares more about portal/cart
        if httpd.get("portal_hits"):
            reasons.append("+1 Retail vertical portal nudge")
            score += 1
    elif v == "finance":
        # finance: DNSSEC absence slightly more concerning
        if not has_dnssec(apex, debug):
            reasons.append("+1 Finance vertical DNSSEC nudge")
            score += 1

    return score, reasons, details

def bucket_from_score(score: int) -> str:
    if score >= 12:
        return "High"
    if score >= 7:
        return "Medium"
    return "Low"

def degrade_bucket(bucket: str, steps: int=1) -> str:
    order = ["High", "Medium", "Low"]
    idx = order.index(bucket)
    idx = min(len(order)-1, idx + steps)
    return order[idx]

# ------------------------------------------------------------
# Main classification (includes coverage logic)
# ------------------------------------------------------------

def classify_row(
    row: Row,
    monitored_apexes: Set[str],
    args
) -> Result:
    host = row.host.strip().lower().strip(".")
    if not is_valid_domain(host):
        return Result(
            host=row.host,
            apex="",
            included_via_subdomain=False,
            redirect_target="",
            included_via_redirect=False,
            signal_priority="Medium",
            score=7,
            reason="Custom defined search term (skipped domain checks)",
            details_json=json.dumps({"note": "custom_search_term"})
        )

    host_apex = apex_of(host)

    # (15) Included via subdomain (covered)
    for apex in monitored_apexes:
        if apex and same_or_sub(host, apex) and host_apex != apex:
            return Result(
                host=row.host,
                apex=host_apex,
                included_via_subdomain=True,
                redirect_target="",
                included_via_redirect=False,
                signal_priority="Included",
                score=0,
                reason=f"Subdomain of monitored apex ({apex})",
                details_json=json.dumps({"coverage":"subdomain","covered_apex":apex})
            )

    # (16) Included via redirect to covered apex
    redirect_target = ""
    included_via_redirect = False
    redirect_chain: List[str] = []
    redirect_via_html = None
    if args.check_redirects:
        tgt, chain, via_html = detect_cross_domain_redirect(host, insecure=args.insecure, debug=args.debug)
        if tgt:
            redirect_target = tgt
            redirect_chain = chain or []
            redirect_via_html = via_html
            tgt_apex = apex_of(tgt)
            if tgt_apex in monitored_apexes and tgt_apex != host_apex:
                included_via_redirect = True
                return Result(
                    host=row.host,
                    apex=host_apex,
                    included_via_subdomain=False,
                    redirect_target=redirect_target,
                    included_via_redirect=True,
                    signal_priority="Included",
                    score=0,
                    reason=f"{'HTML' if via_html else 'HTTP'} redirect to covered apex ({tgt_apex})",
                    details_json=json.dumps({"coverage":"redirect","chain":redirect_chain,"via_html":via_html or ""})
                )

    # Standalone → score
    score, reasons, details = score_host(
        host=row.host,
        primary=row.primary,
        with_http=args.with_http,
        with_ct=args.with_ct,
        with_breach=args.with_breach,
        insecure=args.insecure,
        vertical=args.vertical,
        debug=args.debug
    )

    bucket = bucket_from_score(score)

    # Inactive penalty affects priority tier (−1 step) if with_http was enabled and inactive
    if args.with_http and details.get("http", {}).get("inactive"):
        bucket = degrade_bucket(bucket, 1)

    explain = f"score={score} → {bucket}; " + "; ".join(reasons)
    details_out = {
        "reasons": reasons,
        "details": details,
        "redirect_chain": redirect_chain,
        "redirect_via_html": redirect_via_html
    }
    return Result(
        host=row.host,
        apex=host_apex,
        included_via_subdomain=False,
        redirect_target=redirect_target,
        included_via_redirect=False,
        signal_priority=bucket,
        score=score,
        reason=explain,
        details_json=json.dumps(details_out)
    )

# ------------------------------------------------------------
# Main
# ------------------------------------------------------------

def main():
    import argparse
    p = argparse.ArgumentParser(description=f"[Domain Scanner] {VERSION}")
    p.add_argument("--in", dest="infile", required=True, help="Input CSV: domain[,primary_flag]")
    p.add_argument("--with-http", action="store_true", help="Enable HTTP/robots/sitemap/portal probes")
    p.add_argument("--with-ct", action="store_true", help="Enable CT names count (slow, network)")
    p.add_argument("--with-breach", action="store_true", help="Enable OSINT breach footprint stub (safe)")
    p.add_argument("--check-redirects", action="store_true", help="Enable redirect detection (30x/meta/JS)")
    p.add_argument("--insecure", action="store_true", help="Disable TLS verification for probes")
    p.add_argument("--vertical", default="other", choices=["retail","finance","other"], help="Vertical nudges")
    p.add_argument("--debug", action="store_true", help="Verbose debug logging")
    p.add_argument("--explain", nargs="*", default=[], help="Optional: focus verbosity for host(s)")
    args = p.parse_args()

    rows = load_input_csv(args.infile)
    if not rows:
        print("No input rows found.")
        sys.exit(1)

    # Build monitored apex set
    monitored_apexes: Set[str] = set()
    for r in rows:
        if is_valid_domain(r.host):
            monitored_apexes.add(apex_of(r.host))

    # For explain mode, we still process all rows (so the CSV is complete),
    # but we can print extra info for matching targets.
    explain_targets = set(h.strip().lower().strip(".") for h in args.explain)

    results: List[Result] = []
    print(f"[Domain Scanner] {VERSION}")
    if args.debug:
        print(f"Scanning {len(rows)} item(s)…")

    for r in rows:
        res = classify_row(r, monitored_apexes, args)
        results.append(res)
        if explain_targets and (r.host.lower().strip(".") in explain_targets or apex_of(r.host) in explain_targets):
            print(f"\n[Explain] host={r.host}")
            print(f" - apex(host)={res.apex}")
            print(f" - included_via_subdomain={res.included_via_subdomain}")
            print(f" - redirect_target={res.redirect_target}")
            print(f" - included_via_redirect={res.included_via_redirect}")
            # Print a short summary of HTTP, vendors, etc.
            try:
                d = json.loads(res.details_json)
            except Exception:
                d = {}
            if "details" in d and "http" in d["details"]:
                httpd = d["details"]["http"]
                print(f" - HTTP present={not httpd.get('inactive')} statuses={list(httpd.get('statuses',{}).items())[:3]}")
                print(f" - portal hits (count)={len(httpd.get('portal_hits',[]))}")
            if "reasons" in d:
                print(" - reasons:")
                for rr in d["reasons"]:
                    print(f"   * {rr}")
            if d.get("redirect_chain"):
                print(f" - redirect chain: {d['redirect_chain']}")

    base = os.path.splitext(os.path.basename(args.infile))[0]
    out_path = os.path.join(os.path.dirname(args.infile) or ".", f"{base}_results.csv")
    write_output_csv(out_path, results)
    print(f"\nWrote: {out_path}")

if __name__ == "__main__":
    main()
