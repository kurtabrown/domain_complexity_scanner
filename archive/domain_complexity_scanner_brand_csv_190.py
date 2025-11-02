#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
Domain Complexity Scanner
v1.9.3-apex+nofollow(H,E)+apex-pref+rich-redirect(JS/meta/canonical/og)+httpprobe(paths)+weighted-nomx
+inactive(sig-5,prio-1)+psl-offline+redirect-cols+insecure+brand-hints+subdomain-included+owner-apex

Kurt-ready: lightweight JS/HTML redirect parsing (no Playwright), robust Location capture,
“Included” logic for subdomains & brand-group, flexible CSV.
"""

import argparse, csv, os, sys, logging, random, string, re, unicodedata, socket
from dataclasses import dataclass, asdict
from typing import List, Optional, Tuple, Dict

VERSION = "v1.9.3"
print(f"[Domain Scanner] {VERSION}")

# ---------------- Logging ----------------
LOG = logging.getLogger("domain_scanner")

# ---------------- Deps ----------------
try:
    import dns.resolver
except Exception:
    sys.stderr.write("FATAL: dnspython missing. Install: python3 -m pip install dnspython httpx tldextract\n")
    raise

try:
    import httpx
except Exception:
    httpx = None

try:
    import tldextract
except Exception:
    tldextract = None

# Offline PSL to avoid network flakiness
_EXTRACTOR = tldextract.TLDExtract(suffix_list_urls=None, cache_dir=os.path.expanduser("~/.cache/tldextract")) if tldextract else None

# ---------------- HTTP client defaults ----------------
BROWSER_UA = ("Mozilla/5.0 (Windows NT 10.0; Win64; x64) "
              "AppleWebKit/537.36 (KHTML, like Gecko) "
              "Chrome/120.0.0.0 Safari/537.36")

HTTP_TIMEOUT = 6.0
HTTP_VERIFY = True  # you can still pass --insecure to flip this at runtime

# ---------------- DNS ----------------
RESOLVER = dns.resolver.Resolver(configure=True)
RESOLVER.lifetime = 3.0
RESOLVER.timeout  = 2.0

def q_any(name: str, rtype: str) -> List[str]:
    try:
        ans = RESOLVER.resolve(name, rtype)
        return [str(r.to_text()) for r in ans]
    except Exception as e:
        LOG.debug("%s %s -> %s", rtype, name, e); return []

def q_txt(name: str) -> List[str]:
    try:
        ans = RESOLVER.resolve(name, "TXT")
        return ["".join([p.decode("utf-8","ignore") for p in r.strings]) for r in ans]
    except Exception as e:
        LOG.debug("TXT %s -> %s", name, e); return []

def has_any_address(host: str) -> bool:
    return bool(q_any(host, "A") or q_any(host, "AAAA") or q_any(host, "CNAME"))

# ---------------- Normalization & apex ----------------
def normalize_host(s: str) -> str:
    s = unicodedata.normalize("NFKC", (s or "").strip().lower().strip("."))
    try:
        return s.encode("idna").decode("ascii")
    except Exception:
        return s

def looks_like_domain(s: str) -> bool:
    s = normalize_host(s)
    if not s or " " in s or "/" in s: return False
    parts = s.split(".")
    if len(parts) < 2: return False
    tld = parts[-1]
    return bool(re.match(r"^[a-z]{2,}$", tld, re.IGNORECASE))

def apex_of(host: str) -> Optional[str]:
    host = normalize_host(host)
    if not looks_like_domain(host): return None
    if _EXTRACTOR:
        ext = _EXTRACTOR(host)
        if ext and ext.domain and ext.suffix:
            return f"{ext.domain}.{ext.suffix}".strip(".")
    # fallback: last two labels
    parts = host.split(".")
    if len(parts) >= 2:
        return ".".join(parts[-2:])
    return host

def is_subdomain_of(host: str, apex: str) -> bool:
    host = normalize_host(host); apex = normalize_host(apex)
    return host == apex or host.endswith("." + apex)

# ---------------- Redirect & HTML parsing ----------------
# Regexes for HTML/JS detection
META_REFRESH_RE = re.compile(
    r'<meta[^>]+http-equiv=["\']?\s*refresh\s*["\']?[^>]+content=["\']?\s*\d+\s*;\s*url\s*=\s*([^"\'>\s]+)',
    re.IGNORECASE
)
CANONICAL_RE = re.compile(
    r'<link[^>]+rel=["\']?canonical["\']?[^>]+href=["\']([^"\']+)["\']',
    re.IGNORECASE
)
OG_URL_RE = re.compile(
    r'<meta[^>]+property=["\']og:url["\']\s*content=["\']([^"\']+)["\']',
    re.IGNORECASE
)
JS_REDIRECT_RE = re.compile(
    r'(?:window\.)?location(?:\.href|\.replace|\.assign)?\s*=\s*["\']([^"\']+)["\']'
    r'|setTimeout\s*\([^)]*["\']\s*(https?://[^"\']+)["\']',
    re.IGNORECASE
)

def _parse_body_for_targets(body: str) -> List[str]:
    if not body: return []
    found = []
    for rx in (META_REFRESH_RE, CANONICAL_RE, OG_URL_RE, JS_REDIRECT_RE):
        for m in rx.finditer(body):
            for g in m.groups():
                if g:
                    found.append(g)
    # De-dupe, keep order
    return list(dict.fromkeys(found))

def _host_from_url(url: str, base: Optional[str] = None) -> Optional[str]:
    if not url: return None
    try:
        return normalize_host(httpx.URL(url, base=httpx.URL(base) if base else None).host or "")
    except Exception:
        pass
    # Last resort regex
    m = re.search(r'//([^/\s:]+)', url)
    return normalize_host(m.group(1)) if m else None

def walk_redirect_hosts(domain: str, timeout: float, verify_tls: bool) -> List[str]:
    """
    Collect first Location host from 30x without following further (resilient to TLS issues later).
    """
    if httpx is None: return []
    hosts_seen: List[str] = []
    starts = [
        f"http://{domain}/",
        f"http://www.{domain}/",
        f"https://{domain}/",
        f"https://www.{domain}/",
    ]
    for start in starts:
        try:
            with httpx.Client(follow_redirects=False, timeout=timeout, headers={"User-Agent": BROWSER_UA}, verify=verify_tls) as client:
                r = client.get(start)
                if 300 <= r.status_code < 400:
                    loc = r.headers.get("Location")
                    if loc:
                        h = _host_from_url(loc, base=r.url.human_repr())
                        if h:
                            hosts_seen.append(h)
        except Exception as e:
            LOG.debug("walk_redirect_hosts %s start=%s -> %s", domain, start, e)
    return list(dict.fromkeys(hosts_seen))

def detect_html_js_targets(domain: str, timeout: float, verify_tls: bool) -> Tuple[List[str], str]:
    """
    Fetch page bodies (both http/https, apex/www) and look for meta/canonical/og/js redirect targets.
    Returns (hosts, explain_source)
    """
    if httpx is None: return ([], "")
    hosts: List[str] = []
    explain_bits: List[str] = []
    starts = [
        f"https://{domain}/",
        f"https://www.{domain}/",
        f"http://{domain}/",
        f"http://www.{domain}/",
    ]
    for start in starts:
        try:
            with httpx.Client(follow_redirects=False, timeout=timeout, headers={"User-Agent": BROWSER_UA}, verify=verify_tls) as client:
                r = client.get(start)
                body = r.text if (r.headers.get("content-type","").lower().startswith("text/") or r.status_code < 400) else ""
                if body:
                    urls = _parse_body_for_targets(body)
                    extracted = []
                    for u in urls:
                        h = _host_from_url(u, base=start)
                        if h:
                            hosts.append(h)
                            extracted.append(f"{u} → {h}")
                    if extracted:
                        explain_bits.append(f"{start} ⇒ found targets: " + "; ".join(extracted))
        except Exception as e:
            LOG.debug("detect_html_js_targets %s %s -> %s", domain, start, e)
    return (list(dict.fromkeys(hosts)), " | ".join(explain_bits))

def brand_hints_in_body(domain: str, monitored_apexes: List[str], timeout: float, verify_tls: bool) -> List[str]:
    """
    If body contains any monitored apex string, hint that it belongs to that brand.
    We return hinted apexes (not hosts) – weak signal, used only if nothing else matches.
    """
    if httpx is None: return []
    hints = set()
    starts = [
        f"https://{domain}/",
        f"https://www.{domain}/",
        f"http://{domain}/",
        f"http://www.{domain}/",
    ]
    for start in starts:
        try:
            with httpx.Client(follow_redirects=False, timeout=timeout, headers={"User-Agent": BROWSER_UA}, verify=verify_tls) as client:
                r = client.get(start)
                body = (r.text or "")[:200000]
                if not body: continue
                low = body.lower()
                for a in monitored_apexes:
                    if a in low:
                        hints.add(a)
        except Exception:
            continue
    return list(hints)

# ---------------- CSV I/O ----------------
def read_domains_csv_flexible(path: str) -> List[Tuple[str,bool,Optional[str]]]:
    rows: List[Tuple[str,bool,Optional[str]]] = []
    with open(path, "r", encoding="utf-8") as fh:
        first = fh.readline(); fh.seek(0)
        if "domain" in (first or "").lower():
            rd = csv.DictReader(fh)
            for r in rd:
                d = normalize_host((r.get("domain") or "").strip())
                if not d: continue
                primary = (str(r.get("primary") or "").strip().upper() == "Y")
                owner = normalize_host((r.get("owner_apex") or "").strip()) or None
                rows.append((d, primary, owner))
        else:
            rd = csv.reader(fh)
            for parts in rd:
                if not parts: continue
                d = normalize_host((parts[0] or "").strip())
                if not d: continue
                primary = (len(parts) >= 2 and (parts[1] or "").strip().upper() == "Y")
                owner = normalize_host((parts[2] or "").strip()) if len(parts) >= 3 else None
                rows.append((d, primary, owner))
    return rows

# ---------------- Scoring (lightweight) ----------------
def priority_from_score(score: int) -> str:
    if score >= 11: return "High"
    if score >= 7: return "Medium"
    return "Low"

@dataclass
class DomainResult:
    domain: str
    apex: str
    primary: bool
    owner_apex: Optional[str]
    covered_by: Optional[str]
    coverage_status: str
    coverage_reason: str
    http_present: bool
    http_status: Optional[int]
    inactive: bool
    redirect_chain_hosts: List[str]
    redirect_explain: str
    htmljs_targets: List[str]
    htmljs_explain: str
    hinted_owners: List[str]
    signal_priority: str
    signal_score: int
    signal_reason: str

# ---------------- Analyzer ----------------
def analyze_domain(
    d: str,
    primary: bool,
    owner_apex: Optional[str],
    monitored_apexes: List[str],
    with_http: bool,
    check_redirects: bool,
    insecure: bool,
    debug: bool
) -> DomainResult:
    apex = apex_of(d) or d
    redirect_chain_hosts: List[str] = []
    htmljs_targets: List[str] = []
    hinted_owners: List[str] = []
    redirect_explain = ""
    htmljs_explain = ""
    http_present = False
    http_status = None
    inactive = False
    covered_by_val = None
    coverage_status = "Standalone"
    coverage_reason = ""

    # If domain is subdomain of any monitored apex -> Included
    for a in monitored_apexes:
        if a != apex and is_subdomain_of(d, a):
            coverage_status = f"SubdomainOf:{a}"
            coverage_reason = f"{d} is subdomain of monitored apex {a}"
            covered_by_val = a
            break

    # Declared brand owner coverage (CSV)
    if not covered_by_val and owner_apex and owner_apex in monitored_apexes and apex != owner_apex:
        coverage_status = f"BrandGroup:{owner_apex}"
        coverage_reason = f"Declared owner group; covered by {owner_apex}"
        covered_by_val = owner_apex

    # Check 30x Location targets (record only first hop)
    if not covered_by_val and check_redirects:
        loc_hosts = walk_redirect_hosts(d, timeout=HTTP_TIMEOUT, verify_tls=HTTP_VERIFY and not insecure)
        if loc_hosts:
            redirect_chain_hosts.extend(loc_hosts)
            for h in loc_hosts:
                t_apex = apex_of(h)
                if t_apex and t_apex in monitored_apexes and t_apex != apex:
                    coverage_status = f"AliasOf:{t_apex}"
                    coverage_reason = f"HTTP 30x Location → {h} (apex {t_apex} is monitored)"
                    covered_by_val = t_apex
                    break
        redirect_explain = f"No-follow Location hosts: {redirect_chain_hosts}" if redirect_chain_hosts else "No 30x Location hosts"

    # Parse HTML for meta/canonical/og/js redirect targets
    if not covered_by_val and with_http:
        targets, html_exp = detect_html_js_targets(d, timeout=HTTP_TIMEOUT, verify_tls=HTTP_VERIFY and not insecure)
        htmljs_targets = targets
        htmljs_explain = html_exp or ""
        for h in htmljs_targets:
            t_apex = apex_of(h)
            if t_apex and t_apex in monitored_apexes and t_apex != apex:
                coverage_status = f"AliasOf:{t_apex}"
                coverage_reason = f"HTML/JS signal → {h} (apex {t_apex} is monitored)"
                covered_by_val = t_apex
                break

    # Brand hints (weak)
    if not covered_by_val and with_http:
        hinted = brand_hints_in_body(d, monitored_apexes, timeout=HTTP_TIMEOUT, verify_tls=HTTP_VERIFY and not insecure)
        hinted_owners = hinted
        if hinted_owners:
            # Do not mark Included solely on hint; keep as Standalone but note in reason
            pass

    # HTTP probe for present/inactive
    if with_http:
        tried = [
            f"https://{d}/",
            f"https://www.{d}/",
            f"http://{d}/",
            f"http://www.{d}/",
        ]
        for u in tried:
            try:
                with httpx.Client(follow_redirects=False, timeout=HTTP_TIMEOUT, headers={"User-Agent": BROWSER_UA}, verify=HTTP_VERIFY and not insecure) as client:
                    r = client.get(u)
                    http_present = True
                    http_status = r.status_code
                    break
            except Exception as e:
                LOG.debug("HTTP probe %s -> %s", u, e)
        if not http_present and not has_any_address(d) and not has_any_address("www."+d):
            inactive = True

    # ------------- Scoring -------------
    score = 0
    reasons = []

    # Base: primary brand boost
    if primary:
        score += 5
        reasons.append("Primary brand domain (+5)")

    # HTTP presence implies some exposure
    if http_present:
        score += 2
        reasons.append("HTTP site present (+2)")

    # Inactive penalty
    if inactive:
        score -= 5
        reasons.append("Inactive/unreachable (−5)")

    # DMARC/SPF/DKIM weighting NOTE:
    # We keep them out of this lightweight build for brevity; if you need them,
    # slot the existing DNS TXT evaluators back in here with reduced weight when no MX.
    # (Per previous decisions, DMARC reject should NOT raise priority.)

    # HTML/JS or 30x alias to monitored apex is “Included”
    signal_priority = priority_from_score(score)
    if covered_by_val:
        signal_priority = "Included"
        reasons.append(f"Covered by {covered_by_val} (redirect/subdomain/owner)")

    # If only “brand-hint” evidence exists, nudge score a bit (weak)
    if not covered_by_val and hinted_owners:
        score += 1
        reasons.append(f"Brand hint in body: {', '.join(hinted_owners)} (+1)")
        signal_priority = priority_from_score(score)

    explain_str = f"score={score} → {signal_priority}; " + "; ".join(reasons) if reasons else f"score={score} → {signal_priority}"

    return DomainResult(
        domain=d,
        apex=apex,
        primary=primary,
        owner_apex=owner_apex,
        covered_by=covered_by_val,
        coverage_status=coverage_status,
        coverage_reason=coverage_reason,
        http_present=http_present,
        http_status=http_status,
        inactive=inactive,
        redirect_chain_hosts=redirect_chain_hosts,
        redirect_explain=redirect_explain,
        htmljs_targets=htmljs_targets,
        htmljs_explain=htmljs_explain,
        hinted_owners=hinted_owners,
        signal_priority=signal_priority,
        signal_score=score,
        signal_reason=explain_str
    )

# ---------------- Main ----------------
def main():
    ap = argparse.ArgumentParser(description="Domain complexity scanner (lightweight JS/HTML redirect parsing).")
    ap.add_argument("--in", dest="infile", required=True, help="Input CSV: domain[,primary(Y/N)][,owner_apex]")
    ap.add_argument("--with-http", action="store_true", help="Probe HTTP and parse HTML/JS for redirects")
    ap.add_argument("--check-redirects", action="store_true", help="Capture first 30x Location hosts without following")
    ap.add_argument("--insecure", action="store_true", help="Disable TLS verification for HTTP probes")
    ap.add_argument("--vertical", default="other", help="Unused tag (kept for compatibility)")
    ap.add_argument("--debug", action="store_true", help="Verbose debug logging")
    ap.add_argument("--explain", nargs="*", help="Explain detail for these domains (space-separated)")
    args = ap.parse_args()

    level = logging.DEBUG if args.debug else logging.INFO
    logging.basicConfig(level=level, format="%(levelname)s: %(message)s")

    global HTTP_VERIFY
    if args.insecure:
        HTTP_VERIFY = False

    rows = read_domains_csv_flexible(args.infile)
    monitored_apexes = sorted(list({apex_of(d) or d for (d, _, _) in rows}))

    out_path = os.path.splitext(args.infile)[0] + "_results.csv"

    fields = [
        "domain","apex","primary","owner_apex",
        "covered_by","coverage_status","coverage_reason",
        "http_present","http_status","inactive",
        "redirect_chain_hosts","redirect_explain",
        "htmljs_targets","htmljs_explain",
        "hinted_owners",
        "signal_priority","signal_score","signal_reason"
    ]

    with open(out_path, "w", encoding="utf-8", newline="") as fh:
        w = csv.DictWriter(fh, fieldnames=fields)
        w.writeheader()
        for (d, prim, owner) in rows:
            res = analyze_domain(
                d=d,
                primary=prim,
                owner_apex=owner,
                monitored_apexes=monitored_apexes,
                with_http=args.with_http,
                check_redirects=args.check_redirects,
                insecure=args.insecure,
                debug=args.debug
            )
            row = asdict(res)
            # Serialize lists
            row["redirect_chain_hosts"] = ",".join(res.redirect_chain_hosts)
            row["htmljs_targets"] = ",".join(res.htmljs_targets)
            row["hinted_owners"] = ",".join(res.hinted_owners)
            w.writerow(row)

            if args.explain and d in args.explain:
                print(f"\n[Explain] host={d}")
                print(f" - apex(host)={res.apex}")
                print(f" - monitored apexes={monitored_apexes}")
                print(f" - {res.redirect_explain}")
                if res.htmljs_explain:
                    print(f" - HTML/JS: {res.htmljs_explain}")
                print(f" - HTTP present={res.http_present}, status={res.http_status}")
                print(f" - inactive={res.inactive}")
                if res.coverage_status != "Standalone":
                    print(f" - COVERED: {res.coverage_status} → {res.coverage_reason}")
                elif res.hinted_owners:
                    print(f" - HINTS: body mentions {res.hinted_owners}")
                print(f" - Result: {res.signal_priority} ({res.signal_reason})")

    print(f"\nWrote: {out_path}")

if __name__ == "__main__":
    main()
