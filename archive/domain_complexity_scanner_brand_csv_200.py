#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
Domain Complexity Scanner
v2.0.0-no-browser
- No Playwright/browser usage
- Curl-first redirect detection
- DNS/TCP fast-fail
- Per-domain hard budget (no hangs)
- Flexible CSV (domain[,primary Y/N][,owner_apex])
- Subdomain/owner coverage -> 'Included'
- Non-domain rows -> Medium (custom search term)
"""

import argparse, csv, os, sys, logging, re, unicodedata, shutil, subprocess, time, socket
from dataclasses import dataclass, asdict
from typing import List, Optional, Tuple

VERSION = "v2.0.0-no-browser"
print(f"[Domain Scanner] {VERSION}")

LOG = logging.getLogger("domain_scanner")

# ---------------- Deps ----------------
try:
    import dns.resolver
except Exception:
    sys.stderr.write(
        "FATAL: dnspython missing. Install:\n"
        "  python3 -m pip install dnspython httpx tldextract\n"
    ); raise

try:
    import httpx
except Exception:
    httpx = None

try:
    import tldextract
except Exception:
    tldextract = None

# Offline PSL (no network fetch)
_EXTRACTOR = tldextract.TLDExtract(suffix_list_urls=None,
                                   cache_dir=os.path.expanduser("~/.cache/tldextract")) if tldextract else None

BROWSER_UA = ("Mozilla/5.0 (Windows NT 10.0; Win64; x64) "
              "AppleWebKit/537.36 (KHTML, like Gecko) "
              "Chrome/120.0.0.0 Safari/537.36")

HTTP_TIMEOUT_DEFAULT = 3.0
HTTP_VERIFY = True

# ---------------- DNS ----------------
RESOLVER = dns.resolver.Resolver(configure=True)
RESOLVER.lifetime = 2.0
RESOLVER.timeout  = 1.5

def q_any(name: str, rtype: str) -> List[str]:
    try:
        ans = RESOLVER.resolve(name, rtype)
        return [str(r.to_text()) for r in ans]
    except Exception as e:
        LOG.debug("%s %s -> %s", rtype, name, e)
        return []

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
    if not s or " " in s or "/" in s:
        return False
    parts = s.split(".")
    if len(parts) < 2:
        return False
    return bool(re.match(r"^[a-z0-9-]+(\.[a-z0-9-]+)+$", s))

def apex_of(host: str) -> Optional[str]:
    host = normalize_host(host)
    if not looks_like_domain(host):
        return None
    if _EXTRACTOR:
        ext = _EXTRACTOR(host)
        if ext and ext.domain and ext.suffix:
            return f"{ext.domain}.{ext.suffix}".strip(".")
    parts = host.split(".")
    if len(parts) >= 2:
        return ".".join(parts[-2:])
    return host

def is_subdomain_of(host: str, apex: str) -> bool:
    host = normalize_host(host); apex = normalize_host(apex)
    return host == apex or host.endswith("." + apex)

# ---------------- Redirect & HTML parsing ----------------
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

def _host_from_url(url: str, base: Optional[str] = None) -> Optional[str]:
    if not url:
        return None
    try:
        return normalize_host(httpx.URL(url, base=httpx.URL(base) if base else None).host or "")
    except Exception:
        m = re.search(r'//([^/\s:]+)', url)
        return normalize_host(m.group(1)) if m else None

def _parse_body_for_targets(body: str) -> List[str]:
    if not body: return []
    found = []
    for rx in (META_REFRESH_RE, CANONICAL_RE, OG_URL_RE, JS_REDIRECT_RE):
        for m in rx.finditer(body):
            for g in m.groups():
                if g:
                    found.append(g)
    return list(dict.fromkeys(found))

def time_left(deadline_ts: float) -> float:
    return max(0.0, deadline_ts - time.monotonic())

def walk_redirect_hosts(domain: str, timeout: float, verify_tls: bool, deadline_ts: float) -> List[str]:
    if httpx is None or time_left(deadline_ts) <= 0: return []
    hosts_seen: List[str] = []
    starts = [
        f"http://{domain}/",
        f"https://{domain}/",
        f"http://www.{domain}/",
        f"https://www.{domain}/",
    ]
    for start in starts:
        if time_left(deadline_ts) <= 0: break
        try:
            tout = min(timeout, time_left(deadline_ts))
            with httpx.Client(follow_redirects=False, timeout=tout,
                              headers={"User-Agent": BROWSER_UA}, verify=verify_tls) as client:
                r = client.get(start)
                if 300 <= r.status_code < 400:
                    loc = r.headers.get("Location")
                    if loc:
                        h = _host_from_url(loc, base=r.url.human_repr())
                        if h and h not in hosts_seen:
                            hosts_seen.append(h)
        except Exception as e:
            LOG.debug("walk_redirect_hosts %s start=%s -> %s", domain, start, e)
    return hosts_seen

def detect_html_js_targets(domain: str, timeout: float, verify_tls: bool, deadline_ts: float) -> Tuple[List[str], str]:
    if httpx is None or time_left(deadline_ts) <= 0: return ([], "")
    hosts: List[str] = []
    explain_bits: List[str] = []
    starts = [
        f"https://{domain}/",
        f"http://{domain}/",
        f"https://www.{domain}/",
        f"http://www.{domain}/",
    ]
    for start in starts:
        if time_left(deadline_ts) <= 0: break
        try:
            tout = min(timeout, time_left(deadline_ts))
            with httpx.Client(follow_redirects=False, timeout=tout,
                              headers={"User-Agent": BROWSER_UA}, verify=verify_tls) as client:
                r = client.get(start)
                ctype = r.headers.get("content-type","").lower()
                body = r.text if ("text/" in ctype or "html" in ctype or r.status_code < 400) else ""
                if body:
                    urls = _parse_body_for_targets(body)
                    extracted = []
                    for u in urls:
                        h = _host_from_url(u, base=start)
                        if h:
                            if h not in hosts:
                                hosts.append(h)
                            extracted.append(f"{u} → {h}")
                    if extracted:
                        explain_bits.append(f"{start} ⇒ {', '.join(extracted)}")
        except Exception as e:
            LOG.debug("detect_html_js_targets %s %s -> %s", domain, start, e)
    return (hosts, " | ".join(explain_bits))

# ---------------- CSV I/O ----------------
def read_domains_csv_flexible(path: str):
    rows = []
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

# ---------------- Scoring ----------------
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
    http_timeout: float,
    max_secs_per_domain: float,
    debug: bool
) -> DomainResult:

    deadline_ts = time.monotonic() + max(5.0, max_secs_per_domain)
    def remaining(): return max(0.0, deadline_ts - time.monotonic())

    # Non-domain rows
    if not looks_like_domain(d):
        reason = "Custom defined search term (not a domain)"
        return DomainResult(d, d, primary, owner_apex, None, "Standalone", "", False, None, False,
                            [], "", [], "", "Medium", 7, f"score=7 → Medium; {reason}")

    apex = apex_of(d) or d
    covered_by_val = None
    coverage_status = "Standalone"
    coverage_reason = ""
    redirect_chain_hosts: List[str] = []
    htmljs_targets: List[str] = []
    redirect_explain = ""
    htmljs_explain = ""
    http_present = False
    http_status = None
    inactive = False

    print(f"• {d} ", end="", flush=True)

    # Subdomain coverage
    for a in monitored_apexes:
        if a != apex and is_subdomain_of(d, a):
            coverage_status = f"SubdomainOf:{a}"
            coverage_reason = f"{d} is subdomain of monitored apex {a}"
            covered_by_val = a
            break

    # Owner coverage
    if not covered_by_val and owner_apex and owner_apex in monitored_apexes and apex != owner_apex:
        coverage_status = f"BrandGroup:{owner_apex}"
        coverage_reason = f"Declared owner group; covered by {owner_apex}"
        covered_by_val = owner_apex

    # --- Fast DNS checks ---
    apex_has_dns = has_any_address(d)
    www_has_dns  = has_any_address("www."+d)
    if not apex_has_dns and not www_has_dns:
        inactive = True
        LOG.debug("%s no DNS for apex or www -> inactive", d)

    # --- Curl-first redirects (fast & robust) ---
    if not covered_by_val and check_redirects and remaining() > 0:
        curl = shutil.which("curl")
        if curl:
            for start in (f"http://{d}/", f"https://{d}/", f"http://www.{d}/", f"https://www.{d}/"):
                if remaining() <= 0: break
                try:
                    cmd = [curl, "-sS", "-I", "--http1.1", "-L", "-m", str(int(min(5, max(2, http_timeout)))) , start]
                    if not HTTP_VERIFY: cmd.insert(2, "-k")
                    out = subprocess.run(cmd, capture_output=True, text=True, timeout=min(remaining(), http_timeout+2))
                    if out.returncode == 0 and out.stdout:
                        locs = re.findall(r"^Location:\s*(.+)$", out.stdout, flags=re.IGNORECASE|re.MULTILINE)
                        for loc in locs:
                            h = _host_from_url(loc.strip(), base=start)
                            if h and h not in redirect_chain_hosts:
                                redirect_chain_hosts.append(h)
                except Exception as e:
                    LOG.debug("curl redirect %s -> %s", start, e)
        redirect_explain = f"Curl targets: {','.join(redirect_chain_hosts) or 'none'}"
        for h in redirect_chain_hosts:
            t_apex = apex_of(h)
            if t_apex and t_apex in monitored_apexes and t_apex != apex:
                covered_by_val = t_apex
                coverage_status = f"AliasOf:{t_apex}"
                coverage_reason = f"HTTP Location → {h} (apex {t_apex} is monitored)"
                break

    # --- Static HTML/JS hints (no navigation) ---
    if not covered_by_val and with_http and remaining() > 0 and (apex_has_dns or www_has_dns) and httpx is not None:
        tgs, html_exp = detect_html_js_targets(d, timeout=min(http_timeout, remaining()), verify_tls=HTTP_VERIFY, deadline_ts=deadline_ts)
        htmljs_targets = tgs; htmljs_explain = html_exp or ""
        for h in htmljs_targets:
            t_apex = apex_of(h)
            if t_apex and t_apex in monitored_apexes and t_apex != apex:
                covered_by_val = t_apex
                coverage_status = f"AliasOf:{t_apex}"
                coverage_reason = f"HTML/JS signal → {h} (apex {t_apex} is monitored)"
                break

    # --- HTTP presence (quick) ---
    if with_http and remaining() > 0 and (apex_has_dns or www_has_dns) and httpx is not None:
        for host in (d, "www."+d):
            for scheme in ("https", "http"):
                if remaining() <= 0: break
                try:
                    tout = min(http_timeout, remaining())
                    with httpx.Client(follow_redirects=False, timeout=tout,
                                      headers={"User-Agent": BROWSER_UA},
                                      verify=HTTP_VERIFY) as client:
                        r = client.get(f"{scheme}://{host}/")
                        http_present = True; http_status = r.status_code
                        break
                except Exception as e:
                    LOG.debug("HTTP probe %s://%s -> %s", scheme, host, e)
            if http_present: break

    # Inactive if no DNS (already set) or nothing responds
    if not (apex_has_dns or www_has_dns):
        inactive = True

    # --- Scoring (simple; DMARC/SPF deliberately not included here) ---
    score, reasons = 0, []
    if primary: score += 5; reasons.append("Primary brand domain (+5)")
    if http_present: score += 2; reasons.append("HTTP site present (+2)")
    if inactive: score -= 5; reasons.append("Inactive/unreachable (−5)")
    signal_priority = priority_from_score(score)
    if covered_by_val:
        signal_priority = "Included"
        reasons.append(f"Covered by {covered_by_val} (redirect/subdomain/owner)")
    explain_str = f"score={score} → {signal_priority}; " + "; ".join(reasons) if reasons else f"score={score} → {signal_priority}"

    print(f"→ {signal_priority}")
    return DomainResult(
        domain=d, apex=apex, primary=primary, owner_apex=owner_apex,
        covered_by=covered_by_val, coverage_status=coverage_status, coverage_reason=coverage_reason,
        http_present=http_present, http_status=http_status, inactive=inactive,
        redirect_chain_hosts=redirect_chain_hosts, redirect_explain=redirect_explain,
        htmljs_targets=htmljs_targets, htmljs_explain=htmljs_explain,
        signal_priority=signal_priority, signal_score=score, signal_reason=explain_str
    )

# ---------------- Main ----------------
def main():
    ap = argparse.ArgumentParser(description="Domain complexity scanner (no-browser).")
    ap.add_argument("--in", dest="infile", required=True, help="Input CSV: domain[,primary(Y/N)][,owner_apex]")
    ap.add_argument("--with-http", action="store_true", help="Probe HTTP and parse HTML/JS for redirects")
    ap.add_argument("--check-redirects", action="store_true", help="Capture redirect targets (curl & headers)")
    ap.add_argument("--http-timeout", type=float, default=HTTP_TIMEOUT_DEFAULT, help="HTTP timeout per request (seconds)")
    ap.add_argument("--max-secs-per-domain", type=float, default=15.0, help="Absolute wall-clock budget per domain (seconds)")
    ap.add_argument("--insecure", action="store_true", help="Disable TLS verification for HTTP and for curl (-k)")
    ap.add_argument("--debug", action="store_true", help="Verbose debug logging")
    ap.add_argument("--explain", nargs="*", help="Print explain for these domains")
    args = ap.parse_args()

    level = logging.DEBUG if args.debug else logging.INFO
    logging.basicConfig(level=level, format="%(levelname)s: %(message)s")
    global HTTP_VERIFY
    HTTP_VERIFY = not args.insecure

    rows = read_domains_csv_flexible(args.infile)

    monitored_apexes = sorted(list({
        (apex_of(d) or d)
        for (d, _, _) in rows
        if looks_like_domain(d)
    }))

    out_path = os.path.splitext(args.infile)[0] + "_results.csv"

    fields = [
        "domain","apex","primary","owner_apex",
        "covered_by","coverage_status","coverage_reason",
        "http_present","http_status","inactive",
        "redirect_chain_hosts","redirect_explain",
        "htmljs_targets","htmljs_explain",
        "signal_priority","signal_score","signal_reason"
    ]

    print(f"Scanning {len(rows)} item(s) with max {args.max_secs_per_domain}s/domain…\n")

    with open(out_path, "w", encoding="utf-8", newline="") as fh:
        w = csv.DictWriter(fh, fieldnames=fields); w.writeheader()
        for (d, prim, owner) in rows:
            res = analyze_domain(
                d=d, primary=prim, owner_apex=owner, monitored_apexes=monitored_apexes,
                with_http=args.with_http, check_redirects=args.check_redirects,
                insecure=args.insecure, http_timeout=args.http_timeout,
                max_secs_per_domain=args.max_secs_per_domain, debug=args.debug
            )
            row = asdict(res)
            row["redirect_chain_hosts"] = ",".join(res.redirect_chain_hosts)
            row["htmljs_targets"] = ",".join(res.htmljs_targets)
            w.writerow(row)

            if args.explain and d in (args.explain or []):
                print(f"\n[Explain] host={d}")
                print(f" - apex(host)={res.apex}")
                print(f" - monitored apexes={monitored_apexes}")
                print(f" - {res.redirect_explain or 'No redirect info'}")
                if res.htmljs_explain: print(f" - HTML/JS: {res.htmljs_explain}")
                print(f" - HTTP present={res.http_present}, status={res.http_status}")
                print(f" - inactive={res.inactive}")
                if res.coverage_status != 'Standalone':
                    print(f" - COVERED: {res.coverage_status} → {res.coverage_reason}")
                print(f" - Result: {res.signal_priority} ({res.signal_reason})\n")

    print(f"\nWrote: {out_path}")

if __name__ == "__main__":
    main()
