#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
Domain Complexity Scanner (v3.1.1)

Fixes:
- Redirect inclusion now ignores same-apex/self redirects (e.g., bjs.com -> www.bjs.com).
- "Included" only if redirect ends at a *different* covered apex, or if a subdomain redirects to a covered apex.
- Subdomain inclusion remains: any subdomain of a covered apex is Included.

Features kept:
- No-browser HTTP/portal probing
- Redirect walking (no JS)
- CT (optional), breach stub (optional)
- Flexible flags, robust CSV IO, --explain

Deps:
  pip3 install dnspython tldextract httpx
"""

import argparse
import csv
import re
import sys
import time
from dataclasses import dataclass, field
from typing import List, Optional, Tuple, Set, Dict

import dns.resolver
import httpx

try:
    import tldextract  # robust apex parsing
except Exception:
    tldextract = None

VERSION = "v3.1.1"

# ---------- utils ----------

def normalize_host(s: str) -> str:
    return (s or "").strip().strip(".").lower()

def apex_of(host: str) -> str:
    h = normalize_host(host)
    if tldextract:
        try:
            ext = tldextract.extract(h)
            apex = getattr(ext, "top_domain_under_public_suffix", None) or ext.registered_domain
            return (apex or h).lower()
        except Exception:
            pass
    parts = h.split(".")
    return ".".join(parts[-2:]) if len(parts) >= 2 else h

def strip_www(host: str) -> str:
    h = normalize_host(host)
    return h[4:] if h.startswith("www.") else h

# ---------- models ----------

@dataclass
class Row:
    domain: str
    primary: bool = False

@dataclass
class Result:
    host: str
    apex: str
    included_via_subdomain: bool = False
    included_via_redirect: bool = False
    included_reason: Optional[str] = None
    redirect_target: Optional[str] = None
    redirect_chain: List[str] = field(default_factory=list)

    mx_present: bool = False
    spf: Optional[str] = None
    dkim_found: bool = False
    dmarc_policy: Optional[str] = None
    dnssec: Optional[bool] = None
    mail_vendors: List[str] = field(default_factory=list)

    http_present: bool = False
    http_status: Optional[int] = None
    portal_signal: bool = False

    ct_count: Optional[int] = None
    breach_flag: Optional[bool] = None

    score: int = 0
    signal_priority: str = "Low"
    priority_reason: str = ""
    explain_reasons: List[str] = field(default_factory=list)

# ---------- DNS helpers ----------

def dns_txt(domain: str) -> List[str]:
    vals = []
    try:
        for rr in dns.resolver.resolve(domain, "TXT", lifetime=4.0):
            try:
                vals.append(b"".join(rr.strings).decode("utf-8", "ignore"))
            except Exception:
                vals.append(str(rr))
    except Exception:
        pass
    return vals

def lookup_mx(domain: str) -> List[str]:
    out = []
    try:
        for rr in dns.resolver.resolve(domain, "MX", lifetime=4.0):
            out.append(str(rr.exchange).rstrip(".").lower())
    except Exception:
        pass
    return out

def has_dnssec(domain: str) -> Optional[bool]:
    try:
        for rtype in ("DNSKEY", "DS"):
            try:
                _ = dns.resolver.resolve(domain, rtype, lifetime=3.0)
                return True
            except Exception:
                continue
        return False
    except Exception:
        return None

# ---------- Mail policy ----------

def parse_spf(txts: List[str]) -> Optional[str]:
    for t in txts:
        if t.lower().startswith("v=spf1"):
            return t
    return None

def find_dkim(domain: str) -> bool:
    for sel in ["default","selector1","selector2","google","s1","s2"]:
        name = f"{sel}._domainkey.{domain}"
        try:
            _ = dns.resolver.resolve(name, "TXT", lifetime=2.5)
            return True
        except Exception:
            continue
    return False

def dmarc_policy(domain: str) -> Optional[str]:
    for t in dns_txt(f"_dmarc.{domain}"):
        if t.lower().startswith("v=dmarc1"):
            m = re.search(r"\bp\s*=\s*([a-zA-Z]+)", t, re.I)
            return m.group(1).lower() if m else "unknown"
    return None

def mx_vendor_hint(mx_hosts: List[str]) -> List[str]:
    vendors = set()
    for h in mx_hosts:
        if "pphost" in h or "proofpoint" in h:
            vendors.add("proofpoint")
        elif "mimecast" in h:
            vendors.add("mimecast")
        elif "mail.protection.outlook.com" in h or "outlook" in h or "microsoft" in h:
            vendors.add("microsoft")
        elif "google" in h or "gmail" in h or "googlemail" in h:
            vendors.add("google")
        elif "barracuda" in h:
            vendors.add("barracuda")
    return sorted(vendors)

# ---------- HTTP / redirect ----------

DEFAULT_PATHS = ["/", "/login", "/signin", "/sign-in", "/account", "/cart", "/checkout"]

def try_http_targets(host: str, insecure: bool, client: httpx.Client, paths: List[str]):
    http_present, last_status, portal_signal = False, None, False
    for base in (host, f"www.{host}"):
        for scheme in ("https://", "http://"):
            for path in paths:
                url = f"{scheme}{base}{path}"
                try:
                    r = client.head(url, follow_redirects=False)
                    http_present = True
                    last_status = r.status_code
                    if path in ("/login","/signin","/sign-in","/account","/cart","/checkout"):
                        if r.status_code in (200,301,302,303,307,308,401,403):
                            portal_signal = True
                    if r.status_code >= 400:
                        r2 = client.get(url, follow_redirects=False)
                        http_present = True
                        last_status = r2.status_code
                        if path in ("/login","/signin","/sign-in","/account","/cart","/checkout"):
                            if r2.status_code in (200,301,302,303,307,308,401,403):
                                portal_signal = True
                except Exception:
                    continue
    return http_present, last_status, portal_signal

def detect_redirect_chain(host: str, insecure: bool, paths: Optional[List[str]] = None, max_hops: int = 8, timeout: float = 6.0):
    """
    Returns (final_host, chain_urls). final_host is a hostname (no scheme/path).
    """
    verify = not insecure
    chain: List[str] = []
    client = httpx.Client(timeout=timeout, verify=verify, headers={"User-Agent": "domain-scanner/3.1.1"})
    try:
        start_paths = paths or ["/"]
        starts = []
        for base in (host, f"www.{host}"):
            for scheme in ("https://","http://"):
                for p in start_paths:
                    starts.append(f"{scheme}{base}{p}")

        for start in starts:
            url = start
            chain.clear()
            seen = set()
            hops = 0
            while hops < max_hops:
                if url in seen: break
                seen.add(url)
                chain.append(url)
                try:
                    r = client.get(url, follow_redirects=False)
                except Exception:
                    break
                if r.is_redirect:
                    loc = r.headers.get("location", "")
                    if not loc:
                        break
                    url = str(httpx.URL(url).join(loc))
                    hops += 1
                    continue
                # end: return host portion
                u = httpx.URL(url)
                return normalize_host(u.host or ""), chain[:]
        return None, chain[:]
    finally:
        client.close()

# ---------- Inclusion logic (fixed) ----------

def is_included_by_coverage(host: str, monitored_apexes: Set[str], redirect_target: Optional[str]) -> Tuple[bool, Optional[str], bool, bool]:
    """
    Returns (included, reason, via_subdomain, via_redirect)
    Rules:
      1) Subdomain of a covered apex => Included.
      2) Redirect to a *different* covered apex => Included via redirect.
      3) Ignore self/same-apex redirects (e.g., apex -> www.apex) for inclusion.
      4) If a subdomain redirects to its (covered) apex, it's Included anyway via (1).
    """
    h = normalize_host(host)
    a = apex_of(h)

    # (1) Subdomain of covered apex
    if h != a and a in monitored_apexes:
        return True, f"Subdomain of covered apex {a}", True, False

    # (2) Redirect-based inclusion
    if redirect_target:
        rt = normalize_host(redirect_target)
        rt_apex = apex_of(rt)

        # Same-apex/self redirects should NOT cause inclusion if source is the apex.
        if rt_apex == a:
            # If source is apex (e.g., bjs.com -> www.bjs.com), ignore.
            if h == a:
                return False, None, False, False
            # If source is subdomain, it's already covered by (1) above.
            return True, f"Subdomain redirects to covered apex {rt_apex}", True, True

        # Different apex: include if the destination apex is covered
        if rt_apex in monitored_apexes:
            if rt == rt_apex:
                return True, f"Redirects to covered apex {rt_apex}", False, True
            return True, f"Redirects to host under covered apex {rt_apex}", False, True

    return False, None, False, False

# ---------- CT / breach stubs ----------

def fetch_ct_count(domain: str, timeout: float = 6.0) -> Optional[int]:
    try:
        url = f"https://crt.sh/?q=%25.{domain}&output=json"
        with httpx.Client(timeout=timeout) as c:
            r = c.get(url)
            if r.status_code != 200:
                return None
            try:
                data = r.json()
                return len(data) if isinstance(data, list) else None
            except Exception:
                return r.text.count("{")
    except Exception:
        return None

def breach_stub(domain: str) -> Optional[bool]:
    return None

# ---------- Scoring ----------

def score_result(res: Result, primary: bool, vertical: str):
    reasons = res.explain_reasons

    if res.included_reason:
        res.signal_priority = "Included"
        res.priority_reason = res.included_reason
        res.score = 0
        return

    if primary:
        res.score += 8; reasons.append("+8 Primary brand domain")

    if res.mx_present:
        res.score += 4; reasons.append("+4 MX present")
        if res.spf:
            if "~all" in res.spf:
                res.score += 1; reasons.append("+1 SPF ~all (soft fail)")
            elif "-all" in res.spf:
                res.score += 2; reasons.append("+2 SPF -all (hard fail)")
        if res.dkim_found:
            res.score += 2; reasons.append("+2 DKIM discovered")
        if res.dmarc_policy is None:
            res.score += 3; reasons.append("+3 No DMARC")
        elif res.dmarc_policy in ("none","quarantine"):
            res.score += 1; reasons.append("+1 DMARC p=" + res.dmarc_policy)
    else:
        res.score -= 2; reasons.append("-2 No MX (email risk dampened)")

    if res.dnssec is False:
        res.score += 1; reasons.append("+1 DNSSEC absent")

    if res.mail_vendors:
        res.score += 1; reasons.append(f"+1 Mail vendors {res.mail_vendors}")

    if res.http_present:
        res.score += 3; reasons.append("+3 Active HTTP endpoint")
    if res.portal_signal:
        res.score += 5; reasons.append("+5 Retail/portal paths present")

    if res.ct_count is not None:
        if res.ct_count >= 200:
            res.score += 3; reasons.append("+3 High CT cert footprint")
        elif res.ct_count >= 50:
            res.score += 2; reasons.append("+2 Moderate CT cert footprint")
        elif res.ct_count >= 10:
            res.score += 1; reasons.append("+1 Low CT cert footprint")

    if res.breach_flag:
        res.score += 3; reasons.append("+3 Breach footprint elevated")

    if res.score >= 12:
        res.signal_priority = "High"
    elif res.score >= 8:
        res.signal_priority = "Medium"
    else:
        res.signal_priority = "Low"

    res.priority_reason = f"score={res.score} → {res.signal_priority}; " + "; ".join(reasons)

# ---------- CSV I/O ----------

def load_input_csv(path: str) -> List[Row]:
    rows: List[Row] = []
    with open(path, "r", newline="", encoding="utf-8") as f:
        for cols in csv.reader(f):
            if not cols: continue
            host = normalize_host(cols[0])
            if not host: continue
            primary = bool(len(cols) > 1 and str(cols[1]).strip().upper().startswith("Y"))
            rows.append(Row(domain=host, primary=primary))
    return rows

def write_output_csv(path: str, results: List[Result]):
    headers = [
        "host","apex","signal_priority","priority_reason",
        "included_via_subdomain","included_via_redirect","included_reason",
        "redirect_target","redirect_chain",
        "mx_present","spf","dkim_found","dmarc_policy","dnssec","mail_vendors",
        "http_present","http_status","portal_signal",
        "ct_count","breach_flag",
        "score"
    ]
    with open(path, "w", newline="", encoding="utf-8") as f:
        w = csv.writer(f)
        w.writerow(headers)
        for r in results:
            w.writerow([
                r.host, r.apex, r.signal_priority, r.priority_reason,
                r.included_via_subdomain, r.included_via_redirect, r.included_reason or "",
                r.redirect_target or "", " -> ".join(r.redirect_chain),
                r.mx_present, r.spf or "", r.dkim_found, r.dmarc_policy or "", r.dnssec, ",".join(r.mail_vendors),
                r.http_present, r.http_status or "", r.portal_signal,
                r.ct_count if r.ct_count is not None else "", r.breach_flag if r.breach_flag is not None else "",
                r.score
            ])

# ---------- main ----------

def main():
    ap = argparse.ArgumentParser(description=f"Domain Complexity Scanner {VERSION}")
    ap.add_argument("--in", dest="infile", required=True, help="Input CSV: domain[,Y]")
    ap.add_argument("--vertical", default="other", choices=["retail","saas","finance","other"])
    ap.add_argument("--with-http", action="store_true", help="Probe HTTP endpoints & portal paths")
    ap.add_argument("--check-redirects", action="store_true", help="Walk 30x chains to find final host")
    ap.add_argument("--with-ct", action="store_true", help="Add CT (crt.sh) footprint weighting")
    ap.add_argument("--with-breach", action="store_true", help="Add breach footprint (placeholder)")
    ap.add_argument("--insecure", action="store_true", help="Skip TLS verification on HTTP probes")
    ap.add_argument("--debug", action="store_true", help="Verbose debug")
    ap.add_argument("--explain", nargs="*", help="Show explain for specific host(s)")
    args = ap.parse_args()

    print(f"[Domain Scanner] {VERSION}")

    rows = load_input_csv(args.infile)
    if not rows:
        print("No rows found.", file=sys.stderr)
        sys.exit(2)

    monitored_apexes: Set[str] = {apex_of(r.domain) for r in rows if r.domain}
    primary_map: Dict[str, bool] = {normalize_host(r.domain): r.primary for r in rows}

    http_client = None
    if args.with_http or args.check_redirects:
        http_client = httpx.Client(
            timeout=6.0,
            verify=not args.insecure,
            headers={"User-Agent": "domain-scanner/3.1.1"}
        )

    results: List[Result] = []
    started = time.time()

    try:
        for r in rows:
            host = normalize_host(r.domain)
            apex = apex_of(host)
            res = Result(host=host, apex=apex)

            # Redirect target/chain
            if args.check_redirects:
                rt, chain = detect_redirect_chain(host, args.insecure, paths=["/"])
                res.redirect_target, res.redirect_chain = rt, chain

            # Inclusion decision (fixed)
            inc, reason, via_sub, via_redir = is_included_by_coverage(host, monitored_apexes, res.redirect_target)
            if inc:
                res.included_reason = reason
                res.included_via_subdomain = via_sub
                res.included_via_redirect = via_redir

            # DNS/Mail posture
            mx_hosts = lookup_mx(host)
            res.mx_present = bool(mx_hosts)
            res.mail_vendors = mx_vendor_hint(mx_hosts)
            res.spf = parse_spf(dns_txt(host))
            res.dkim_found = find_dkim(host)
            res.dmarc_policy = dmarc_policy(host)
            res.dnssec = has_dnssec(host)

            # HTTP / portal
            if args.with_http and http_client:
                hp, status, portal = try_http_targets(host, args.insecure, http_client, DEFAULT_PATHS)
                res.http_present, res.http_status, res.portal_signal = hp, status, portal

            # CT / breach
            if args.with_ct:
                res.ct_count = fetch_ct_count(host)
            if args.with_breach:
                res.breach_flag = breach_stub(host)

            # Score & label
            score_result(res, primary=primary_map.get(host, False), vertical=args.vertical)

            # Explain (optional)
            if args.explain and (host in [normalize_host(h) for h in args.explain]):
                print(f"\n[Explain] host={host}")
                print(f" - apex(host)={apex}")
                print(f" - monitored apexes={sorted(monitored_apexes)}")
                print(f" - included_via_subdomain={res.included_via_subdomain}")
                print(f" - redirect_target={res.redirect_target or ''}")
                print(f" - included_via_redirect={res.included_via_redirect}")
                if res.included_reason:
                    print(f" - included_reason={res.included_reason}")
                print(f" - http_present={res.http_present}, http_status={res.http_status}, portal_signal={res.portal_signal}")
                print(f" - mx_present={res.mx_present}, spf={'yes' if res.spf else 'no'}, dkim={res.dkim_found}, dmarc={res.dmarc_policy}, dnssec={res.dnssec}")
                print(f" - mail_vendors={res.mail_vendors}")
                if args.with_ct: print(f" - ct_count={res.ct_count}")
                if args.with_breach: print(f" - breach_flag={res.breach_flag}")
                print(f" - Result: {res.signal_priority} ({res.priority_reason or 'n/a'})")

            results.append(res)

    finally:
        if http_client:
            http_client.close()

    out = f"{args.infile.rsplit('.',1)[0]}_results.csv"
    write_output_csv(out, results)
    print(f"\nWrote: {out}")
    if args.debug:
        print(f"Processed {len(rows)} domains in {time.time()-started:.1f}s")

if __name__ == "__main__":
    main()
