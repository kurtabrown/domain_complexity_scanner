#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
Domain Complexity Scanner — v2.0.5 (no-browser + robust CSV + portal paths)

What’s in this build:
- Robust CSV parsing:
  * Works with headered or headerless CSV.
  * Safely falls back to comma if csv.Sniffer() can’t determine delimiter.
  * Accepts one or two columns; single-column rows default primary=N.
- Always-on HTTP probing and simple redirect detection (HEAD/GET Location).
- Portal detection:
  * Treat 200/3xx/401/403/405 on retail-ish paths as portal evidence.
  * Logs which paths hit in --explain.
- “Included” coverage:
  * If a subdomain is covered by a monitored apex in the input set → priority=Included.
  * If a domain redirects into another monitored apex → priority=Included.
- Inactive penalty: if no DNS A/AAAA/CNAME and no HTTP presence → signal −5 and nudge priority down.
- Email scoring: MX (+3), DKIM (+2). DMARC present is recorded but neutral to score.
- Reduced SPF/DMARC influence when no MX (−2 dampener).
- Auto-named output file: <input>_results.csv
"""

import argparse
import csv
import re
from dataclasses import dataclass, field
from typing import Dict, List, Optional, Tuple, Set

import httpx
import dns.resolver
import dns.exception
import tldextract

# -------------------------
# Tunables / constants
# -------------------------
HTTP_TIMEOUT = 6.0
CONNECT_TIMEOUT = 6.0

PORTAL_PATHS: List[str] = [
    "/login", "/signin", "/sign-in",
    "/account", "/myaccount",
    "/cart", "/basket", "/checkout"
]
PORTAL_POSITIVE_CODES: Set[int] = {200, 301, 302, 303, 307, 308, 401, 403, 405}

USER_AGENT = "DomainComplexityScanner/2.0.5 (+https://upguard.com/)"

# Weights
WEIGHT_PRIMARY_BRAND = 8
WEIGHT_ACTIVE_HTTP = 3
WEIGHT_ECOSYSTEM_HUB = 2
WEIGHT_PORTAL = 5
WEIGHT_INACTIVE_SIG = -5      # signal penalty for inactive
PRIORITY_INACTIVE_NUDGE = True  # downshift priority if inactive

WEIGHT_MX_PRESENT = 3
WEIGHT_DKIM_PRESENT = 2
WEIGHT_NO_MX_SPFDKIM_DAMPENER = -2  # reduce weight if no MX
# DMARC policy is noted but score-neutral (per earlier request)

INCLUDED_PRIORITY = "Included"
INCLUDED_REASON = "Covered by monitored apex (subdomain or redirect target)"

# -------------------------
# Helpers
# -------------------------
def is_likely_domain(s: str) -> bool:
    if not s or " " in s or "://" in s:
        return False
    # domain labels with a dot, no leading/trailing hyphen on labels
    return bool(re.match(r"^(?!-)[A-Za-z0-9-]+(\.[A-Za-z0-9-]+)+$", s.strip(".")))

def apex_of(host: str) -> str:
    ext = tldextract.extract(host)
    return ext.registered_domain.lower() if ext.registered_domain else host.lower()

def dns_any(host: str) -> Tuple[bool, Dict[str, List[str]]]:
    details: Dict[str, List[str]] = {"A": [], "AAAA": [], "CNAME": []}
    has_any = False
    try:
        for rtype in ("A", "AAAA", "CNAME"):
            try:
                ans = dns.resolver.resolve(host, rtype, lifetime=3.0)
                vals = [r.to_text() for r in ans]
                details[rtype] = vals
                if vals:
                    has_any = True
            except (dns.resolver.NoAnswer, dns.resolver.NXDOMAIN,
                    dns.exception.Timeout, dns.resolver.NoNameservers):
                pass
    except Exception:
        pass
    return has_any, details

def resolve_mx(host: str) -> List[str]:
    try:
        ans = dns.resolver.resolve(host, 'MX', lifetime=4.0)
        return [r.exchange.to_text(omit_final_dot=True).lower() for r in ans]
    except Exception:
        return []

def has_txt(host: str, needle: str) -> bool:
    try:
        ans = dns.resolver.resolve(host, 'TXT', lifetime=4.0)
        for r in ans:
            txt = "".join(
                [p.decode("utf-8") if isinstance(p, bytes) else str(p)
                 for p in getattr(r, "strings", [])]
            ) if hasattr(r, "strings") else r.to_text().strip('"')
            if needle in txt:
                return True
    except Exception:
        return False
    return False

def get_dmarc_policy(host: str) -> Optional[str]:
    dmarc = f"_dmarc.{host}"
    try:
        ans = dns.resolver.resolve(dmarc, 'TXT', lifetime=4.0)
        for r in ans:
            txt = r.to_text().strip('"')
            m = re.search(r"p=([a-zA-Z]+)", txt)
            if m:
                return m.group(1).lower()
    except Exception:
        return None
    return None

def pick_http_targets(host: str) -> List[str]:
    return [
        f"https://{host}",
        f"https://www.{host}",
        f"http://{host}",
        f"http://www.{host}",
    ]

def safe_request(client: httpx.Client, method: str, url: str,
                 allow_redirects: bool = False) -> Optional[httpx.Response]:
    try:
        return client.request(method, url, follow_redirects=allow_redirects,
                              timeout=httpx.Timeout(HTTP_TIMEOUT, connect=CONNECT_TIMEOUT))
    except Exception:
        return None

# -------------------------
# Data classes
# -------------------------
@dataclass
class ProbeOutcome:
    http_present: bool = False
    http_status_any: Optional[int] = None  # any status seen during base GETs
    inactive: bool = False
    redirect_target_host: Optional[str] = None
    redirect_chain_hosts: List[str] = field(default_factory=list)
    portal_signal: bool = False
    portal_hit_paths: List[str] = field(default_factory=list)

@dataclass
class DomainRow:
    host: str
    primary: bool = False

# -------------------------
# HTTP / portal / redirects
# -------------------------
def detect_redirect_target(host: str, insecure: bool) -> Tuple[Optional[str], List[str]]:
    chain: List[str] = []
    with httpx.Client(headers={"User-Agent": USER_AGENT},
                      verify=not insecure) as c:
        for base in pick_http_targets(host):
            for method in ("HEAD", "GET"):
                r = safe_request(c, method, base, allow_redirects=False)
                if not r:
                    continue
                loc = r.headers.get("Location")
                if r.status_code in (301, 302, 303, 307, 308) and loc:
                    try:
                        loc_url = httpx.URL(loc, allow_relative=True)
                        if loc_url.host is None:
                            loc_url = httpx.URL(base).join(loc)
                        chain.append(loc_url.host.lower())
                        return loc_url.host.lower(), chain
                    except Exception:
                        continue
    return None, chain

def probe_http_and_portal(host: str, insecure: bool) -> ProbeOutcome:
    outcome = ProbeOutcome()
    targets = pick_http_targets(host)

    with httpx.Client(headers={"User-Agent": USER_AGENT},
                      verify=not insecure) as c:
        # Check base presence
        for base in targets:
            r = safe_request(c, "GET", base, allow_redirects=False)
            if r:
                outcome.http_present = True
                outcome.http_status_any = r.status_code

        # Portal paths
        for base in targets:
            for path in PORTAL_PATHS:
                url = base.rstrip("/") + path
                for method in ("HEAD", "GET"):
                    r = safe_request(c, method, url, allow_redirects=False)
                    if r and r.status_code in PORTAL_POSITIVE_CODES:
                        outcome.portal_signal = True
                        tag = f"{method} {url} → {r.status_code}"
                        if tag not in outcome.portal_hit_paths:
                            outcome.portal_hit_paths.append(tag)

    # Inactive: no DNS+no HTTP handled by caller after DNS check
    return outcome

# -------------------------
# Scoring / priority
# -------------------------
def score_domain(apex: str,
                 primary: bool,
                 mx: List[str],
                 dkim: bool,
                 dmarc: Optional[str],
                 http_outcome: ProbeOutcome,
                 subdomain_count: int) -> Tuple[str, int, str]:
    score = 0
    reasons: List[str] = []

    if primary:
        score += WEIGHT_PRIMARY_BRAND
        reasons.append(f"Primary brand domain (+{WEIGHT_PRIMARY_BRAND})")

    if http_outcome.http_present:
        score += WEIGHT_ACTIVE_HTTP
        reasons.append(f"Active HTTP endpoint (+{WEIGHT_ACTIVE_HTTP})")

    if http_outcome.portal_signal:
        score += WEIGHT_PORTAL
        reasons.append(f"Retail/portal paths present (+{WEIGHT_PORTAL})")

    if mx:
        score += WEIGHT_MX_PRESENT
        reasons.append(f"MX present (+{WEIGHT_MX_PRESENT})")
        if dkim:
            score += WEIGHT_DKIM_PRESENT
            reasons.append(f"DKIM found (+{WEIGHT_DKIM_PRESENT})")
    else:
        score += WEIGHT_NO_MX_SPFDKIM_DAMPENER
        reasons.append(f"No MX: dampen mail risk ({WEIGHT_NO_MX_SPFDKIM_DAMPENER})")

    if dmarc:
        reasons.append(f"DMARC policy={dmarc} (not counted)")

    if subdomain_count >= 3:
        score += WEIGHT_ECOSYSTEM_HUB
        reasons.append(f"Ecosystem hub with {subdomain_count} subdomains (+{WEIGHT_ECOSYSTEM_HUB})")

    if http_outcome.inactive:
        score += WEIGHT_INACTIVE_SIG
        reasons.append(f"Inactive host ({WEIGHT_INACTIVE_SIG})")

    # Bucket
    if score >= 12:
        prio = "High"
    elif score >= 7:
        prio = "Medium"
    else:
        prio = "Low"

    # Nudge down if inactive
    if PRIORITY_INACTIVE_NUDGE and http_outcome.inactive:
        if prio == "High":
            prio = "Medium"
        elif prio == "Medium":
            prio = "Low"

    return prio, score, "; ".join(reasons)

# -------------------------
# CSV I/O
# -------------------------
def load_input_csv(path: str) -> List[DomainRow]:
    rows: List[DomainRow] = []
    with open(path, newline="", encoding="utf-8") as f:
        sample = f.read(2048)
        f.seek(0)
        # Try to sniff; if it fails, default to comma
        try:
            dialect = csv.Sniffer().sniff(sample)
        except csv.Error:
            dialect = csv.get_dialect("excel")
        reader = csv.reader(f, dialect)

        # Detect header optionally
        peek = next(reader, None)
        if peek is None:
            return rows
        is_header = False
        if len(peek) >= 1:
            h0 = (peek[0] or "").strip().lower()
            if h0 in ("domain", "host", "hostname"):
                is_header = True

        if not is_header:
            # Treat first row as data
            row = [c.strip() for c in peek if c.strip() != ""]
            if row:
                host = row[0].lower()
                primary = False
                if len(row) > 1 and row[1]:
                    primary = row[1].strip().upper().startswith("Y")
                rows.append(DomainRow(host=host, primary=primary))

        # Remaining rows
        for raw in reader:
            if not raw:
                continue
            raw = [c.strip() for c in raw if c.strip() != ""]
            if not raw:
                continue
            host = raw[0].lower()
            primary = False
            if len(raw) > 1 and raw[1]:
                primary = raw[1].strip().upper().startswith("Y")
            rows.append(DomainRow(host=host, primary=primary))
    return rows

def default_out_name(in_path: str) -> str:
    base = in_path[:-4] if in_path.lower().endswith(".csv") else in_path
    return f"{base}_results.csv"

# -------------------------
# Main
# -------------------------
def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--in", dest="infile", required=True,
                    help="Input CSV: domain[,Y] (Y marks primary)")
    ap.add_argument("--insecure", action="store_true",
                    help="Ignore SSL verification errors")
    ap.add_argument("--explain", dest="explain", nargs="*",
                    help="Show verbose reasoning for listed domain(s)")
    args = ap.parse_args()

    rows = load_input_csv(args.infile)
    if not rows:
        print("No rows found in input CSV.", flush=True)
        return

    # Build monitored apex set
    apexes_in_input = {apex_of(r.host) for r in rows}

    outname = default_out_name(args.infile)
    with open(outname, "w", newline="", encoding="utf-8") as outf:
        writer = csv.writer(outf)
        writer.writerow(["domain", "priority", "score", "reason"])

        for row in rows:
            host = row.host
            if not is_likely_domain(host):
                writer.writerow([host, "Medium", 5, "Custom search term"])
                continue

            apex = apex_of(host)

            # DNS & HTTP probe (on apex for signal)
            has_dns, _ = dns_any(apex)
            http_outcome = probe_http_and_portal(apex, args.insecure)

            # Mark inactive if neither DNS nor HTTP
            if not has_dns and not http_outcome.http_present:
                http_outcome.inactive = True

            # Redirect target detection (apex-level)
            redirect_target, chain = detect_redirect_target(apex, args.insecure)
            http_outcome.redirect_target_host = redirect_target
            http_outcome.redirect_chain_hosts = chain

            # Coverage / Included logic
            is_subdomain = (host != apex and host.endswith("." + apex))
            covered_by_apex = (is_subdomain and apex in apexes_in_input)
            redirected_to_monitored_apex = False
            if redirect_target:
                rt_apex = apex_of(redirect_target)
                if rt_apex in apexes_in_input and rt_apex != apex:
                    redirected_to_monitored_apex = True

            if covered_by_apex or redirected_to_monitored_apex:
                priority = INCLUDED_PRIORITY
                score = 0
                reason = INCLUDED_REASON
                if args.explain and host in args.explain:
                    print(f"[Explain] host={host}")
                    print(f" - apex(host)={apex}")
                    print(f" - monitored apexes={sorted(apexes_in_input)}")
                    print(f" - covered_by_apex={covered_by_apex}, redirected_to_monitored_apex={redirected_to_monitored_apex}")
                    print(f" - Result: {priority} ({reason})")
                writer.writerow([host, priority, score, reason])
                continue

            # Email signals (apex)
            mx = resolve_mx(apex)
            dkim = has_txt(apex, "v=DKIM1")
            dmarc = get_dmarc_policy(apex)

            # Ecosystem hub: count siblings under same apex
            subdomain_count = sum(1 for r in rows if apex_of(r.host) == apex and r.host != apex)

            priority, score, reason = score_domain(
                apex=apex,
                primary=row.primary,
                mx=mx,
                dkim=dkim,
                dmarc=dmarc,
                http_outcome=http_outcome,
                subdomain_count=subdomain_count
            )

            if args.explain and host in args.explain:
                print(f"[Explain] host={host}")
                print(f" - apex(host)={apex}")
                print(f" - monitored apexes={sorted(apexes_in_input)}")
                print(f" - portal_signal={http_outcome.portal_signal}")
                if http_outcome.portal_hit_paths:
                    print(" - portal hits:")
                    for hit in http_outcome.portal_hit_paths:
                        print(f"   {hit}")
                print(f" - HTTP present={http_outcome.http_present}, any_status={http_outcome.http_status_any}")
                print(f" - redirect_target={http_outcome.redirect_target_host}, chain={http_outcome.redirect_chain_hosts}")
                print(f" - inactive={http_outcome.inactive}")
                print(f" - MX={bool(mx)} ({mx}), DKIM={dkim}, DMARC={dmarc}")
                print(f" - siblings under apex={subdomain_count}")
                print(f" - Result: {priority} (score={score} → {priority}; {reason})")

            writer.writerow([host, priority, score, reason])

    print(f"Wrote: {outname}")

if __name__ == "__main__":
    main()
