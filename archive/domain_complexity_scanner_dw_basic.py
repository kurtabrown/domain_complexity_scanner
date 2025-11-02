#!/usr/bin/env python3
"""
Domain Attack Surface Complexity Scanner (dark-web signal weighted) + Reasons
Robust version: auto output name, DNS timeouts, per-domain error reporting, --debug.

Usage:
  python3 domain_complexity_scanner_dw.py --in domains.txt [--with-ct] [--debug]
  -> writes domains_results.csv
"""

import argparse, csv, os, sys, logging, random, string, traceback
from dataclasses import dataclass, asdict
from typing import List, Optional, Tuple

# ---- Dependencies ----
try:
    import dns.resolver
except Exception as e:
    sys.stderr.write("FATAL: dnspython missing. Install with: python3 -m pip install dnspython httpx\n")
    raise

try:
    import httpx  # optional for --with-ct
except Exception:
    httpx = None

# ---- Logging ----
LOG = logging.getLogger("domain_scanner")

# ---- DNS resolver with short timeouts (avoid silent hangs) ----
RESOLVER = dns.resolver.Resolver(configure=True)
RESOLVER.lifetime = 3.0   # total seconds per query
RESOLVER.timeout  = 2.0   # per try

def q_txt(name: str) -> List[str]:
    try:
        answers = RESOLVER.resolve(name, "TXT")
        return ["".join([p.decode("utf-8", "ignore") for p in r.strings]) for r in answers]
    except Exception as e:
        LOG.debug("TXT %s -> %s", name, e)
        return []

def q_any(name: str, rtype: str) -> List[str]:
    try:
        answers = RESOLVER.resolve(name, rtype)
        return [str(r.to_text()) for r in answers]
    except Exception as e:
        LOG.debug("%s %s -> %s", rtype, name, e)
        return []

def has_ds(domain: str) -> bool:
    return len(q_any(domain, "DS")) > 0

def is_wildcard(domain: str) -> bool:
    rand = ''.join(random.choices(string.ascii_lowercase + string.digits, k=12))
    test = f"{rand}.{domain}"
    return bool(q_any(test, "A") or q_any(test, "AAAA") or q_any(test, "CNAME"))

# ---- Parsers / detectors ----
def parse_spf(txts: List[str]):
    spfs = [t for t in txts if t.lower().startswith("v=spf1")]
    if not spfs:
        return {"present": False}
    spf = spfs[0]
    mech = spf.split()
    include = [m.split(":",1)[1] for m in mech if m.startswith("include:")]
    all_mech = [m for m in mech if m.endswith("all")]
    qualifiers = [m[0] if m and m[0] in ['+','~','-','?'] else '+' for m in all_mech]
    risky_all = any(q in ['+','?'] for q in qualifiers)
    return {"present": True, "includes": include, "all_qualifier": qualifiers[0] if qualifiers else None, "risky_all": risky_all}

DKIM_COMMON_SELECTORS = ["default","selector1","selector2","google","sendgrid","mailgun","amazonses"]

def probe_dkim(domain: str, selectors: Optional[List[str]]=None):
    selectors = selectors or DKIM_COMMON_SELECTORS
    hits = {}
    for sel in selectors:
        name = f"{sel}._domainkey.{domain}"
        txts = q_txt(name)
        if txts:
            hits[sel] = txts
    return {"any": bool(hits), "selectors_found": list(hits.keys())}

VENDOR_MAP_MX = {
    "google": ["aspmx.l.google.com"],
    "microsoft": ["protection.outlook.com"],
    "proofpoint": ["pphosted.com"],
    "mimecast": ["mimecast.com"],
    "zoho": ["zoho.com"],
    "mailgun": ["mailgun.org"],
    "sendgrid": ["sendgrid.net"],
}

def map_vendor(value: str, mapping):
    val = value.lower()
    for vendor, needles in mapping.items():
        if any(n in val for n in needles):
            return vendor
    return None

def discover_third_parties(domain: str, spf_info, mx_hosts: List[str]) -> List[str]:
    vendors = set()
    for mx in mx_hosts:
        v = map_vendor(mx, VENDOR_MAP_MX)
        if v: vendors.add(v)
    for inc in spf_info.get("includes", []) or []:
        v = map_vendor(inc, VENDOR_MAP_MX)
        if v: vendors.add(v)
    return sorted(vendors)

RISKY_CNAME_SUFFIXES = [
    ".github.io",".herokuapp.com",".netlify.app",".vercel.app",
    ".s3.amazonaws.com",".cloudfront.net",".azurewebsites.net",".pages.dev",".render.com",".repl.co"
]

def check_cname_targets(domain: str):
    subs = ["www","mail","api","dev","status","cdn","docs"]
    targets = []
    for s in subs:
        fqdn = f"{s}.{domain}"
        cnames = q_any(fqdn, "CNAME")
        for c in cnames:
            tgt = c.strip(".")
            if any(tgt.endswith(suf) for suf in RISKY_CNAME_SUFFIXES):
                targets.append((fqdn, tgt))
    return targets

async def fetch_ct_names(domain: str) -> List[str]:
    if httpx is None:
        return []
    url = f"https://crt.sh/?q=%25.{domain}&output=json"
    try:
        async with httpx.AsyncClient(timeout=20.0) as client:
            r = await client.get(url)
            r.raise_for_status()
            data = r.json()
            names = set()
            for row in data:
                for n in row.get("name_value","").split("\n"):
                    n = n.strip().lstrip("*.") 
                    if n.endswith(domain):
                        names.add(n)
            return sorted(names)
    except Exception as e:
        LOG.debug("CT query failed for %s: %s", domain, e)
        return []

# ---- Data model ----
@dataclass
class DomainFeatures:
    domain: str
    has_mx: bool
    mail_vendors: str
    spf_present: bool
    spf_risky_all: bool
    dkim_any: bool
    dmarc_present: bool
    dmarc_policy: Optional[str]
    dnssec: bool
    wildcard: bool
    risky_cname_count: int
    ct_subdomain_count: int
    priority: str
    priority_reason: str
    signal_priority: str
    signal_priority_reason: str

# ---- Classifiers (with reasons) ----
def classify_priority(f: DomainFeatures):
    score, reasons = 0, []
    if f.has_mx: score += 3; reasons.append("MX present (+3)")
    if f.spf_risky_all: score += 3; reasons.append("SPF risky all (+3)")
    if f.dkim_any: score += 2; reasons.append("DKIM found (+2)")
    if f.dmarc_policy in ("none","quarantine"): score += 1; reasons.append(f"DMARC {f.dmarc_policy} (+1)")
    if f.dmarc_policy == "reject": score -= 1; reasons.append("DMARC reject (−1)")
    if not f.dnssec: score += 1; reasons.append("DNSSEC absent (+1)")
    if f.wildcard: score += 2; reasons.append("Wildcard (+2)")
    if f.risky_cname_count: score += 2; reasons.append("Risky CNAME (+2)")
    if f.ct_subdomain_count >= 50: score += 3; reasons.append("CT breadth >=50 (+3)")
    elif f.ct_subdomain_count >= 10: score += 2; reasons.append("CT breadth >=10 (+2)")
    label = "High" if score >= 7 else "Medium" if score >= 4 else "Low"
    reasons.insert(0, f"score={score} → {label}")
    return label, "; ".join(reasons)

def classify_signal_priority(f: DomainFeatures):
    score, reasons = 0, []
    if f.has_mx: score += 4; reasons.append("MX present (+4)")
    if not f.spf_present: score += 2; reasons.append("No SPF (+2)")
    if f.spf_risky_all: score += 3; reasons.append("SPF risky all (+3)")
    if not f.dmarc_present: score += 3; reasons.append("No DMARC (+3)")
    elif f.dmarc_policy in ("none","quarantine"): score += 3; reasons.append(f"DMARC {f.dmarc_policy} (+3)")
    elif f.dmarc_policy == "reject": score -= 3; reasons.append("DMARC reject (−3)")
    if not f.dkim_any: score += 1; reasons.append("No DKIM (+1)")
    vendors = [v for v in f.mail_vendors.split(",") if v]
    if vendors:
        bump = min(4, len(set(vendors))); score += bump; reasons.append(f"Vendors {vendors} (+{bump})")
    if f.ct_subdomain_count >= 200: score += 6; reasons.append("CT breadth >=200 (+6)")
    elif f.ct_subdomain_count >= 50: score += 4; reasons.append("CT breadth >=50 (+4)")
    elif f.ct_subdomain_count >= 10: score += 2; reasons.append("CT breadth >=10 (+2)")
    elif f.ct_subdomain_count >= 1: score += 1; reasons.append("CT breadth >=1 (+1)")
    if f.risky_cname_count:
        bump = min(6, 2*f.risky_cname_count); score += bump; reasons.append(f"{f.risky_cname_count} risky CNAMEs (+{bump})")
    if f.wildcard: score += 1; reasons.append("Wildcard (+1)")
    if f.dnssec: score -= 1; reasons.append("DNSSEC present (−1)")
    label = "High" if score >= 12 else "Medium" if score >= 7 else "Low"
    reasons.insert(0, f"score={score} → {label}")
    return label, "; ".join(reasons)

# ---- Analyzer ----
def parse_dmarc(txts: List[str]):
    recs = [t for t in txts if t.lower().startswith("v=dmarc1")]
    if not recs: return False, None
    policy = None
    for part in recs[0].split(";"):
        part = part.strip()
        if part.startswith("p="):
            policy = part.split("=",1)[1].strip()
    return True, policy

async def _ct_count(domain: str) -> int:
    try:
        names = await fetch_ct_names(domain)
        return len(names)
    except Exception as e:
        LOG.debug("CT count error for %s: %s", domain, e)
        return 0

def analyze_domain(domain: str, with_ct=False) -> DomainFeatures:
    d = domain.strip().lower().strip(".")
    mx_records = q_any(d, "MX")
    mx_hosts = [mx.split()[-1].strip(".") for mx in mx_records]
    has_mx = bool(mx_hosts)

    spf_info = parse_spf(q_txt(d))
    dkim_info = probe_dkim(d)
    dmarc_present, dmarc_policy = parse_dmarc(q_txt(f"_dmarc.{d}"))
    dnssec = has_ds(d)
    wildcard = is_wildcard(d)
    risky_cnames = check_cname_targets(d)

    ct_count = 0
    if with_ct and httpx is not None:
        import asyncio
        try:
            ct_count = asyncio.run(_ct_count(d))
        except Exception as e:
            LOG.debug("asyncio.run failed on CT for %s: %s", d, e)
            ct_count = 0

    vendors = discover_third_parties(d, spf_info, mx_hosts)

    f = DomainFeatures(
        domain=d,
        has_mx=has_mx,
        mail_vendors=",".join(vendors),
        spf_present=spf_info.get("present", False),
        spf_risky_all=spf_info.get("risky_all", False),
        dkim_any=dkim_info.get("any", False),
        dmarc_present=dmarc_present,
        dmarc_policy=dmarc_policy,
        dnssec=dnssec,
        wildcard=wildcard,
        risky_cname_count=len(risky_cnames),
        ct_subdomain_count=ct_count,
        priority="",
        priority_reason="",
        signal_priority="",
        signal_priority_reason=""
    )

    p_label, p_reason = classify_priority(f)
    s_label, s_reason = classify_signal_priority(f)
    f.priority, f.priority_reason = p_label, p_reason
    f.signal_priority, f.signal_priority_reason = s_label, s_reason
    return f

# ---- CLI ----
def main():
    ap = argparse.ArgumentParser(description="Domain Attack Surface Scanner (robust)")
    ap.add_argument("--in", dest="infile", required=True, help="Path to domains file")
    ap.add_argument("--with-ct", action="store_true", help="Query CT logs (slower)")
    ap.add_argument("--debug", action="store_true", help="Verbose debug logging")
    args = ap.parse_args()

    logging.basicConfig(
        level=logging.DEBUG if args.debug else logging.INFO,
        format="%(levelname)s: %(message)s"
    )

    infile = args.infile
    if not os.path.isfile(infile):
        sys.stderr.write(f"FATAL: input file not found: {infile}\n")
        sys.exit(2)

    base, _ = os.path.splitext(infile)
    outfile = f"{base}_results.csv"

    try:
        with open(infile, "r", encoding="utf-8") as fh:
            domains = [d.strip() for d in fh if d.strip() and not d.startswith("#")]
    except Exception as e:
        sys.stderr.write(f"FATAL: unable to read {infile}: {e}\n")
        sys.exit(2)

    fields = [f.name for f in DomainFeatures.__dataclass_fields__.values()]
    wrote = 0
    try:
        with open(outfile, "w", newline="", encoding="utf-8") as f:
            w = csv.DictWriter(f, fieldnames=fields)
            w.writeheader()
            for d in domains:
                try:
                    row = asdict(analyze_domain(d, with_ct=args.with_ct))
                    w.writerow(row); wrote += 1
                except Exception as e:
                    sys.stderr.write(f"ERROR: domain '{d}' failed: {e}\n")
                    LOG.debug("Trace:\n%s", traceback.format_exc())
                    w.writerow({"domain": d, "priority": "Error", "priority_reason": "Exception",
                                "signal_priority": "Error", "signal_priority_reason": "Exception"})
        print(f"Wrote results for {wrote} domains to {outfile}")
    except Exception as e:
        sys.stderr.write(f"FATAL: unable to write {outfile}: {e}\n")
        sys.exit(2)

if __name__ == "__main__":
    main()
