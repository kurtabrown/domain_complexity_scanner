
#!/usr/bin/env python3
"""
Domain Attack Surface Complexity Scanner (starter script)
--------------------------------------------------------
- Inputs: a newline-separated list of domains (e.g., domains.txt)
- Outputs: CSV with per-domain features and a priority classification.

Requires: Python 3.9+, pip install: dnspython, httpx (optional for CT lookups)
    pip install dnspython httpx

Usage:
    python domain_complexity_scanner.py --in domains.txt --out results.csv [--with-ct]
"""

import argparse
import csv
import random
import re
import socket
import string
from dataclasses import dataclass, asdict
from typing import List, Optional, Tuple, Dict

try:
    import dns.resolver
    import dns.name
    import dns.exception
except Exception as e:
    raise SystemExit("This script requires 'dnspython'. Install with: pip install dnspython") from e

try:
    import httpx  # optional (for Certificate Transparency enumeration)
except Exception:
    httpx = None

# ---------- Helpers ----------

def q_txt(name: str) -> List[str]:
    try:
        answers = dns.resolver.resolve(name, "TXT")
        out = []
        for r in answers:
            # each r.strings may contain multiple quoted chunks
            s = "".join([p.decode("utf-8", "ignore") for p in r.strings])
            out.append(s)
        return out
    except (dns.resolver.NXDOMAIN, dns.resolver.NoAnswer, dns.resolver.LifetimeTimeout, dns.exception.DNSException):
        return []

def q_any(name: str, rtype: str) -> List[str]:
    try:
        answers = dns.resolver.resolve(name, rtype)
        return [str(r.to_text()) for r in answers]
    except (dns.resolver.NXDOMAIN, dns.resolver.NoAnswer, dns.resolver.LifetimeTimeout, dns.exception.DNSException):
        return []

def has_ds(domain: str) -> bool:
    # Presence of DS at parent suggests DNSSEC is configured
    return len(q_any(domain, "DS")) > 0

def is_wildcard(domain: str) -> bool:
    # naive wildcard check: resolve a random subdomain; if it resolves, likely wildcard
    rand = ''.join(random.choices(string.ascii_lowercase + string.digits, k=16))
    test = f"{rand}.{domain}"
    return bool(q_any(test, "A") or q_any(test, "AAAA") or q_any(test, "CNAME"))

def parse_spf(txts: List[str]) -> Dict[str, object]:
    spfs = [t for t in txts if t.lower().startswith("v=spf1 ") or t.lower() == "v=spf1"]
    if not spfs:
        return {"present": False}
    # Take first SPF (multiple is misconfig); concatenate for analysis
    spf = spfs[0]
    mech = spf.split()
    include = [m.split(":")[1] for m in mech if m.startswith("include:")]
    redirect = [m.split(":")[1] for m in mech if m.startswith("redirect=")]
    all_mech = [m for m in mech if m.endswith("all")]
    qualifiers = [m[0] if m.endswith("all") and m[0] in ['+','~','-','?'] else '+' for m in all_mech]
    risky_all = any(q in ['+','?'] for q in qualifiers)
    # crude DNS-lookup count (RFC 7208): include, a, mx, ptr, exists, redirect (each can trigger lookups)
    lookup_like = sum(m.split(":")[0] in ["include","a","mx","ptr","exists","redirect"] for m in mech)
    return {
        "present": True,
        "record": spf,
        "includes": include,
        "redirect": redirect,
        "lookup_like_count": lookup_like,
        "all_qualifier": qualifiers[0] if qualifiers else None,
        "risky_all": risky_all,
        "mechanism_count": len(mech),
    }

DKIM_COMMON_SELECTORS = [
    "default","selector1","selector2","google","mandrill","mailchimp",
    "sendgrid","s1","s2","smtp","k1","k2","mail","mx","mailgun","amazonses"
]

def probe_dkim(domain: str, selectors: Optional[List[str]]=None) -> Dict[str, object]:
    selectors = selectors or DKIM_COMMON_SELECTORS
    hits = {}
    for sel in selectors:
        name = f"{sel}._domainkey.{domain}"
        txts = q_txt(name)
        if txts:
            hits[sel] = txts
    return {"any": bool(hits), "selectors_found": list(hits.keys()), "records": hits}

VENDOR_MAP_MX = {
    "google": ["aspmx.l.google.com", "google.com"],
    "microsoft": ["outlook.com", "protection.outlook.com", "outlook.office365.com"],
    "proofpoint": ["pphosted.com"],
    "mimecast": ["mimecast.com"],
    "zoho": ["zoho.com"],
    "fastmail": ["fastmail.com"],
    "yahoo": ["yahoodns.net"],
    "icloud": ["icloud.com"],
}

VENDOR_MAP_SPF = {
    "google": ["_spf.google.com"],
    "microsoft": ["spf.protection.outlook.com"],
    "sendgrid": ["sendgrid.net"],
    "mailgun": ["mailgun.org"],
    "amazonses": ["amazonses.com"],
    "mandrill": ["mandrillapp.com"],
    "hubspot": ["hubspotemail.net"],
    "sparkpost": ["sparkpostmail.com"],
    "mailchimp": ["servers.mcsv.net","mailchimp.com"],
}

RISKY_CNAME_SUFFIXES = [
    # dangling/SaaS takeovers (non-exhaustive)
    ".aws.amazon.com", ".amazonaws.com", ".cloudfront.net", ".s3.amazonaws.com",
    ".azurewebsites.net", ".blob.core.windows.net", ".trafficmanager.net",
    ".github.io", ".herokuapp.com", ".fastly.net", ".edgekey.net", ".edgesuite.net",
    ".netlify.app", ".vercel.app", ".pages.dev", ".render.com", ".repl.co",
    ".readme.io", ".wpengine.com", ".zendesk.com", ".shopify.com"
]

def map_vendor(value: str, mapping: Dict[str, List[str]]) -> Optional[str]:
    val = value.lower()
    for vendor, needles in mapping.items():
        for n in needles:
            if n in val:
                return vendor
    return None

def discover_third_parties(domain: str, spf_info: Dict[str, object], mx_hosts: List[str]) -> List[str]:
    vendors = set()
    for mx in mx_hosts:
        v = map_vendor(mx, VENDOR_MAP_MX)
        if v: vendors.add(v)
    for inc in spf_info.get("includes", []) or []:
        v = map_vendor(inc, VENDOR_MAP_SPF)
        if v: vendors.add(v)
    return sorted(vendors)

def check_caa(domain: str) -> List[str]:
    return q_any(domain, "CAA")

def check_cname_targets(domain: str) -> List[Tuple[str,str]]:
    # Probe a few common subdomains for potential dangling CNAMEs
    targets = []
    subs = ["www", "mail", "m", "blog", "status", "docs", "dev", "api", "cdn"]
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
    # crt.sh supports simple JSON output (undocumented but widely used)
    url = f"https://crt.sh/?q=%25.{domain}&output=json"
    try:
        async with httpx.AsyncClient(timeout=20.0) as client:
            r = await client.get(url)
            r.raise_for_status()
            data = r.json()
            names = set()
            for row in data:
                name_value = row.get("name_value", "")
                for n in name_value.split("\n"):
                    n = n.strip().lstrip("*.")
                    if n.endswith(domain):
                        names.add(n)
            return sorted(names)
    except Exception:
        return []

@dataclass
class DomainFeatures:
    domain: str
    has_mx: bool
    mx_hosts: str
    mail_vendors: str
    spf_present: bool
    spf_all: Optional[str]
    spf_risky_all: bool
    spf_lookup_like_count: int
    dkim_any: bool
    dkim_selectors: str
    dmarc_present: bool
    dmarc_policy: Optional[str]
    dmarc_rua_external: bool
    dnssec: bool
    caa_present: bool
    wildcard: bool
    risky_cname_count: int
    risky_cnames: str
    ct_subdomain_count: int
    # priority is derived at the end
    priority: str

def parse_dmarc(txts: List[str]) -> Tuple[bool, Optional[str], bool]:
    recs = [t for t in txts if t.lower().startswith("v=dmarc1")]
    if not recs:
        return False, None, False
    r = recs[0]
    # extract p= and rua=
    p = None
    rua_external = False
    parts = r.split(";")
    for part in parts:
        part = part.strip()
        if part.startswith("p="):
            p = part.split("=",1)[1].strip()
        if part.startswith("rua="):
            val = part.split("=",1)[1].strip()
            # rua can contain multiple mailto:, check domains external to org
            addrs = [a.replace("mailto:","").strip() for a in val.split(",")]
            # external if any addr domain not matching base domain
            for addr in addrs:
                if "@" in addr:
                    _, dom = addr.split("@",1)
                    if not dom.endswith(dom):  # placeholder, compute below
                        pass
    # To compute external, we need the base domain; will handle outside
    return True, p, False

def dmarc_external_rua(domain: str, txts: List[str]) -> bool:
    recs = [t for t in txts if t.lower().startswith("v=dmarc1")]
    if not recs:
        return False
    r = recs[0]
    parts = r.split(";")
    ext = False
    for part in parts:
        part = part.strip()
        if part.startswith("rua="):
            val = part.split("=",1)[1].strip()
            addrs = [a.replace("mailto:","").strip() for a in val.split(",") if a.strip()]
            for addr in addrs:
                if "@" in addr:
                    _, dom = addr.split("@",1)
                    if not dom.endswith(domain):
                        ext = True
    return ext

def classify_priority(f: DomainFeatures) -> str:
    score = 0
    # Mail surface
    if f.has_mx: score += 3
    if f.spf_present and f.spf_risky_all: score += 3
    if f.dkim_any: score += 2
    if f.dmarc_present and f.dmarc_policy in ("none","quarantine"): score += 1
    if f.dmarc_present and f.dmarc_policy == "reject": score -= 1

    # DNS posture
    if not f.dnssec: score += 1
    if f.wildcard: score += 2
    if f.caa_present: score -= 1  # presence is hygiene
    if f.risky_cname_count > 0: score += min(3, f.risky_cname_count)

    # Third parties increase surface
    vendors = (f.mail_vendors or "").split(",")
    vendors = [v for v in vendors if v]
    score += min(3, len(set(vendors)))

    # Subdomain breadth
    if f.ct_subdomain_count >= 50: score += 3
    elif f.ct_subdomain_count >= 10: score += 2
    elif f.ct_subdomain_count >= 1: score += 1

    # Heuristic thresholds
    if score >= 7: return "High"
    if score >= 4: return "Medium"
    return "Low"

def analyze_domain(domain: str, with_ct: bool=False) -> DomainFeatures:
    domain = domain.strip().lower().strip(".")
    if not domain: raise ValueError("empty domain")

    mx_records = q_any(domain, "MX")
    mx_hosts = [mx.split()[-1].strip(".") for mx in mx_records] if mx_records else []
    has_mx = len(mx_hosts) > 0
    mail_vendors = discover_third_parties(domain, {"includes": []}, mx_hosts)

    spf_txts = q_txt(domain)
    spf_info = parse_spf(spf_txts)
    if spf_info.get("present"):
        # Update vendors based on SPF includes
        for v in discover_third_parties(domain, spf_info, []):
            if v not in mail_vendors:
                mail_vendors.append(v)

    dkim_info = probe_dkim(domain)

    dmarc_txts = q_txt(f"_dmarc.{domain}")
    dmarc_present, dmarc_policy, _ = parse_dmarc(dmarc_txts)
    dmarc_external = dmarc_external_rua(domain, dmarc_txts)

    caa = check_caa(domain)
    wildcard = is_wildcard(domain)
    dnssec = has_ds(domain)
    risky_cnames = check_cname_targets(domain)
    ct_count = 0
    if with_ct:
        # optional and slow; skip when httpx not available
        try:
            import asyncio
            if httpx is not None:
                ct_names = asyncio.get_event_loop().run_until_complete(fetch_ct_names(domain))
                ct_count = len(ct_names)
        except Exception:
            ct_count = 0

    features = DomainFeatures(
        domain=domain,
        has_mx=has_mx,
        mx_hosts=";".join(mx_hosts),
        mail_vendors=",".join(mail_vendors),
        spf_present=bool(spf_info.get("present")),
        spf_all=spf_info.get("all_qualifier"),
        spf_risky_all=bool(spf_info.get("risky_all")),
        spf_lookup_like_count=int(spf_info.get("lookup_like_count",0)),
        dkim_any=bool(dkim_info.get("any")),
        dkim_selectors=",".join(dkim_info.get("selectors_found", [])),
        dmarc_present=dmarc_present,
        dmarc_policy=dmarc_policy,
        dmarc_rua_external=dmarc_external,
        dnssec=dnssec,
        caa_present=bool(caa),
        wildcard=wildcard,
        risky_cname_count=len(risky_cnames),
        risky_cnames=";".join([f"{h}->{t}" for h,t in risky_cnames]),
        ct_subdomain_count=ct_count,
        priority="",
    )
    features.priority = classify_priority(features)
    return features

def main():
    parser = argparse.ArgumentParser(description="Domain Attack Surface Complexity Scanner")
    parser.add_argument("--in", dest="infile", required=True, help="Path to domains.txt (one domain per line)")
    parser.add_argument("--out", dest="outfile", required=True, help="Path to write results CSV")
    parser.add_argument("--with-ct", action="store_true", help="Also query Certificate Transparency (crt.sh) to estimate subdomain breadth")
    args = parser.parse_args()

    domains = []
    with open(args.infile, "r", encoding="utf-8") as f:
        for line in f:
            d = line.strip()
            if d and not d.startswith("#"):
                domains.append(d)

    fields = [f.name for f in DomainFeatures.__dataclass_fields__.values()]
    rows = []
    for d in domains:
        try:
            feat = analyze_domain(d, with_ct=args.with_ct)
            rows.append(asdict(feat))
        except Exception as e:
            rows.append({
                "domain": d, "priority": "Error",
                "has_mx": False, "mx_hosts": "", "mail_vendors": "",
                "spf_present": False, "spf_all": None, "spf_risky_all": False,
                "spf_lookup_like_count": 0, "dkim_any": False, "dkim_selectors": "",
                "dmarc_present": False, "dmarc_policy": None, "dmarc_rua_external": False,
                "dnssec": False, "caa_present": False, "wildcard": False,
                "risky_cname_count": 0, "risky_cnames": "", "ct_subdomain_count": 0
            })

    with open(args.outfile, "w", newline="", encoding="utf-8") as f:
        writer = csv.DictWriter(f, fieldnames=fields)
        writer.writeheader()
        for r in rows:
            writer.writerow(r)

    print(f"Wrote {len(rows)} rows to {args.outfile}")

if __name__ == "__main__":
    main()
