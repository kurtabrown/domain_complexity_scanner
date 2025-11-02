#!/usr/bin/env python3
VERSION = "v1.6.0-apex+explain+httpprobe(paths)+weighted-nomx+psl-offline"

"""
Domain Attack Surface Complexity Scanner
- Apex-aware coverage: subdomains covered under apex; CNAME/HTTP alias -> Included
- Signal scoring: DMARC p=reject ignored; SPF/DMARC weights reduced if no MX
- Optional HTTP probe (--with-http): now scans /, /login, /signin, /auth
- Flexible CSV (headered or headerless). Non-domains => Medium/Medium with reason
- --explain <host> prints coverage and HTTP reasoning for one host and exits
"""

import argparse, csv, os, sys, logging, random, string, re, unicodedata
from dataclasses import dataclass, asdict
from typing import List, Optional, Tuple, Dict

print(f"[Domain Scanner] {VERSION}")

# ----- deps -----
try:
    import dns.resolver
except Exception:
    sys.stderr.write("FATAL: dnspython missing. Install with: python3 -m pip install dnspython httpx tldextract\n")
    raise

try:
    import httpx
except Exception:
    httpx = None

# tldextract with offline PSL snapshot (no network fetch)
try:
    import tldextract
except Exception:
    tldextract = None

_EXTRACTOR = None
if tldextract is not None:
    _EXTRACTOR = tldextract.TLDExtract(
        suffix_list_urls=None,  # use packaged PSL snapshot; no HTTP
        cache_dir=os.path.expanduser("~/.cache/tldextract"),
    )

LOG = logging.getLogger("domain_scanner")

# ----- DNS helpers -----
RESOLVER = dns.resolver.Resolver(configure=True)
RESOLVER.lifetime = 3.0
RESOLVER.timeout  = 2.0

def q_txt(name: str):
    try:
        ans = RESOLVER.resolve(name, "TXT")
        return ["".join([p.decode("utf-8","ignore") for p in r.strings]) for r in ans]
    except Exception as e:
        LOG.debug("TXT %s -> %s", name, e); return []

def q_any(name: str, rtype: str):
    try:
        ans = RESOLVER.resolve(name, rtype)
        return [str(r.to_text()) for r in ans]
    except Exception as e:
        LOG.debug("%s %s -> %s", rtype, name, e); return []

def has_ds(domain: str) -> bool:
    return len(q_any(domain, "DS")) > 0

def is_wildcard(domain: str) -> bool:
    rand = ''.join(random.choices(string.ascii_lowercase + string.digits, k=12))
    test = f"{rand}.{domain}"
    return bool(q_any(test, "A") or q_any(test, "AAAA") or q_any(test, "CNAME"))

# ----- normalization -----
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
    if _EXTRACTOR is not None:
        ext = _EXTRACTOR(host)
        if ext.domain and ext.suffix:
            return f"{ext.domain}.{ext.suffix}".lower()
        return host
    # fallback (not perfect for multi-level TLDs)
    parts = host.split(".")
    return ".".join(parts[-2:]) if len(parts) >= 2 else host

# ----- parsers -----
def parse_spf(txts: List[str]) -> Dict[str, object]:
    spfs = [t for t in txts if t.lower().startswith("v=spf1")]
    if not spfs: return {"present": False}
    spf = spfs[0]; mech = spf.split()
    include = [m.split(":",1)[1] for m in mech if m.startswith("include:")]
    all_mech = [m for m in mech if m.endswith("all")]
    q = [m[0] if m and m[0] in ['+','~','-','?'] else '+' for m in all_mech]
    risky_all = any(x in ['+','?'] for x in q)
    lookup_like = sum(m.split(":")[0] in ["include","a","mx","ptr","exists","redirect"] for m in mech)
    return {"present": True, "includes": include, "all_qualifier": (q[0] if q else None),
            "risky_all": risky_all, "lookup_like_count": lookup_like}

DKIM_COMMON_SELECTORS = [
    "default","selector","selector1","selector2","selector3","google","s1","s2","k1","k2",
    "dkim","dkim1","dkim2","mail","mx","smtp","pp","pp1","pp2","pp3","proof","proofpoint",
    "sendgrid","mailgun","amazonses","mandrill","mailchimp","sparkpost"
] + [f"s{i}" for i in range(1,11)] + [f"selector{i}" for i in range(1,11)]

def probe_dkim(domain: str, selectors=None):
    selectors = selectors or DKIM_COMMON_SELECTORS
    hits = {}
    for sel in selectors:
        name = f"{sel}._domainkey.{domain}"
        txts = q_txt(name)
        if txts: hits[sel] = txts
    return {"any": bool(hits), "selectors_found": list(hits.keys())}

VENDOR_MAP_MX = {
    "google": ["aspmx.l.google.com","google.com"],
    "microsoft": ["protection.outlook.com","outlook.com","office365.com","outlook.office365.com"],
    "proofpoint": ["pphosted.com"],
    "mimecast": ["mimecast.com"],
    "zoho": ["zoho.com"],
    "mailgun": ["mailgun.org"],
    "sendgrid": ["sendgrid.net"],
    "fastmail": ["fastmail.com"],
    "yahoo": ["yahoodns.net"],
}

def map_vendor(value: str, mapping: Dict[str, List[str]]) -> Optional[str]:
    val = value.lower()
    for vendor, needles in mapping.items():
        if any(n in val for n in needles):
            return vendor
    return None

def discover_third_parties(domain: str, spf_info: Dict[str, object], mx_hosts: List[str]) -> List[str]:
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
    ".s3.amazonaws.com",".cloudfront.net",".azurewebsites.net",".pages.dev",".render.com",".repl.co",
    ".wpengine.com",".zendesk.com",".readme.io",".shopify.com",".blob.core.windows.net",".trafficmanager.net"
]

def check_cname_targets(domain: str):
    subs = ["www","mail","api","dev","status","cdn","docs","help","support"]
    targets = []
    for s in subs:
        fqdn = f"{s}.{domain}"
        cn = q_any(fqdn, "CNAME")
        for c in cn:
            tgt = normalize_host(c.strip("."))
            if any(tgt.endswith(suf) for suf in RISKY_CNAME_SUFFIXES):
                targets.append((fqdn, tgt))
    return targets

async def fetch_ct_names(domain: str) -> List[str]:
    if httpx is None: return []
    url = f"https://crt.sh/?q=%25.{domain}&output=json"
    try:
        async with httpx.AsyncClient(timeout=20.0) as client:
            r = await client.get(url); r.raise_for_status()
            data = r.json(); names = set()
            for row in data:
                for n in (row.get("name_value","") or "").split("\n"):
                    n = normalize_host(n).lstrip("*.") 
                    if n.endswith(domain): names.add(n)
            return sorted(names)
    except Exception as e:
        LOG.debug("CT fail %s: %s", domain, e); return []

# ----- coverage (apex-aware) -----
def covered_by_apex(domain: str, input_apexes: List[str]) -> Optional[str]:
    d = normalize_host(domain)
    for apex in input_apexes:
        if d == apex: continue
        if d.endswith("." + apex): return apex
    return None

def resolve_cname_chain(host: str, max_hops=5) -> Optional[str]:
    current = normalize_host(host)
    try:
        for _ in range(max_hops):
            cn = q_any(current, "CNAME")
            if not cn: return current
            nxt = normalize_host(cn[0].strip("."))
            if nxt == current: return current
            current = nxt
        return current
    except Exception as e:
        LOG.debug("CNAME chain fail %s: %s", host, e); return None

def http_canonical_host(domain: str, timeout: float = 4.0) -> Optional[str]:
    if httpx is None: return None
    try:
        with httpx.Client(follow_redirects=True, timeout=timeout,
                          headers={"User-Agent": "UpGuard-Scanner/1.0"}) as client:
            candidates = [
                f"https://{domain}",
                f"https://www.{domain}",
                f"http://{domain}",
                f"http://www.{domain}",
            ]
            for url in candidates:
                try:
                    r = client.get(url)
                    if r.url.host:
                        return normalize_host(r.url.host)
                except Exception as e:
                    LOG.debug("HTTP check %s failed: %s", url, e)
            return None
    except Exception as e:
        LOG.debug("HTTP canonical fail %s: %s", domain, e); return None

# ----- HTTP probe with common paths -----
def http_probe(domain: str, timeout: float = 6.0) -> Tuple[bool, Optional[int], Optional[str], bool, str]:
    """
    Returns: (present, status, title, has_login_form, kind)
      kind ∈ {"webapp","api","marketing","unknown"}
    Tries apex and www, schemes https/http, and paths: /, /login, /signin, /auth
    """
    if httpx is None:
        return (False, None, None, False, "unknown")

    title_re = re.compile(r"<\s*title[^>]*>(.*?)</\s*title\s*>", re.IGNORECASE | re.DOTALL)
    login_kw_re = re.compile(r"(sign[\s-]*in|log[\s-]*in|account|password|auth)", re.IGNORECASE)

    hosts = [domain, f"www.{domain}"] if not domain.startswith("www.") else [domain]
    paths = ["/", "/login", "/signin", "/auth"]
    schemes = ["https://", "http://"]

    def classify(status: int, body: str, content_type: str, url_path: str) -> Tuple[bool, str, bool, Optional[str]]:
        ct = (content_type or "").lower()
        is_json = ("application/json" in ct) or (body.strip().startswith("{") and body.strip().endswith(("}", "}]")))
        has_password = ("type=\"password\"" in body.lower()) or bool(login_kw_re.search(body)) or ("<form" in body.lower() and ("login" in body.lower() or "signin" in body.lower()))
        # title
        m = title_re.search(body)
        title = m.group(1).strip() if m else None
        # availability
        available = (status is not None) and ((200 <= status < 400) or status in (401, 403))
        # kind
        if has_password or status in (401, 403) or "/login" in url_path.lower() or "/signin" in url_path.lower() or "/auth" in url_path.lower():
            kind = "webapp"
        elif is_json or "/api" in url_path.lower() or "swagger" in body.lower():
            kind = "api"
        elif (status is not None and 200 <= status < 400 and not is_json):
            kind = "marketing"
        else:
            kind = "unknown"
        return available, kind, has_password, title

    try:
        with httpx.Client(follow_redirects=True, timeout=timeout,
                          headers={"User-Agent": "UpGuard-HTTPProbe/1.1"}) as client:
            for host in hosts:
                for scheme in schemes:
                    for path in paths:
                        url = f"{scheme}{host}{path}"
                        try:
                            r = client.get(url)
                            available, kind, has_pw, title = classify(r.status_code, r.text or "", r.headers.get("content-type",""), r.url.path)
                            if available:
                                # prefer more “app-like” results; return early on webapp/api
                                if kind in ("webapp", "api"):
                                    return (True, r.status_code, title, has_pw, kind)
                                # otherwise keep looking for stronger signals but remember marketing
                                if kind == "marketing":
                                    # return marketing if we don't find webapp/api later
                                    marketing_snapshot = (True, r.status_code, title, has_pw, kind)
                                    # keep scanning; if nothing stronger is found, fall back
                                    fallback = marketing_snapshot
                                    # continue scanning; if nothing else triggers, we'll return fallback after loops
                        except Exception as e:
                            LOG.debug("HTTP probe %s failed: %s", url, e)
            # If we collected a marketing fallback above, return it
            try:
                return fallback  # type: ignore[name-defined]
            except NameError:
                return (False, None, None, False, "unknown")
    except Exception as e:
        LOG.debug("HTTP probe setup failed %s: %s", domain, e)
        return (False, None, None, False, "unknown")

# ----- model -----
@dataclass
class DomainFeatures:
    domain: str
    coverage_status: str
    coverage_reason: str
    covered_by: Optional[str]
    final_http_host: Optional[str]

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

    # HTTP probe
    http_present: bool
    http_status: Optional[int]
    http_title: Optional[str]
    http_login_form: bool
    http_kind: str  # marketing | webapp | api | unknown

    brand_critical: bool
    vertical: str

    priority: str
    priority_reason: str
    signal_priority: str
    signal_priority_reason: str

VERTICAL_WEIGHTS = {"retail":3,"finance":4,"healthcare":4,"gov":4,"tech":2,"other":0}

def is_short_brand_like(domain: str) -> bool:
    parts = domain.split(".")
    return len(parts)==2 and len(parts[0]) <= 5

def classify_priority(f: DomainFeatures):
    score, reasons = 0, []
    if f.has_mx: score += 3; reasons.append("MX present (+3)")
    if f.spf_risky_all: score += 3; reasons.append("SPF risky all (+3)")
    if f.dkim_any: score += 2; reasons.append("DKIM found (+2)")
    if f.dmarc_policy in ("none","quarantine"): score += 1; reasons.append(f"DMARC {f.dmarc_policy} (+1)")
    if f.dmarc_policy == "reject": score -= 1; reasons.append("DMARC reject (−1)")
    if not f.dnssec: score += 1; reasons.append("DNSSEC absent (+1)")
    if f.wildcard: score += 2; reasons.append("Wildcard (+2)")
    if f.risky_cname_count: score += 2; reasons.append(f"{f.risky_cname_count} risky CNAME(s) (+2)")
    if f.ct_subdomain_count >= 50: score += 3; reasons.append("CT breadth >=50 (+3)")
    elif f.ct_subdomain_count >= 10: score += 2; reasons.append("CT breadth >=10 (+2)")
    if f.http_present and f.http_kind == "webapp":
        score += 1; reasons.append("HTTP webapp present (+1)")
    if f.brand_critical: score += 5; reasons.append("Primary brand domain (+5)")
    elif is_short_brand_like(f.domain): score += 3; reasons.append("Short apex brand-like (+3)")
    vb = VERTICAL_WEIGHTS.get(f.vertical,0)
    if vb: score += vb; reasons.append(f"Vertical weighting: {f.vertical} (+{vb})")
    label = "High" if score >= 8 else "Medium" if score >= 5 else "Low"
    reasons.insert(0, f"score={score} → {label}")
    return label, "; ".join(reasons)

def classify_signal_priority(f: DomainFeatures):
    # Coverage short-circuit
    if f.coverage_status != "Standalone":
        return "Included", f"Covered by {f.covered_by} ({f.coverage_status}); monitoring apex covers this domain"

    score, reasons = 0, []

    # Base mail exposure
    if f.has_mx:
        score += 4; reasons.append("MX present (+4)")

    # Weight multipliers if no MX (reduced contributions but still spoofable)
    w_nmx = 0.5 if not f.has_mx else 1.0

    # SPF/DMARC (independent of MX, scaled when has_mx=False)
    if not f.spf_present:
        bump = 2 if w_nmx == 1.0 else 1
        score += bump; reasons.append(f"No SPF (+{bump})")
    if f.spf_risky_all:
        bump = 3 if w_nmx == 1.0 else 2
        score += bump; reasons.append(f"SPF risky all (+{bump})")

    if not f.dmarc_present:
        bump = 3 if w_nmx == 1.0 else 2
        score += bump; reasons.append(f"No DMARC (+{bump})")
    elif f.dmarc_policy in ("none","quarantine"):
        bump = 3 if w_nmx == 1.0 else 2
        score += bump; reasons.append(f"DMARC policy {f.dmarc_policy} (+{bump})")
    # p=reject intentionally ignored

    if not f.dkim_any:
        bump = 1  # unchanged
        score += bump; reasons.append(f"No DKIM (+{bump})")

    # Ecosystem breadth
    vendors = [v for v in f.mail_vendors.split(",") if v]
    if vendors:
        bump = min(4, len(set(vendors)))
        score += bump; reasons.append(f"Mail vendors {vendors} (+{bump})")

    # CT breadth
    if f.ct_subdomain_count >= 200:
        score += 6; reasons.append("CT breadth >=200 (+6)")
    elif f.ct_subdomain_count >= 50:
        score += 4; reasons.append("CT breadth >=50 (+4)")
    elif f.ct_subdomain_count >= 10:
        score += 2; reasons.append("CT breadth >=10 (+2)")
    elif f.ct_subdomain_count >= 1:
        score += 1; reasons.append("CT breadth >=1 (+1)")

    # SaaS CNAMEs
    if f.risky_cname_count:
        bump = min(6, 2*f.risky_cname_count)
        score += bump; reasons.append(f"{f.risky_cname_count} risky SaaS CNAME(s) (+{bump})")

    # Wildcard and DNSSEC
    if f.wildcard:
        score += 1; reasons.append("Wildcard (+1)")
    if f.dnssec:
        score -= 1; reasons.append("DNSSEC present (−1)")

    # HTTP purpose boosts (from probe)
    if f.http_present:
        if f.http_kind == "webapp":
            score += 3; reasons.append("HTTP indicates login-capable webapp (+3)")
        elif f.http_kind == "api":
            score += 2; reasons.append("HTTP indicates API surface (+2)")
        elif f.http_kind == "marketing":
            reasons.append("HTTP marketing/brochure (±0)")

    # Business context
    if f.brand_critical:
        score += 6; reasons.append("Primary brand domain (+6)")
    elif is_short_brand_like(f.domain):
        score += 3; reasons.append("Short apex brand-like (+3)")

    vb = VERTICAL_WEIGHTS.get(f.vertical,0)
    if vb:
        score += vb; reasons.append(f"Vertical weighting: {f.vertical} (+{vb})")

    label = "High" if score >= 13 else "Medium" if score >= 8 else "Low"
    reasons.insert(0, f"score={score} → {label}")
    return label, "; ".join(reasons)

# ----- analyzer -----
def parse_dmarc(txts: List[str]):
    recs = [t for t in txts if t.lower().startswith("v=dmarc1")]
    if not recs: return False, None
    policy=None
    for part in recs[0].split(";"):
        part=part.strip()
        if part.startswith("p="): policy=part.split("=",1)[1].strip()
    return True,policy

async def _ct_count(domain: str) -> int:
    try:
        names = await fetch_ct_names(domain); return len(names)
    except Exception as e:
        LOG.debug("CT error %s: %s", domain, e); return 0

def analyze_domain(domain: str, with_ct=False, with_http=False, brand_critical=False, vertical="other",
                   input_apexes: Optional[List[str]] = None,
                   check_redirects: bool = False) -> DomainFeatures:

    d = normalize_host(domain)
    if not looks_like_domain(d):
        return DomainFeatures(d,"Standalone","N/A",None,None,
                              False,"",False,False,False,False,None,False,False,0,0,
                              False,None,None,False,"unknown",
                              brand_critical,vertical,
                              "Medium","Custom search term (not a domain)",
                              "Medium","Custom search term (not a domain)")

    input_apexes = [normalize_host(x) for x in (input_apexes or [])]

    # Coverage
    coverage_status, coverage_reason, covered_by_val, final_http_host = "Standalone", "", None, None

    covered_apex = covered_by_apex(d, input_apexes)
    if covered_apex:
        coverage_status = f"IncludedUnder:{covered_apex}"
        coverage_reason = f"Subdomain of monitored apex {covered_apex}"
        covered_by_val = covered_apex

    if coverage_status == "Standalone":
        cname_final = resolve_cname_chain(d)
        if cname_final:
            cname_apex = apex_of(cname_final)
            if cname_apex and cname_apex in input_apexes and d != cname_apex:
                coverage_status = f"AliasOf:{cname_apex}"
                coverage_reason = f"CNAME ultimately targets {cname_final} (apex {cname_apex} in monitored set)"
                covered_by_val = cname_apex

    if coverage_status == "Standalone" and check_redirects and httpx is not None:
        try:
            final_http_host = http_canonical_host(d)
            if final_http_host:
                http_apex = apex_of(final_http_host)
                if http_apex and http_apex in input_apexes and d != http_apex:
                    coverage_status = f"AliasOf:{http_apex}"
                    coverage_reason = f"HTTP redirect ends at {final_http_host} (apex {http_apex} in monitored set)"
                    covered_by_val = http_apex
        except Exception as e:
            LOG.debug("Redirect check fail %s: %s", d, e)

    # Technicals
    mx_records = q_any(d, "MX")
    mx_hosts = [normalize_host(mx.split()[-1].strip(".")) for mx in mx_records]
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
            LOG.debug("asyncio.run CT fail %s: %s", d, e)

    # HTTP probe (optional)
    http_present, http_status, http_title, http_login_form, http_kind = (False, None, None, False, "unknown")
    if with_http:
        http_present, http_status, http_title, http_login_form, http_kind = http_probe(d)

    vendors = discover_third_parties(d, spf_info, mx_hosts)

    f = DomainFeatures(
        domain=d,
        coverage_status=coverage_status,
        coverage_reason=(coverage_reason or "N/A") if coverage_status != "Standalone" else "N/A",
        covered_by=covered_by_val,
        final_http_host=final_http_host,
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
        http_present=http_present,
        http_status=http_status,
        http_title=http_title,
        http_login_form=http_login_form,
        http_kind=http_kind,
        brand_critical=brand_critical,
        vertical=vertical,
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

# ----- CSV reader -----
def read_domains_csv_flexible(path: str) -> List[Tuple[str, bool]]:
    rows: List[Tuple[str,bool]] = []
    with open(path, "r", encoding="utf-8") as fh:
        first = fh.readline()
        if not first: return rows
        fh.seek(0)
        headered = ("domain" in first.lower())
        if headered:
            rd = csv.DictReader(fh)
            want = any(fn.lower()=="domain" for fn in (rd.fieldnames or []))
            if not want: raise SystemExit("FATAL: CSV must have a 'domain' column")
            for r in rd:
                d = normalize_host((r.get("domain") or "").strip())
                if not d: continue
                primary = (str(r.get("primary") or "").strip().upper() == "Y")
                rows.append((d, primary))
        else:
            rd = csv.reader(fh)
            for parts in rd:
                if not parts: continue
                d = normalize_host((parts[0] or "").strip())
                if not d: continue
                primary = False
                if len(parts) >= 2 and (parts[1] or "").strip().upper() == "Y":
                    primary = True
                rows.append((d, primary))
    return rows

# ----- explain -----
def explain_host(host: str, input_apexes: List[str], check_redirects: bool, with_http: bool):
    d = normalize_host(host)
    print(f"\n[Explain] host={d}")
    if not looks_like_domain(d):
        print(" - Not a domain: treated as custom search term → signal=Medium, priority=Medium")
        return
    print(f" - apex(host)={apex_of(d)}")
    print(f" - monitored apexes={input_apexes}")
    inc = covered_by_apex(d, input_apexes)
    if inc:
        print(f" - INCLUDED under apex {inc} via subdomain rule"); return
    cn_final = resolve_cname_chain(d)
    print(f" - CNAME final={cn_final}, apex={apex_of(cn_final) if cn_final else None}")
    if cn_final:
        cn_apex = apex_of(cn_final)
        if cn_apex in input_apexes and d != cn_apex:
            print(f" - ALIAS of apex {cn_apex} via CNAME rule"); return
    if check_redirects and httpx:
        http_host = http_canonical_host(d)
        print(f" - HTTP final host={http_host}, apex={apex_of(http_host) if http_host else None}")
        if http_host:
            http_apex = apex_of(http_host)
            if http_apex in input_apexes and d != http_apex:
                print(f" - ALIAS of apex {http_apex} via HTTP redirect rule"); return
    if with_http:
        present, status, title, pw, kind = http_probe(d)
        print(f" - HTTP present={present}, status={status}, kind={kind}, login_form={pw}, title={title!r}")
    print(" - No coverage match → Standalone (will be scored normally)")

# ----- CLI -----
def main():
    ap = argparse.ArgumentParser(description="Domain Attack Surface Scanner (apex-aware, coverage, explain, httpprobe)")
    ap.add_argument("--in", dest="infile", required=True, help="Path to domains.csv")
    ap.add_argument("--with-ct", action="store_true")
    ap.add_argument("--with-http", action="store_true", help="Probe homepage and common paths (login/signin/auth)")
    ap.add_argument("--check-redirects", action="store_true")
    ap.add_argument("--debug", action="store_true")
    ap.add_argument("--vertical", dest="vertical", default="other",
                    choices=["retail","finance","healthcare","gov","tech","other"])
    ap.add_argument("--explain", dest="explain_host", help="Explain coverage/HTTP decision for a single host and exit")
    args = ap.parse_args()

    logging.basicConfig(level=logging.DEBUG if args.debug else logging.INFO,
                        format="%(levelname)s: %(message)s")
    if not args.debug:
        logging.getLogger("httpx").setLevel(logging.WARNING)
        logging.getLogger("httpcore").setLevel(logging.WARNING)

    if not os.path.isfile(args.infile):
        sys.stderr.write(f"FATAL: input not found: {args.infile}\n"); sys.exit(2)

    rows = read_domains_csv_flexible(args.infile)
    if not rows:
        sys.stderr.write("FATAL: no domains parsed from CSV.\n"); sys.exit(2)

    # Build monitored apex set from inputs
    input_apexes = []
    for d,_ in rows:
        a = apex_of(d)
        if a and a not in input_apexes:
            input_apexes.append(a)

    # Explain-and-exit
    if args.explain_host:
        explain_host(args.explain_host, input_apexes, args.check_redirects, args.with_http)
        return

    base,_ = os.path.splitext(args.infile)
    outfile = f"{base}_results.csv"

    fields = [f.name for f in DomainFeatures.__dataclass_fields__.values()]
    wrote = 0
    with open(outfile, "w", newline="", encoding="utf-8") as f:
        w = csv.DictWriter(f, fieldnames=fields)
        w.writeheader()
        for d, primary in rows:
            try:
                rec = asdict(analyze_domain(
                    d,
                    with_ct=args.with_ct,
                    with_http=args.with_http,
                    brand_critical=primary,
                    vertical=args.vertical,
                    input_apexes=input_apexes,
                    check_redirects=args.check_redirects
                ))
                w.writerow(rec); wrote += 1
            except Exception as e:
                sys.stderr.write(f"ERROR: {d} -> {e}\n")
                w.writerow({
                    "domain": d,
                    "coverage_status": "Standalone",
                    "coverage_reason": "Exception",
                    "covered_by": None,
                    "final_http_host": None,
                    "has_mx": False, "mail_vendors":"", "spf_present": False, "spf_risky_all": False,
                    "dkim_any": False, "dmarc_present": False, "dmarc_policy": None,
                    "dnssec": False, "wildcard": False, "risky_cname_count": 0, "ct_subdomain_count": 0,
                    "http_present": False, "http_status": None, "http_title": None, "http_login_form": False, "http_kind": "unknown",
                    "brand_critical": primary, "vertical": args.vertical,
                    "priority": "Error", "priority_reason": "Exception",
                    "signal_priority": "Error", "signal_priority_reason": "Exception"
                })
    print(f"Wrote {wrote} rows → {outfile}")

if __name__ == "__main__":
    main()
