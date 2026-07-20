"""
bridge_to_github.py
====================
Pushes threat intelligence to pakistaninfosec.github.io
Sources: Pakistan CERT, NCCS Pakistan, CISA KEV, NVD (recent CVEs)
"""

import os, json, glob, base64, hashlib, requests
from datetime import datetime, date, timezone, timedelta
from collections import Counter
from bs4 import BeautifulSoup

GITHUB_REPO   = os.environ.get("GITHUB_REPO", "pakistaninfosec/pakistaninfosec.github.io")
GITHUB_TOKEN  = os.environ.get("GITHUB_TOKEN", "")
GROQ_API_KEY  = os.environ.get("GROQ_API_KEY", "")

PAKISTAN_SOURCES  = {"Pakistan CERT", "NCCS Pakistan"}
ZERODAY_SOURCES   = {
    "CISA KEV", "Google Project Zero", "Vulners",
    "ZDI", "Zero Day Initiative", "Exploit-DB",
    "Packet Storm", "Exploit Database", "NVD Zero-Day"
}
EXPLOITED_SOURCES = {"CISA KEV"}

HEADERS = {
    "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 Chrome/120.0.0.0 Safari/537.36"
}


# ── Pakistan CERT + NCCS ──────────────────────────────────────────────────────

def _scrape_pakistan_direct():
    results = []

    # PKCERT — scrape only real PDF advisories (Advisory No XX)
    found = []
    # Known advisory PDFs pattern: /advisory/26/1.pdf to /advisory/26/XX.pdf
    try:
        res = requests.get("https://pkcert.gov.pk/", headers=HEADERS, timeout=15)
        if res.status_code == 200:
            soup = BeautifulSoup(res.text, "html.parser")
            # Only grab links that point to actual PDF advisories
            for a in soup.find_all("a", href=True):
                href = a["href"]
                title = a.get_text(strip=True)
                # Only real advisory PDFs or advisory pages
                if (
                    ".pdf" in href.lower() or
                    "advisory" in href.lower() or
                    "advisory" in title.lower()
                ) and len(title) > 15 and (
                    "Advisory No" in title or
                    "CVE" in title or
                    "Vulnerabilit" in title or
                    "Exploit" in title or
                    "Critical" in title or
                    "Security" in title or
                    "Patch" in title or
                    "Malware" in title or
                    "Ransomware" in title or
                    "Phishing" in title or
                    "Zero-Day" in title or
                    "FortiNet" in title or
                    "Microsoft" in title or
                    "Cisco" in title or
                    "WhatsApp" in title or
                    "Attack" in title
                ):
                    # Skip navigation/menu items
                    skip_words = ["capacity building","abc program","report to us",
                                  "knowledge base","public notice","internship",
                                  "contact","home","about","careers","info@"]
                    if not any(sw in title.lower() for sw in skip_words):
                        full_link = href if href.startswith("http") else "https://pkcert.gov.pk/" + href.lstrip("/")
                        found.append({"title": title, "link": full_link})
    except Exception as e:
        print(f"[!] PKCERT scrape error: {e}")

    # Deduplicate
    seen = set()
    unique_found = []
    for f in found:
        if f["title"] not in seen:
            seen.add(f["title"])
            unique_found.append(f)

    for adv in unique_found[:20]:
        title = adv["title"]
        link  = adv["link"]
        # Build meaningful description
        desc = f"Pakistan CERT Security Advisory: {title}. Pakistani organizations are advised to review this advisory and apply recommended mitigations immediately."
        results.append({
            "source": "Pakistan CERT", "category": "Pakistan Advisory",
            "id": "PKCERT-" + hashlib.md5(title.encode()).hexdigest()[:8].upper(),
            "title": title,
            "description": desc,
            "severity": "HIGH", "cvss_score": 7.5, "cwe": "",
            "affected_products": "Pakistani government and critical infrastructure",
            "references": link,
            "published_date": date.today().isoformat(),
            "last_modified": date.today().isoformat(),
            "url": link or "https://pkcert.gov.pk/",
            "vendor": "Pakistan CERT", "price": "",
            "tags": "pakistan,cert,advisory,government",
        })

    if len(results) < 5:
        # Always use hardcoded known real advisories from 2026 as base
        known = [
            ("Advisory No 13: Critical Vulnerabilities in Fortinet FortiSandbox Under Active Exploitation", "https://pkcert.gov.pk/advisory/26/13.pdf"),
            ("Advisory No 12: Large-Scale Compromise of Fortinet FortiGate Firewalls and VPN Infrastructure", "https://pkcert.gov.pk/advisory/26/12.pdf"),
            ("Advisory No 11: Critical Vulnerability in Palo Alto Networks GlobalProtect (CVE-2026-0257) Actively Exploited", "https://pkcert.gov.pk/advisory/26/11.pdf"),
            ("Advisory No 10: Critical Remote Code Execution Vulnerabilities in n8n Workflow Automation Platform", "https://pkcert.gov.pk/advisory/26/10.pdf"),
            ("Advisory No 09: Critical Authentication Bypass in Cisco SD-WAN Manager (CVE-2026-20127)", "https://pkcert.gov.pk/advisory/26/8.pdf"),
            ("Advisory No 08: Persistent Application Security Weaknesses Requiring Immediate Remediation", "https://pkcert.gov.pk/advisory/26/7.pdf"),
            ("Advisory No 07: Critical Pre-Authentication RCE Vulnerability in BeyondTrust Remote Support", "https://pkcert.gov.pk/advisory/26/6.pdf"),
            ("Advisory No 06: Active Exploitation of Zero-Day Vulnerabilities in Ivanti EPMM", "https://pkcert.gov.pk/advisory/26/5.pdf"),
            ("Advisory No 05: Actively Exploited Microsoft Office Zero-Day Vulnerability (CVE-2026-21509)", "https://pkcert.gov.pk/advisory/26/4.pdf"),
            ("Advisory No 04: Critical Fortinet FortiSIEM and FortiOS Remote Code Execution Vulnerabilities", "https://pkcert.gov.pk/advisory/26/3.pdf"),
            ("Advisory No 03: Critical n8n Remote Code Execution Vulnerability", "https://pkcert.gov.pk/advisory/26/2.pdf"),
            ("Advisory No 02: Widespread WhatsApp Account Hijacking and Unauthorized Access Incidents", "https://pkcert.gov.pk/advisory/26/1.pdf"),
        ]
        existing_ids = {r["id"] for r in results}
        for title, link in known:
            adv_id = "PKCERT-" + hashlib.md5(title.encode()).hexdigest()[:8].upper()
            if adv_id not in existing_ids:
                desc = f"Pakistan CERT Security Advisory: {title}. Pakistani organizations are advised to review this advisory and apply recommended mitigations immediately. Full technical details available in the linked PDF."
                results.append({
                    "source": "Pakistan CERT", "category": "Pakistan Advisory",
                    "id": adv_id,
                    "title": title,
                    "description": desc,
                    "severity": "HIGH", "cvss_score": 7.5, "cwe": "",
                    "affected_products": "Pakistani government and critical infrastructure",
                    "references": link,
                    "published_date": date.today().isoformat(),
                    "last_modified": date.today().isoformat(),
                    "url": link,
                    "vendor": "Pakistan CERT", "price": "",
                    "tags": "pakistan,cert,advisory,government",
                })
                existing_ids.add(adv_id)

    print(f"[✓] PKCERT: {len(results)} real advisories")

    # NCCS Pakistan
    nccs_found = []
    for url in [
        "https://nccs.pk/NCCSBlog/TWICS.html",
        "https://nccs.pk/NCCSBlog/",
        "https://nccs.pk/advisories/",
    ]:
        try:
            res = requests.get(url, headers=HEADERS, timeout=15)
            if res.status_code == 200:
                soup = BeautifulSoup(res.text, "html.parser")
                for a in soup.find_all("a", href=True):
                    title = a.get_text(strip=True)
                    href  = a["href"]
                    if len(title) > 20 and any(kw in title for kw in [
                        "Threat","Cyber","Security","Vulnerability","Malware",
                        "Alert","Advisory","Intelligence","Attack","Patch"
                    ]):
                        skip = ["nccs","home","about","contact","login","register"]
                        if not any(s in title.lower() for s in skip):
                            full = href if href.startswith("http") else "https://nccs.pk/" + href.lstrip("/")
                            if title not in [x["title"] for x in nccs_found]:
                                nccs_found.append({"title": title, "link": full})
        except Exception:
            continue

    for adv in nccs_found[:15]:
        title = adv["title"]
        link  = adv["link"]
        desc  = f"NCCS Pakistan Cyber Security Advisory: {title}. Organizations in Pakistan are advised to take immediate action as per NCCS guidelines."
        results.append({
            "source": "NCCS Pakistan", "category": "Pakistan Advisory",
            "id": "NCCS-" + hashlib.md5(title.encode()).hexdigest()[:8].upper(),
            "title": title,
            "description": desc,
            "severity": "HIGH", "cvss_score": 7.0, "cwe": "",
            "affected_products": "Pakistani organizations and critical infrastructure",
            "references": link,
            "published_date": date.today().isoformat(),
            "last_modified": date.today().isoformat(),
            "url": link or "https://nccs.pk",
            "vendor": "NCCS Pakistan", "price": "",
            "tags": "pakistan,nccs,threat-intelligence,advisory",
        })

    if not nccs_found:
        results.append({
            "source": "NCCS Pakistan", "category": "Pakistan Advisory",
            "id": f"NCCS-{date.today().strftime('%Y%m%d')}",
            "title": "NCCS Pakistan Weekly Cyber Threat Intelligence Summary",
            "description": "NCCS Pakistan publishes weekly cyber threat intelligence reports covering threats targeting Pakistani organizations, government entities and critical infrastructure. Visit nccs.pk for the latest advisories.",
            "severity": "MEDIUM", "cvss_score": 5.5, "cwe": "",
            "affected_products": "Pakistani organizations and universities",
            "references": "https://nccs.pk/NCCSBlog/TWICS.html",
            "published_date": date.today().isoformat(),
            "last_modified": date.today().isoformat(),
            "url": "https://nccs.pk/NCCSBlog/TWICS.html",
            "vendor": "NCCS Pakistan", "price": "",
            "tags": "pakistan,nccs,weekly,threat-intelligence",
        })

    print(f"[✓] Pakistan total: {len(results)} records")
    return results


# ── CISA KEV — Actively Exploited ────────────────────────────────────────────

def _scrape_cisa_kev_direct(days_back=30):
    results = []
    try:
        res = requests.get(
            "https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json",
            headers=HEADERS, timeout=20
        )
        res.raise_for_status()
        vulns = res.json().get("vulnerabilities", [])
        vulns.sort(key=lambda x: x.get("dateAdded", ""), reverse=True)

        # Only include entries added in the last N days
        cutoff = (date.today() - timedelta(days=days_back)).isoformat()
        recent = [v for v in vulns if v.get("dateAdded","") >= cutoff]

        # Always include at least 5 even if none are recent
        if len(recent) < 5:
            recent = vulns[:10]

        for v in recent:
            cve_id  = v.get("cveID", "")
            name    = v.get("vulnerabilityName", "")
            desc    = v.get("shortDescription", "")
            product = v.get("product", "")
            vendor  = v.get("vendorProject", "")
            added   = v.get("dateAdded", date.today().isoformat())
            results.append({
                "source":            "CISA KEV",
                "category":          "Actively Exploited",
                "id":                cve_id or ("KEV-" + hashlib.md5(name.encode()).hexdigest()[:8].upper()),
                "title":             f"{cve_id}: {name}" if cve_id else name,
                "description":       desc or f"Actively exploited vulnerability in {vendor} {product}.",
                "severity":          "CRITICAL",
                "cvss_score":        9.0,
                "cwe":               "",
                "affected_products": f"{vendor} {product}".strip(),
                "references":        f"https://nvd.nist.gov/vuln/detail/{cve_id}" if cve_id else "",
                "published_date":    added,
                "last_modified":     added,
                "url":               f"https://nvd.nist.gov/vuln/detail/{cve_id}" if cve_id else "https://www.cisa.gov/known-exploited-vulnerabilities-catalog",
                "vendor":            vendor,
                "price":             "",
                "tags":              "cisa,kev,actively-exploited,zero-day",
            })
        print(f"[✓] CISA KEV: {len(results)} records (last {days_back} days)")
    except Exception as e:
        print(f"[!] CISA KEV failed: {e}")
    return results


# ── NVD — Recent CVEs (Zero-Day candidates) ───────────────────────────────────

def _scrape_nvd_recent(days_back=1, max_results=500):
    results = []
    try:
        end   = datetime.utcnow()
        start = end - timedelta(days=days_back)
        params = {
            "pubStartDate": start.strftime("%Y-%m-%dT00:00:00.000"),
            "pubEndDate":   end.strftime("%Y-%m-%dT23:59:59.999"),
            "resultsPerPage": min(max_results, 2000),
            "startIndex": 0,
        }
        res = requests.get("https://services.nvd.nist.gov/rest/json/cves/2.0",
                           params=params, headers=HEADERS, timeout=30)
        res.raise_for_status()
        items = res.json().get("vulnerabilities", [])

        for item in items:
            cve  = item.get("cve", {})
            cid  = cve.get("id", "")
            desc_list = cve.get("descriptions", [])
            desc = next((d["value"] for d in desc_list if d["lang"] == "en"), "")
            metrics   = cve.get("metrics", {})
            score     = 0.0
            severity  = "MEDIUM"
            for key in ["cvssMetricV31","cvssMetricV30","cvssMetricV2"]:
                if key in metrics and metrics[key]:
                    m        = metrics[key][0].get("cvssData", {})
                    score    = float(m.get("baseScore", 0))
                    severity = m.get("baseSeverity", "MEDIUM").upper()
                    break
            pub_date = cve.get("published", date.today().isoformat())[:10]
            results.append({
                "source":            "NVD/NIST",
                "category":          "CVE Vulnerability",
                "id":                cid,
                "title":             f"{cid}: {desc[:100]}",
                "description":       desc[:300],
                "severity":          severity,
                "cvss_score":        score,
                "cwe":               "",
                "affected_products": "",
                "references":        f"https://nvd.nist.gov/vuln/detail/{cid}",
                "published_date":    pub_date,
                "last_modified":     pub_date,
                "url":               f"https://nvd.nist.gov/vuln/detail/{cid}",
                "vendor":            "NVD/NIST",
                "price":             "",
                "tags":              "nvd,cve,vulnerability",
            })
        print(f"[✓] NVD recent: {len(results)} records")
    except Exception as e:
        print(f"[!] NVD failed: {e}")
    return results


# ── Exploit-DB RSS — Zero Days ────────────────────────────────────────────────

def _scrape_exploitdb(max_results=100):
    results = []
    try:
        import feedparser
        feed = feedparser.parse("https://www.exploit-db.com/rss.xml")
        for entry in feed.entries[:max_results]:
            title = entry.get("title","")
            link  = entry.get("link","")
            desc  = entry.get("summary","")[:300]
            pub   = entry.get("published","")[:10] if entry.get("published") else date.today().isoformat()
            uid   = "EDB-" + hashlib.md5(title.encode()).hexdigest()[:8].upper()
            results.append({
                "source":            "Exploit-DB",
                "category":          "Zero Day Exploit",
                "id":                uid,
                "title":             title,
                "description":       desc or f"Exploit-DB entry: {title}",
                "severity":          "HIGH",
                "cvss_score":        8.0,
                "cwe":               "",
                "affected_products": "",
                "references":        link,
                "published_date":    pub,
                "last_modified":     pub,
                "url":               link,
                "vendor":            "Exploit-DB",
                "price":             "",
                "tags":              "exploit,zero-day,exploit-db",
            })
        print(f"[✓] Exploit-DB: {len(results)} records")
    except Exception as e:
        print(f"[!] Exploit-DB failed: {e}")
    return results


# ── Helpers ───────────────────────────────────────────────────────────────────

def find_latest_json():
    patterns = [
        "scraper/output/infosec_products_*.json",
        "output/infosec_products_*.json",
        "infosec_products_*.json",
    ]
    files = []
    for p in patterns:
        files.extend(glob.glob(p))
    if not files:
        return None
    latest = max(files, key=os.path.getmtime)
    print(f"[✓] Found scraper output: {latest}")
    return latest


def is_pakistan(r):
    return r.get("source", "") in PAKISTAN_SOURCES

def is_zeroday(r):
    src  = r.get("source", "")
    tags = str(r.get("tags", "")).lower()
    cat  = str(r.get("category", "")).lower()
    return (
        src in ZERODAY_SOURCES or
        "zero-day" in tags or "zeroday" in tags or
        "exploit" in tags or "exploit" in cat or
        "zero day" in tags
    )

def map_severity(r):
    sev   = str(r.get("severity", "")).upper()
    score = float(r.get("cvss_score", 0) or 0)
    if sev == "CRITICAL" or score >= 9.0: return "CRITICAL"
    if sev == "HIGH"     or score >= 7.0: return "HIGH"
    if sev == "MEDIUM"   or score >= 4.0: return "MEDIUM"
    return "LOW"

def clean_date(val):
    if not val: return date.today().isoformat()
    s = str(val).strip()
    # Try common formats
    formats = [
        "%Y-%m-%d",
        "%Y-%m-%dT%H:%M:%S",
        "%Y-%m-%dT%H:%M:%SZ",
        "%Y-%m-%dT%H:%M:%S.%fZ",
        "%a, %d %b %Y %H:%M:%S %Z",
        "%a, %d %b %Y %H:%M:%S GMT",
        "%a, %d %b %Y %H:%M:%S +0000",
        "%d %b %Y %H:%M:%S %Z",
        "%B %d, %Y",
    ]
    for fmt in formats:
        try:
            return datetime.strptime(s[:len(fmt)+5].strip(), fmt).strftime("%Y-%m-%d")
        except Exception:
            pass
    # Last resort: try dateutil if available
    try:
        from dateutil import parser as dp
        return dp.parse(s).strftime("%Y-%m-%d")
    except Exception:
        pass
    # If it starts with YYYY-MM-DD just use that
    if len(s) >= 10 and s[4] == '-' and s[7] == '-':
        return s[:10]
    return date.today().isoformat()


def generate_ai_summary(threats):
    if not GROQ_API_KEY:
        return None
    try:
        from groq import Groq
        client   = Groq(api_key=GROQ_API_KEY)
        critical = [t for t in threats if t["severity"] == "CRITICAL"][:5]
        zd       = [t for t in threats if t["zeroday"]][:5]
        pk       = [t for t in threats if t["pakistan"]][:5]

        def fmt(lst):
            return "\n".join([f"  - {t['id']} ({t['source']}): {t.get('description','')[:120]}" for t in lst]) or "  None"

        prompt = f"""You are a senior cybersecurity analyst at Pakistan's national CERT. Write a concise 3-sentence executive summary for today's threat intelligence digest. Make it specific, actionable and mention the most critical threats by name.

TODAY'S STATS:
- Total vulnerabilities: {len(threats)}
- Critical severity: {len([t for t in threats if t['severity']=='CRITICAL'])}
- High severity: {len([t for t in threats if t['severity']=='HIGH'])}
- Zero-Day exploits: {len([t for t in threats if t['zeroday']])}
- Actively exploited (CISA KEV): {len([t for t in threats if 'kev' in str(t.get('tags','')).lower()])}
- Pakistan CERT/NCCS alerts: {len(pk)}

TOP CRITICAL VULNERABILITIES:
{fmt(critical)}

ZERO-DAY EXPLOITS:
{fmt(zd)}

PAKISTAN-SPECIFIC ALERTS:
{fmt(pk)}

Write 3 sentences. Mention specific CVE IDs and vendors. Focus on what Pakistani organizations should prioritize. Plain text only, no bullets, no markdown."""

        response = client.chat.completions.create(
            model="llama-3.3-70b-versatile",
            messages=[{"role": "user", "content": prompt}],
            max_tokens=250, temperature=0.5,
        )
        return response.choices[0].message.content.strip()
    except Exception as e:
        print(f"[!] Groq failed: {e}")
        return None


def convert_records(raw_records):
    threats = []
    for r in raw_records:
        tags_raw = r.get("tags", "")
        tags = tags_raw if isinstance(tags_raw, list) else \
               [t.strip() for t in str(tags_raw).split(",") if t.strip()]
        cat = r.get("category", "")
        if cat and cat not in tags:
            tags.append(cat)
        desc = str(r.get("description", "") or r.get("title", "") or "")[:300]
        threats.append({
            "id":       r.get("id") or r.get("title", "UNKNOWN"),
            "desc":     desc,
            "severity": map_severity(r),
            "source":   r.get("source", "Unknown"),
            "date":     clean_date(r.get("published_date") or r.get("last_modified")),
            "pakistan": is_pakistan(r),
            "zeroday":  is_zeroday(r),
            "tags":     tags[:5],
            "url":      r.get("url", ""),
            "cvss":     str(r.get("cvss_score", "")),
            "cwe":      str(r.get("cwe", "")),
        })
    return threats


def build_threats_json(raw_data):
    all_raw = list(raw_data.get("records", []))

    # Always fetch these directly — no scraper pipeline dependency
    all_raw.extend(_scrape_pakistan_direct())
    all_raw.extend(_scrape_cisa_kev_direct())
    all_raw.extend(_scrape_nvd_recent(days_back=1))
    all_raw.extend(_scrape_exploitdb())

    threats = convert_records(all_raw)

    src_counter = Counter(t["source"] for t in threats)
    sources = [{"name": k, "count": v}
               for k, v in sorted(src_counter.items(), key=lambda x: -x[1])]

    zeroday   = sum(1 for t in threats if t["zeroday"])
    exploited = sum(1 for t in threats if t["source"] in EXPLOITED_SOURCES)
    pakistan  = sum(1 for t in threats if t["pakistan"])
    new_cnt   = len(threats)

    prev_total = 0
    try:
        with open("data/threats.json") as f:
            prev_total = json.load(f).get("stats", {}).get("total", 0)
    except Exception:
        pass

    ai = generate_ai_summary(threats)
    if not ai:
        ai = (f"Today's digest contains {new_cnt} vulnerabilities across "
              f"{len(sources)} sources. {zeroday} zero-day exploits detected, "
              f"{exploited} actively exploited from CISA KEV, and "
              f"{pakistan} Pakistan CERT/NCCS advisories.")

    return {
        "generated": datetime.now(timezone.utc).isoformat(),
        "summary":   ai,
        "stats": {
            "new":      new_cnt,
            "changed":  0,
            "removed":  0,
            "total":    prev_total + new_cnt,
            "zeroday":  zeroday,
            "exploited":exploited,
            "pakistan": pakistan,
        },
        "sources": sources,
        "threats": threats,
    }


def build_reports_json(td):
    today   = date.today().isoformat()
    threats = td["threats"]
    stats   = td["stats"]

    zi = [{"id": t["id"], "desc": t["desc"]} for t in threats if t["zeroday"]][:10]
    ei = [{"id": t["id"], "desc": t["desc"]} for t in threats if t["source"] in EXPLOITED_SOURCES][:10]
    pi = [{"id": t["id"], "desc": t["desc"]} for t in threats if t["pakistan"]][:10]

    sections = []
    if zi: sections.append({"label": "Zero Day Exploits",  "color": "red",    "items": zi})
    if ei: sections.append({"label": "Actively Exploited", "color": "orange", "items": ei})
    if pi: sections.append({"label": "Pakistan Alerts",    "color": "green",  "items": pi})

    new_report = {"date": today, "stats": stats, "summary": td["summary"], "sections": sections}

    try:
        with open("data/reports.json") as f:
            rd = json.load(f)
    except Exception:
        rd = {"reports": []}

    rd["reports"] = [r for r in rd["reports"] if r.get("date") != today]
    rd["reports"].insert(0, new_report)
    rd["reports"] = rd["reports"][:90]
    return rd


def push_to_github(filename, content_dict, is_html=False):
    if not GITHUB_TOKEN:
        print(f"[!] No GITHUB_TOKEN — skipping {filename}")
        return False

    # HTML blog posts go to root, JSON data goes to data/
    if is_html:
        url = f"https://api.github.com/repos/{GITHUB_REPO}/contents/{filename}"
        msg = f"blog: daily digest {date.today()}"
        raw = content_dict.encode() if isinstance(content_dict, str) else json.dumps(content_dict).encode()
    else:
        url = f"https://api.github.com/repos/{GITHUB_REPO}/contents/data/{filename}"
        msg = f"threat data: {date.today()}"
        raw = json.dumps(content_dict, indent=2, ensure_ascii=False).encode()

    headers = {"Authorization": f"token {GITHUB_TOKEN}", "Accept": "application/vnd.github.v3+json"}
    res = requests.get(url, headers=headers)
    sha = res.json().get("sha", "") if res.status_code == 200 else ""
    content = base64.b64encode(raw).decode()
    payload = {"message": msg, "content": content}
    if sha:
        payload["sha"] = sha
    res = requests.put(url, headers=headers, json=payload)
    if res.status_code in [200, 201]:
        print(f"[✓] {filename} pushed!")
        return True
    print(f"❌ Failed {filename}: {res.status_code} — {res.text[:200]}")
    return False


def main():
    print("\n🚀 InfoSec Pakistan — Bridge to GitHub")
    print("=" * 45)

    f = find_latest_json()
    if not f:
        print("[!] No scraper output — running direct sources only")
        raw = {"records": [], "total_records": 0}
    else:
        with open(f, encoding="utf-8") as fh:
            raw = json.load(fh)
        print(f"[✓] Loaded {raw.get('total_records', 0)} records")

    td = build_threats_json(raw)
    rd = build_reports_json(td)

    print(f"[✓] Threats:  {len(td['threats'])}")
    print(f"[✓] Zero-Day: {td['stats']['zeroday']}")
    print(f"[✓] Exploited:{td['stats']['exploited']}")
    print(f"[✓] Pakistan: {td['stats']['pakistan']} (PKCERT + NCCS)")

    # Generate daily AI blog post
    print("\n📝 Generating daily AI blog post...")
    try:
        generate_daily_blog(td)
    except Exception as e:
        print(f"[!] Blog generation failed: {e}")

    if GITHUB_TOKEN:
        print("\n📤 Pushing to GitHub...")
        push_to_github("threats.json", td)
        push_to_github("reports.json", rd)
    else:
        print("[!] No GITHUB_TOKEN — data not pushed")

    print("\n✅ Done! https://pakistaninfosec.github.io")


# ══════════════════════════════════════════════════════════════
#  DAILY AI BLOG GENERATOR
# ══════════════════════════════════════════════════════════════

def fetch_news_rss():
    """Fetch top cybersecurity news from RSS feeds."""
    import feedparser
    FEEDS = [
        ("The Hacker News",    "https://feeds.feedburner.com/TheHackersNews"),
        ("Bleeping Computer",  "https://www.bleepingcomputer.com/feed/"),
        ("Krebs on Security",  "https://krebsonsecurity.com/feed/"),
        ("Dark Reading",       "https://www.darkreading.com/rss.xml"),
        ("SANS ISC",           "https://isc.sans.edu/rssfeed_full.xml"),
    ]
    articles = []
    for source, url in FEEDS:
        try:
            feed = feedparser.parse(url)
            for entry in feed.entries[:3]:
                title = entry.get("title","").strip()
                desc  = entry.get("summary","") or entry.get("description","")
                desc  = desc[:500].strip()
                link  = entry.get("link","")
                pub   = entry.get("published","")
                if title and len(title) > 15:
                    articles.append({
                        "source": source,
                        "title":  title,
                        "desc":   desc,
                        "link":   link,
                        "pub":    pub,
                    })
        except Exception as e:
            print(f"  [!] Feed {source} failed: {e}")
    print(f"[✓] Fetched {len(articles)} news articles from {len(FEEDS)} feeds")
    return articles


def select_top_news(articles, threats):
    """Use AI to select the 3 most important articles for Pakistani orgs."""
    if not GROQ_API_KEY or not articles:
        return articles[:3]
    try:
        from groq import Groq
        client = Groq(api_key=GROQ_API_KEY)
        art_list = "\n".join([f"{i+1}. [{a['source']}] {a['title']}" for i,a in enumerate(articles)])
        pk_alerts = len([t for t in threats.get("threats",[]) if t.get("pakistan")])
        prompt = f"""You are a cybersecurity editor for InfoSec Pakistan — Pakistan's threat intelligence platform.

Today's threat stats: {len(threats.get('threats',[]))} threats, {pk_alerts} Pakistan alerts.

Here are today's cybersecurity news articles:
{art_list}

Select the 3 most important article numbers for Pakistani security professionals (banking, telecom, government, healthcare sectors).
Prioritize: Pakistan-relevant threats, ransomware, critical vulnerabilities, data breaches, nation-state attacks.

Reply with ONLY 3 numbers separated by commas. Example: 2,5,9"""
        resp = client.chat.completions.create(
            model="llama-3.3-70b-versatile",
            messages=[{"role":"user","content":prompt}],
            max_tokens=20, temperature=0.2,
        )
        nums = resp.choices[0].message.content.strip()
        indices = [int(n.strip())-1 for n in nums.split(",") if n.strip().isdigit()]
        selected = [articles[i] for i in indices if 0 <= i < len(articles)]
        if selected:
            print(f"[✓] AI selected {len(selected)} top articles")
            return selected
    except Exception as e:
        print(f"[!] Article selection failed: {e}")
    return articles[:3]


def generate_blog_html(articles, threats, today_str):
    """Generate a full HTML blog post from selected articles."""
    if not GROQ_API_KEY:
        return None
    try:
        from groq import Groq
        client = Groq(api_key=GROQ_API_KEY)

        # Build context
        pk_threats = [t for t in threats.get("threats",[]) if t.get("pakistan")][:5]
        pk_list = "\n".join([f"- {t['id']}: {t['desc'][:100]}" for t in pk_threats])
        stats = threats.get("stats",{})

        art_context = ""
        for i, a in enumerate(articles, 1):
            art_context += f"\n\nARTICLE {i}: [{a['source']}]\nTitle: {a['title']}\nSummary: {a['desc']}\nURL: {a['link']}"

        prompt = f"""You are a senior cybersecurity analyst and writer for InfoSec Pakistan — Pakistan's leading threat intelligence platform. Write a comprehensive 1000-word blog post for today's cybersecurity digest.

TODAY'S DATE: {today_str}
TODAY'S THREAT STATS:
- Total threats monitored: {stats.get('total',0):,}
- New threats today: {stats.get('new',0)}
- Zero-day exploits: {stats.get('zeroday',0)}
- Actively exploited: {stats.get('exploited',0)}
- Pakistan-specific alerts: {stats.get('pakistan',0)}

PAKISTAN-SPECIFIC THREATS TODAY:
{pk_list if pk_list else "No specific Pakistan alerts today"}

TOP NEWS ARTICLES TO COVER:
{art_context}

WRITING INSTRUCTIONS:
- Write exactly 1000 words
- Write like a human security analyst — conversational, authoritative, not robotic
- Structure: Opening hook → Article 1 analysis → Article 2 analysis → Article 3 analysis → Pakistan Impact → Actionable Recommendations → Closing
- Always connect global threats to Pakistani organizations (banking, telecom, government, healthcare)
- Use section headers with ## prefix
- Include specific CVE IDs, vendor names, and technical details where relevant
- End with 3-5 concrete actions Pakistani security teams should take today
- Tone: Professional but accessible — a CISO should find it valuable, but a developer should understand it

Output ONLY the blog content. No preamble. Start directly with the opening paragraph."""

        resp = client.chat.completions.create(
            model="llama-3.3-70b-versatile",
            messages=[{"role":"user","content":prompt}],
            max_tokens=2000, temperature=0.6,
        )
        content = resp.choices[0].message.content.strip()
        print(f"[✓] AI generated blog post ({len(content)} chars)")
        return content
    except Exception as e:
        print(f"[!] Blog generation failed: {e}")
        return None


def content_to_html(content, articles, today_str, stats):
    """Convert markdown-style blog content to beautiful HTML."""
    import re
    from datetime import datetime

    # Parse sections
    lines = content.split("\n")
    html_body = ""
    in_list = False

    for line in lines:
        line = line.strip()
        if not line:
            if in_list:
                html_body += "</ul>\n"
                in_list = False
            html_body += "<br>\n"
            continue

        # Headers
        if line.startswith("## "):
            if in_list: html_body += "</ul>\n"; in_list = False
            text = line[3:].strip()
            html_body += f'<h2 class="blog-h2">{text}</h2>\n'
        elif line.startswith("# "):
            text = line[2:].strip()
            html_body += f'<h1 class="blog-h1">{text}</h1>\n'
        elif line.startswith("### "):
            text = line[4:].strip()
            html_body += f'<h3 class="blog-h3">{text}</h3>\n'
        # Bullet points
        elif line.startswith("- ") or line.startswith("* "):
            if not in_list:
                html_body += '<ul class="blog-list">\n'
                in_list = True
            text = line[2:].strip()
            text = re.sub(r'\*\*(.+?)\*\*', r'<strong>\1</strong>', text)
            html_body += f'<li>{text}</li>\n'
        # Numbered list
        elif re.match(r'^\d+\. ', line):
            if not in_list:
                html_body += '<ol class="blog-list">\n'
                in_list = True
            text = re.sub(r'^\d+\. ', '', line)
            text = re.sub(r'\*\*(.+?)\*\*', r'<strong>\1</strong>', text)
            html_body += f'<li>{text}</li>\n'
        # Regular paragraph
        else:
            if in_list: html_body += "</ul>\n"; in_list = False
            text = re.sub(r'\*\*(.+?)\*\*', r'<strong>\1</strong>', text if 'text' in dir() else line)
            text = re.sub(r'\*\*(.+?)\*\*', r'<strong>\1</strong>', line)
            text = re.sub(r'`(.+?)`', r'<code>\1</code>', text)
            html_body += f'<p class="blog-p">{text}</p>\n'

    if in_list:
        html_body += "</ul>\n"

    # Build sources section
    sources_html = ""
    for a in articles:
        sources_html += f'''<a href="{a['link']}" target="_blank" rel="noopener" class="source-ref">
          <span class="src-badge">{a['source']}</span>
          <span class="src-title">{a['title'][:80]}{'...' if len(a['title'])>80 else ''}</span>
          <span class="src-arrow">→</span>
        </a>'''

    # Stat cards
    total = stats.get('total',0)
    new   = stats.get('new',0)
    zd    = stats.get('zeroday',0)
    pk    = stats.get('pakistan',0)
    exp   = stats.get('exploited',0)

    # Format date nicely
    try:
        dt = datetime.strptime(today_str, "%Y-%m-%d")
        nice_date = dt.strftime("%B %d, %Y")
        slug_date = dt.strftime("%Y-%m-%d")
    except:
        nice_date = today_str
        slug_date = today_str

    html = f'''<!DOCTYPE html>
<html lang="en">
<head>
  <script async src="https://pagead2.googlesyndication.com/pagead/js/adsbygoogle.js?client=ca-pub-1391334995238896" crossorigin="anonymous"></script>
  <meta charset="UTF-8">
  <meta name="viewport" content="width=device-width, initial-scale=1.0">
  <title>Daily Cyber Digest — {nice_date} | InfoSec Pakistan</title>
  <meta name="description" content="Daily cybersecurity analysis for Pakistani organizations — {nice_date}. {new} new threats, {zd} zero-days, {pk} Pakistan alerts.">
  <link rel="preconnect" href="https://fonts.googleapis.com">
  <link href="https://fonts.googleapis.com/css2?family=Inter:wght@300;400;500;600;700;800&family=Space+Grotesk:wght@400;500;600;700&display=swap" rel="stylesheet">
<style>
:root{{--bg:#05070d;--bg2:#090d16;--bg3:#0e1420;--bg4:#141b28;--border:rgba(255,255,255,0.06);--border2:rgba(255,255,255,0.1);--text:#fff;--text2:#94a3b8;--text3:#64748b;--blue:#2563eb;--blue2:#3b82f6;--blue3:#60a5fa;--red:#ef4444;--red2:#f87171;--orange:#f97316;--green:#22c55e;--cyan:#06b6d4;--purple:#a855f7;--body:'Inter',sans-serif;--display:'Space Grotesk',sans-serif;}}
*,*::before,*::after{{box-sizing:border-box;margin:0;padding:0;}}
body{{background:var(--bg);color:var(--text);font-family:var(--body);line-height:1.7;min-height:100vh;-webkit-font-smoothing:antialiased;}}
body::before{{content:'';position:fixed;inset:0;background-image:linear-gradient(rgba(37,99,235,0.02) 1px,transparent 1px),linear-gradient(90deg,rgba(37,99,235,0.02) 1px,transparent 1px);background-size:56px 56px;pointer-events:none;z-index:0;}}
nav{{position:sticky;top:0;z-index:100;display:flex;align-items:center;justify-content:space-between;padding:0 48px;height:64px;background:rgba(5,7,13,0.95);backdrop-filter:blur(20px);border-bottom:1px solid var(--border);}}
.brand{{display:flex;align-items:center;gap:14px;text-decoration:none;}}
.brand-icon{{width:36px;height:36px;background:var(--blue);border-radius:8px;display:flex;align-items:center;justify-content:center;font-size:18px;}}
.brand-name{{font-family:var(--display);font-weight:700;font-size:16px;color:#fff;}}
.brand-name span{{color:var(--blue3);}}
.nav-links{{display:flex;gap:2px;}}
.nav-links a{{color:var(--text3);text-decoration:none;padding:8px 18px;font-size:13.5px;font-weight:500;border-radius:8px;transition:all 0.2s;}}
.nav-links a:hover,.nav-links a.active{{color:#fff;background:var(--bg3);}}
.live-badge{{display:flex;align-items:center;gap:7px;font-size:12px;font-weight:600;color:var(--green);background:rgba(34,197,94,0.08);border:1px solid rgba(34,197,94,0.2);padding:7px 16px;border-radius:6px;}}
.live-dot{{width:7px;height:7px;background:var(--green);border-radius:50%;animation:blink 2s infinite;}}
@keyframes blink{{0%,100%{{opacity:1}}50%{{opacity:0.3}}}}
.hamburger{{display:none;flex-direction:column;gap:5px;background:none;border:none;cursor:pointer;padding:4px;}}
.hamburger span{{display:block;width:22px;height:2px;background:#fff;border-radius:2px;transition:all 0.3s;}}
.hamburger.open span:nth-child(1){{transform:translateY(7px) rotate(45deg);}}
.hamburger.open span:nth-child(2){{opacity:0;}}
.hamburger.open span:nth-child(3){{transform:translateY(-7px) rotate(-45deg);}}
.page-wrap{{position:relative;z-index:1;max-width:1100px;margin:0 auto;padding:48px 48px 80px;display:grid;grid-template-columns:1fr 300px;gap:48px;align-items:start;}}
.breadcrumb{{display:flex;align-items:center;gap:8px;font-size:12px;color:var(--text3);margin-bottom:24px;}}
.breadcrumb a{{color:var(--blue3);text-decoration:none;}}
.post-cat{{display:inline-flex;align-items:center;gap:6px;background:rgba(168,85,247,0.1);border:1px solid rgba(168,85,247,0.25);color:var(--purple);font-size:11px;font-weight:700;letter-spacing:0.08em;text-transform:uppercase;padding:4px 12px;border-radius:4px;margin-bottom:14px;}}
.post-title{{font-family:var(--display);font-size:clamp(22px,3.5vw,36px);font-weight:700;line-height:1.15;color:#fff;letter-spacing:-0.02em;margin-bottom:14px;}}
.post-meta{{display:flex;align-items:center;gap:14px;flex-wrap:wrap;padding:14px 0;border-top:1px solid var(--border);border-bottom:1px solid var(--border);margin-bottom:28px;}}
.meta-item{{font-size:12px;color:var(--text3);display:flex;align-items:center;gap:5px;}}
.meta-item strong{{color:var(--text2);}}
.ai-badge{{display:inline-flex;align-items:center;gap:5px;background:rgba(37,99,235,0.1);border:1px solid rgba(37,99,235,0.2);color:var(--blue3);font-size:10px;font-weight:700;padding:3px 10px;border-radius:20px;}}
/* STAT CARDS */
.stat-cards{{display:grid;grid-template-columns:repeat(5,1fr);gap:10px;margin-bottom:32px;}}
.stat-card{{background:var(--bg2);border:1px solid var(--border);border-radius:10px;padding:14px;text-align:center;position:relative;overflow:hidden;}}
.stat-card::before{{content:'';position:absolute;top:0;left:0;right:0;height:2px;}}
.sc-red::before{{background:var(--red);}} .sc-orange::before{{background:var(--orange);}}
.sc-blue::before{{background:var(--blue2);}} .sc-green::before{{background:var(--green);}}
.sc-purple::before{{background:var(--purple);}}
.sc-num{{font-family:var(--display);font-size:26px;font-weight:900;line-height:1;}}
.sc-num.red{{color:var(--red);}} .sc-num.orange{{color:var(--orange);}}
.sc-num.blue{{color:var(--blue3);}} .sc-num.green{{color:var(--green);}}
.sc-num.purple{{color:var(--purple);}}
.sc-label{{font-size:10px;color:var(--text3);margin-top:5px;font-weight:500;}}
/* BLOG CONTENT */
.blog-h1{{font-family:var(--display);font-size:22px;font-weight:700;color:#fff;margin:32px 0 14px;}}
.blog-h2{{font-family:var(--display);font-size:19px;font-weight:700;color:#fff;margin:32px 0 12px;padding-bottom:8px;border-bottom:1px solid var(--border);display:flex;align-items:center;gap:8px;}}
.blog-h2::before{{content:'▋';color:var(--purple);font-size:14px;}}
.blog-h3{{font-family:var(--display);font-size:15px;font-weight:700;color:var(--blue3);margin:20px 0 10px;}}
.blog-p{{font-size:14.5px;color:var(--text2);line-height:1.85;margin-bottom:18px;}}
.blog-p strong{{color:#fff;}}
.blog-p code{{background:var(--bg3);border:1px solid var(--border);border-radius:4px;padding:2px 7px;font-family:'Courier New',monospace;font-size:12px;color:var(--cyan);}}
.blog-list{{color:var(--text2);font-size:14px;padding-left:20px;margin-bottom:18px;}}
.blog-list li{{margin-bottom:7px;line-height:1.7;}}
.blog-list li::marker{{color:var(--purple);}}
/* SOURCES */
.sources-section{{margin-top:36px;padding-top:24px;border-top:1px solid var(--border);}}
.sources-title{{font-family:var(--display);font-size:13px;font-weight:700;color:var(--text3);margin-bottom:12px;letter-spacing:0.06em;text-transform:uppercase;}}
.source-ref{{display:flex;align-items:center;gap:10px;padding:10px 14px;background:var(--bg2);border:1px solid var(--border);border-radius:8px;text-decoration:none;margin-bottom:8px;transition:all 0.2s;}}
.source-ref:hover{{border-color:var(--border2);transform:translateX(3px);}}
.src-badge{{font-size:10px;font-weight:700;color:var(--purple);background:rgba(168,85,247,0.1);border:1px solid rgba(168,85,247,0.2);padding:2px 8px;border-radius:4px;white-space:nowrap;}}
.src-title{{font-size:12.5px;color:var(--text2);flex:1;}}
.src-arrow{{color:var(--purple);font-size:12px;}}
/* SIDEBAR */
aside{{position:sticky;top:84px;}}
.sb-card{{background:var(--bg2);border:1px solid var(--border);border-radius:12px;padding:18px;margin-bottom:14px;}}
.sb-title{{font-family:var(--display);font-size:12px;font-weight:700;color:#fff;margin-bottom:12px;padding-bottom:8px;border-bottom:1px solid var(--border);}}
.back-btn{{display:flex;align-items:center;gap:8px;padding:10px 14px;background:var(--bg3);border:1px solid var(--border2);border-radius:8px;text-decoration:none;font-size:12.5px;color:var(--text2);margin-bottom:8px;transition:all 0.2s;}}
.back-btn:hover{{color:#fff;}}
.share-btn{{display:flex;align-items:center;gap:8px;padding:9px 12px;background:var(--bg3);border:1px solid var(--border);border-radius:7px;font-size:12px;color:var(--text2);cursor:pointer;border:none;width:100%;text-align:left;margin-bottom:6px;transition:all 0.2s;text-decoration:none;}}
.share-btn:hover{{color:#fff;}}
footer{{position:relative;z-index:1;border-top:1px solid var(--border);padding:24px 48px;display:flex;align-items:center;justify-content:space-between;flex-wrap:wrap;gap:12px;}}
.footer-brand{{font-family:var(--display);font-size:14px;font-weight:700;color:var(--text2);}}
.footer-brand span{{color:var(--blue3);}}
.footer-link{{color:var(--blue3);text-decoration:none;font-size:12px;}}
.footer-txt{{font-size:12px;color:var(--text3);}}
@media(max-width:900px){{.page-wrap{{grid-template-columns:1fr;padding:28px 16px 60px;}}aside{{display:none;}}}}
@media(max-width:768px){{nav{{padding:0 16px;}}.hamburger{{display:flex;}}.nav-links{{display:none;flex-direction:column;position:fixed;top:64px;left:0;right:0;background:rgba(5,7,13,0.98);backdrop-filter:blur(20px);border-bottom:1px solid var(--border);padding:16px;gap:4px;z-index:150;}}.nav-links.open{{display:flex;}}.nav-links a{{padding:12px 16px;font-size:15px;border-radius:8px;border-bottom:1px solid var(--border);}}.stat-cards{{grid-template-columns:1fr 1fr;}}footer{{padding:20px 16px;flex-direction:column;text-align:center;}}}}
</style>
</head>
<body>
<nav>
  <a class="brand" href="index.html"><div class="brand-icon">🛡</div><div class="brand-name">INFOSEC <span>PAKISTAN</span></div></a>
  <div class="nav-links" id="nav-links">
    <a href="index.html">Dashboard</a><a href="reports.html">Daily Reports</a>
    <a href="database.html">CVE Database</a><a href="news.html">News</a>
    <a href="blogs.html" class="active">Blogs</a><a href="about.html">About</a>
    <a href="contact.html">Contact</a><a href="sandbox.html">Sandbox</a>
  </div>
  <div style="display:flex;align-items:center;gap:12px;">
    <div class="live-badge"><div class="live-dot"></div>LIVE</div>
    <button class="hamburger" id="hamburger" onclick="toggleNav()" aria-label="Menu"><span></span><span></span><span></span></button>
  </div>
</nav>
<div class="page-wrap">
<article>
  <div class="breadcrumb"><a href="index.html">Home</a> › <a href="blogs.html">Blogs</a> › Daily Digest</div>
  <div class="post-cat">📰 Daily AI Digest · {nice_date}</div>
  <h1 class="post-title">Cybersecurity Digest — {nice_date}: What Pakistani Security Teams Need to Know Today</h1>
  <div class="post-meta">
    <div class="meta-item">📅 <strong>{nice_date}</strong></div>
    <div class="meta-item">✍️ <strong>InfoSec Pakistan</strong></div>
    <div class="meta-item">⏱ <strong>~5 min read</strong></div>
    <div class="meta-item">🤖 <span class="ai-badge">AI Analysis · LLaMA 70B</span></div>
    <div class="meta-item">🇵🇰 <strong>Pakistan Focused</strong></div>
  </div>

  <!-- STAT CARDS -->
  <div class="stat-cards">
    <div class="stat-card sc-red"><div class="sc-num red">{new}</div><div class="sc-label">New Threats</div></div>
    <div class="stat-card sc-orange"><div class="sc-num orange">{zd}</div><div class="sc-label">Zero-Days</div></div>
    <div class="stat-card sc-blue"><div class="sc-num blue">{exp}</div><div class="sc-label">Actively Exploited</div></div>
    <div class="stat-card sc-green"><div class="sc-num green">{pk}</div><div class="sc-label">🇵🇰 PK Alerts</div></div>
    <div class="stat-card sc-purple"><div class="sc-num purple">{total:,}</div><div class="sc-label">Total Monitored</div></div>
  </div>

  <!-- BLOG CONTENT -->
  {html_body}

  <!-- SOURCES -->
  <div class="sources-section">
    <div class="sources-title">📰 Sources Covered in This Digest</div>
    {sources_html}
  </div>

  <!-- NAV -->
  <div style="margin-top:28px;display:flex;gap:12px;flex-wrap:wrap;">
    <a href="blogs.html" style="color:var(--blue3);font-size:13px;text-decoration:none;">← All Blog Posts</a>
    <a href="index.html" style="color:var(--text3);font-size:13px;text-decoration:none;">← Dashboard</a>
  </div>
</article>
<aside>
  <div class="sb-card">
    <div class="sb-title">🔗 Navigation</div>
    <a class="back-btn" href="blogs.html">← All Blog Posts</a>
    <a class="back-btn" href="index.html">🏠 Dashboard</a>
    <a class="back-btn" href="database.html">📋 CVE Database</a>
    <a class="back-btn" href="sandbox.html">🔬 Sandbox Tool</a>
  </div>
  <div class="sb-card">
    <div class="sb-title">📊 Today's Stats</div>
    <div style="font-size:12px;color:var(--text2);display:flex;flex-direction:column;gap:8px;">
      <div>🔴 <strong style="color:#fff">{new}</strong> new threats today</div>
      <div>⚡ <strong style="color:var(--orange)">{zd}</strong> zero-day exploits</div>
      <div>🎯 <strong style="color:var(--red2)">{exp}</strong> actively exploited</div>
      <div>🇵🇰 <strong style="color:var(--green)">{pk}</strong> Pakistan alerts</div>
      <div>📊 <strong style="color:var(--blue3)">{total:,}</strong> total monitored</div>
    </div>
  </div>
  <div class="sb-card">
    <div class="sb-title">🔗 Share</div>
    <button class="share-btn" onclick="navigator.clipboard.writeText(window.location.href).then(()=>alert('Copied!'))">📋 Copy Link</button>
    <a class="share-btn" href="https://twitter.com/intent/tweet?text=Daily+Cybersecurity+Digest+{today_str}+by+InfoSec+Pakistan&url=https://pakistaninfosec.github.io/blog-{slug_date}.html" target="_blank">𝕏 Share on X</a>
    <a class="share-btn" href="https://wa.me/?text=Daily+Cyber+Digest+{nice_date}+https://pakistaninfosec.github.io/blog-{slug_date}.html" target="_blank">💬 WhatsApp</a>
  </div>
</aside>
</div>
<footer>
  <div class="footer-brand">INFOSEC <span>PAKISTAN</span></div>
  <div style="display:flex;gap:16px;flex-wrap:wrap;">
    <a class="footer-link" href="privacy.html">Privacy</a>
    <a class="footer-link" href="disclaimer.html">Disclaimer</a>
    <a class="footer-link" href="terms.html">Terms</a>
  </div>
  <div class="footer-txt">AI-Assisted Digest · <a class="footer-link" href="https://pakistaninfosec.github.io">pakistaninfosec.github.io</a></div>
</footer>
<script>
function toggleNav(){{
  document.getElementById('nav-links').classList.toggle('open');
  document.getElementById('hamburger').classList.toggle('open');
}}
document.querySelectorAll('.nav-links a').forEach(a=>{{
  a.addEventListener('click',()=>{{
    document.getElementById('nav-links').classList.remove('open');
    document.getElementById('hamburger').classList.remove('open');
  }});
}});
</script>
</body>
</html>'''
    return html


def update_blogs_index(today_str, title_snippet):
    """Update blogs.json index file with new post reference."""
    try:
        import requests as req
        headers = {"Authorization": f"token {GITHUB_TOKEN}",
                   "Accept": "application/vnd.github.v3+json"}
        url = f"https://api.github.com/repos/{GITHUB_REPO}/contents/data/blogs.json"

        # Get existing
        r = req.get(url, headers=headers)
        if r.status_code == 200:
            import base64
            existing = json.loads(base64.b64decode(r.json()["content"]).decode())
            sha = r.json()["sha"]
        else:
            existing = {"posts": []}
            sha = None

        # Add new post
        new_post = {
            "date": today_str,
            "title": f"Cybersecurity Digest — {today_str}",
            "slug": f"blog-{today_str}.html",
            "snippet": title_snippet[:150],
        }

        # Remove duplicate if same date exists
        existing["posts"] = [p for p in existing.get("posts",[]) if p.get("date") != today_str]
        existing["posts"].insert(0, new_post)
        existing["posts"] = existing["posts"][:30]  # Keep last 30

        import base64
        content_b64 = base64.b64encode(json.dumps(existing, indent=2).encode()).decode()
        payload = {"message": f"blog: add digest {today_str}", "content": content_b64}
        if sha:
            payload["sha"] = sha

        r2 = req.put(url, headers=headers, json=payload)
        if r2.status_code in [200, 201]:
            print(f"[✓] Updated blogs.json index")
        else:
            print(f"[!] blogs.json update failed: {r2.status_code}")
    except Exception as e:
        print(f"[!] blogs.json update error: {e}")


def generate_daily_blog(threats):
    """Main function to generate and publish daily blog post."""
    today_str = date.today().isoformat()
    filename  = f"blog-{today_str}.html"

    print(f"[→] Generating blog for {today_str}...")

    # 1. Fetch news
    articles = fetch_news_rss()
    if not articles:
        print("[!] No news articles fetched — skipping blog")
        return

    # 2. Select top 3
    selected = select_top_news(articles, threats)
    if not selected:
        print("[!] No articles selected — skipping blog")
        return

    # 3. Generate content
    content = generate_blog_html(selected, threats, today_str)
    if not content:
        print("[!] AI content generation failed — skipping blog")
        return

    # 4. Build HTML
    stats = threats.get("stats", {})
    html = content_to_html(content, selected, today_str, stats)

    # 5. Push to GitHub
    push_to_github(filename, html, is_html=True)
    print(f"[✓] Published blog: {filename}")

    # 6. Update index
    update_blogs_index(today_str, content[:150])



if __name__ == "__main__":
    main()
