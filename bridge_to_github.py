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

    if not results:
        # Fallback — hardcode known real advisories from 2026
        known = [
            ("Advisory No 13: Critical Vulnerabilities in Fortinet FortiSandbox Under Active Exploitation", "https://pkcert.gov.pk/advisory/26/13.pdf"),
            ("Advisory No 12: Large-Scale Compromise of Fortinet FortiGate Firewalls and VPN Infrastructure", "https://pkcert.gov.pk/advisory/26/12.pdf"),
            ("Advisory No 11: Critical Vulnerability in Palo Alto Networks GlobalProtect (CVE-2026-0257)", "https://pkcert.gov.pk/advisory/26/11.pdf"),
            ("Advisory No 10: Critical Remote Code Execution Vulnerabilities in n8n Workflow Automation", "https://pkcert.gov.pk/advisory/26/10.pdf"),
            ("Advisory No 09: Critical Authentication Bypass in Cisco SD-WAN Manager", "https://pkcert.gov.pk/advisory/26/8.pdf"),
            ("Advisory No 08: Persistent Application Security Weaknesses Requiring Immediate Remediation", "https://pkcert.gov.pk/advisory/26/7.pdf"),
            ("Advisory No 07: Critical Pre-Authentication RCE in BeyondTrust Remote Support", "https://pkcert.gov.pk/advisory/26/6.pdf"),
            ("Advisory No 06: Active Exploitation of Zero-Day Vulnerabilities in Ivanti EPMM", "https://pkcert.gov.pk/advisory/26/5.pdf"),
            ("Advisory No 05: Actively Exploited Microsoft Office Zero-Day Vulnerability", "https://pkcert.gov.pk/advisory/26/4.pdf"),
            ("Advisory No 04: Critical Fortinet FortiSIEM and FortiOS RCE Vulnerabilities", "https://pkcert.gov.pk/advisory/26/3.pdf"),
            ("Advisory No 03: Critical n8n Remote Code Execution Vulnerability", "https://pkcert.gov.pk/advisory/26/2.pdf"),
            ("Advisory No 01: Widespread WhatsApp Account Hijacking and Unauthorized Access", "https://pkcert.gov.pk/advisory/26/1.pdf"),
        ]
        for title, link in known:
            desc = f"Pakistan CERT Security Advisory: {title}. Pakistani organizations should review this advisory and apply mitigations immediately. Full details available in the linked PDF."
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
                "url": link,
                "vendor": "Pakistan CERT", "price": "",
                "tags": "pakistan,cert,advisory,government",
            })

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
    for fmt in ["%Y-%m-%d", "%Y-%m-%dT%H:%M:%S", "%Y-%m-%dT%H:%M:%SZ"]:
        try:
            return datetime.strptime(s[:len(fmt)], fmt).strftime("%Y-%m-%d")
        except Exception:
            pass
    return s[:10] if len(s) >= 10 else date.today().isoformat()


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


def push_to_github(filename, content_dict):
    if not GITHUB_TOKEN:
        print(f"[!] No GITHUB_TOKEN — skipping {filename}")
        return False
    url     = f"https://api.github.com/repos/{GITHUB_REPO}/contents/data/{filename}"
    headers = {"Authorization": f"token {GITHUB_TOKEN}", "Accept": "application/vnd.github.v3+json"}
    res = requests.get(url, headers=headers)
    sha = res.json().get("sha", "") if res.status_code == 200 else ""
    content = base64.b64encode(
        json.dumps(content_dict, indent=2, ensure_ascii=False).encode()
    ).decode()
    payload = {"message": f"threat data: {date.today()}", "content": content}
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

    if GITHUB_TOKEN:
        print("\n📤 Pushing to GitHub...")
        push_to_github("threats.json", td)
        push_to_github("reports.json", rd)
    else:
        print("[!] No GITHUB_TOKEN — data not pushed")

    print("\n✅ Done! https://pakistaninfosec.github.io")


if __name__ == "__main__":
    main()
