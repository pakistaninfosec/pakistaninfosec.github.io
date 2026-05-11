"""
scraper/sources/pakistan.py
============================
Scrapes Pakistan-specific cybersecurity advisories from:
1. PKCERT (National CERT of Pakistan) - https://pkcert.gov.pk
2. NCCS Pakistan - https://nccs.pk
"""

import requests
import hashlib
from datetime import date
from bs4 import BeautifulSoup

HEADERS = {
    "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 Chrome/120.0.0.0 Safari/537.36"
}


# ─────────────────────────────────────────────
# PKCERT — pkcert.gov.pk/advisories.asp
# ─────────────────────────────────────────────
def scrape_pkcert(max_results=20):
    """Scrape advisories from Pakistan CERT"""
    results = []
    try:
        url = "https://pkcert.gov.pk/advisories.asp"
        res = requests.get(url, headers=HEADERS, timeout=15)
        res.raise_for_status()
        soup = BeautifulSoup(res.text, "html.parser")

        # Find advisory rows/cards on the page
        advisories = []

        # Try table rows
        rows = soup.find_all("tr")
        for row in rows:
            cols = row.find_all("td")
            if len(cols) >= 2:
                title_el = cols[0].find("a") or cols[0]
                title = title_el.get_text(strip=True)
                link  = title_el.get("href","") if title_el.name=="a" else ""
                date_text = cols[-1].get_text(strip=True) if cols else ""

                if title and len(title) > 10:
                    advisories.append({
                        "title": title,
                        "link":  link,
                        "date":  date_text
                    })

        # Try div/article cards if no table rows found
        if not advisories:
            cards = soup.find_all(["div","article","li"], class_=lambda c: c and any(
                x in str(c).lower() for x in ["advisory","alert","notice","item","card"]
            ))
            for card in cards:
                title_el = card.find(["h2","h3","h4","a","strong"])
                if title_el:
                    title = title_el.get_text(strip=True)
                    link  = title_el.get("href","") if title_el.name=="a" else ""
                    if title and len(title) > 10:
                        advisories.append({"title":title,"link":link,"date":""})

        # Convert to standard format
        for adv in advisories[:max_results]:
            title = adv["title"]
            link  = adv["link"]
            if link and not link.startswith("http"):
                link = "https://pkcert.gov.pk/" + link.lstrip("/")

            # Generate unique ID
            uid = "PKCERT-" + hashlib.md5(title.encode()).hexdigest()[:8].upper()

            # Parse date
            date_str = date.today().isoformat()
            raw_date = adv.get("date","")
            if raw_date:
                try:
                    from datetime import datetime
                    for fmt in ["%d-%m-%Y","%Y-%m-%d","%d %b %Y","%B %d, %Y"]:
                        try:
                            date_str = datetime.strptime(raw_date.strip()[:len(fmt)+2], fmt).strftime("%Y-%m-%d")
                            break
                        except: pass
                except: pass

            results.append({
                "source":         "Pakistan CERT",
                "category":       "Pakistan Advisory",
                "id":             uid,
                "title":          title,
                "description":    f"Pakistan CERT Advisory: {title}. Issued by the National Cyber Emergency Response Team of Pakistan.",
                "severity":       "HIGH",
                "cvss_score":     7.5,
                "cwe":            "",
                "affected_products": "Pakistan government and critical infrastructure systems",
                "references":     link,
                "published_date": date_str,
                "last_modified":  date_str,
                "url":            link or url,
                "vendor":         "Pakistan CERT",
                "price":          "",
                "tags":           "pakistan,cert,advisory,government",
            })

        print(f"[✓] PKCERT: {len(results)} advisories")

    except Exception as e:
        print(f"[!] PKCERT scrape failed: {e}")

        # Fallback: return a placeholder if site is down
        results.append({
            "source":         "Pakistan CERT",
            "category":       "Pakistan Advisory",
            "id":             f"PKCERT-{date.today().strftime('%Y%m%d')}",
            "title":          "Pakistan CERT Daily Advisory Check",
            "description":    "Pakistan CERT advisories are checked daily. Visit pkcert.gov.pk for the latest security advisories affecting Pakistani organizations.",
            "severity":       "MEDIUM",
            "cvss_score":     5.0,
            "cwe":            "",
            "affected_products": "Pakistan government and critical infrastructure",
            "references":     "https://pkcert.gov.pk/advisories.asp",
            "published_date": date.today().isoformat(),
            "last_modified":  date.today().isoformat(),
            "url":            "https://pkcert.gov.pk/advisories.asp",
            "vendor":         "Pakistan CERT",
            "price":          "",
            "tags":           "pakistan,cert,advisory",
        })

    return results


# ─────────────────────────────────────────────
# NCCS — nccs.pk/NTL/Home.html
# ─────────────────────────────────────────────
def scrape_nccs(max_results=10):
    """Scrape threat intelligence from NCCS Pakistan"""
    results = []
    try:
        # Try National Threat Library first
        urls_to_try = [
            "https://nccs.pk/NTL/Home.html",
            "https://nccs.pk/NCCSBlog/TWICS.html",
            "https://nccs.pk/",
        ]

        advisories = []
        for url in urls_to_try:
            try:
                res = requests.get(url, headers=HEADERS, timeout=15)
                if res.status_code == 200:
                    soup = BeautifulSoup(res.text, "html.parser")

                    # Find threat/advisory entries
                    entries = soup.find_all(["div","article","li","tr"])
                    for entry in entries:
                        title_el = entry.find(["h2","h3","h4","a","strong","b"])
                        if title_el:
                            title = title_el.get_text(strip=True)
                            link  = title_el.get("href","") if title_el.name=="a" else ""
                            if title and len(title) > 15 and "nccs" not in title.lower():
                                advisories.append({"title":title,"link":link,"source_url":url})
                    if advisories:
                        break
            except: continue

        for adv in advisories[:max_results]:
            title = adv["title"]
            link  = adv.get("link","")
            if link and not link.startswith("http"):
                link = "https://nccs.pk/" + link.lstrip("/")

            uid = "NCCS-" + hashlib.md5(title.encode()).hexdigest()[:8].upper()

            results.append({
                "source":         "NCCS Pakistan",
                "category":       "Pakistan Advisory",
                "id":             uid,
                "title":          title,
                "description":    f"NCCS Pakistan Threat Intelligence: {title}. Published by National Centre for Cyber Security Pakistan.",
                "severity":       "HIGH",
                "cvss_score":     7.0,
                "cwe":            "",
                "affected_products": "Pakistani organizations and critical infrastructure",
                "references":     link or "https://nccs.pk",
                "published_date": date.today().isoformat(),
                "last_modified":  date.today().isoformat(),
                "url":            link or "https://nccs.pk/NTL/Home.html",
                "vendor":         "NCCS Pakistan",
                "price":          "",
                "tags":           "pakistan,nccs,threat-intelligence,advisory",
            })

        print(f"[✓] NCCS: {len(results)} entries")

    except Exception as e:
        print(f"[!] NCCS scrape failed: {e}")

    # Always add NCCS as a source entry
    if not results:
        results.append({
            "source":         "NCCS Pakistan",
            "category":       "Pakistan Advisory",
            "id":             f"NCCS-{date.today().strftime('%Y%m%d')}",
            "title":          "NCCS Pakistan Weekly Cyber Security Update",
            "description":    "National Centre for Cyber Security Pakistan publishes weekly threat intelligence. Visit nccs.pk for latest advisories affecting Pakistani cyberspace.",
            "severity":       "MEDIUM",
            "cvss_score":     5.5,
            "cwe":            "",
            "affected_products": "Pakistani organizations and universities",
            "references":     "https://nccs.pk/NCCSBlog/TWICS.html",
            "published_date": date.today().isoformat(),
            "last_modified":  date.today().isoformat(),
            "url":            "https://nccs.pk/NCCSBlog/TWICS.html",
            "vendor":         "NCCS Pakistan",
            "price":          "",
            "tags":           "pakistan,nccs,weekly,threat-intelligence",
        })

    return results


# ─────────────────────────────────────────────
# MAIN FUNCTION — called by scraper
# ─────────────────────────────────────────────
def scrape(max_results=30):
    """Scrape all Pakistan sources"""
    print("\n[Pakistan Sources] Scraping PKCERT + NCCS...")
    results = []
    results.extend(scrape_pkcert(max_results=20))
    results.extend(scrape_nccs(max_results=10))
    print(f"[✓] Total Pakistan alerts: {len(results)}")
    return results


if __name__ == "__main__":
    items = scrape()
    for item in items:
        print(f"  [{item['source']}] {item['id']}: {item['title'][:60]}")
