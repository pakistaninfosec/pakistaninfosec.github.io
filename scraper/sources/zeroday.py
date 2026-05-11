"""
Zero-day & exploit data sources:
  - CISA Known Exploited Vulnerabilities  (cisa.gov JSON API)
  - Zero Day Initiative                   (zerodayinitiative.com)
  - Exploit Database                      (exploit-db.com)
  - Google Project Zero                   (googleprojectzero.blogspot.com RSS)
  - Packet Storm Security                 (packetstormsecurity.com)
  - Vulners                               (vulners.com public API)
"""

import json
import logging
import xml.etree.ElementTree as ET
from typing import Generator

from bs4 import BeautifulSoup
from ..utils import build_session, safe_get, polite_delay, random_headers

log = logging.getLogger(__name__)

CISA_KEV_URL = (
    "https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json"
)
_NO_BR = {"Accept-Encoding": "gzip, deflate"}


def _text(tag, default: str = "") -> str:
    return tag.get_text(strip=True) if tag else default


def _rss_items(xml_text: str) -> list[dict]:
    """Parse RSS 2.0 or Atom feed."""
    try:
        root = ET.fromstring(xml_text)
    except ET.ParseError:
        return []
    ATOM = "http://www.w3.org/2005/Atom"
    items = []
    for item in root.iter("item"):
        title = (item.findtext("title") or "").strip()
        link = (item.findtext("link") or "").strip()
        desc = (item.findtext("description") or "").strip()[:500]
        pub = (item.findtext("pubDate") or "")[:10]
        if title:
            items.append({"title": title, "url": link, "description": desc, "date": pub})
    for entry in root.iter(f"{{{ATOM}}}entry"):
        title_el = entry.find(f"{{{ATOM}}}title")
        title = (title_el.text or "").strip() if title_el is not None else ""
        link_el = entry.find(f"{{{ATOM}}}link")
        link = link_el.get("href", "") if link_el is not None else ""
        summary_el = entry.find(f"{{{ATOM}}}summary") or entry.find(f"{{{ATOM}}}content")
        summary = (summary_el.text or "").strip()[:500] if summary_el is not None else ""
        pub_el = entry.find(f"{{{ATOM}}}published") or entry.find(f"{{{ATOM}}}updated")
        pub = (pub_el.text or "")[:10] if pub_el is not None else ""
        if title:
            items.append({"title": title, "url": link, "description": summary, "date": pub})
    return items


def scrape_cisa_kev(max_results: int = 50) -> Generator[dict, None, None]:
    """CISA Known Exploited Vulnerabilities catalog — reliable public JSON API."""
    session = build_session()
    log.info("Scraping CISA Known Exploited Vulnerabilities catalog…")
    resp = safe_get(
        session,
        CISA_KEV_URL,
        headers={"Accept": "application/json"},
        logger=log,
    )
    if not resp:
        return

    try:
        data = resp.json()
    except Exception as exc:
        log.warning("CISA KEV JSON parse error: %s", exc)
        return

    vulns = data.get("vulnerabilities", [])
    log.info("CISA KEV: %d total entries (returning newest %d)", len(vulns), max_results)

    for vuln in vulns[-max_results:]:
        cve_id = vuln.get("cveID", "")
        name = vuln.get("vulnerabilityName", cve_id)
        product = vuln.get("product", "")
        vendor = vuln.get("vendorProject", "")
        desc = vuln.get("shortDescription", "")[:500]
        date_added = vuln.get("dateAdded", "")
        action = vuln.get("requiredAction", "")
        url = f"https://nvd.nist.gov/vuln/detail/{cve_id}" if cve_id else ""

        yield {
            "source": "CISA KEV",
            "category": "Zero Day",
            "id": cve_id or name,
            "title": f"{cve_id} — {name}" if cve_id else name,
            "description": f"{desc} Required action: {action}".strip() if action else desc,
            "severity": "HIGH",
            "cvss_score": "",
            "cwe": "",
            "affected_products": f"{vendor}/{product}" if vendor and product else product,
            "references": url,
            "published_date": date_added,
            "last_modified": vuln.get("dueDate", ""),
            "url": url,
            "vendor": vendor,
            "price": "",
            "tags": "zero-day,actively-exploited,cisa,kev",
        }

    polite_delay()


def scrape_zdi(max_advisories: int = 30) -> Generator[dict, None, None]:
    session = build_session()
    log.info("Scraping Zero Day Initiative advisories…")
    resp = safe_get(
        session,
        "https://www.zerodayinitiative.com/advisories/published/",
        headers=random_headers(),
        logger=log,
    )
    if not resp:
        return

    soup = BeautifulSoup(resp.text, "lxml")
    rows = (
        soup.select("table.advisories-table tbody tr")
        or soup.select("div.advisory-list div.advisory-item")
        or soup.select("tr[class*='advisory']")
        or soup.select("article")
    )

    count = 0
    for row in rows:
        if count >= max_advisories:
            break
        cells = row.select("td")
        title_tag = row.select_one("a")
        if not title_tag:
            continue

        title = _text(title_tag)
        href = title_tag.get("href", "")
        url = href if href.startswith("http") else f"https://www.zerodayinitiative.com{href}"

        cvss = ""
        severity = ""
        date = ""
        if cells:
            texts = [_text(c) for c in cells]
            for t in texts:
                if t.replace(".", "").isdigit() and 0 < float(t) <= 10:
                    cvss = t
                    score = float(t)
                    severity = "CRITICAL" if score >= 9 else "HIGH" if score >= 7 else "MEDIUM"
                if len(t) == 10 and t[4] == "-":
                    date = t

        if not title or len(title) < 5:
            continue

        yield {
            "source": "Zero Day Initiative",
            "category": "Zero Day",
            "id": url,
            "title": title,
            "description": f"ZDI advisory. CVSS: {cvss}" if cvss else "ZDI advisory.",
            "severity": severity,
            "cvss_score": cvss,
            "cwe": "",
            "affected_products": "",
            "references": url,
            "published_date": date,
            "last_modified": "",
            "url": url,
            "vendor": "Zero Day Initiative",
            "price": "",
            "tags": "zero-day,zdi,exploit",
        }
        count += 1

    polite_delay()


def scrape_exploit_db(max_results: int = 30) -> Generator[dict, None, None]:
    session = build_session()
    log.info("Scraping Exploit Database…")
    resp = safe_get(
        session,
        "https://www.exploit-db.com/",
        headers=random_headers(),
        logger=log,
    )
    if not resp:
        return

    soup = BeautifulSoup(resp.text, "lxml")
    rows = soup.select("table#exploits-table tbody tr") or soup.select("tr.exploit-row")

    count = 0
    for row in rows:
        if count >= max_results:
            break
        cells = row.select("td")
        title_tag = row.select_one("td.description a") or row.select_one("a")
        if not title_tag:
            continue

        title = _text(title_tag)
        href = title_tag.get("href", "")
        url = href if href.startswith("http") else f"https://www.exploit-db.com{href}"
        date = _text(cells[0]) if cells else ""
        exploit_type = _text(cells[3]) if len(cells) > 3 else ""
        platform = _text(cells[4]) if len(cells) > 4 else ""

        if not title or len(title) < 5:
            continue

        yield {
            "source": "Exploit Database",
            "category": "Zero Day",
            "id": url,
            "title": title,
            "description": f"Type: {exploit_type} | Platform: {platform}".strip(" |"),
            "severity": "HIGH",
            "cvss_score": "",
            "cwe": "",
            "affected_products": platform,
            "references": url,
            "published_date": date[:10] if date else "",
            "last_modified": "",
            "url": url,
            "vendor": "Exploit-DB",
            "price": "",
            "tags": f"zero-day,exploit,exploit-db,{exploit_type.lower()}",
        }
        count += 1

    polite_delay()


def scrape_project_zero(max_articles: int = 20) -> Generator[dict, None, None]:
    session = build_session()
    log.info("Scraping Google Project Zero blog…")
    resp = safe_get(
        session,
        "https://projectzero.google/feed.xml",
        headers={**random_headers(), **_NO_BR},
        logger=log,
    )
    if not resp:
        return

    for item in _rss_items(resp.text)[:max_articles]:
        if not item["title"]:
            continue
        from bs4 import BeautifulSoup as BS
        clean_desc = BS(item["description"], "lxml").get_text()[:400]
        yield {
            "source": "Google Project Zero",
            "category": "Zero Day",
            "id": item["url"],
            "title": item["title"],
            "description": clean_desc,
            "severity": "",
            "cvss_score": "",
            "cwe": "",
            "affected_products": "",
            "references": item["url"],
            "published_date": item["date"],
            "last_modified": "",
            "url": item["url"],
            "vendor": "Google",
            "price": "",
            "tags": "zero-day,project-zero,google,research",
        }

    polite_delay()


def scrape_packet_storm(max_results: int = 30) -> Generator[dict, None, None]:
    session = build_session()
    log.info("Scraping Packet Storm Security…")
    resp = safe_get(
        session,
        "https://packetstormsecurity.com/files/newest/",
        headers=random_headers(),
        logger=log,
    )
    if not resp:
        return

    soup = BeautifulSoup(resp.text, "lxml")
    items = soup.select("dl.file-list dt") or soup.select("div.list dl dt")

    count = 0
    for item in items:
        if count >= max_results:
            break
        title_tag = item.select_one("a")
        if not title_tag:
            continue

        title = _text(title_tag)
        href = title_tag.get("href", "")
        url = href if href.startswith("http") else f"https://packetstormsecurity.com{href}"

        dd = item.find_next_sibling("dd")
        desc = _text(dd)[:400] if dd else ""

        if not title or len(title) < 5:
            continue

        is_zeroday = any(kw in title.lower() for kw in ["0day", "zero-day", "zero day", "remote code", "rce", "exploit"])
        tags = "zero-day,packet-storm,exploit" if is_zeroday else "packet-storm,vulnerability"

        yield {
            "source": "Packet Storm",
            "category": "Zero Day",
            "id": url,
            "title": title,
            "description": desc,
            "severity": "HIGH" if is_zeroday else "",
            "cvss_score": "",
            "cwe": "",
            "affected_products": "",
            "references": url,
            "published_date": "",
            "last_modified": "",
            "url": url,
            "vendor": "Packet Storm",
            "price": "",
            "tags": tags,
        }
        count += 1

    polite_delay()


def scrape_vulners(max_results: int = 20) -> Generator[dict, None, None]:
    """Vulners public RSS feed for recent vulnerability bulletins."""
    session = build_session()
    log.info("Scraping Vulners recent bulletins…")
    resp = safe_get(
        session,
        "https://vulners.com/rss.xml",
        headers={**random_headers(), **_NO_BR},
        logger=log,
    )
    if not resp:
        return

    for item in _rss_items(resp.text)[:max_results]:
        if not item["title"]:
            continue
        from bs4 import BeautifulSoup as BS
        clean_desc = BS(item["description"], "lxml").get_text()[:400]
        title_lower = item["title"].lower()
        is_critical = any(kw in title_lower for kw in ["critical", "zero-day", "0day", "rce", "remote code"])
        yield {
            "source": "Vulners",
            "category": "Zero Day",
            "id": item["url"],
            "title": item["title"],
            "description": clean_desc,
            "severity": "CRITICAL" if is_critical else "HIGH",
            "cvss_score": "",
            "cwe": "",
            "affected_products": "",
            "references": item["url"],
            "published_date": item["date"],
            "last_modified": "",
            "url": item["url"],
            "vendor": "Vulners",
            "price": "",
            "tags": "zero-day,vulners,vulnerability-db",
        }

    polite_delay()
