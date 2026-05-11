"""
Threat Intelligence scrapers:
  - Palo Alto Unit42         (unit42.paloaltonetworks.com)
  - CrowdStrike Blog         (crowdstrike.com/blog)
  - Kaspersky Securelist     (securelist.com/feed/)
  - Pakistan CERT            (pkcert.gov.pk)
  - SANS Internet Stormcast  (isc.sans.edu/rssfeed.xml)
  - Recorded Future Blog     (recordedfuture.com/blog)
"""

import logging
import xml.etree.ElementTree as ET
from typing import Generator

from bs4 import BeautifulSoup
from ..utils import build_session, safe_get, polite_delay, random_headers

log = logging.getLogger(__name__)


def _text(tag, default: str = "") -> str:
    return tag.get_text(strip=True) if tag else default


_NO_BR = {"Accept-Encoding": "gzip, deflate"}


def _rss_items(xml_text: str) -> list[dict]:
    """Parse RSS 2.0 or Atom feed and return list of {title, url, description, date}."""
    try:
        root = ET.fromstring(xml_text)
    except ET.ParseError:
        return []

    ATOM = "http://www.w3.org/2005/Atom"
    items = []

    for item in root.iter("item"):
        title = (item.findtext("title") or "").strip()
        link = (item.findtext("link") or "").strip()
        desc = (item.findtext("description") or "").strip()[:400]
        pub = (item.findtext("pubDate") or "").strip()[:10]
        if title:
            items.append({"title": title, "url": link, "description": desc, "date": pub})

    for entry in root.iter(f"{{{ATOM}}}entry"):
        title_el = entry.find(f"{{{ATOM}}}title")
        title = (title_el.text or "").strip() if title_el is not None else ""
        link_el = entry.find(f"{{{ATOM}}}link")
        link = link_el.get("href", "") if link_el is not None else ""
        summary_el = entry.find(f"{{{ATOM}}}summary") or entry.find(f"{{{ATOM}}}content")
        summary = (summary_el.text or "").strip()[:400] if summary_el is not None else ""
        pub_el = entry.find(f"{{{ATOM}}}published") or entry.find(f"{{{ATOM}}}updated")
        pub = (pub_el.text or "")[:10] if pub_el is not None else ""
        if title:
            items.append({"title": title, "url": link, "description": summary, "date": pub})

    return items


def scrape_unit42(max_articles: int = 20) -> Generator[dict, None, None]:
    session = build_session()
    log.info("Scraping Palo Alto Unit42 threat blog…")
    resp = safe_get(session, "https://unit42.paloaltonetworks.com/", headers=random_headers(), logger=log)
    if not resp:
        return

    soup = BeautifulSoup(resp.text, "lxml")
    articles = (
        soup.select("article.post")
        or soup.select("div.post-item")
        or soup.select("div.entry-wrapper")
        or soup.select("article")
    )

    count = 0
    for art in articles:
        if count >= max_articles:
            break
        title_tag = art.select_one("h2 a") or art.select_one("h3 a") or art.select_one("h1 a")
        date_tag = art.select_one("time") or art.select_one(".post-date") or art.select_one(".date")
        excerpt_tag = art.select_one("p.excerpt") or art.select_one(".post-summary p") or art.select_one("p")

        title = _text(title_tag)
        href = title_tag.get("href", "") if title_tag else ""
        url = href if href.startswith("http") else f"https://unit42.paloaltonetworks.com{href}"
        date = date_tag.get("datetime", _text(date_tag)) if date_tag else ""
        excerpt = _text(excerpt_tag)[:400]

        if not title or len(title) < 10:
            continue

        yield {
            "source": "Palo Alto Unit42",
            "category": "Threat Intelligence",
            "id": url,
            "title": title,
            "description": excerpt,
            "severity": "",
            "cvss_score": "",
            "cwe": "",
            "affected_products": "",
            "references": url,
            "published_date": date[:10] if date else "",
            "last_modified": "",
            "url": url,
            "vendor": "Palo Alto Networks",
            "price": "",
            "tags": "threat-intelligence,unit42,apt",
        }
        count += 1

    polite_delay()


def scrape_crowdstrike_blog(max_articles: int = 20) -> Generator[dict, None, None]:
    session = build_session()
    log.info("Scraping CrowdStrike threat intelligence blog…")
    resp = safe_get(
        session,
        "https://www.crowdstrike.com/blog/category/threat-intelligence/",
        headers=random_headers(),
        logger=log,
    )
    if not resp:
        return

    soup = BeautifulSoup(resp.text, "lxml")
    articles = (
        soup.select("article.cs-blog-post")
        or soup.select("div.blog-post-card")
        or soup.select("article")
        or soup.select("div.post")
    )

    count = 0
    for art in articles:
        if count >= max_articles:
            break
        title_tag = art.select_one("h2 a") or art.select_one("h3 a") or art.select_one(".post-title a")
        date_tag = art.select_one("time") or art.select_one(".post-date")
        excerpt_tag = art.select_one(".post-excerpt p") or art.select_one("p.excerpt") or art.select_one("p")

        title = _text(title_tag)
        href = title_tag.get("href", "") if title_tag else ""
        url = href if href.startswith("http") else f"https://www.crowdstrike.com{href}"
        date = date_tag.get("datetime", _text(date_tag)) if date_tag else ""
        excerpt = _text(excerpt_tag)[:400]

        if not title or len(title) < 10:
            continue

        yield {
            "source": "CrowdStrike Blog",
            "category": "Threat Intelligence",
            "id": url,
            "title": title,
            "description": excerpt,
            "severity": "",
            "cvss_score": "",
            "cwe": "",
            "affected_products": "",
            "references": url,
            "published_date": date[:10] if date else "",
            "last_modified": "",
            "url": url,
            "vendor": "CrowdStrike",
            "price": "",
            "tags": "threat-intelligence,crowdstrike,apt",
        }
        count += 1

    polite_delay()


def scrape_kaspersky(max_articles: int = 20) -> Generator[dict, None, None]:
    session = build_session()
    log.info("Scraping Kaspersky Securelist…")
    resp = safe_get(session, "https://securelist.com/feed/", headers={**random_headers(), **_NO_BR}, logger=log)
    if not resp:
        return

    for item in _rss_items(resp.text)[:max_articles]:
        if not item["title"]:
            continue
        yield {
            "source": "Kaspersky Securelist",
            "category": "Threat Intelligence",
            "id": item["url"],
            "title": item["title"],
            "description": item["description"],
            "severity": "",
            "cvss_score": "",
            "cwe": "",
            "affected_products": "",
            "references": item["url"],
            "published_date": item["date"],
            "last_modified": "",
            "url": item["url"],
            "vendor": "Kaspersky",
            "price": "",
            "tags": "threat-intelligence,kaspersky,malware",
        }

    polite_delay()


def scrape_pakistan_cert(max_articles: int = 20) -> Generator[dict, None, None]:
    session = build_session()
    log.info("Scraping Pakistan CERT advisories…")
    resp = safe_get(session, "https://www.pkcert.gov.pk/", headers=random_headers(), logger=log)
    if not resp:
        return

    soup = BeautifulSoup(resp.text, "lxml")
    articles = (
        soup.select("div.advisory-item")
        or soup.select("div.alert-item")
        or soup.select("article")
        or soup.select("li.views-row")
        or soup.select("div.views-row")
        or soup.select("tr")
    )

    count = 0
    for art in articles:
        if count >= max_articles:
            break
        title_tag = art.select_one("a") or art.select_one("h2 a") or art.select_one("h3 a")
        date_tag = art.select_one("time") or art.select_one(".date") or art.select_one("span.date-display-single")
        desc_tag = art.select_one("p") or art.select_one(".description")

        title = _text(title_tag)
        href = title_tag.get("href", "") if title_tag else ""
        if not href:
            continue
        url = href if href.startswith("http") else f"https://www.pkcert.gov.pk{href}"
        date = _text(date_tag)[:10] if date_tag else ""
        desc = _text(desc_tag)[:400] if desc_tag else ""

        if not title or len(title) < 5:
            continue

        yield {
            "source": "Pakistan CERT",
            "category": "Pakistan Alert",
            "id": url,
            "title": title,
            "description": desc,
            "severity": "",
            "cvss_score": "",
            "cwe": "",
            "affected_products": "",
            "references": url,
            "published_date": date,
            "last_modified": "",
            "url": url,
            "vendor": "PK-CERT",
            "price": "",
            "tags": "pakistan-alert,cert,advisory",
        }
        count += 1

    polite_delay()


def scrape_sans_isc(max_articles: int = 20) -> Generator[dict, None, None]:
    session = build_session()
    log.info("Scraping SANS Internet Stormcast RSS…")
    resp = safe_get(session, "https://isc.sans.edu/rssfeed.xml", headers={**random_headers(), **_NO_BR}, logger=log)
    if not resp:
        return

    for item in _rss_items(resp.text)[:max_articles]:
        if not item["title"]:
            continue
        from bs4 import BeautifulSoup as BS
        clean_desc = BS(item["description"], "lxml").get_text()[:400]
        yield {
            "source": "SANS ISC",
            "category": "Threat Intelligence",
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
            "vendor": "SANS Institute",
            "price": "",
            "tags": "threat-intelligence,sans,isc,stormcast",
        }

    polite_delay()


def scrape_recorded_future(max_articles: int = 20) -> Generator[dict, None, None]:
    session = build_session()
    log.info("Scraping Recorded Future blog…")
    resp = safe_get(session, "https://www.recordedfuture.com/blog", headers=random_headers(), logger=log)
    if not resp:
        return

    soup = BeautifulSoup(resp.text, "lxml")
    articles = (
        soup.select("article.blog-post")
        or soup.select("div.blog-card")
        or soup.select("div.post-item")
        or soup.select("article")
    )

    count = 0
    for art in articles:
        if count >= max_articles:
            break
        title_tag = art.select_one("h2 a") or art.select_one("h3 a") or art.select_one(".post-title a")
        date_tag = art.select_one("time") or art.select_one(".post-date") or art.select_one(".date")
        excerpt_tag = art.select_one(".excerpt") or art.select_one("p.summary") or art.select_one("p")

        title = _text(title_tag)
        href = title_tag.get("href", "") if title_tag else ""
        url = href if href.startswith("http") else f"https://www.recordedfuture.com{href}"
        date = date_tag.get("datetime", _text(date_tag)) if date_tag else ""
        excerpt = _text(excerpt_tag)[:400]

        if not title or len(title) < 10:
            continue

        yield {
            "source": "Recorded Future",
            "category": "Threat Intelligence",
            "id": url,
            "title": title,
            "description": excerpt,
            "severity": "",
            "cvss_score": "",
            "cwe": "",
            "affected_products": "",
            "references": url,
            "published_date": date[:10] if date else "",
            "last_modified": "",
            "url": url,
            "vendor": "Recorded Future",
            "price": "",
            "tags": "threat-intelligence,recorded-future,apt",
        }
        count += 1

    polite_delay()
