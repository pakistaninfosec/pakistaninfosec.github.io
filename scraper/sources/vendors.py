"""
Vendor security product page scrapers:
  - Palo Alto Networks
  - CrowdStrike
  - Fortinet
  - Tenable
  - SentinelOne
  - Check Point
"""

import logging
from typing import Generator
from bs4 import BeautifulSoup
from ..utils import build_session, safe_get, polite_delay, random_headers

log = logging.getLogger(__name__)


def _text(tag, default: str = "") -> str:
    return tag.get_text(strip=True) if tag else default


def scrape_palo_alto() -> Generator[dict, None, None]:
    session = build_session()
    log.info("Scraping Palo Alto Networks products…")

    urls = [
        ("https://www.paloaltonetworks.com/network-security", "Network Security"),
        ("https://www.paloaltonetworks.com/cloud-security", "Cloud Security"),
        ("https://www.paloaltonetworks.com/soc-security-operations", "SOC / Security Operations"),
    ]

    for url, category in urls:
        resp = safe_get(session, url, headers=random_headers(), logger=log)
        if not resp:
            polite_delay()
            continue

        soup = BeautifulSoup(resp.text, "lxml")

        cards = (
            soup.select("div.product-card")
            or soup.select("div.card")
            or soup.select("section.product")
            or soup.select("article")
        )

        for card in cards:
            title_tag = (
                card.select_one("h3")
                or card.select_one("h2")
                or card.select_one(".card-title")
                or card.select_one("h4")
            )
            desc_tag = card.select_one("p") or card.select_one(".card-description")
            link_tag = card.select_one("a")

            title = _text(title_tag)
            desc = _text(desc_tag)[:400]
            href = link_tag.get("href", "") if link_tag else ""
            prod_url = href if href.startswith("http") else f"https://www.paloaltonetworks.com{href}"

            if not title or len(title) < 4:
                continue

            yield {
                "source": "Palo Alto Networks",
                "category": f"Vendor Product — {category}",
                "id": prod_url,
                "title": title,
                "description": desc,
                "severity": "",
                "cvss_score": "",
                "cwe": "",
                "affected_products": "",
                "references": prod_url,
                "published_date": "",
                "last_modified": "",
                "url": prod_url,
                "vendor": "Palo Alto Networks",
                "price": "",
                "tags": f"product,vendor,palo-alto,{category.lower().replace(' ', '-')}",
            }

        polite_delay()


def scrape_crowdstrike() -> Generator[dict, None, None]:
    session = build_session()
    log.info("Scraping CrowdStrike products…")

    resp = safe_get(
        session,
        "https://www.crowdstrike.com/products/",
        headers=random_headers(),
        logger=log,
    )
    if not resp:
        return

    soup = BeautifulSoup(resp.text, "lxml")

    cards = (
        soup.select("div.product-card")
        or soup.select("div.cs-card")
        or soup.select("div[class*='product']")
        or soup.select("article")
        or soup.select("div.card")
    )

    for card in cards:
        title_tag = card.select_one("h3") or card.select_one("h2") or card.select_one("h4")
        desc_tag = card.select_one("p")
        link_tag = card.select_one("a")

        title = _text(title_tag)
        desc = _text(desc_tag)[:400]
        href = link_tag.get("href", "") if link_tag else ""
        prod_url = href if href.startswith("http") else f"https://www.crowdstrike.com{href}"

        if not title or len(title) < 4:
            continue

        yield {
            "source": "CrowdStrike",
            "category": "Vendor Product — Endpoint & Cloud Security",
            "id": prod_url,
            "title": title,
            "description": desc,
            "severity": "",
            "cvss_score": "",
            "cwe": "",
            "affected_products": "",
            "references": prod_url,
            "published_date": "",
            "last_modified": "",
            "url": prod_url,
            "vendor": "CrowdStrike",
            "price": "",
            "tags": "product,vendor,crowdstrike,endpoint-security",
        }

    polite_delay()


def scrape_fortinet() -> Generator[dict, None, None]:
    session = build_session()
    log.info("Scraping Fortinet products…")

    resp = safe_get(
        session,
        "https://www.fortinet.com/products",
        headers=random_headers(),
        logger=log,
    )
    if not resp:
        return

    soup = BeautifulSoup(resp.text, "lxml")

    cards = (
        soup.select("div.product-family-card")
        or soup.select("div.product-card")
        or soup.select("div[class*='card']")
        or soup.select("article")
    )

    for card in cards:
        title_tag = card.select_one("h3") or card.select_one("h2") or card.select_one("h4")
        desc_tag = card.select_one("p") or card.select_one(".description")
        link_tag = card.select_one("a")

        title = _text(title_tag)
        desc = _text(desc_tag)[:400]
        href = link_tag.get("href", "") if link_tag else ""
        prod_url = href if href.startswith("http") else f"https://www.fortinet.com{href}"

        if not title or len(title) < 4:
            continue

        yield {
            "source": "Fortinet",
            "category": "Vendor Product — Network & Firewall Security",
            "id": prod_url,
            "title": title,
            "description": desc,
            "severity": "",
            "cvss_score": "",
            "cwe": "",
            "affected_products": "",
            "references": prod_url,
            "published_date": "",
            "last_modified": "",
            "url": prod_url,
            "vendor": "Fortinet",
            "price": "",
            "tags": "product,vendor,fortinet,firewall",
        }

    polite_delay()


def scrape_tenable() -> Generator[dict, None, None]:
    session = build_session()
    log.info("Scraping Tenable products…")

    resp = safe_get(
        session,
        "https://www.tenable.com/products",
        headers=random_headers(),
        logger=log,
    )
    if not resp:
        return

    soup = BeautifulSoup(resp.text, "lxml")

    cards = (
        soup.select("div.product-card")
        or soup.select("div.solution-card")
        or soup.select("div[class*='product']")
        or soup.select("section.product")
        or soup.select("article")
    )

    for card in cards:
        title_tag = card.select_one("h3") or card.select_one("h2") or card.select_one("h4")
        desc_tag = card.select_one("p") or card.select_one(".card-body p")
        link_tag = card.select_one("a")

        title = _text(title_tag)
        desc = _text(desc_tag)[:400]
        href = link_tag.get("href", "") if link_tag else ""
        prod_url = href if href.startswith("http") else f"https://www.tenable.com{href}"

        if not title or len(title) < 4:
            continue

        yield {
            "source": "Tenable",
            "category": "Vendor Product — Vulnerability Management",
            "id": prod_url,
            "title": title,
            "description": desc,
            "severity": "",
            "cvss_score": "",
            "cwe": "",
            "affected_products": "",
            "references": prod_url,
            "published_date": "",
            "last_modified": "",
            "url": prod_url,
            "vendor": "Tenable",
            "price": "",
            "tags": "product,vendor,tenable,vulnerability-management",
        }

    polite_delay()


def scrape_sentinelone() -> Generator[dict, None, None]:
    session = build_session()
    log.info("Scraping SentinelOne products…")

    resp = safe_get(
        session,
        "https://www.sentinelone.com/platform/",
        headers=random_headers(),
        logger=log,
    )
    if not resp:
        return

    soup = BeautifulSoup(resp.text, "lxml")

    cards = (
        soup.select("div.platform-card")
        or soup.select("div.feature-card")
        or soup.select("div[class*='card']")
        or soup.select("section[class*='product']")
        or soup.select("article")
    )

    for card in cards:
        title_tag = card.select_one("h3") or card.select_one("h2") or card.select_one("h4")
        desc_tag = card.select_one("p")
        link_tag = card.select_one("a")

        title = _text(title_tag)
        desc = _text(desc_tag)[:400]
        href = link_tag.get("href", "") if link_tag else ""
        prod_url = href if href.startswith("http") else f"https://www.sentinelone.com{href}"

        if not title or len(title) < 4:
            continue

        yield {
            "source": "SentinelOne",
            "category": "Vendor Product — AI-Powered Security",
            "id": prod_url,
            "title": title,
            "description": desc,
            "severity": "",
            "cvss_score": "",
            "cwe": "",
            "affected_products": "",
            "references": prod_url,
            "published_date": "",
            "last_modified": "",
            "url": prod_url,
            "vendor": "SentinelOne",
            "price": "",
            "tags": "product,vendor,sentinelone,AI,endpoint",
        }

    polite_delay()


def scrape_checkpoint() -> Generator[dict, None, None]:
    session = build_session()
    log.info("Scraping Check Point products…")

    resp = safe_get(
        session,
        "https://www.checkpoint.com/products/",
        headers=random_headers(),
        logger=log,
    )
    if not resp:
        return

    soup = BeautifulSoup(resp.text, "lxml")

    cards = (
        soup.select("div.product-card")
        or soup.select("div.solution-item")
        or soup.select("div[class*='card']")
        or soup.select("article")
    )

    for card in cards:
        title_tag = card.select_one("h3") or card.select_one("h2") or card.select_one("h4")
        desc_tag = card.select_one("p")
        link_tag = card.select_one("a")

        title = _text(title_tag)
        desc = _text(desc_tag)[:400]
        href = link_tag.get("href", "") if link_tag else ""
        prod_url = href if href.startswith("http") else f"https://www.checkpoint.com{href}"

        if not title or len(title) < 4:
            continue

        yield {
            "source": "Check Point",
            "category": "Vendor Product — Network & Cloud Security",
            "id": prod_url,
            "title": title,
            "description": desc,
            "severity": "",
            "cvss_score": "",
            "cwe": "",
            "affected_products": "",
            "references": prod_url,
            "published_date": "",
            "last_modified": "",
            "url": prod_url,
            "vendor": "Check Point",
            "price": "",
            "tags": "product,vendor,checkpoint,firewall",
        }

    polite_delay()
