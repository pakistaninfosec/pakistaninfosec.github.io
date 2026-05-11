"""
Security product marketplace scrapers:
  - G2 (g2.com) — endpoint security, network security categories
  - Capterra — security software
"""

import logging
from typing import Generator
from bs4 import BeautifulSoup
from ..utils import build_session, safe_get, polite_delay, random_headers

log = logging.getLogger(__name__)


def _text(tag, default: str = "") -> str:
    return tag.get_text(strip=True) if tag else default


def scrape_g2(max_pages: int = 3) -> Generator[dict, None, None]:
    session = build_session()

    categories = [
        ("endpoint-security", "Endpoint Security"),
        ("network-security", "Network Security"),
        ("cloud-security", "Cloud Security"),
        ("vulnerability-scanner", "Vulnerability Scanner"),
        ("siem", "SIEM"),
    ]

    for cat_slug, cat_name in categories:
        log.info("Scraping G2 category: %s…", cat_name)
        for page in range(1, max_pages + 1):
            url = f"https://www.g2.com/categories/{cat_slug}"
            params = {"page": page} if page > 1 else {}

            resp = safe_get(session, url, params=params, headers=random_headers(), logger=log)
            if not resp:
                break

            soup = BeautifulSoup(resp.text, "lxml")

            product_cards = (
                soup.select("div[data-track='product-card']")
                or soup.select("li.product-listing")
                or soup.select("div.product-listing")
                or soup.select("div.product-card")
                or soup.select("div[class*='product-card']")
            )

            if not product_cards:
                break

            for card in product_cards:
                title_tag = (
                    card.select_one("p.product-name")
                    or card.select_one("[itemprop='name']")
                    or card.select_one("h3")
                    or card.select_one("h2")
                    or card.select_one(".product-listing__name")
                )
                desc_tag = (
                    card.select_one("p.product-description")
                    or card.select_one("[itemprop='description']")
                    or card.select_one(".product-listing__blurb")
                    or card.select_one("p")
                )
                rating_tag = (
                    card.select_one("span.fw-semibold")
                    or card.select_one("[data-rating]")
                    or card.select_one(".rating-value")
                )
                reviews_tag = card.select_one("span.ratings-count") or card.select_one(".review-count")
                link_tag = card.select_one("a[href*='/products/']") or card.select_one("a")

                title = _text(title_tag)
                desc = _text(desc_tag)[:400]
                rating = _text(rating_tag)
                reviews = _text(reviews_tag)
                href = link_tag.get("href", "") if link_tag else ""
                prod_url = href if href.startswith("http") else f"https://www.g2.com{href}"

                if not title or len(title) < 3:
                    continue

                yield {
                    "source": "G2",
                    "category": f"Marketplace — {cat_name}",
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
                    "vendor": "",
                    "price": "",
                    "tags": f"marketplace,g2,{cat_slug},{rating},{reviews}",
                }

            polite_delay(2.0, 4.0)


def scrape_capterra(max_pages: int = 3) -> Generator[dict, None, None]:
    session = build_session()

    categories = [
        ("security-software", "Security Software"),
        ("endpoint-protection-software", "Endpoint Protection"),
        ("network-security-software", "Network Security"),
        ("vulnerability-management-software", "Vulnerability Management"),
        ("siem-software", "SIEM"),
    ]

    for cat_slug, cat_name in categories:
        log.info("Scraping Capterra category: %s…", cat_name)
        for page in range(1, max_pages + 1):
            url = f"https://www.capterra.com/{cat_slug}/"
            params = {"page": page} if page > 1 else {}

            resp = safe_get(session, url, params=params, headers=random_headers(), logger=log)
            if not resp:
                break

            soup = BeautifulSoup(resp.text, "lxml")

            product_cards = (
                soup.select("div[data-testid='product-card']")
                or soup.select("div.product-card")
                or soup.select("article.product-listing")
                or soup.select("li[class*='product']")
                or soup.select("div[class*='ProductCard']")
            )

            if not product_cards:
                break

            for card in product_cards:
                title_tag = (
                    card.select_one("h3")
                    or card.select_one("h2")
                    or card.select_one("[data-testid='product-name']")
                    or card.select_one(".product-name")
                )
                desc_tag = (
                    card.select_one("p[data-testid='product-description']")
                    or card.select_one("p.product-description")
                    or card.select_one("p")
                )
                rating_tag = card.select_one("[data-testid='rating']") or card.select_one(".rating")
                price_tag = card.select_one("[data-testid='price']") or card.select_one(".price")
                link_tag = card.select_one("a[href*='/p/']") or card.select_one("a")

                title = _text(title_tag)
                desc = _text(desc_tag)[:400]
                rating = _text(rating_tag)
                price = _text(price_tag)
                href = link_tag.get("href", "") if link_tag else ""
                prod_url = href if href.startswith("http") else f"https://www.capterra.com{href}"

                if not title or len(title) < 3:
                    continue

                yield {
                    "source": "Capterra",
                    "category": f"Marketplace — {cat_name}",
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
                    "vendor": "",
                    "price": price,
                    "tags": f"marketplace,capterra,{cat_slug},{rating}",
                }

            polite_delay(2.0, 4.0)
