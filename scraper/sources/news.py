"""
Security news scrapers:
  - Krebs on Security  (krebsonsecurity.com)
  - Dark Reading       (darkreading.com)
  - SecurityWeek       (securityweek.com)
  - The Hacker News    (thehackernews.com)
"""

import logging
from typing import Generator
from bs4 import BeautifulSoup
from ..utils import build_session, safe_get, polite_delay, random_headers

log = logging.getLogger(__name__)


def _text(tag, default: str = "") -> str:
    return tag.get_text(strip=True) if tag else default


def scrape_krebs(max_articles: int = 30) -> Generator[dict, None, None]:
    session = build_session()
    log.info("Scraping Krebs on Security…")
    resp = safe_get(session, "https://krebsonsecurity.com/", headers=random_headers(), logger=log)
    if not resp:
        return

    soup = BeautifulSoup(resp.text, "lxml")
    articles = soup.select("article.post")[:max_articles]

    for art in articles:
        title_tag = art.select_one("h2.entry-title a") or art.select_one("h1 a")
        date_tag = art.select_one("time.entry-date") or art.select_one(".entry-meta time")
        excerpt_tag = art.select_one(".entry-content p") or art.select_one(".entry-summary p")
        category_tags = art.select(".cat-links a")

        title = _text(title_tag)
        url = title_tag["href"] if title_tag and title_tag.get("href") else ""
        date = date_tag.get("datetime", _text(date_tag)) if date_tag else ""
        excerpt = _text(excerpt_tag)[:400]
        categories = " | ".join(_text(c) for c in category_tags)

        if not title:
            continue

        yield {
            "source": "Krebs on Security",
            "category": "Security News",
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
            "vendor": "Krebs on Security",
            "price": "",
            "tags": f"news,security,{categories}",
        }

    polite_delay()


def scrape_dark_reading(max_articles: int = 30) -> Generator[dict, None, None]:
    session = build_session()
    log.info("Scraping Dark Reading…")

    for section_url in [
        "https://www.darkreading.com/threat-intelligence",
        "https://www.darkreading.com/vulnerabilities-threats",
        "https://www.darkreading.com/endpoint-security",
    ]:
        resp = safe_get(session, section_url, headers=random_headers(), logger=log)
        if not resp:
            polite_delay()
            continue

        soup = BeautifulSoup(resp.text, "lxml")

        selectors = [
            "article.article-listing",
            "div.listing-item",
            "div[data-type='article']",
            "li.listview-item",
            "article",
        ]
        articles = []
        for sel in selectors:
            articles = soup.select(sel)
            if articles:
                break

        count = 0
        for art in articles:
            if count >= max_articles:
                break
            title_tag = (
                art.select_one("h3 a")
                or art.select_one("h2 a")
                or art.select_one(".article-title a")
                or art.select_one("a[href*='/articles/']")
            )
            date_tag = art.select_one("time") or art.select_one(".article-date")
            excerpt_tag = art.select_one("p.deck") or art.select_one("p.article-summary") or art.select_one("p")

            title = _text(title_tag)
            href = title_tag.get("href", "") if title_tag else ""
            url = href if href.startswith("http") else f"https://www.darkreading.com{href}"
            date = date_tag.get("datetime", _text(date_tag)) if date_tag else ""
            excerpt = _text(excerpt_tag)[:400]

            if not title:
                continue

            yield {
                "source": "Dark Reading",
                "category": "Security News",
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
                "vendor": "Dark Reading",
                "price": "",
                "tags": "news,security,threat-intelligence",
            }
            count += 1

        polite_delay()


def scrape_security_week(max_articles: int = 30) -> Generator[dict, None, None]:
    session = build_session()
    log.info("Scraping SecurityWeek…")
    resp = safe_get(session, "https://www.securityweek.com/", headers=random_headers(), logger=log)
    if not resp:
        return

    soup = BeautifulSoup(resp.text, "lxml")

    selectors = ["article", "div.post", "div.article-item", "div.td-block-span6"]
    articles = []
    for sel in selectors:
        articles = soup.select(sel)
        if articles:
            break

    count = 0
    for art in articles:
        if count >= max_articles:
            break
        title_tag = (
            art.select_one("h3 a")
            or art.select_one("h2 a")
            or art.select_one("h4 a")
            or art.select_one(".entry-title a")
        )
        date_tag = art.select_one("time") or art.select_one(".td-post-date time")
        excerpt_tag = art.select_one(".entry-summary p") or art.select_one("p")

        title = _text(title_tag)
        href = title_tag.get("href", "") if title_tag else ""
        url = href if href.startswith("http") else f"https://www.securityweek.com{href}"
        date = date_tag.get("datetime", _text(date_tag)) if date_tag else ""
        excerpt = _text(excerpt_tag)[:400]

        if not title or len(title) < 10:
            continue

        yield {
            "source": "SecurityWeek",
            "category": "Security News",
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
            "vendor": "SecurityWeek",
            "price": "",
            "tags": "news,security",
        }
        count += 1

    polite_delay()


def scrape_hacker_news_sec(max_articles: int = 30) -> Generator[dict, None, None]:
    session = build_session()
    log.info("Scraping The Hacker News…")
    resp = safe_get(session, "https://thehackernews.com/", headers=random_headers(), logger=log)
    if not resp:
        return

    soup = BeautifulSoup(resp.text, "lxml")

    articles = soup.select("div.body-post") or soup.select("article") or soup.select("div.story-link")

    count = 0
    for art in articles:
        if count >= max_articles:
            break
        title_tag = (
            art.select_one("h2.home-title")
            or art.select_one("h2 a")
            or art.select_one("h3 a")
            or art.select_one("a.story-link")
        )
        date_tag = art.select_one("span.h-datetime") or art.select_one("time") or art.select_one(".item-label")
        excerpt_tag = art.select_one("div.home-desc") or art.select_one("p")

        title = _text(title_tag)
        href = title_tag.get("href", "") if title_tag else ""
        url = href if href.startswith("http") else f"https://thehackernews.com{href}"
        date = _text(date_tag)
        excerpt = _text(excerpt_tag)[:400]

        if not title or len(title) < 10:
            continue

        yield {
            "source": "The Hacker News",
            "category": "Security News",
            "id": url,
            "title": title,
            "description": excerpt,
            "severity": "",
            "cvss_score": "",
            "cwe": "",
            "affected_products": "",
            "references": url,
            "published_date": date,
            "last_modified": "",
            "url": url,
            "vendor": "The Hacker News",
            "price": "",
            "tags": "news,security,hacking",
        }
        count += 1

    polite_delay()
