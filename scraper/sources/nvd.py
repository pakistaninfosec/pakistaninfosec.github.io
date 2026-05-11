"""
NVD / NIST CVE scraper — uses the public NVD REST API v2.
Docs: https://nvd.nist.gov/developers/vulnerabilities
"""

import logging
from datetime import datetime, timedelta
from typing import Generator
from ..utils import build_session, safe_get, polite_delay

log = logging.getLogger(__name__)

NVD_API_BASE = "https://services.nvd.nist.gov/rest/json/cves/2.0"
RESULTS_PER_PAGE = 100


def _parse_cve(item: dict) -> dict:
    cve = item.get("cve", {})
    cve_id = cve.get("id", "")
    published = cve.get("published", "")
    modified = cve.get("lastModified", "")

    descriptions = cve.get("descriptions", [])
    description = next(
        (d["value"] for d in descriptions if d.get("lang") == "en"), ""
    )

    metrics = cve.get("metrics", {})
    cvss_v3 = metrics.get("cvssMetricV31") or metrics.get("cvssMetricV30") or []
    cvss_v2 = metrics.get("cvssMetricV2", [])

    base_score = ""
    severity = ""
    if cvss_v3:
        data = cvss_v3[0].get("cvssData", {})
        base_score = data.get("baseScore", "")
        severity = data.get("baseSeverity", "")
    elif cvss_v2:
        data = cvss_v2[0].get("cvssData", {})
        base_score = data.get("baseScore", "")
        severity = cvss_v2[0].get("baseSeverity", "")

    references = cve.get("references", [])
    ref_urls = " | ".join(r.get("url", "") for r in references[:5])

    weaknesses = cve.get("weaknesses", [])
    cwe_ids = []
    for w in weaknesses:
        for d in w.get("description", []):
            if d.get("lang") == "en":
                cwe_ids.append(d.get("value", ""))
    cwe = " | ".join(cwe_ids)

    vendor_comments = cve.get("vendorComments", [])
    affected_products = []
    configs = cve.get("configurations", [])
    for cfg in configs:
        for node in cfg.get("nodes", []):
            for match in node.get("cpeMatch", []):
                cpe = match.get("criteria", "")
                if cpe:
                    parts = cpe.split(":")
                    if len(parts) >= 5:
                        vendor = parts[3]
                        product = parts[4]
                        affected_products.append(f"{vendor}/{product}")
    affected_str = " | ".join(dict.fromkeys(affected_products[:10]))

    return {
        "source": "NVD/NIST",
        "category": "CVE/Vulnerability",
        "id": cve_id,
        "title": cve_id,
        "description": description[:500],
        "severity": severity,
        "cvss_score": base_score,
        "cwe": cwe,
        "affected_products": affected_str,
        "references": ref_urls,
        "published_date": published[:10] if published else "",
        "last_modified": modified[:10] if modified else "",
        "url": f"https://nvd.nist.gov/vuln/detail/{cve_id}",
        "vendor": "",
        "price": "",
        "tags": "vulnerability,CVE",
    }


def scrape_nvd(
    days_back: int = 30,
    keyword: str = "security",
    max_results: int = 200,
) -> Generator[dict, None, None]:
    session = build_session()
    end_date = datetime.utcnow()
    start_date = end_date - timedelta(days=days_back)

    pub_start = start_date.strftime("%Y-%m-%dT%H:%M:%S.000")
    pub_end = end_date.strftime("%Y-%m-%dT%H:%M:%S.000")

    start_index = 0
    total_fetched = 0

    log.info("Scraping NVD CVE data (last %d days, keyword=%r)…", days_back, keyword)

    while total_fetched < max_results:
        params = {
            "pubStartDate": pub_start,
            "pubEndDate": pub_end,
            "keywordSearch": keyword,
            "resultsPerPage": min(RESULTS_PER_PAGE, max_results - total_fetched),
            "startIndex": start_index,
        }

        resp = safe_get(
            session,
            NVD_API_BASE,
            params=params,
            headers={"Accept": "application/json"},
            logger=log,
        )
        if resp is None:
            break

        data = resp.json()
        vulnerabilities = data.get("vulnerabilities", [])
        total_results = data.get("totalResults", 0)

        if not vulnerabilities:
            break

        for item in vulnerabilities:
            yield _parse_cve(item)
            total_fetched += 1

        log.info("NVD: fetched %d / %d", total_fetched, min(total_results, max_results))

        if start_index + RESULTS_PER_PAGE >= total_results:
            break

        start_index += RESULTS_PER_PAGE
        polite_delay(2.0, 4.0)

    log.info("NVD scrape complete — %d records", total_fetched)
