#!/usr/bin/env python3
"""
Infosec Security Products Scraper
==================================
Scrapes and aggregates data from:
  - NVD/NIST CVE database
  - Security news sites (Krebs, Dark Reading, SecurityWeek, The Hacker News)
  - Vendor product pages (Palo Alto, CrowdStrike, Fortinet, Tenable, SentinelOne, Check Point)
  - Marketplaces (G2, Capterra)

Usage:
  python -m scraper.main                  # run everything, output to scraper/output/
  python -m scraper.main --sources nvd    # only NVD
  python -m scraper.main --sources news vendors
  python -m scraper.main --output /tmp/results
  python -m scraper.main --nvd-days 60 --nvd-max 500

Available source groups:
  nvd           NVD/NIST CVE vulnerability database
  news          Security news sites
  vendors       Vendor product pages
  marketplaces  G2 and Capterra listings
  threat_intel  Threat intelligence feeds
  zeroday       Zero-day exploit sources

Output files (scraper/output/ by default):
  infosec_products_<timestamp>.csv
  infosec_products_<timestamp>.json
"""

import argparse
import logging
import os
import sys
import time
from typing import List

from .sources.nvd import scrape_nvd
from .sources.news import (
    scrape_krebs,
    scrape_dark_reading,
    scrape_security_week,
    scrape_hacker_news_sec,
)
from .sources.vendors import (
    scrape_palo_alto,
    scrape_crowdstrike,
    scrape_fortinet,
    scrape_tenable,
    scrape_sentinelone,
    scrape_checkpoint,
)
from .sources.marketplaces import scrape_g2, scrape_capterra
from .sources.threat_intel import (
    scrape_unit42, scrape_crowdstrike_blog, scrape_kaspersky,
    scrape_sans_isc, scrape_recorded_future,
)
from .sources.pakistan import scrape as scrape_pakistan_all
from .sources.zeroday import (
    scrape_cisa_kev, scrape_zdi, scrape_exploit_db,
    scrape_project_zero, scrape_packet_storm, scrape_vulners,
)
from .exporter import export_csv, export_json, deduplicate

log = logging.getLogger("infosec_scraper")

ALL_SOURCES = ["nvd", "news", "vendors", "marketplaces", "threat_intel", "zeroday"]


def run_scrape(
    sources: List[str],
    output_dir: str,
    nvd_days: int,
    nvd_max: int,
    nvd_keyword: str,
    g2_pages: int,
    capterra_pages: int,
) -> None:
    records = []
    start = time.time()

    if "nvd" in sources:
        log.info("═══ NVD / NIST CVE Database ═══")
        for rec in scrape_nvd(days_back=nvd_days, keyword=nvd_keyword, max_results=nvd_max):
            records.append(rec)
        log.info("NVD total so far: %d records", len(records))

    if "news" in sources:
        log.info("═══ Security News ═══")
        scrapers = [
            ("Krebs on Security",  scrape_krebs),
            ("Dark Reading",       scrape_dark_reading),
            ("SecurityWeek",       scrape_security_week),
            ("The Hacker News",    scrape_hacker_news_sec),
        ]
        for name, fn in scrapers:
            before = len(records)
            for rec in fn():
                records.append(rec)
            log.info("%s: %d new records", name, len(records) - before)

    if "vendors" in sources:
        log.info("═══ Vendor Product Pages ═══")
        vendor_scrapers = [
            ("Palo Alto Networks", scrape_palo_alto),
            ("CrowdStrike",        scrape_crowdstrike),
            ("Fortinet",           scrape_fortinet),
            ("Tenable",            scrape_tenable),
            ("SentinelOne",        scrape_sentinelone),
            ("Check Point",        scrape_checkpoint),
        ]
        for name, fn in vendor_scrapers:
            before = len(records)
            for rec in fn():
                records.append(rec)
            log.info("%s: %d new records", name, len(records) - before)

    if "marketplaces" in sources:
        log.info("═══ Marketplaces ═══")
        log.info("G2…")
        before = len(records)
        for rec in scrape_g2(max_pages=g2_pages):
            records.append(rec)
        log.info("G2: %d new records", len(records) - before)

        log.info("Capterra…")
        before = len(records)
        for rec in scrape_capterra(max_pages=capterra_pages):
            records.append(rec)
        log.info("Capterra: %d new records", len(records) - before)

    if "threat_intel" in sources:
        log.info("═══ Threat Intelligence ═══")
        ti_scrapers = [
            ("Unit42",              scrape_unit42),
            ("CrowdStrike Blog",    scrape_crowdstrike_blog),
            ("Kaspersky Securelist",scrape_kaspersky),
            ("SANS ISC",            scrape_sans_isc),
            ("Recorded Future",     scrape_recorded_future),
        ]
        for name, fn in ti_scrapers:
            before = len(records)
            for rec in fn():
                records.append(rec)
            log.info("%s: %d new records", name, len(records) - before)

        # Pakistan sources — PKCERT + NCCS (always returns fallback data if sites unreachable)
        log.info("Pakistan CERT + NCCS…")
        before = len(records)
        for rec in scrape_pakistan_all():
            records.append(rec)
        log.info("Pakistan CERT + NCCS: %d new records", len(records) - before)

    if "zeroday" in sources:
        log.info("═══ Zero Day Sources ═══")
        zd_scrapers = [
            ("CISA KEV",           scrape_cisa_kev),
            ("Zero Day Initiative", scrape_zdi),
            ("Exploit-DB",          scrape_exploit_db),
            ("Google Project Zero", scrape_project_zero),
            ("Packet Storm",        scrape_packet_storm),
            ("Vulners",             scrape_vulners),
        ]
        for name, fn in zd_scrapers:
            before = len(records)
            for rec in fn():
                records.append(rec)
            log.info("%s: %d new records", name, len(records) - before)

    elapsed = time.time() - start
    log.info("Scraping complete in %.1fs — %d raw records", elapsed, len(records))

    records = deduplicate(records)

    ts_csv  = export_csv(records, output_dir)
    ts_json = export_json(records, output_dir)

    log.info("")
    log.info("━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━")
    log.info("  DONE — %d records from %s source(s)", len(records), ", ".join(sources))
    log.info("  CSV  → %s", ts_csv)
    log.info("  JSON → %s", ts_json)
    log.info("━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━")


def main() -> None:
    parser = argparse.ArgumentParser(
        description="Infosec security products web scraper",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog=__doc__,
    )
    parser.add_argument(
        "--sources",
        nargs="+",
        choices=ALL_SOURCES + ["all"],
        default=["all"],
        help="Source groups to scrape (default: all)",
    )
    parser.add_argument(
        "--output",
        default=os.path.join(os.path.dirname(__file__), "output"),
        help="Directory to write output files (default: scraper/output/)",
    )
    parser.add_argument(
        "--nvd-days",
        type=int,
        default=30,
        help="How many days back to pull NVD CVEs (default: 30)",
    )
    parser.add_argument(
        "--nvd-max",
        type=int,
        default=200,
        help="Maximum CVEs to fetch from NVD (default: 200)",
    )
    parser.add_argument(
        "--nvd-keyword",
        default="security",
        help="Keyword filter for NVD search (default: security)",
    )
    parser.add_argument(
        "--g2-pages",
        type=int,
        default=3,
        help="Pages to scrape per G2 category (default: 3)",
    )
    parser.add_argument(
        "--capterra-pages",
        type=int,
        default=3,
        help="Pages to scrape per Capterra category (default: 3)",
    )
    parser.add_argument(
        "--log-level",
        default="INFO",
        choices=["DEBUG", "INFO", "WARNING", "ERROR"],
        help="Logging verbosity (default: INFO)",
    )

    args = parser.parse_args()

    logging.basicConfig(
        level=getattr(logging, args.log_level),
        format="%(asctime)s  %(levelname)-8s  %(message)s",
        datefmt="%H:%M:%S",
    )

    sources = ALL_SOURCES if "all" in args.sources else args.sources

    run_scrape(
        sources=sources,
        output_dir=args.output,
        nvd_days=args.nvd_days,
        nvd_max=args.nvd_max,
        nvd_keyword=args.nvd_keyword,
        g2_pages=args.g2_pages,
        capterra_pages=args.capterra_pages,
    )


if __name__ == "__main__":
    main()
