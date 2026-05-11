#!/usr/bin/env python3
"""
Daily scheduled runner for the infosec scraper.
Runs every day at 09:00 local time, writes results, computes a diff against
the previous run, and logs what is new / changed / removed.

Usage:
  python -m scraper.scheduler              # schedule at 09:00 (default)
  python -m scraper.scheduler --time 14:30 # schedule at 14:30
  python -m scraper.scheduler --run-now    # fire once immediately, then schedule
"""

import argparse
import json
import logging
import os
import signal
import sys
import time
from datetime import datetime, timezone

import schedule

from .exporter import FIELDS

log = logging.getLogger("infosec_scheduler")

OUTPUT_DIR = os.path.join(os.path.dirname(__file__), "output")

_SEV_ORDER = ["CRITICAL", "HIGH", "MEDIUM", "LOW", ""]


def _filter_diff_by_severity(diff: dict, min_severity: str) -> dict:
    """Return a copy of diff with new/changed lists filtered to >= min_severity.

    Records with no severity field are excluded when a min_severity is set.
    Removed records are always kept (they carry no meaningful severity signal).
    The summary counters are recomputed from the filtered lists.
    """
    if not min_severity:
        return diff

    min_sev = min_severity.upper()
    allowed: set[str] = set()
    for s in _SEV_ORDER:
        if s:
            allowed.add(s)
        if s == min_sev:
            break

    def _passes(rec: dict) -> bool:
        sev = str(rec.get("severity", "")).strip().upper()
        return sev in allowed

    filtered_new = [r for r in diff.get("new", []) if _passes(r)]
    filtered_changed = [r for r in diff.get("changed", []) if _passes(r)]
    removed = diff.get("removed", [])
    unchanged = diff.get("unchanged", [])

    filtered_summary = dict(diff.get("summary", {}))
    filtered_summary["new"] = len(filtered_new)
    filtered_summary["changed"] = len(filtered_changed)
    filtered_summary["removed"] = len(removed)
    filtered_summary["unchanged"] = len(unchanged)

    return {
        **diff,
        "new": filtered_new,
        "changed": filtered_changed,
        "removed": removed,
        "unchanged": unchanged,
        "summary": filtered_summary,
    }


HISTORY_FILE = os.path.join(OUTPUT_DIR, "run_history.json")
LATEST_FILE = os.path.join(OUTPUT_DIR, "latest_run.json")
LATEST_DIFF_FILE = os.path.join(OUTPUT_DIR, "latest_diff.json")

DEFAULT_SOURCES = ["nvd", "news", "vendors", "marketplaces", "threat_intel", "zeroday"]
DEFAULT_RUN_TIME = "09:00"


def _load_history() -> list:
    if os.path.exists(HISTORY_FILE):
        try:
            with open(HISTORY_FILE, encoding="utf-8") as f:
                return json.load(f)
        except Exception:
            pass
    return []


def _save_history(history: list) -> None:
    os.makedirs(OUTPUT_DIR, exist_ok=True)
    with open(HISTORY_FILE, "w", encoding="utf-8") as f:
        json.dump(history, f, indent=2)


def _save_latest(entry: dict) -> None:
    os.makedirs(OUTPUT_DIR, exist_ok=True)
    with open(LATEST_FILE, "w", encoding="utf-8") as f:
        json.dump(entry, f, indent=2)


def _save_latest_diff(diff: dict) -> None:
    os.makedirs(OUTPUT_DIR, exist_ok=True)
    with open(LATEST_DIFF_FILE, "w", encoding="utf-8") as f:
        json.dump(diff, f, indent=2, ensure_ascii=False)


def _count_by_source(records: list) -> dict:
    counts: dict = {}
    for r in records:
        src = r.get("source", "unknown")
        counts[src] = counts.get(src, 0) + 1
    return counts


def _get_prev_records(history: list) -> tuple[list, str]:
    """Return (records, prev_run_id) for the most recent successful run."""
    for entry in history:
        if entry.get("status") == "success" and entry.get("json_file"):
            json_path = os.path.join(OUTPUT_DIR, entry["json_file"])
            if os.path.exists(json_path):
                from .diff import load_records_from_file
                return load_records_from_file(json_path), entry["run_id"]
    return [], ""


def do_scrape_run(
    sources: list,
    nvd_days: int,
    nvd_max: int,
    nvd_keyword: str,
    g2_pages: int,
    capterra_pages: int,
    notify_only_on_changes: bool = False,
    min_severity: str = "",
) -> None:
    started_at = datetime.now(timezone.utc).isoformat()
    log.info("═══════════════════════════════════════════════")
    log.info("  SCHEDULED RUN STARTED  —  %s", started_at)
    log.info("  Sources: %s", ", ".join(sources))
    log.info("═══════════════════════════════════════════════")

    ts = datetime.utcnow().strftime("%Y%m%d_%H%M%S")
    csv_filename = f"infosec_products_{ts}.csv"
    json_filename = f"infosec_products_{ts}.json"

    error = None
    records_collected = 0
    csv_path = ""
    json_path = ""
    diff_summary: dict = {}
    diff_filename = ""

    history = _load_history()
    prev_records, prev_run_id = _get_prev_records(history)
    first_run = len(prev_records) == 0 and len(history) == 0

    try:
        from .exporter import export_csv, export_json, deduplicate
        from .sources.nvd import scrape_nvd
        from .sources.news import (
            scrape_krebs, scrape_dark_reading,
            scrape_security_week, scrape_hacker_news_sec,
        )
        from .sources.vendors import (
            scrape_palo_alto, scrape_crowdstrike, scrape_fortinet,
            scrape_tenable, scrape_sentinelone, scrape_checkpoint,
        )
        from .sources.marketplaces import scrape_g2, scrape_capterra
        from .sources.threat_intel import (
            scrape_unit42, scrape_crowdstrike_blog, scrape_kaspersky,
            scrape_pakistan_cert, scrape_sans_isc, scrape_recorded_future,
        )
        from .sources.zeroday import (
            scrape_cisa_kev, scrape_zdi, scrape_exploit_db,
            scrape_project_zero, scrape_packet_storm, scrape_vulners,
        )
        from .diff import compute_diff, save_diff

        records = []

        if "nvd" in sources:
            for rec in scrape_nvd(days_back=nvd_days, keyword=nvd_keyword, max_results=nvd_max):
                records.append(rec)

        if "news" in sources:
            for fn in [scrape_krebs, scrape_dark_reading, scrape_security_week, scrape_hacker_news_sec]:
                for rec in fn():
                    records.append(rec)

        if "vendors" in sources:
            for fn in [scrape_palo_alto, scrape_crowdstrike, scrape_fortinet,
                       scrape_tenable, scrape_sentinelone, scrape_checkpoint]:
                for rec in fn():
                    records.append(rec)

        if "marketplaces" in sources:
            for rec in scrape_g2(max_pages=g2_pages):
                records.append(rec)
            for rec in scrape_capterra(max_pages=capterra_pages):
                records.append(rec)

        if "threat_intel" in sources:
            for fn in [scrape_unit42, scrape_crowdstrike_blog, scrape_kaspersky,
                       scrape_pakistan_cert, scrape_sans_isc, scrape_recorded_future]:
                for rec in fn():
                    records.append(rec)

        if "zeroday" in sources:
            for fn in [scrape_cisa_kev, scrape_zdi, scrape_exploit_db,
                       scrape_project_zero, scrape_packet_storm, scrape_vulners]:
                for rec in fn():
                    records.append(rec)

        records = deduplicate(records)
        records_collected = len(records)

        csv_path = export_csv(records, OUTPUT_DIR, csv_filename)
        json_path = export_json(records, OUTPUT_DIR, json_filename)

        by_source = _count_by_source(records)

        if not first_run:
            log.info("Computing diff against previous run (%s)…", prev_run_id)
            diff = compute_diff(
                prev_records=prev_records,
                curr_records=records,
                run_id=ts,
                prev_run_id=prev_run_id,
            )
            diff_filename = save_diff(diff, OUTPUT_DIR)
            _save_latest_diff(diff)
            diff_summary = diff["summary"]
        else:
            log.info("First run — no previous data to diff against")
            diff_summary = {
                "new": records_collected,
                "changed": 0,
                "removed": 0,
                "unchanged": 0,
                "note": "first_run",
            }

    except Exception as exc:
        error = str(exc)
        log.exception("Scrape run failed: %s", exc)
        by_source = {}

    finished_at = datetime.now(timezone.utc).isoformat()

    entry = {
        "run_id": ts,
        "started_at": started_at,
        "finished_at": finished_at,
        "status": "error" if error else "success",
        "error": error,
        "sources": sources,
        "records_collected": records_collected,
        "by_source": by_source,
        "csv_file": csv_filename if not error else "",
        "json_file": json_filename if not error else "",
        "diff_file": diff_filename if not error else "",
        "diff_summary": diff_summary if not error else {},
        "prev_run_id": prev_run_id,
    }

    _save_latest(entry)
    history.insert(0, entry)
    history = history[:90]
    _save_history(history)

    log.info("═══════════════════════════════════════════════")
    if error:
        log.error("  RUN FAILED  —  %s", error)
    else:
        log.info("  RUN COMPLETE  —  %d records", records_collected)
        for src, cnt in sorted(by_source.items(), key=lambda x: -x[1]):
            log.info("    %-30s %d", src, cnt)
        if diff_summary:
            log.info(
                "  DIFF  +%d new  ~%d changed  -%d removed  =%d unchanged",
                diff_summary.get("new", 0),
                diff_summary.get("changed", 0),
                diff_summary.get("removed", 0),
                diff_summary.get("unchanged", 0),
            )
        log.info("  CSV  → %s", csv_path)
        log.info("  JSON → %s", json_path)

        # Send email digest if diff data is available
        if diff and diff_summary.get("note") != "first_run":
            email_diff = _filter_diff_by_severity(diff, min_severity)
            if min_severity:
                filtered_new = email_diff["summary"].get("new", 0)
                filtered_changed = email_diff["summary"].get("changed", 0)
                log.info(
                    "  Severity filter ≥%s: %d new, %d changed qualify for email",
                    min_severity.upper(), filtered_new, filtered_changed,
                )
            has_changes = email_diff["summary"].get("new", 0) > 0 or email_diff["summary"].get("changed", 0) > 0
            if notify_only_on_changes and not has_changes:
                log.info("  No qualifying records — skipping email (--notify-only-on-changes + --min-severity %s)", min_severity or "ALL")
            else:
                try:
                    from .notifier import send_digest
                    from .airtable_contacts import fetch_ciso_contacts
                    from .groq_digest import generate_digest

                    contacts = fetch_ciso_contacts()

                    if contacts:
                        log.info("  Sending personalised digest to %d CISO contact(s)…", len(contacts))
                        sent = 0
                        for contact in contacts:
                            ai_body = generate_digest(run_id=ts, diff=email_diff, contact=contact)
                            ok = send_digest(
                                run_id=ts,
                                diff=email_diff,
                                run_entry=entry,
                                recipients=[contact["email"]],
                                ai_plain_body=ai_body,
                            )
                            if ok:
                                sent += 1
                        log.info("  Digest sent to %d/%d contacts", sent, len(contacts))
                    else:
                        log.info("  No Airtable contacts — falling back to EMAIL_TO")
                        ai_body = generate_digest(run_id=ts, diff=email_diff, contact={})
                        send_digest(run_id=ts, diff=email_diff, run_entry=entry, ai_plain_body=ai_body)
                except Exception as exc:
                    log.warning("Email notification failed: %s", exc)
        elif diff_summary.get("note") == "first_run":
            log.info("  First run — skipping email digest (no previous data to diff)")

    log.info("═══════════════════════════════════════════════")


def main() -> None:
    parser = argparse.ArgumentParser(description="Infosec scraper scheduled runner")
    parser.add_argument("--time", default=DEFAULT_RUN_TIME, help="Daily run time HH:MM (default: 09:00)")
    parser.add_argument("--run-now", action="store_true", help="Fire one run immediately, then keep schedule")
    parser.add_argument("--sources", nargs="+", default=DEFAULT_SOURCES, help="Source groups to scrape")
    parser.add_argument("--nvd-days", type=int, default=7, help="NVD look-back days (default: 7)")
    parser.add_argument("--nvd-max", type=int, default=200, help="Max NVD records (default: 200)")
    parser.add_argument("--nvd-keyword", default="security", help="NVD keyword filter")
    parser.add_argument("--g2-pages", type=int, default=3, help="G2 pages per category")
    parser.add_argument("--capterra-pages", type=int, default=3, help="Capterra pages per category")
    parser.add_argument("--log-level", default="INFO", choices=["DEBUG", "INFO", "WARNING", "ERROR"])
    parser.add_argument(
        "--notify-only-on-changes",
        action="store_true",
        help="Only send email when there are new or changed records (suppress quiet-day emails)",
    )
    parser.add_argument(
        "--min-severity",
        default="",
        metavar="LEVEL",
        help="Minimum severity for email inclusion: CRITICAL, HIGH, MEDIUM, LOW (default: all severities)",
    )
    args = parser.parse_args()

    logging.getLogger().setLevel(getattr(logging, args.log_level))

    kwargs = dict(
        sources=args.sources,
        nvd_days=args.nvd_days,
        nvd_max=args.nvd_max,
        nvd_keyword=args.nvd_keyword,
        g2_pages=args.g2_pages,
        capterra_pages=args.capterra_pages,
        notify_only_on_changes=args.notify_only_on_changes,
        min_severity=args.min_severity,
    )

    def job():
        do_scrape_run(**kwargs)

    schedule.every().day.at(args.time).do(job)
    log.info("Scheduler started — daily run at %s", args.time)
    log.info("Sources: %s", ", ".join(args.sources))

    if args.run_now:
        log.info("--run-now flag set, firing immediately…")
        job()

    def _handle_signal(sig, frame):
        log.info("Received signal %s, shutting down.", sig)
        sys.exit(0)

    signal.signal(signal.SIGTERM, _handle_signal)
    signal.signal(signal.SIGINT, _handle_signal)

    while True:
        n = schedule.next_run()
        if n:
            log.info("Next run scheduled at: %s", n.strftime("%Y-%m-%d %H:%M:%S"))
        schedule.run_pending()
        time.sleep(30)


if __name__ == "__main__":
    main()
