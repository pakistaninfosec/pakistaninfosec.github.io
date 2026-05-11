import csv
import json
import logging
import os
from datetime import datetime
from typing import List

log = logging.getLogger(__name__)

FIELDS = [
    "source",
    "category",
    "id",
    "title",
    "description",
    "severity",
    "cvss_score",
    "cwe",
    "affected_products",
    "references",
    "published_date",
    "last_modified",
    "url",
    "vendor",
    "price",
    "tags",
]


def _ensure_dir(path: str) -> None:
    os.makedirs(path, exist_ok=True)


def export_csv(records: List[dict], output_dir: str, filename: str = "") -> str:
    _ensure_dir(output_dir)
    if not filename:
        ts = datetime.utcnow().strftime("%Y%m%d_%H%M%S")
        filename = f"infosec_products_{ts}.csv"
    filepath = os.path.join(output_dir, filename)

    with open(filepath, "w", newline="", encoding="utf-8") as f:
        writer = csv.DictWriter(f, fieldnames=FIELDS, extrasaction="ignore")
        writer.writeheader()
        for rec in records:
            row = {field: rec.get(field, "") for field in FIELDS}
            writer.writerow(row)

    log.info("CSV exported → %s (%d records)", filepath, len(records))
    return filepath


def export_json(records: List[dict], output_dir: str, filename: str = "") -> str:
    _ensure_dir(output_dir)
    if not filename:
        ts = datetime.utcnow().strftime("%Y%m%d_%H%M%S")
        filename = f"infosec_products_{ts}.json"
    filepath = os.path.join(output_dir, filename)

    sanitized = [{field: rec.get(field, "") for field in FIELDS} for rec in records]
    with open(filepath, "w", encoding="utf-8") as f:
        json.dump(
            {
                "generated_at": datetime.utcnow().isoformat() + "Z",
                "total_records": len(sanitized),
                "records": sanitized,
            },
            f,
            indent=2,
            ensure_ascii=False,
        )

    log.info("JSON exported → %s (%d records)", filepath, len(records))
    return filepath


def deduplicate(records: List[dict]) -> List[dict]:
    seen = set()
    result = []
    for rec in records:
        key = (rec.get("source", ""), rec.get("title", "").lower().strip())
        if key not in seen:
            seen.add(key)
            result.append(rec)
    removed = len(records) - len(result)
    if removed:
        log.info("Deduplicated %d duplicate records", removed)
    return result
