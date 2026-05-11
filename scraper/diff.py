"""
Diff engine — compares two runs of scraped records and classifies every
record as new, changed, removed, or unchanged.

Key:  (source, title.lower().strip())
Tracked fields for change detection: all 16 schema fields
"""

import json
import logging
import os
from datetime import datetime, timezone
from typing import TypedDict

from .exporter import FIELDS

log = logging.getLogger(__name__)

IGNORED_FIELDS = {"last_modified"}

CHANGE_WEIGHT = {
    "severity": 3,
    "cvss_score": 3,
    "description": 2,
    "affected_products": 2,
    "cwe": 2,
    "price": 2,
    "title": 1,
    "references": 1,
    "tags": 0,
}


class DiffRecord(TypedDict):
    record: dict
    changed_fields: list


def _record_key(rec: dict) -> tuple:
    return (rec.get("source", "").strip(), rec.get("title", "").lower().strip())


def _field_changed(field: str, old_val: object, new_val: object) -> bool:
    if field in IGNORED_FIELDS:
        return False
    return str(old_val or "").strip() != str(new_val or "").strip()


def compute_diff(
    prev_records: list[dict],
    curr_records: list[dict],
    run_id: str,
    prev_run_id: str,
) -> dict:
    prev_map = {_record_key(r): r for r in prev_records}
    curr_map = {_record_key(r): r for r in curr_records}

    new_records: list[dict] = []
    changed_records: list[dict] = []
    removed_records: list[dict] = []
    unchanged_count = 0

    for key, curr in curr_map.items():
        if key not in prev_map:
            new_records.append(curr)
        else:
            prev = prev_map[key]
            diffs = [
                f
                for f in FIELDS
                if f not in IGNORED_FIELDS and _field_changed(f, prev.get(f, ""), curr.get(f, ""))
            ]
            if diffs:
                entry = dict(curr)
                entry["_changed_fields"] = diffs
                entry["_prev"] = {f: prev.get(f, "") for f in diffs}
                changed_records.append(entry)
            else:
                unchanged_count += 1

    for key, prev in prev_map.items():
        if key not in curr_map:
            removed_records.append(prev)

    result = {
        "run_id": run_id,
        "prev_run_id": prev_run_id,
        "generated_at": datetime.now(timezone.utc).isoformat(),
        "summary": {
            "new": len(new_records),
            "changed": len(changed_records),
            "removed": len(removed_records),
            "unchanged": unchanged_count,
        },
        "new": new_records,
        "changed": changed_records,
        "removed": removed_records,
    }

    log.info(
        "Diff: +%d new  ~%d changed  -%d removed  =%d unchanged",
        len(new_records),
        len(changed_records),
        len(removed_records),
        unchanged_count,
    )
    return result


def load_records_from_file(json_path: str) -> list[dict]:
    try:
        with open(json_path, encoding="utf-8") as f:
            data = json.load(f)
        return data.get("records", [])
    except Exception as exc:
        log.warning("Could not load records from %s: %s", json_path, exc)
        return []


def save_diff(diff: dict, output_dir: str) -> str:
    os.makedirs(output_dir, exist_ok=True)
    filename = f"diff_{diff['run_id']}.json"
    filepath = os.path.join(output_dir, filename)
    with open(filepath, "w", encoding="utf-8") as f:
        json.dump(diff, f, indent=2, ensure_ascii=False)
    log.info("Diff saved → %s", filepath)
    return filename
