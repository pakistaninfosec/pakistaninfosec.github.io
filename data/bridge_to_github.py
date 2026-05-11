"""
bridge_to_github.py
====================
Add this file to your Replit scraper project.
It reads your existing scraper output and pushes
it to your GitHub Pages website automatically.

SETUP:
Add these to Replit Secrets (🔒 tab):
  GITHUB_TOKEN  = your GitHub personal access token
  GITHUB_REPO   = pakistaninfosec/pakistaninfosec.github.io
"""

import os
import json
import base64
import requests
from datetime import datetime, date
from collections import Counter
import glob

# ─────────────────────────────────────────────
# FIND LATEST SCRAPER OUTPUT FILE
# ─────────────────────────────────────────────

def find_latest_json():
    """Find the most recent infosec_products_*.json file"""
    files = glob.glob("scraper/output/infosec_products_*.json")
    if not files:
        files = glob.glob("output/infosec_products_*.json")
    if not files:
        print("❌ No scraper output files found!")
        return None
    latest = max(files, key=os.path.getmtime)
    print(f"[✓] Found scraper output: {latest}")
    return latest


# ─────────────────────────────────────────────
# CONVERT SCRAPER FORMAT → WEBSITE FORMAT
# ─────────────────────────────────────────────

ZERODAY_SOURCES = {"CISA KEV", "Google Project Zero", "Vulners", "NVD/NIST"}
EXPLOITED_SOURCES = {"CISA KEV"}
PAKISTAN_KEYWORDS = ["pakistan", "pk", "pkc", "gov.pk", "pta", "nadra", "hec", "nccs"]

def is_pakistan_related(record):
    """Check if a record is Pakistan-specific"""
    text = " ".join([
        record.get("title", ""),
        record.get("description", ""),
        record.get("affected_products", ""),
        record.get("tags", ""),
    ]).lower()
    return any(kw in text for kw in PAKISTAN_KEYWORDS)

def map_severity(record):
    """Map cvss_score or severity field to website severity levels"""
    sev = record.get("severity", "").upper()
    score = float(record.get("cvss_score", 0) or 0)

    if sev in ["CRITICAL"] or score >= 9.0:
        return "CRITICAL"
    elif sev in ["HIGH"] or score >= 7.0:
        return "HIGH"
    elif sev in ["MEDIUM"] or score >= 4.0:
        return "MEDIUM"
    else:
        return "LOW"

def convert_records(raw_records):
    """Convert scraper records to website threat format"""
    threats = []
    for r in raw_records:
        tags = [t.strip() for t in r.get("tags", "").split(",") if t.strip()]
        category = r.get("category", "")
        if category and category not in tags:
            tags.append(category)

        threats.append({
            "id":       r.get("id") or r.get("title", "UNKNOWN"),
            "desc":     r.get("description", "")[:200],
            "severity": map_severity(r),
            "source":   r.get("source", "Unknown"),
            "date":     (r.get("published_date") or r.get("last_modified") or date.today().isoformat())[:10],
            "pakistan": is_pakistan_related(r),
            "tags":     tags[:5],
            "url":      r.get("url", ""),
            "cvss":     r.get("cvss_score", ""),
            "cwe":      r.get("cwe", ""),
        })
    return threats


# ─────────────────────────────────────────────
# BUILD threats.json
# ─────────────────────────────────────────────

def build_threats_json(raw_data, ai_summary=""):
    threats = convert_records(raw_data.get("records", []))

    # Source counts
    source_counter = Counter(t["source"] for t in threats)
    sources = [
        {"name": name, "count": count}
        for name, count in sorted(source_counter.items(), key=lambda x: -x[1])
    ]

    # Stats
    total_new = len(threats)
    zeroday   = sum(1 for t in threats if t["source"] in ZERODAY_SOURCES)
    exploited = sum(1 for t in threats if t["source"] in EXPLOITED_SOURCES)
    pakistan  = sum(1 for t in threats if t["pakistan"])

    # Load previous total for running count
    prev_total = 0
    try:
        with open("data/threats.json") as f:
            prev = json.load(f)
            prev_total = prev.get("stats", {}).get("total", 0)
    except Exception:
        pass

    return {
        "generated": datetime.utcnow().isoformat() + "Z",
        "summary": ai_summary or (
            f"Today's digest contains {total_new} new vulnerabilities across {len(sources)} sources. "
            f"{zeroday} zero-day exploits detected, {exploited} actively exploited entries from CISA KEV, "
            f"and {pakistan} Pakistan-specific advisories. Priority patching recommended for all CRITICAL entries."
        ),
        "stats": {
            "new":       total_new,
            "changed":   raw_data.get("diff_summary", {}).get("changed", 0),
            "removed":   raw_data.get("diff_summary", {}).get("removed", 0),
            "total":     prev_total + total_new,
            "zeroday":   zeroday,
            "exploited": exploited,
            "pakistan":  pakistan,
        },
        "sources": sources,
        "threats": threats,
    }


# ─────────────────────────────────────────────
# BUILD reports.json (rolling archive)
# ─────────────────────────────────────────────

def build_reports_json(threats_data):
    today = date.today().isoformat()
    threats = threats_data["threats"]
    stats   = threats_data["stats"]

    # Build sections for report page
    sections = []
    zeroday_items = [
        {"id": t["id"], "desc": t["desc"]}
        for t in threats if t["source"] in ZERODAY_SOURCES
    ][:10]
    exploited_items = [
        {"id": t["id"], "desc": t["desc"]}
        for t in threats if t["source"] in EXPLOITED_SOURCES
    ][:10]
    pakistan_items = [
        {"id": t["id"], "desc": t["desc"]}
        for t in threats if t["pakistan"]
    ][:10]

    if zeroday_items:
        sections.append({"label": "Zero Day Exploits",  "color": "red",    "items": zeroday_items})
    if exploited_items:
        sections.append({"label": "Actively Exploited", "color": "orange", "items": exploited_items})
    if pakistan_items:
        sections.append({"label": "Pakistan Alerts",    "color": "green",  "items": pakistan_items})

    new_report = {
        "date": today,
        "stats": stats,
        "summary": threats_data["summary"],
        "sections": sections,
    }

    # Load existing reports
    try:
        with open("data/reports.json") as f:
            reports_data = json.load(f)
    except Exception:
        reports_data = {"reports": []}

    # Remove today's entry if re-running, then prepend
    reports_data["reports"] = [
        r for r in reports_data["reports"] if r.get("date") != today
    ]
    reports_data["reports"].insert(0, new_report)
    reports_data["reports"] = reports_data["reports"][:90]  # keep 90 days

    return reports_data


# ─────────────────────────────────────────────
# PUSH TO GITHUB
# ─────────────────────────────────────────────

def push_to_github(filename, content_dict):
    token = os.environ.get("GITHUB_TOKEN")
    repo  = os.environ.get("GITHUB_REPO", "pakistaninfosec/pakistaninfosec.github.io")

    if not token:
        print("❌ GITHUB_TOKEN not found in Replit Secrets!")
        return False

    path    = f"data/{filename}"
    url     = f"https://api.github.com/repos/{repo}/contents/{path}"
    headers = {
        "Authorization": f"token {token}",
        "Accept": "application/vnd.github.v3+json"
    }

    # Get current file SHA
    res = requests.get(url, headers=headers)
    sha = res.json().get("sha", "") if res.status_code == 200 else ""

    # Encode content to base64
    content = base64.b64encode(
        json.dumps(content_dict, indent=2).encode("utf-8")
    ).decode("utf-8")

    # Push
    payload = {
        "message": f"threat data: {date.today().isoformat()}",
        "content": content,
    }
    if sha:
        payload["sha"] = sha

    res = requests.put(url, headers=headers, json=payload)

    if res.status_code in [200, 201]:
        print(f"[✓] {filename} pushed to GitHub successfully!")
        return True
    else:
        print(f"❌ Failed to push {filename}: {res.status_code} — {res.text[:200]}")
        return False


# ─────────────────────────────────────────────
# MAIN — Run this after your scraper finishes
# ─────────────────────────────────────────────

def main(ai_summary=""):
    print("\n🚀 InfoSec Pakistan — Bridge to GitHub")
    print("=" * 45)

    # 1. Find latest scraper output
    json_file = find_latest_json()
    if not json_file:
        return

    # 2. Load raw scraper data
    with open(json_file, encoding="utf-8") as f:
        raw_data = json.load(f)
    print(f"[✓] Loaded {raw_data.get('total_records', 0)} records")

    # 3. Also load latest_run.json for diff stats
    try:
        with open("scraper/output/latest_run.json") as f:
            run_data = json.load(f)
        raw_data["diff_summary"] = run_data.get("diff_summary", {})
    except Exception:
        pass

    # 4. Convert to website format
    threats_data = build_threats_json(raw_data, ai_summary)
    reports_data = build_reports_json(threats_data)
    print(f"[✓] Converted {len(threats_data['threats'])} threats")
    print(f"[✓] Pakistan alerts: {threats_data['stats']['pakistan']}")

    # 5. Save locally first
    os.makedirs("data", exist_ok=True)
    with open("data/threats.json", "w") as f:
        json.dump(threats_data, f, indent=2)
    with open("data/reports.json", "w") as f:
        json.dump(reports_data, f, indent=2)
    print("[✓] Saved locally to data/")

    # 6. Push to GitHub
    print("\n📤 Pushing to GitHub...")
    push_to_github("threats.json", threats_data)
    push_to_github("reports.json", reports_data)

    print("\n✅ Done! Your website will update in ~30 seconds.")
    print("🌐 https://pakistaninfosec.github.io")


if __name__ == "__main__":
    # If you have a Groq summary string, pass it here
    # Otherwise leave empty and it will auto-generate one
    main(ai_summary="")
