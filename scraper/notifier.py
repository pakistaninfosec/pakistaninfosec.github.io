"""
Email notifier — sends a daily digest via Brevo SMTP after each scheduled run.
Only fires when new or changed records are present in the diff.

Config (all read from environment variables):
  SMTP_HOST      — SMTP server host        (default: smtp-relay.brevo.com)
  SMTP_PORT      — SMTP port               (default: 587)
  SMTP_LOGIN     — SMTP login / username
  SMTP_PASSWORD  — SMTP password           (required)
  SMTP_FROM      — From address            (default: same as SMTP_LOGIN)
  EMAIL_TO       — Recipient address(es), comma-separated
"""

import logging
import os
import smtplib
from email.mime.multipart import MIMEMultipart
from email.mime.text import MIMEText
from typing import Optional

log = logging.getLogger(__name__)

SEV_COLOUR = {
    "CRITICAL": "#7c3aed",
    "HIGH": "#dc2626",
    "MEDIUM": "#d97706",
    "LOW": "#16a34a",
}


def _env(key: str, default: str = "") -> str:
    return os.environ.get(key, default).strip()


def _get_badges(rec: dict) -> str:
    """Return HTML badge pills based on category and tags."""
    tags = str(rec.get("tags", "")).lower()
    category = str(rec.get("category", "")).lower()
    badges = []

    if "zero-day" in tags or "zero day" in category or category == "zero day":
        badges.append(
            '<span style="background:#dc2626;color:#fff;border-radius:3px;padding:2px 8px;'
            'font-size:10px;font-weight:800;letter-spacing:.06em;margin-right:4px">&#9888; ZERO DAY</span>'
        )
    if "actively-exploited" in tags:
        badges.append(
            '<span style="background:#ea580c;color:#fff;border-radius:3px;padding:2px 8px;'
            'font-size:10px;font-weight:800;letter-spacing:.06em;margin-right:4px">&#128293; ACTIVELY EXPLOITED</span>'
        )
    if "pakistan-alert" in tags or "pakistan alert" in category:
        badges.append(
            '<span style="background:#16a34a;color:#fff;border-radius:3px;padding:2px 8px;'
            'font-size:10px;font-weight:800;letter-spacing:.06em;margin-right:4px">&#127477;&#127472; PAKISTAN ALERT</span>'
        )
    return "".join(badges)


def _build_record_row(rec: dict, kind: str) -> str:
    border = {"new": "#22c55e", "changed": "#f59e0b", "removed": "#ef4444"}.get(kind, "#334155")
    label = {"new": "NEW", "changed": "CHANGED", "removed": "REMOVED"}.get(kind, kind.upper())
    label_colour = border

    title = rec.get("title", "")
    source = rec.get("source", "")
    desc = str(rec.get("description", ""))[:300]
    url = rec.get("url", "")
    severity = str(rec.get("severity", "")).upper()
    cvss = rec.get("cvss_score", "")
    category = rec.get("category", "")
    changed_fields: list = rec.get("_changed_fields", [])
    prev: dict = rec.get("_prev", {})

    sev_bg = SEV_COLOUR.get(severity, "#1e293b")
    sev_pill = (
        f'<span style="background:{sev_bg};color:#fff;border-radius:3px;padding:1px 7px;'
        f'font-size:11px;margin-right:4px">{severity} {cvss}</span>'
        if severity else ""
    )

    badges_html = _get_badges(rec)

    changed_html = ""
    if changed_fields:
        rows = "".join(
            f'<tr><td style="padding:2px 8px;color:#94a3b8;font-size:11px">{f}</td>'
            f'<td style="padding:2px 8px;color:#f87171;font-size:11px;text-decoration:line-through">'
            f'{prev.get(f,"")[:120]}</td></tr>'
            for f in changed_fields
        )
        changed_html = f'<table style="margin-top:6px;border-collapse:collapse">{rows}</table>'

    link_html = (
        f'<a href="{url}" style="color:#60a5fa;font-size:11px;text-decoration:none">↗ view</a>'
        if url else ""
    )

    return f"""
    <div style="border-left:3px solid {border};background:#1e293b;border-radius:0 6px 6px 0;
                padding:12px 16px;margin-bottom:10px">
      <div style="margin-bottom:5px">{badges_html}</div>
      <div style="display:flex;align-items:center;gap:8px;margin-bottom:4px;flex-wrap:wrap">
        <span style="color:{label_colour};font-size:10px;font-weight:700;letter-spacing:.08em">{label}</span>
        <span style="color:#f1f5f9;font-size:13px;font-weight:600">{title}</span>
        <span style="color:#64748b;font-size:11px">{source}</span>
        {link_html}
      </div>
      {f'<p style="color:#94a3b8;font-size:12px;margin:4px 0">{desc}</p>' if desc else ""}
      <div style="margin-top:6px">{sev_pill}
        {f'<span style="background:#0f172a;color:#94a3b8;border-radius:3px;padding:1px 7px;font-size:11px">{category}</span>' if category else ""}
      </div>
      {changed_html}
    </div>"""


def build_html(run_id: str, diff: dict, run_entry: Optional[dict] = None, ai_plain_body: Optional[str] = None) -> str:
    from datetime import datetime, timezone as tz

    summary = diff.get("summary", {})
    new_count = summary.get("new", 0)
    changed_count = summary.get("changed", 0)
    removed_count = summary.get("removed", 0)
    unchanged_count = summary.get("unchanged", 0)

    new_records = diff.get("new", [])[:50]
    changed_records = diff.get("changed", [])[:30]
    removed_records = diff.get("removed", [])[:20]

    dashboard_url = _env("DASHBOARD_URL", "")

    def section(title: str, items: list, kind: str, colour: str) -> str:
        if not items:
            return ""
        rows = "".join(_build_record_row(r, kind) for r in items)
        return f"""
        <h3 style="color:{colour};font-size:12px;text-transform:uppercase;letter-spacing:.1em;
                   margin:24px 0 10px;font-weight:700">{title}</h3>
        {rows}"""

    def _cat_group(rec: dict) -> str:
        tags = str(rec.get("tags", "")).lower()
        cat = str(rec.get("category", "")).lower()
        if "zero-day" in tags or cat == "zero day":
            return "zeroday"
        if "actively-exploited" in tags or "cisa kev" in cat:
            return "cisa"
        if "pakistan-alert" in tags or cat == "pakistan alert":
            return "pakistan"
        if "threat-intelligence" in tags or cat == "threat intelligence":
            return "threat_intel"
        if "cve" in cat or "vulnerability" in cat or "nvd" in cat:
            return "cve"
        return "other"

    groups: dict = {"zeroday": [], "cisa": [], "pakistan": [], "threat_intel": [], "cve": [], "other": []}
    for r in new_records:
        groups[_cat_group(r)].append(r)

    def cat_section(header: str, icon: str, colour: str, accent: str, items: list) -> str:
        if not items:
            return ""
        rows = "".join(_build_record_row(r, "new") for r in items)
        return f"""
        <div style="margin-bottom:28px">
          <div style="display:flex;align-items:center;gap:10px;margin-bottom:12px">
            <div style="width:3px;height:20px;background:{accent};border-radius:2px;flex-shrink:0"></div>
            <h3 style="color:{colour};font-size:12px;text-transform:uppercase;letter-spacing:.1em;
                       margin:0;font-weight:700">{icon} {header}
              <span style="color:#475569;font-weight:400;font-size:11px;text-transform:none;
                           letter-spacing:0">({len(items)})</span>
            </h3>
          </div>
          {rows}
        </div>"""

    new_section = ""
    if new_records:
        new_section = (
            cat_section("Zero Day Exploits", "&#9888;", "#f87171", "#dc2626", groups["zeroday"]) +
            cat_section("CISA — Actively Exploited", "&#128293;", "#fb923c", "#ea580c", groups["cisa"]) +
            cat_section("Pakistan Alerts", "&#127477;&#127472;", "#4ade80", "#16a34a", groups["pakistan"]) +
            cat_section("Threat Intelligence", "&#128202;", "#60a5fa", "#1d4ed8", groups["threat_intel"]) +
            cat_section("CVE / Vulnerabilities", "&#128274;", "#c084fc", "#7c3aed", groups["cve"]) +
            cat_section("Other Findings", "&#128196;", "#94a3b8", "#475569", groups["other"])
        )

    changed_section = section(f"Updated Records ({changed_count})", changed_records, "changed", "#f59e0b")
    removed_section = section(f"Resolved / Removed ({removed_count})", removed_records, "removed", "#ef4444")

    records_total = run_entry.get("records_collected", 0) if run_entry else 0
    today = datetime.now(tz.utc).strftime("%B %d, %Y")

    diff_link = (
        f'<a href="{dashboard_url}/api/scrape/diff?run_id={run_id}" '
        f'style="background:#1d4ed8;color:#fff;padding:8px 20px;border-radius:6px;'
        f'text-decoration:none;font-size:13px;font-weight:600">View Full Report →</a>'
        if dashboard_url else ""
    )

    threat_badge = (
        f'<span style="background:#dc2626;color:#fff;border-radius:4px;padding:3px 10px;'
        f'font-size:11px;font-weight:700;letter-spacing:.06em">{new_count} NEW THREATS</span>'
        if new_count else
        f'<span style="background:#1e3a5f;color:#93c5fd;border-radius:4px;padding:3px 10px;'
        f'font-size:11px;font-weight:700;letter-spacing:.06em">NO NEW THREATS TODAY</span>'
    )

    return f"""<!DOCTYPE html>
<html lang="en">
<head><meta charset="UTF-8"><meta name="viewport" content="width=device-width,initial-scale=1"></head>
<body style="margin:0;padding:0;background:#0a0f1e;font-family:system-ui,-apple-system,sans-serif">

  <!-- Header banner -->
  <div style="background:linear-gradient(135deg,#0d1f3c 0%,#1a3560 100%);padding:0">
    <div style="max-width:680px;margin:0 auto;padding:28px 24px 24px">
      <table width="100%" cellpadding="0" cellspacing="0" style="border-collapse:collapse">
        <tr>
          <td style="vertical-align:middle">
            <div style="display:inline-block;background:#1e40af;border-radius:6px;
                        padding:8px 14px;margin-bottom:10px">
              <span style="color:#fff;font-size:11px;font-weight:800;letter-spacing:.2em;
                           text-transform:uppercase">&#x1F6E1; INFOSEC PAKISTAN</span>
            </div>
            <div style="color:#f8fafc;font-size:22px;font-weight:700;
                        letter-spacing:-.02em;line-height:1.2;margin-bottom:6px">
              Daily Security Digest
            </div>
            <div style="color:#93c5fd;font-size:12px">{today} &nbsp;|&nbsp; Threat Intelligence Report</div>
          </td>
          <td style="text-align:right;vertical-align:top;padding-top:4px">
            {threat_badge}
          </td>
        </tr>
      </table>
    </div>
    <!-- Accent bar -->
    <div style="height:3px;background:linear-gradient(90deg,#1d4ed8,#7c3aed,#1d4ed8)"></div>
  </div>

  <div style="max-width:680px;margin:0 auto;padding:24px 24px 32px">

    <!-- Stats row -->
    <div style="display:flex;gap:10px;margin-bottom:24px;flex-wrap:wrap">
      <div style="flex:1;min-width:80px;background:#0d1f0d;border:1px solid #166534;
                  border-radius:8px;padding:14px 16px;text-align:center">
        <div style="color:#4ade80;font-size:26px;font-weight:800;line-height:1">+{new_count}</div>
        <div style="color:#16a34a;font-size:10px;text-transform:uppercase;
                    letter-spacing:.08em;margin-top:4px">New</div>
      </div>
      <div style="flex:1;min-width:80px;background:#1c0f00;border:1px solid #92400e;
                  border-radius:8px;padding:14px 16px;text-align:center">
        <div style="color:#fb923c;font-size:26px;font-weight:800;line-height:1">{changed_count}</div>
        <div style="color:#c2410c;font-size:10px;text-transform:uppercase;
                    letter-spacing:.08em;margin-top:4px">Changed</div>
      </div>
      <div style="flex:1;min-width:80px;background:#1a0505;border:1px solid #7f1d1d;
                  border-radius:8px;padding:14px 16px;text-align:center">
        <div style="color:#f87171;font-size:26px;font-weight:800;line-height:1">{removed_count}</div>
        <div style="color:#b91c1c;font-size:10px;text-transform:uppercase;
                    letter-spacing:.08em;margin-top:4px">Removed</div>
      </div>
      <div style="flex:1;min-width:80px;background:#0f172a;border:1px solid #1e3a5f;
                  border-radius:8px;padding:14px 16px;text-align:center">
        <div style="color:#f1f5f9;font-size:26px;font-weight:800;line-height:1">{records_total}</div>
        <div style="color:#475569;font-size:10px;text-transform:uppercase;
                    letter-spacing:.08em;margin-top:4px">Monitored</div>
      </div>
    </div>

    <!-- AI Analysis panel -->
    {f'''<div style="background:#07173a;border:1px solid #1e40af;border-radius:8px;
                padding:20px 22px;margin-bottom:24px">
      <div style="display:flex;align-items:center;gap:8px;margin-bottom:14px">
        <span style="background:#1e40af;border-radius:4px;padding:3px 9px;
                     color:#bfdbfe;font-size:10px;font-weight:700;letter-spacing:.1em">
          AI ANALYSIS &nbsp;·&nbsp; Powered by Groq
        </span>
      </div>
      <div style="color:#e2e8f0;font-size:13px;line-height:1.8;white-space:pre-wrap">{ai_plain_body}</div>
    </div>''' if ai_plain_body else ""}

    {new_section}
    {changed_section}
    {removed_section}

    {f'<div style="margin-top:28px">{diff_link}</div>' if diff_link else ""}

    <!-- Footer -->
    <div style="margin-top:36px;border-top:2px solid #1e3a5f">

      <!-- Signature block -->
      <div style="background:#07173a;padding:20px 24px;margin-top:0">
        <table width="100%" cellpadding="0" cellspacing="0" style="border-collapse:collapse">
          <tr>
            <td style="vertical-align:top">
              <div style="color:#f1f5f9;font-size:13px;font-weight:700;margin-bottom:2px">
                Syed Imtiaz Hussain
              </div>
              <div style="color:#93c5fd;font-size:11px;margin-bottom:1px">
                Cybersecurity Professional
              </div>
              <div style="color:#64748b;font-size:11px;margin-bottom:6px">
                Karachi, Pakistan
              </div>
              <a href="mailto:imtiazhusain15@gmail.com"
                 style="color:#60a5fa;font-size:11px;text-decoration:none">
                imtiazhusain15@gmail.com
              </a>
            </td>
            <td style="text-align:right;vertical-align:top">
              <div style="display:inline-block;background:#1e40af;border-radius:5px;
                          padding:6px 12px">
                <span style="color:#fff;font-size:10px;font-weight:800;
                             letter-spacing:.18em;text-transform:uppercase">
                  &#x1F6E1; INFOSEC PAKISTAN
                </span>
              </div>
            </td>
          </tr>
        </table>
      </div>

      <!-- Legal strip -->
      <div style="background:#0a0f1e;border-top:1px solid #1e293b;padding:14px 24px">
        <p style="color:#334155;font-size:10px;margin:0 0 6px;line-height:1.6">
          You are receiving this email because you are subscribed to the
          <strong style="color:#475569">InfoSec Pakistan Daily Security Digest</strong>.
          To unsubscribe, reply to this email with the word <em>Unsubscribe</em>.
        </p>
        <p style="color:#1e293b;font-size:10px;margin:0">
          &copy; 2026 InfoSec Pakistan. All rights reserved. &nbsp;|&nbsp;
          Automated daily threat intelligence. Sources: NVD/NIST, Krebs on Security,
          SecurityWeek, The Hacker News, Palo Alto Networks, CrowdStrike, Fortinet,
          Tenable, SentinelOne, Check Point.
        </p>
      </div>

    </div>

</body>
</html>"""


def build_plain(run_id: str, diff: dict) -> str:
    from datetime import datetime, timezone as tz
    s = diff.get("summary", {})
    today = datetime.now(tz.utc).strftime("%B %d, %Y")
    lines = [
        "INFOSEC PAKISTAN — Daily Security Digest",
        f"Threat Intelligence Report | {today}",
        "",
        f"+{s.get('new',0)} new threats  |  {s.get('changed',0)} updated  |  {s.get('removed',0)} removed  |  {s.get('unchanged',0)} monitored",
        "",
    ]
    for rec in diff.get("new", [])[:30]:
        lines.append(f"[NEW] {rec.get('title','')}  ({rec.get('source','')})")
        if rec.get("url"):
            lines.append(f"      {rec['url']}")
    for rec in diff.get("changed", [])[:20]:
        fields = ", ".join(rec.get("_changed_fields", []))
        lines.append(f"[CHANGED] {rec.get('title','')}  — {fields}")
        if rec.get("url"):
            lines.append(f"          {rec['url']}")
    for rec in diff.get("removed", [])[:10]:
        lines.append(f"[REMOVED] {rec.get('title','')}  ({rec.get('source','')})")
    lines += [
        "",
        "─" * 60,
        "",
        "Curated by: Syed Imtiaz Hussain",
        "Cybersecurity Professional | Karachi, Pakistan",
        "imtiazhusain15@gmail.com",
        "",
        "You are receiving this email because you are subscribed to",
        "the InfoSec Pakistan Daily Security Digest.",
        "To unsubscribe, reply to this email with the word: Unsubscribe",
        "",
        "© 2026 InfoSec Pakistan. All rights reserved.",
    ]
    return "\n".join(lines)


def send_digest(
    run_id: str,
    diff: dict,
    run_entry: Optional[dict] = None,
    recipients: Optional[list[str]] = None,
    ai_plain_body: Optional[str] = None,
) -> bool:
    """Send a digest email.

    If `recipients` is provided it overrides EMAIL_TO.
    If `ai_plain_body` is provided it is prepended to the plain-text part as an
    AI-written executive summary before the structured diff listing.
    """
    password = _env("SMTP_PASSWORD") or _env("BREVO_SMTP_PASSWORD")
    if not password:
        log.warning("SMTP_PASSWORD not set — skipping email notification")
        return False

    smtp_host = _env("SMTP_HOST", "smtp-relay.brevo.com")
    smtp_port = int(_env("SMTP_PORT", "587"))
    smtp_login = _env("SMTP_LOGIN")
    smtp_from = _env("SMTP_FROM") or smtp_login

    if not smtp_login:
        log.warning("SMTP_LOGIN not set — skipping email notification")
        return False

    if not recipients:
        email_to_raw = _env("EMAIL_TO")
        if not email_to_raw:
            log.warning("EMAIL_TO not set — skipping email notification")
            return False
        recipients = [e.strip() for e in email_to_raw.split(",") if e.strip()]

    summary = diff.get("summary", {})
    new_count = summary.get("new", 0)
    changed_count = summary.get("changed", 0)

    threat_count = new_count + changed_count
    if new_count:
        subject = f"InfoSec Pakistan — Daily Security Digest | {new_count} New Threat{'s' if new_count != 1 else ''} Detected"
    elif changed_count:
        subject = f"InfoSec Pakistan — Daily Security Digest | {changed_count} Update{'s' if changed_count != 1 else ''} Detected"
    else:
        subject = "InfoSec Pakistan — Daily Security Digest | No New Threats Today"

    sender_name = "InfoSec Pakistan Security Team"
    from_header = f"{sender_name} <{smtp_from}>"

    msg = MIMEMultipart("alternative")
    msg["Subject"] = subject
    msg["From"] = from_header
    msg["To"] = ", ".join(recipients)

    structured_plain = build_plain(run_id, diff)
    if ai_plain_body:
        plain = ai_plain_body + "\n\n" + "─" * 60 + "\n\nFull diff listing:\n\n" + structured_plain
    else:
        plain = structured_plain

    html = build_html(run_id, diff, run_entry, ai_plain_body=ai_plain_body)
    msg.attach(MIMEText(plain, "plain"))
    msg.attach(MIMEText(html, "html"))

    try:
        log.info("Sending digest email to %s via %s:%d…", recipients, smtp_host, smtp_port)
        with smtplib.SMTP(smtp_host, smtp_port, timeout=30) as server:
            server.ehlo()
            server.starttls()
            server.ehlo()
            server.login(smtp_login, password)
            server.sendmail(smtp_from, recipients, msg.as_string())
        log.info("Digest email sent successfully to %s", recipients)
        return True
    except smtplib.SMTPAuthenticationError as e:
        log.error("SMTP authentication failed: %s", e)
    except smtplib.SMTPException as e:
        log.error("SMTP error sending digest: %s", e)
    except Exception as e:
        log.error("Unexpected error sending digest: %s", e)
    return False
