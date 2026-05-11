"""
Uses Groq LLM to generate a professional security digest email body
from the scraper diff data.

Config (environment variables):
  GROQ_API_KEY  — Groq API key
  GROQ_MODEL    — Model ID (default: llama-3.3-70b-versatile)
"""

import logging
import os
from typing import Optional

log = logging.getLogger(__name__)

_DEFAULT_MODEL = "llama-3.3-70b-versatile"


def _env(key: str, default: str = "") -> str:
    return os.environ.get(key, default).strip()


def _build_prompt(run_id: str, diff: dict, contact: dict) -> str:
    summary = diff.get("summary", {})
    new_records = diff.get("new", [])[:20]
    changed_records = diff.get("changed", [])[:10]

    new_lines = []
    for r in new_records:
        sev = r.get("severity", "")
        cvss = r.get("cvss_score", "")
        sev_str = f" [{sev} {cvss}]".strip() if sev else ""
        desc = str(r.get("description", ""))[:200]
        new_lines.append(f"- {r.get('title', 'Untitled')}{sev_str} ({r.get('source', '')}): {desc}")

    changed_lines = []
    for r in changed_records:
        fields = ", ".join(r.get("_changed_fields", []))
        changed_lines.append(f"- {r.get('title', 'Untitled')} — changed: {fields}")

    new_block = "\n".join(new_lines) if new_lines else "None"
    changed_block = "\n".join(changed_lines) if changed_lines else "None"

    recipient_context = ""
    if contact.get("name"):
        recipient_context = f"The recipient is {contact['name']}"
        if contact.get("title"):
            recipient_context += f", {contact['title']}"
        if contact.get("organization"):
            recipient_context += f" at {contact['organization']}"
        recipient_context += "."

    return f"""You are a senior cybersecurity analyst writing a professional daily threat intelligence digest email.

{recipient_context}

Today's scrape summary (Run {run_id}):
- New vulnerabilities/products: {summary.get('new', 0)}
- Changed records: {summary.get('changed', 0)}
- Removed: {summary.get('removed', 0)}
- Total monitored: {summary.get('unchanged', 0) + summary.get('new', 0)}

NEW entries:
{new_block}

CHANGED entries:
{changed_block}

Write a concise, professional security digest email body (no subject line, no greeting — start directly with the content). Use clear sections:
1. Executive Summary (2-3 sentences on the threat landscape today)
2. Critical New Vulnerabilities (if any HIGH/CRITICAL entries exist, highlight them with brief impact analysis)
3. Notable Changes (if any records changed)
4. Recommended Actions (2-4 bullet points appropriate for a CISO audience)

Keep the tone authoritative but concise. Plain text only — no markdown, no asterisks, no bullet symbols other than simple hyphens. Total length: 200-350 words."""


def generate_digest(run_id: str, diff: dict, contact: Optional[dict] = None) -> Optional[str]:
    """Call Groq and return a plain-text email body, or None on failure."""
    api_key = _env("GROQ_API_KEY")
    if not api_key:
        log.warning("GROQ_API_KEY not set — skipping AI digest generation")
        return None

    model = _env("GROQ_MODEL", _DEFAULT_MODEL)
    contact = contact or {}

    try:
        from groq import Groq
        client = Groq(api_key=api_key)
        prompt = _build_prompt(run_id, diff, contact)
        response = client.chat.completions.create(
            model=model,
            messages=[{"role": "user", "content": prompt}],
            max_tokens=1024,
            temperature=0.4,
        )
        text = response.choices[0].message.content.strip()
        log.info("Groq digest generated (%d chars) using %s", len(text), model)
        return text
    except Exception as exc:
        log.error("Groq digest generation failed: %s", exc)
        return None
