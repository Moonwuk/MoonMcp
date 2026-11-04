"""Prompt-injection scanner for fetched content (B1 gap fill).

The retired ``hermes-pipeline`` server shipped ``detect_prompt_injection`` ---
a defence scan run over any content the agent fetched from a target before the
agent acts on it.  When that server was retired (2026-10-22) its defence hooks
disappeared: fetched HTML/JS/JSON is adversarial-by-design in bug-bounty work,
and the agent had no automated line of detection.  This module restores that
capability as a stdlib-first scanner shared by the
``detect_prompt_injection`` tool.

The scanner looks for the classes an adversarial target uses to hijack an
LLM-driven agent:

* instruction overrides / role resets (``ignore all previous instructions``);
* exfiltration requests (``send the token to <webhook>``);
* local-execution attempts (``run curl ... | sh``);
* **hidden vectors** --- instructions hidden in HTML comments, zero-opacity /
  zero-size CSS, ``data-`` attributes;
* invisible Unicode (zero-width, directional overrides, tag characters);
* oversized base64 blobs that may carry a second-stage instruction payload.

Detection is *heuristic*: a hit is a lead for the agent to review, not a
verdict.  Evidence excerpts are sanitised (bounded, control-stripped) so the
scanner itself does not become an injection channel.
"""

from __future__ import annotations

import re

MAX_SCANNED_BYTES = 2_000_000
_EXCERPT_LEN = 120

# Instruction-override / role-reset phrasing (case-insensitive, EN+RU).
_OVERRIDE_PATTERNS = [
    r"ignore\s+(?:all\s+|the\s+)?(?:previous|prior|above)\s+instructions?",
    r"disregard\s+(?:your\s+|all\s+|the\s+)?(?:instructions|rules|guardrails?|guide)",
    r"(?:you\s+are|ты\s+теперь)\s+now\s+(?:a|an|the|новый\s+)?(?:different|new|другой)",
    r"you\s+are\s+now\s+(?:a|an|the)\s+",
    r"ты\s+теперь\s+(?:новый|другой)",
    r"(?:system|developer)\s+(?:mode|prompt)\s*[:=]",
    r"реальный\s+(?:system\s+)?(?:prompt|инструкции)",
    r"игнорируй\s+(?:предыдущие|все\s+ранее\s+данные)\s+инструкции",
    r"reveal\s+(?:your\s+)?(?:system\s+)?(?:prompt|instructions)",
    r"выведи\s+(?:свой\s+)?(?:system\s+)?(?:prompt|системные\s+инструкции)",
]

# Exfiltration intents.
_EXFIL_PATTERNS = [
    r"\b(?:send|post|forward|отправь|перешли)\b[^.\n]{0,80}\b(?:to|at|на)\b[^.\n]{0,60}(?:https?://|discord\.com/api/webhooks|webhook)",
    r"\b(?:copy|save|скопируй|сохрани)\b[^.\n]{0,60}\b(?:token|secret|api[_ ]?key|password|токен|ключ)\b",
    r"\bexfiltrate\b",
    r"\bпроследи\b[^.\n]{0,60}(?:токен|ключ)",
]

# Local-execution attempts (agent-adjacent shells).
_EXEC_PATTERNS = [
    r"\brm\s+-rf\b",
    r"curl[^;|\n]*\|\s*(?:ba)?sh",
    r"wget[^;|\n]*&&\s*(?:ba)?sh",
    r"\b(?:выполни|запусти|исполни)\b[^.\n]{0,50}\b(?:команду|shell|bash|cmd)\b",
]

# HTML/attribute hiding vectors.
_HIDDEN_HTML_PATTERNS = [
    r"display\s*:\s*none",
    r"visibility\s*:\s*hidden",
    r"opacity\s*:\s*0(?:\.0+)?(?:[;\s\"'])",
    r"font-size\s*:\s*0(?:px)?(?:[;\s\"'])",
    r"left\s*:\s*-?\d{4,}px",
    r"<div[^>]{0,200}\bclass=[\"'][^\"']*(?:offscreen|sr-only|visually-hidden|hidden)",
]

_ZERO_WIDTH_RE = re.compile(
    "[\u200b-\u200f\u2060-\u2064\ufeff]"
)
_TAG_CHAR_RE = re.compile("[\U000e0001-\U000e007f]")
_BASE64_RE = re.compile(r"[A-Za-z0-9+/]{240,}={0,2}")
_COMMENT_INJECT_RE = re.compile(
    r"<!(?:--)?\[[^\]]{0,40}\]?>?|<!--(.*?)-->", re.DOTALL
)

_CONTROL_RE = re.compile(r"[\x00-\x08\x0b-\x1f\x7f]")


def _excerpt(text: str) -> str:
    text = _CONTROL_RE.sub(" ", text)
    text = " ".join(text.split())
    return text[:_EXCERPT_LEN] + ("…" if len(text) > _EXCERPT_LEN else "")


def _hits(patterns: list[str], text: str) -> list[dict]:
    out: list[dict] = []
    for raw in patterns:
        try:
            m = re.search(raw, text, re.IGNORECASE)
        except re.error:
            continue
        if m:
            start = max(0, m.start() - 30)
            out.append(
                {"pattern": raw[:60], "excerpt": _excerpt(text[start : m.end() + 40])}
            )
    return out


def scan_text(text: str) -> dict:
    """Scan *text* (HTML/JS/JSON/plain) for prompt-injection indicators.

    Returns a dict with per-category leads and summary counts.  Pure function
    (no network) so it is unit-testable; the tool layer does the fetching.
    """

    scanned = text[:MAX_SCANNED_BYTES]
    categories: dict[str, list[dict]] = {}
    for group, patterns in (
        ("instruction_override", _OVERRIDE_PATTERNS),
        ("exfiltration", _EXFIL_PATTERNS),
        ("execution", _EXEC_PATTERNS),
        ("hidden_html", _HIDDEN_HTML_PATTERNS),
    ):
        hits = _hits(patterns, scanned)
        if hits:
            categories[group] = hits[:8]

    zw = len(_ZERO_WIDTH_RE.findall(scanned))
    tc = len(_TAG_CHAR_RE.findall(scanned))
    invisible: list[dict] = []
    if zw or tc:
        invis_ex = _excerpt(_ZERO_WIDTH_RE.sub("·", scanned)[:160])
        invisible.append(
            {
                "kind": "invisible-unicode",
                "zero_width": zw,
                "tag_chars": tc,
                "excerpt": invis_ex,
            }
        )
        categories["invisible_unicode"] = invisible

    for m in _BASE64_RE.finditer(scanned):
        blob = m.group(0)
        categories.setdefault("base64_blob", []).append(
            {"excerpt": blob[:_EXCERPT_LEN], "length": len(blob)}
        )
        break  # one blob sample is enough to flag

    # Instructions hidden inside HTML comments.
    comment_leads: list[dict] = []
    for cm in re.finditer(r"<!--(.*?)-->", scanned, re.DOTALL):
        body = cm.group(1)
        if len(body) > 40 and _hits(
            [
                r"\b(?:instructions?|prompt|system|игнорир|инструкц|бот)\b",
                r"\b(?:ignore|disregard|do not tell|не\s+рассказывай)\b",
            ],
            body,
        ):
            comment_leads.append({"excerpt": _excerpt(body)})
        if len(comment_leads) >= 5:
            break
    if comment_leads:
        categories["hidden_comment"] = comment_leads

    total = sum(len(v) for v in categories.values())
    severity = "none"
    if total:
        if "instruction_override" in categories or "exfiltration" in categories:
            severity = "high"
        elif "execution" in categories or "invisible_unicode" in categories:
            severity = "medium"
        else:
            severity = "low"
    return {
        "scanned_bytes": min(len(text), MAX_SCANNED_BYTES),
        "total_leads": total,
        "severity": severity,
        "categories": categories,
    }