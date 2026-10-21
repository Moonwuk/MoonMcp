"""Bounded advisory screening of untrusted browser observations."""

from __future__ import annotations

import re
from itertools import islice
from typing import Any

SCAN_CHARS = 64000
SCAN_ITEMS = 512
SCAN_DEPTH = 12
_RULES = (
    ("instruction_override", re.compile(
        r"(?:ignore|disregard|forget)\s+(?:all\s+)?(?:previous|prior|above|system)\s+"
        r"(?:instructions?|prompts?|rules?)", re.IGNORECASE)),
    ("instruction_override_ru", re.compile(
        r"(?:игнорируй|забудь|отмени)\s+(?:все\s+)?(?:предыдущие|системные|прежние)\s+"
        r"(?:инструкции|указания|правила)", re.IGNORECASE)),
    ("role_marker", re.compile(
        r"<\|(?:im_start|system|assistant)\|>|(?:^|\n)\s*(?:system|developer)\s*:", re.IGNORECASE)),
    ("secret_request", re.compile(
        r"(?:reveal|exfiltrate|send|print)\s+(?:the\s+)?(?:system\s+prompt|api[ _-]?keys?|"
        r"access[ _-]?tokens?|credentials|secrets)", re.IGNORECASE)),
)


def screen_observation(observation: Any) -> dict:
    """Flag patterns without copying matches or interpreting them as instructions.

    A clean scan never upgrades trust. Character, item and depth limits keep
    attacker-shaped data from making this advisory operation unbounded.
    """
    stack = [(observation, "observation", 0)]
    seen: set[int] = set()
    findings: list[dict[str, str]] = []
    remaining = SCAN_CHARS
    visited = 0
    truncated = False
    while stack and visited < SCAN_ITEMS:
        value, path, depth = stack.pop()
        visited += 1
        if isinstance(value, str):
            sample = value[:remaining]
            remaining -= len(sample)
            truncated = truncated or len(sample) < len(value)
            for label, pattern in _RULES:
                if pattern.search(sample):
                    findings.append({"kind": label, "path": path})
            if remaining == 0:
                truncated = truncated or bool(stack)
                break
        elif isinstance(value, (dict, list, tuple)):
            if depth >= SCAN_DEPTH or id(value) in seen:
                truncated = True
                continue
            seen.add(id(value))
            capacity = max(0, SCAN_ITEMS - visited - len(stack))
            if isinstance(value, dict):
                # Include attacker-controlled keys, but never echo them in paths.
                count = min(len(value), capacity // 2)
                pairs = list(islice(value.items(), count))
                for index, (key, child) in reversed(list(enumerate(pairs))):
                    stack.append((child, f"{path}[{index}]", depth + 1))
                    stack.append((key, f"{path}[{index}].key", depth + 1))
                truncated = truncated or count < len(value)
            else:
                count = min(len(value), capacity)
                for index in reversed(range(count)):
                    stack.append((value[index], f"{path}[{index}]", depth + 1))
                truncated = truncated or count < len(value)
    return {
        "trust": "untrusted",
        "scan": "advisory",
        "suspicious": bool(findings),
        "findings": findings,
        "truncated": truncated or bool(stack),
        "limits": {"characters": SCAN_CHARS, "items": SCAN_ITEMS, "depth": SCAN_DEPTH},
    }


def screen_result(result: Any) -> Any:
    result.content_safety = screen_observation({
        key: value for key, value in vars(result).items() if key != "content_safety"
    })
    return result
