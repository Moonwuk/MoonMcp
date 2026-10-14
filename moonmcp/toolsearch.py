"""Small local lexical retriever over the exposed registry and capabilities.

Unicode normalization and reviewed domain aliases are intentionally modest:
they support a labelled vocabulary, not general multilingual understanding.
Cards help selection; they do not change schemas loaded by an MCP client.
"""

from __future__ import annotations

import math
import re
import unicodedata
from collections import Counter
from typing import Any

from . import toolspec

_PHASES = {
    "recon": "subdomain dns wayback fingerprint recon crawl",
    "injection": "sqli xss ssti cmdi xxe nosqli injection lfi traversal",
    "auth": "auth jwt oauth saml session idor access control authz bola mfa login",
    "logic": "logic race workflow value parameter ratelimit",
    "infra": "waf cache cors vhost desync smuggling edge backend timing",
    "ssrf": "ssrf gopher metadata protocol callback",
    "report": "finding report export cvss remediation triage sarif",
    "knowledge": "knowledge payload cheat writeup dataset cve playbook",
    "oast": "oast blind callback canary interactsh",
    "run": "run task coverage budget artifact",
}

# Explicit vocabulary, not machine translation. Keep phrases narrow enough to
# avoid conflating requesting authorization with checking access control.
_QUERY_ALIASES = {
    "sql injection": "sqli", "sql-инъекция": "sqli", "sql инъекция": "sqli",
    "sql注入": "sqli", "sql 인젝션": "sqli", "injeção sql": "sqli",
    "sql इंजेक्शन": "sqli", "sql injection testing": "sqli",
    "проверить авторизацию": "authorization check", "проверка авторизации": "authorization check",
    "контроль доступа": "access control authorization", "аутентификация": "authentication",
    "身份验证": "authentication check", "权限检查": "authorization check",
    "访问控制": "access control", "인증 검사": "authentication check",
    "권한 검사": "authorization check", "접근 제어": "access control",
    "verificar autorização": "authorization check", "controle de acesso": "access control",
    "autenticação": "authentication", "प्राधिकरण जांच": "authorization check",
    "प्रमाणीकरण": "authentication", "доступные цели": "scope list",
    "проверить scope": "scope list", "область проверки": "scope list",
    "授权范围": "scope list", "범위 확인": "scope list",
    "verificar escopo": "scope list", "दायरा जांच": "scope list",
    "бюджет запуска": "run budget", "остаток бюджета": "run budget remaining",
    "运行预算": "run budget", "실행 예산": "run budget",
    "orçamento da execução": "run budget", "रन बजट": "run budget",
    "скриншот": "screenshot", "浏览器截图": "browser screenshot",
    "브라우저 스크린샷": "browser screenshot", "captura de tela": "screenshot",
    "स्क्रीनशॉट": "screenshot", "сохранить наблюдение": "flag observation add",
    "гипотеза": "hypothesis", "假设": "hypothesis", "가설": "hypothesis",
    "hipótese": "hypothesis", "परिकल्पना": "hypothesis",
}

_STOP = {"the", "a", "an", "to", "for", "of", "and", "or", "with", "in", "is", "this", "tool", "tools"}
_MUTATIONS = {"add", "remove", "exclude", "clear", "set", "configure", "start", "update", "usage", "record", "create", "delete"}


def _normalize(text: str) -> str:
    return unicodedata.normalize("NFKC", text).casefold()


def _tokens(text: str) -> set[str]:
    # Unicode categories preserve combining marks (essential for Hindi), and
    # split snake_case while keeping the complete identifier as an exact term.
    normalized = _normalize(text)
    words: list[str] = []
    current: list[str] = []
    for char in normalized:
        if unicodedata.category(char)[0] in {"L", "N", "M"}:
            current.append(char)
        elif current:
            words.append("".join(current))
            current = []
    if current:
        words.append("".join(current))
    identifiers = re.findall(r"\b[a-z][a-z0-9]*(?:_[a-z0-9]+)+\b", normalized)
    return {word for word in [*words, *identifiers] if len(word) > 1 and word not in _STOP}


def _query_tokens(query: str) -> set[str]:
    normal = _normalize(query)
    terms = _tokens(normal)
    for phrase, expanded in _QUERY_ALIASES.items():
        cjk_phrase = any("CJK" in unicodedata.name(char, "") for char in phrase)
        for match in re.finditer(re.escape(phrase), normal):
            if not cjk_phrase:
                adjacent = normal[match.start() - 1:match.start()] if match.start() else ""
                adjacent += normal[match.end():match.end() + 1]
                if any(unicodedata.category(char)[0] in {"L", "N", "M"} or char == "_"
                       for char in adjacent):
                    continue
            terms.update(_tokens(expanded))
            break
    return terms


def search(query: str, phase: str = "", available_only: bool = True,
           limit: int = 5) -> dict[str, Any]:
    """Rank cards; known missing dependencies/gates can be filtered.

    Unknown target/role requirements remain visible and explicitly unknown.
    They can only be checked using the eventual invocation arguments.
    """
    specs = toolspec.registry()
    q = _query_tokens((query or "")[:2000])
    phase_terms = _tokens(_PHASES.get(_normalize(phase), phase))
    documents: dict[str, tuple[set[str], set[str], set[str]]] = {
        name: (_tokens(name), _tokens(spec.aliases), _tokens(spec.purpose))
        for name, spec in specs.items()
    }
    df: Counter[str] = Counter()
    for fields in documents.values():
        df.update(set().union(*fields))
    total = max(len(documents), 1)
    avg_length = sum(len(set().union(*fields)) for fields in documents.values()) / total or 1
    ranked: list[tuple[float, str, list[str]]] = []
    for name, spec in specs.items():
        if available_only and spec.availability["status"] == "unavailable":
            continue
        name_terms, aliases, purpose = documents[name]
        all_terms = name_terms | aliases | purpose
        matched = q & all_terms
        phase_matches = phase_terms & all_terms
        if not matched and not phase_matches:
            continue
        # BM25 with field-weighted term frequency. Length normalization uses
        # the short card, preventing long boilerplate from dominating results.
        norm = 1.2 * (0.25 + 0.75 * len(all_terms) / avg_length)
        score = 0.0
        for term in matched:
            freq = 5 * (term in name_terms) + 3 * (term in aliases) + (term in purpose)
            inverse = math.log(1 + (total - df[term] + 0.5) / (df[term] + 0.5))
            score += inverse * freq * 2.2 / (freq + norm)
        score += 0.15 * len(phase_matches)
        reasons = ["matched: " + ", ".join(sorted(matched)[:5])] if matched else []
        if phase_matches:
            reasons.append("phase: " + phase)
        if _normalize(query.strip()) == name:
            score += 100
            reasons.append("exact registered name")
        # Default scope/budget intents are inspection; mutation must be explicit.
        changes = q & _MUTATIONS
        if "scope" in q:
            if name == "scope_list" and not changes:
                score += 12
                reasons.append("inspect scope")
            elif name.startswith("scope_") and changes & name_terms:
                score += 12
                reasons.append("explicit scope change")
        if "budget" in q and "run" in q and name == "run_status" and not changes:
            score += 12
            reasons.append("inspect run budget")
        if (q & {"check", "view", "list", "remaining"}) and name_terms & _MUTATIONS and not changes:
            score *= 0.4
        ranked.append((score, name, reasons))
    ranked.sort(key=lambda item: (-item[0], item[1]))
    cards = [{**specs[name].card(), "reason": "; ".join(reasons)}
             for _, name, reasons in ranked[:max(1, min(limit, 10))]]
    return {
        "query": query, "phase": phase or None, "candidates": cards, "count": len(cards),
        "registry_version": toolspec.registry_version(specs),
        "hint": (
            "Cards only; use tool_describe for the real schema. available_only excludes known "
            "missing dependencies/disabled gates; unknown scope/auth/argument requirements remain. "
            "Rank is not permission and does not reduce client-loaded schemas."
        ) if cards else "No candidates; try a supported domain term or available_only=false to inspect missing prerequisites.",
    }
