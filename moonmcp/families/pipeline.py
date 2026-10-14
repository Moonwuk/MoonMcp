"""Pipeline tool family. Public signatures and payloads remain compatible."""

from __future__ import annotations

from collections.abc import Callable
from typing import Any

from .. import pipeline as pipe
from . import local_registration


def register(mcp: Any, safe_tool: Callable) -> dict[str, Callable]:
    """Bind tools to this server; imports do not register or create context."""
    exported: dict[str, Callable] = {}
    local = local_registration(mcp, safe_tool, exported, structured_output=False)

    @local
    async def queue_task(text: str, target: str = "") -> str:
        """Поставить задачу в очередь для Hermes-агента (обработает processor.py).
        Опционально: target — имя таргета из targets.yaml для авто-подстановки headers."""
        return pipe.queue_task(text, target=target or None)

    @local
    async def list_queue() -> str:
        """Показать текущие задачи в очереди Hermes (ожидающие обработки)."""
        return pipe.list_queue()

    @local
    async def search_bugbounty_reports(vuln_type: str, limit: int = 10) -> str:
        """Поиск по локальной базе реальных публичных bug bounty отчётов (HackerOne,
        28 категорий уязвимостей). Используй для калибровки: как выглядят реальные
        принятые репорты данного типа, какие формулировки impact работают."""
        return pipe.search_bugbounty_reports(vuln_type, limit=limit)

    @local
    async def list_report_categories() -> str:
        """Список всех доступных категорий уязвимостей в базе репортов."""
        return pipe.list_report_categories()

    @local
    async def search_knowledge_base(source: str, keyword: str, limit: int = 20) -> str:
        """Полнотекстовый поиск по локальной базе знаний: waf_bypass, payloads
        (PayloadsAllTheThings), business_logic, writeups, chained_writeups,
        creative_writeups, enumeration_methodology, src_hunter_cn, hacktricks,
        ssrf_cloud_metadata, graphql_security, owasp_cheatsheets, secret_patterns,
        zero_trust, kernel_exploitation. Возвращает file:line: text-совпадения."""
        return pipe.search_knowledge_base(source, keyword, limit=limit)

    @local
    async def search_datasets(dataset: str, query: str, limit: int = 5,
                              full_answer: bool = False) -> str:
        """FTS5-поиск по датасетам airecon: bug_bounty_pentest (методология BB:
        exploitation steps, payload examples, WAF bypass, report templates),
        web_vuln_patterns (HTTP-индикаторы XSS/SQLi/SSTI/SSRF/LFI/RCE + validation
        steps), nuclei_templates (canonical CVE records + готовые DAST шаблоны,
        23k CVE)."""
        return pipe.search_datasets(dataset, query, limit=limit,
                                               full_answer=full_answer)

    @local
    async def get_target(name: str) -> str:
        """Получить конфигурацию таргета (base_url, headers с подставленными
        env-переменными, scope) из targets.yaml."""
        return pipe.get_target(name)

    @local
    async def list_targets() -> str:
        """Список всех настроенных таргетов из targets.yaml."""
        return pipe.list_targets()

    @local
    async def match_signature_to_cve(technology: str, min_severity: str = "",
                                     limit: int = 15) -> str:
        """По названию технологии/стека (nginx, wordpress, bitrix...) находит
        релевантные CVE и detection-сигнатуры из индекса nuclei-templates (9430+
        шаблонов, web-relevant категории). Возвращает только совпадения."""
        return pipe.match_signature_to_cve(
            technology, min_severity=min_severity or None, limit=limit)

    @local
    async def get_nuclei_template(template_id: str) -> str:
        """Получить полное содержимое nuclei-шаблона по его id (например
        CVE-2021-44228) для детального изучения PoC/matcher-логики."""
        return pipe.get_nuclei_template(template_id)

    @local
    async def search_web_security_resources(category: str, keyword: str = "",
                                            difficulty: str = "", language: str = "",
                                            type: str = "", limit: int = 15) -> str:
        """Структурированный поиск по каталогу 524 курируемых web security ресурсов
        (100 категорий). Фильтры: difficulty (intro/intermediate/advanced), language
        (en/zh/jp), type. Каждая запись содержит archive_url как fallback."""
        return pipe.search_web_security_resources(
            category, keyword=keyword or None, difficulty=difficulty or None,
            language=language or None, type_=type or None, limit=limit)

    @local
    async def list_web_security_categories() -> str:
        """Список всех 100 категорий каталога web security ресурсов."""
        return pipe.list_web_security_categories()

    @local
    async def check_subdomain_takeover(service: str) -> str:
        """Проверяет CNAME-цель или сервис по базе can-i-take-over-xyz (76 сервисов)
        — возвращает fingerprint и статус (Vulnerable/Not vulnerable/Edge case)."""
        return pipe.check_subdomain_takeover(service)

    return exported
