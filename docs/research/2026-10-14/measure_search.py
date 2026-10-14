"""Compare live tool search with an offline identifier-tokenization experiment.

This is a diagnostic sample, not a held-out retrieval benchmark. No network I/O.
"""
import json
import re
import unicodedata
from unittest.mock import patch

from moonmcp import catalog, server, toolsearch

QUERIES = [
    "scope", "check scope", "sql injection", "sqli", "run budget",
    "browser screenshot", "проверить авторизацию", "身份验证", "인증 검사",
    "verificar autorização", "authentication check", "missing playwright",
]


def identifier_tokens(text):
    normalized = unicodedata.normalize("NFKC", text).casefold()
    words = re.findall(r"\w+", normalized)
    return {part for word in words for part in [word, *word.split("_")]
            if len(part) > 1}


tools = server.mcp._tool_manager.list_tools()
schemas = [{"name": t.name, "description": t.description or "",
            "inputSchema": t.parameters} for t in tools]


def queries():
    return {q: [c["name"] for c in toolsearch.search(q)["candidates"]] for q in QUERIES}


result = {"tools": len(tools),
          "schema_bytes_utf8": len(json.dumps(schemas, ensure_ascii=False).encode("utf-8")),
          "schema_measurement": "JSON array of name/description/inputSchema, ensure_ascii=False",
          "profile_counts": {p: len(catalog.select_profile({t.name for t in tools}, profile=p))
                             for p in ("full", "strix", "passive", "knowledge", "recon")},
          "queries": queries()}
with patch.object(toolsearch, "_tokens", identifier_tokens):
    result["identifier_tokenization_experiment"] = queries()
print(json.dumps(result, ensure_ascii=False, indent=2))
