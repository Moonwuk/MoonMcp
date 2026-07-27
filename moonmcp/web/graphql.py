"""GraphQL endpoint discovery and introspection check.

Probes the common GraphQL paths, confirms which respond like a GraphQL server,
and tests whether schema **introspection** is enabled (a frequent bug-bounty
finding, since it leaks the full API surface).
"""

from __future__ import annotations

import json
from dataclasses import dataclass, field
from urllib.parse import urljoin

from ..net.http import HttpClient

COMMON_PATHS = [
    "/graphql", "/api/graphql", "/v1/graphql", "/v2/graphql", "/graphql/v1",
    "/query", "/gql", "/api/gql", "/graphql.php", "/index.php?graphql",
    "/graphiql", "/graphql/console", "/api", "/api/v1/graphql",
]

_TYPENAME_QUERY = json.dumps({"query": "{__typename}"})
_INTROSPECTION_QUERY = json.dumps(
    {"query": "query{__schema{queryType{name} types{name kind}}}"}
)


@dataclass
class GraphQLEndpoint:
    url: str
    is_graphql: bool
    introspection_enabled: bool = False
    type_count: int = 0
    query_type: str | None = None
    detail: str = ""


@dataclass
class GraphQLResult:
    base_url: str
    endpoints: list[GraphQLEndpoint] = field(default_factory=list)

    @property
    def found(self) -> bool:
        return any(e.is_graphql for e in self.endpoints)


async def _test_endpoint(client: HttpClient, url: str, scope_check) -> GraphQLEndpoint | None:
    r = await client.fetch(
        url, method="POST", headers={"Content-Type": "application/json"},
        body=_TYPENAME_QUERY.encode(), follow_redirects=False, timeout=12.0, scope_check=scope_check,
    )
    if r.status is None:
        return None
    body = r.text(limit=20_000)
    ctype = (r.header("Content-Type") or "").lower()
    # Require a STRUCTURAL signal — a bare "GraphQL" substring matches any page
    # that merely mentions the word in prose (docs, error text, marketing).
    looks_graphql = (
        '"__typename"' in body
        or '"data"' in body and '"errors"' in body
        or "Must provide query string" in body
        or ("json" in ctype and ('"data"' in body or '"errors"' in body))
    )
    if not looks_graphql:
        return None
    ep = GraphQLEndpoint(url=url, is_graphql=True, detail="responds to GraphQL query")

    intro = await client.fetch(
        url, method="POST", headers={"Content-Type": "application/json"},
        body=_INTROSPECTION_QUERY.encode(), follow_redirects=False, timeout=12.0, scope_check=scope_check,
    )
    if intro.status is not None:
        try:
            data = json.loads(intro.text(limit=200_000))
            schema = (data.get("data") or {}).get("__schema")
            if schema:
                ep.introspection_enabled = True
                ep.type_count = len(schema.get("types") or [])
                ep.query_type = (schema.get("queryType") or {}).get("name")
                ep.detail = f"introspection ENABLED — {ep.type_count} types exposed"
        except (json.JSONDecodeError, ValueError, AttributeError):
            pass
    return ep


async def discover_graphql(
    client: HttpClient, base_url: str, *, scope_check=None
) -> GraphQLResult:
    result = GraphQLResult(base_url=base_url)
    for path in COMMON_PATHS:
        url = urljoin(base_url, path)
        try:
            ep = await _test_endpoint(client, url, scope_check)
        except Exception:
            ep = None
        if ep:
            result.endpoints.append(ep)
    return result
