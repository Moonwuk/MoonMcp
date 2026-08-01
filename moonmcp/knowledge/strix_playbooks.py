"""Strix-derived security testing playbooks — 51 structured methodology files
extracted from the Strix AI pentesting tool and converted to a searchable
knowledge base for MoonMCP.

Categories:
- vulnerabilities (24): SQLi, XSS, SSRF, RCE, IDOR, CSRF, XXE, SSTI, etc.
- frameworks (4): Next.js, Django, FastAPI, NestJS
- protocols (2): OAuth, GraphQL
- scan_modes (3): quick, standard, deep
- technologies (2): Supabase, Firebase Firestore
- tooling (11): nmap, nuclei, sqlmap, ffuf, httpx, katana, etc.
- cloud (2): AWS, Kubernetes
- coordination (2): root_agent, source_aware_whitebox
- custom (1): source_aware_sast

Each playbook contains:
- Attack surface mapping
- Detection channels (error, boolean, time, OAST)
- DBMS/framework-specific primitives
- Exploitation techniques
- WAF bypass strategies
- Payload examples

Source: https://github.com/usestrix/strix (Apache 2.0)
"""

from __future__ import annotations

from .strix_playbooks_data import PLAYBOOKS, PLAYBOOK_INDEX

__all__ = ["PLAYBOOKS", "PLAYBOOK_INDEX"]