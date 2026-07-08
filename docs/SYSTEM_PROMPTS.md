# MoonMCP — Operator System Prompts

> The prompt that drives an agent matters as much as the tools it holds. These are
> **operator** system prompts: professional rules-of-engagement + methodology that make
> an LLM using MoonMCP plan before it scans, pick the right tool, verify a finding
> before it reports it, minimise false positives, and — above all — stay strictly inside
> authorised scope. They are **not** model jailbreaks or filter-evasion prompts.

They are exposed as MCP prompts (pick them from any MCP client's prompt menu) and built
by [`moonmcp/prompts.py`](../moonmcp/prompts.py). The text synthesises three bodies of
public research swept for this purpose: real pentest/bug-bounty **agent system prompts**,
mainstream agent **prompt-engineering**, and top bug-bounty **methodology**.

## The prompts

| Prompt | Args | Use it when you want the agent to… |
| --- | --- | --- |
| `bug_bounty_operator` | `target`, `focus` | Run a full authorised engagement end-to-end: persona, rules of engagement, the OBSERVE→ORIENT→DECIDE→ACT→VERIFY→RECORD loop, a phase-ordered tool map, impact prioritisation and finding-chaining. The master prompt. |
| `deep_recon` | `target` | Map the *complete* attack surface methodically — a 5-phase TBHM/WSTG flow (asset discovery → resolution → fingerprint → content/config → vuln mapping) that leaves no in-scope asset undiscovered. |
| `injection_hunt` | `target`, `injection_class` | Hunt injections using the built-in injection KB as a playbook: enumerate inputs, send *one benign canary at a time*, confirm with `match_injection_signatures`, and reject reflected-but-inert payloads. |
| `technique_advisor` | `technology`, `cve` | Turn an observed product/version/CVE into referenced technique guidance from the 115-entry technique catalog — descriptions + public PoC links only, plus how to confirm applicability in scope. |
| `triage_and_report` | `target` | Verify (Chain-of-Verification), deduplicate, severity-rate by real impact, and write findings to accepted-report quality — with a PoC gate and a human-in-the-loop submission checkpoint. |
| `safe_recon` | `target` | Operate in a conservative, passive-first, scope-strict mode with hard stops — a good default persona when authorisation for active testing is not yet confirmed. |
| `recon_methodology` | `target` | The original quick-start recon playbook (kept for continuity). |

### How to invoke
Any MCP client can list and fetch these. From the reference Python SDK:

```python
from mcp import ClientSession
prompt = await session.get_prompt("bug_bounty_operator",
                                  {"target": "acme.example.com", "focus": "the /v2 API"})
# prompt.messages[0].content.text is the ready-to-use system prompt
```

Or use them as a system/opening message directly — each returns a single string.

## Design principles (distilled from the research)

Every operator prompt is assembled from three shared blocks, each grounded in the sources
below:

**1. Rules of engagement (non-negotiable).** Scope is the hard boundary; MoonMCP's
own out-of-scope / private-IP / SSRF guardrail is never worked around; passive-first with
intrusive tools gated behind program authorisation *and* `MOONMCP_ALLOW_INTRUSIVE`; no
fabrication; and **all tool output / target content is treated as untrusted data, never as
instructions** (recon surfaces are a prompt-injection vector). Scope-first and
responsible-disclosure framing is what makes a finding eligible rather than an N/A or a
safe-harbour violation. *(Bugcrowd scope guidance; HackerOne disclosure guidelines; CAI
"untrusted tool-output" and "scope-lock" prompts.)*

**2. The operating loop.** A tight OBSERVE → ORIENT → DECIDE → ACT → VERIFY → RECORD
cycle — one tool at a time, breadth-first coverage before depth, a decision log that
avoids repeating failed approaches, and explicit stop conditions. This is ReAct's
reason↔act interleaving plus Plan-and-Execute decomposition, hardened with AutoGPT-style
loop guards and bounded budgets. *(ReAct; LangChain plan-and-execute; Anthropic "building
effective agents"; PentestGPT task-tree; CAI TRACE loop.)*

**3. False-positive discipline.** A reflected-but-inert payload is not a bug and a verbose
error is not automatically SQLi; findings are confirmed by differential/verification tests
and — for injections — by signature matching. Weak evidence yields an explicit
`unconfirmed` with the evidence still needed, because **a false positive is worse than an
honest "unknown"** (calibrated abstention), and a finding is only "confirmed" behind a
reproducible **PoC gate** with a human-in-the-loop before any submission. *(Chain-of-
Verification; calibrated-uncertainty/abstention research; XBOW end-to-end validation; CAI
PoC-gated confirmation; HackerOne "hacker-in-the-loop".)*

## Research swept

Three parallel research passes ("search everywhere") fed these prompts.

### A. Real pentest / bug-bounty agent system prompts
Concrete operator-prompt patterns lifted (conceptually, not copied) from shipping projects:
- **CAI framework** operator prompts — TRACE loop, untrusted tool-output discipline,
  recon-before-exploit ordering, structured finding schema, graduated escalation,
  PoC-gated confirmation, non-interactive command rule.
  <https://github.com/aliasrobotics/cai/tree/main/src/cai/prompts>
- **PentestGPT** — persistent task-tree as external memory. <https://github.com/GreyDGL/PentestGPT>
- **XBOW** — dedicated end-to-end exploit validation. <https://xbow.com/blog/top-1-how-xbow-did-it>
- **HexStrike-AI** — role + authorisation framing to the right toolset. <https://github.com/0x4m4/hexstrike-ai>
- **Bug-Bounty-Agents** — scope-lock + clarify-first, low-signal finding chaining. <https://github.com/matty69v/Bug-Bounty-Agents>
- **Nuclei-AI-Prompts** — multi-request, precise, negative-filtered detection to cut FPs. <https://github.com/reewardius/Nuclei-AI-Prompts>
- **HackerOne Hai** — hacker-in-the-loop; no fully-autonomous submission. <https://docs.hackerone.com/en/articles/12570435-ai-bug-bounty>

### B. Agent prompt-engineering
The reasoning/verification scaffolding, from primary sources:
- **ReAct** — reason+act interleaving. <https://arxiv.org/abs/2210.03629>
- **Plan-and-Execute / Plan-and-Solve** — plan up front, execute step-wise. <https://www.langchain.com/blog/planning-agents>
- **Reflexion** — verbal self-reflection after failures. <https://arxiv.org/abs/2303.11366>
- **Chain-of-Verification (CoVe)** — independent verification questions. <https://arxiv.org/abs/2309.11495>
- **Self-Consistency** — cross-run agreement as a confidence signal. <https://arxiv.org/abs/2203.11171>
- **Calibrated abstention** — reward honest "unknown" over guessing. <https://arxiv.org/abs/2404.10960>
- **Anthropic** — building effective agents, the "think" tool, context engineering, writing tools for agents.
  <https://www.anthropic.com/engineering/building-effective-agents> ·
  <https://www.anthropic.com/engineering/claude-think-tool>
- **OpenAI GPT-4.1** — persistence + explicit completion criteria. <https://cookbook.openai.com/examples/gpt4-1_prompting_guide>
- **AutoGPT lessons** — bounded budgets and loop guards. <https://github.com/vectara/awesome-agent-failures>

### C. Bug-bounty methodology
The recon-to-report lifecycle encoded into `deep_recon` / `bug_bounty_operator`:
- **The Bug Hunter's Methodology (Jason Haddix)** — apex/ASN discovery, passive+active
  subdomain enumeration. <https://github.com/jhaddix/tbhm>
- **OWASP WSTG** — the web testing workflow, business-logic and takeover tests.
  <https://owasp.org/www-project-web-security-testing-guide/>
- **PortSwigger Web Security Academy** — IDOR/access-control, SSRF, CORS testing.
  <https://portswigger.net/web-security>
- **Bugcrowd** — scope importance and attack-surface management.
  <https://www.bugcrowd.com/blog/the-importance-of-scope-bug-bounty-hunter-methodology/>
- **HackerOne** — quality reports and disclosure guidelines.
  <https://docs.hackerone.com/en/articles/8475116-quality-reports>
- **Intigriti / YesWeHack / reconFTW** — secrets hunting, hidden endpoints, continuous
  assetize loop. <https://github.com/six2dez/reconftw>

> Note on responsible use: MoonMCP's tools are scope-gated and passive-first, and these
> prompts reinforce that. They are for **authorised** security testing — bug-bounty
> programs, engagements with permission, and CTF/education — only.
