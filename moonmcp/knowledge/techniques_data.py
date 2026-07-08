"""Techniques & notable-PoC catalog — structured data.

A REFERENCED catalog for authorised security research: each entry describes a
technique or landmark vulnerability conceptually and links to the public PoC /
research.  It intentionally contains NO weaponized exploit code or shellcode.

Fields: id, name, category, languages[], severity, summary, technique,
affected_context, detection_indicators[], cve[], poc_references[],
research_references[].

Categories: web | deserialization | memory-corruption | famous-cve |
language-specific | kernel-lowlevel.

This is the seed set; it is expanded from authoritative public sources
(PortSwigger, OWASP, HackTricks, PayloadsAllTheThings, ExploitDB, Phrack,
Project Zero, how2heap, vendor advisories).
"""

from __future__ import annotations

TECHNIQUES: list[dict] = [
    {
        "id": "log4shell",
        "name": "Log4Shell (Log4j JNDI RCE)",
        "category": "famous-cve",
        "languages": ["java"],
        "severity": "critical",
        "summary": "A crafted string logged by Apache Log4j 2 triggers a JNDI lookup that loads a remote class, yielding RCE.",
        "technique": "User-controlled data reaches a logging call; Log4j's message-lookup evaluates ${jndi:ldap://…}, causing the JVM to fetch and deserialize a remote object.",
        "affected_context": "Apache Log4j 2.0-beta9 to 2.14.1; any field that gets logged (User-Agent, headers, form fields).",
        "detection_indicators": ["${jndi:ldap://", "${jndi:rmi://", "${${lower:j}ndi:", "outbound LDAP/RMI to attacker host", "log4j 2.x in dependency manifests"],
        "cve": ["CVE-2021-44228", "CVE-2021-45046"],
        "poc_references": ["https://github.com/christophetd/log4shell-vulnerable-app"],
        "research_references": ["https://www.lunasec.io/docs/blog/log4j-zero-day/",
                                 "https://nvd.nist.gov/vuln/detail/CVE-2021-44228"],
    },
    {
        "id": "java-deser-cc",
        "name": "Java Deserialization (Commons-Collections gadget)",
        "category": "deserialization",
        "languages": ["java"],
        "severity": "critical",
        "summary": "Deserializing attacker-controlled Java objects triggers a gadget chain (e.g. Commons-Collections) that reaches Runtime.exec.",
        "technique": "readObject on untrusted data instantiates gadget classes whose side effects chain into code execution; ysoserial generates the payloads.",
        "affected_context": "Endpoints accepting serialized Java objects (RMI, JMX, HTTP body, T3, ViewState).",
        "detection_indicators": ["base64 starting with rO0AB", "hex AC ED 00 05 (serialized stream magic)", "Content-Type application/x-java-serialized-object"],
        "cve": [],
        "poc_references": ["https://github.com/frohoff/ysoserial"],
        "research_references": ["https://foxglovesecurity.com/2015/11/06/what-do-weblogic-websphere-jboss-jenkins-opennms-and-your-application-have-in-common-this-vulnerability/"],
    },
    {
        "id": "http-request-smuggling",
        "name": "HTTP Request Smuggling (CL.TE / TE.CL)",
        "category": "web",
        "languages": ["protocol"],
        "severity": "high",
        "summary": "Front-end and back-end servers disagree on request boundaries (Content-Length vs Transfer-Encoding), letting an attacker prepend a request to another user's.",
        "technique": "Ambiguous framing (both CL and TE, or obfuscated TE) is parsed differently by two hops, desynchronising the connection.",
        "affected_context": "Chained HTTP/1.1 proxies/load-balancers; HTTP/2 downgrade (H2.CL/H2.TE).",
        "detection_indicators": ["differential handling of duplicate/obfuscated Transfer-Encoding", "timing differences on crafted framing", "unexpected responses to a following request"],
        "cve": [],
        "poc_references": ["https://github.com/PortSwigger/http-request-smuggler"],
        "research_references": ["https://portswigger.net/research/http-desync-attacks-request-smuggling-reborn",
                                 "https://portswigger.net/web-security/request-smuggling"],
    },
    {
        "id": "stack-buffer-overflow-rop",
        "name": "Stack Buffer Overflow → ROP",
        "category": "memory-corruption",
        "languages": ["c", "c++", "asm-x86", "asm-x64"],
        "severity": "critical",
        "summary": "Overflowing a stack buffer overwrites the saved return address; with NX enabled, execution is redirected through a chain of existing code gadgets (ROP).",
        "technique": "Conceptually: control EIP/RIP via the overwrite, then chain `ret`-terminated gadgets to set up a syscall/library call (e.g. ret2libc) — mitigations (canary, ASLR, NX, PIE) must be leaked/bypassed.",
        "affected_context": "Native binaries using unbounded copies (strcpy/gets/memcpy) on stack buffers.",
        "detection_indicators": ["SIGSEGV with controlled instruction pointer", "missing stack canary / NX / PIE (checksec)", "crash on long input"],
        "cve": [],
        "poc_references": ["https://github.com/shellphish/how2heap", "https://github.com/guyinatuxedo/nightmare"],
        "research_references": ["http://phrack.org/issues/58/4.html",
                                 "https://ctf101.org/binary-exploitation/return-oriented-programming/"],
    },
    {
        "id": "ssti-jinja2-rce",
        "name": "Server-Side Template Injection → RCE (Jinja2)",
        "category": "language-specific",
        "languages": ["python"],
        "severity": "critical",
        "summary": "User input rendered as a Jinja2 template escapes the sandbox via Python object introspection to reach os-level command execution.",
        "technique": "From an evaluated {{ }} context, walk __class__/__mro__/__subclasses__ to a class exposing os/subprocess — the classic SSTI-to-RCE pivot.",
        "affected_context": "Flask/Jinja2 apps that render user input as template source.",
        "detection_indicators": ["{{7*7}} → 49", "{{7*'7'}} → 7777777 (Jinja2/Python)", "TemplateSyntaxError in responses"],
        "cve": [],
        "poc_references": ["https://github.com/swisskyrepo/PayloadsAllTheThings/tree/master/Server%20Side%20Template%20Injection"],
        "research_references": ["https://portswigger.net/research/server-side-template-injection"],
    },
    {
        "id": "dependency-confusion",
        "name": "Dependency Confusion (supply chain)",
        "category": "kernel-lowlevel",
        "languages": ["javascript", "python", "ruby", "java"],
        "severity": "high",
        "summary": "Publishing a public package with the same name as an org's private one and a higher version tricks build tooling into fetching the attacker's package.",
        "technique": "Package managers that merge public+private indexes may prefer the higher public version, executing attacker code at install time.",
        "affected_context": "npm/pip/gem/maven builds resolving internal package names against public registries.",
        "detection_indicators": ["internal package names leaked in JS bundles / lockfiles", "build resolving names not on the public registry"],
        "cve": [],
        "poc_references": [],
        "research_references": ["https://medium.com/@alex.birsan/dependency-confusion-4a5d60fec610"],
    },
]
