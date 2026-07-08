"""Privilege-escalation knowledge base — structured data.

A REFERENCED catalog for authorised security research: privilege-escalation
techniques across Linux / Windows / container / cloud / Active Directory, plus a
catalog of the tooling used to find and exploit them.  Conceptual descriptions,
benign enumeration commands, detection indicators and links to public research —
NO weaponized exploit code.

Technique fields: id, name, platform, category, severity, summary, technique,
prerequisites[], enumeration[], detection_indicators[], tools[], cve[],
mitigation[], poc_references[], research_references[].
Tool fields: id, name, platform, category, summary, usage_note, language, url.

Platforms: linux | windows | container | cloud | active-directory | macos |
cross-platform.  This is the seed set; it is expanded from authoritative public
sources (HackTricks, GTFOBins, LOLBAS, PayloadsAllTheThings, PEASS-ng, the
Exploit-DB, vendor advisories and NVD).
"""

from __future__ import annotations

PRIVESC: list[dict] = [
    {
        "id": "linux-sudo-nopasswd-gtfobins",
        "name": "Sudo NOPASSWD / abusable binary (GTFOBins)",
        "platform": "linux",
        "category": "sudo",
        "severity": "high",
        "summary": "A user allowed to run a binary via sudo (often NOPASSWD) can abuse that binary's features to spawn a root shell or read/write arbitrary files.",
        "technique": "`sudo -l` reveals permitted commands; if any has a GTFOBins escape (shell-out, file read/write, command exec) it runs with the elevated privilege, yielding root.",
        "prerequisites": ["a sudo rule granting a GTFOBins-abusable binary"],
        "enumeration": ["sudo -l", "sudo -l -l"],
        "detection_indicators": ["NOPASSWD", "(ALL : ALL) ALL", "env_keep", "!authenticate"],
        "tools": ["gtfobins", "linpeas", "sudo-killer"],
        "cve": [],
        "mitigation": ["Grant sudo only to non-abusable binaries", "Avoid NOPASSWD", "Use Defaults!command noexec"],
        "poc_references": ["https://gtfobins.github.io/"],
        "research_references": ["https://book.hacktricks.xyz/linux-hardening/privilege-escalation#sudo-and-suid"],
    },
    {
        "id": "linux-capabilities-setuid",
        "name": "Linux capabilities (cap_setuid / cap_dac_read_search)",
        "platform": "linux",
        "category": "capabilities",
        "severity": "high",
        "summary": "A binary with a powerful file capability (e.g. cap_setuid+ep) can change its UID to 0 or read protected files without being SUID-root.",
        "technique": "`getcap -r /` finds capability-endowed binaries; interpreters with cap_setuid can setuid(0) then exec a shell; cap_dac_read_search bypasses read permission checks.",
        "prerequisites": ["a binary with an abusable file capability"],
        "enumeration": ["getcap -r / 2>/dev/null", "/usr/sbin/getpcaps $$"],
        "detection_indicators": ["cap_setuid", "cap_dac_read_search", "cap_dac_override", "cap_sys_admin", "=ep"],
        "tools": ["gtfobins", "linpeas"],
        "cve": [],
        "mitigation": ["Remove unnecessary file capabilities", "Prefer least-privilege capability sets"],
        "poc_references": ["https://gtfobins.github.io/#+capabilities"],
        "research_references": ["https://book.hacktricks.xyz/linux-hardening/privilege-escalation#capabilities"],
    },
    {
        "id": "container-docker-socket",
        "name": "Mounted Docker socket container escape",
        "platform": "container",
        "category": "container-escape",
        "severity": "critical",
        "summary": "Access to /var/run/docker.sock (or membership of the docker group) is root-equivalent: it lets you start a container that mounts the host filesystem.",
        "technique": "The Docker API on the socket can launch a privileged container bind-mounting the host root, giving full read/write on the host and thus root.",
        "prerequisites": ["readable/writable docker.sock or docker group membership"],
        "enumeration": ["id", "ls -la /var/run/docker.sock", "docker ps"],
        "detection_indicators": ["docker.sock", "docker", "/var/run/docker.sock"],
        "tools": ["linpeas", "deepce", "cdk"],
        "cve": [],
        "mitigation": ["Never expose docker.sock to untrusted workloads", "Restrict docker group membership"],
        "poc_references": ["https://book.hacktricks.xyz/linux-hardening/privilege-escalation/docker-security"],
        "research_references": ["https://docs.docker.com/engine/security/"],
    },
    {
        "id": "windows-seimpersonate-potato",
        "name": "SeImpersonatePrivilege potato attack",
        "platform": "windows",
        "category": "token-impersonation",
        "severity": "high",
        "summary": "A service account holding SeImpersonatePrivilege can coerce a SYSTEM token via a named-pipe/RPC trick and impersonate it (the 'potato' family).",
        "technique": "Tools like PrintSpoofer/RoguePotato/GodPotato coerce a privileged authentication to a named pipe, then impersonate the resulting SYSTEM token to run code as SYSTEM.",
        "prerequisites": ["SeImpersonatePrivilege or SeAssignPrimaryTokenPrivilege"],
        "enumeration": ["whoami /priv", "whoami /all"],
        "detection_indicators": ["SeImpersonatePrivilege", "SeAssignPrimaryTokenPrivilege", "Enabled"],
        "tools": ["printspoofer", "godpotato", "juicypotato", "roguepotato"],
        "cve": [],
        "mitigation": ["Remove SeImpersonate from non-essential service accounts", "Patch and isolate service hosts"],
        "poc_references": ["https://github.com/itm4n/PrintSpoofer"],
        "research_references": ["https://book.hacktricks.xyz/windows-hardening/windows-local-privilege-escalation/privilege-escalation-abusing-tokens"],
    },
    {
        "id": "windows-unquoted-service-path",
        "name": "Unquoted service path",
        "platform": "windows",
        "category": "service-misconfig",
        "severity": "high",
        "summary": "A service whose ImagePath contains spaces and is unquoted lets an attacker who can write to an earlier path segment plant a binary Windows will execute as the service account.",
        "technique": "Windows resolves `C:\\Program Files\\...` ambiguously; a writable `C:\\Program.exe` runs first, as the (often SYSTEM) service account, on service start.",
        "prerequisites": ["an unquoted service path with a writable parent directory", "ability to (re)start the service"],
        "enumeration": ["wmic service get name,pathname,startmode", "sc qc <service>"],
        "detection_indicators": ["unquoted", "BINARY_PATH_NAME", "AUTO_START"],
        "tools": ["powerup", "winpeas", "sharpup"],
        "cve": [],
        "mitigation": ["Quote all service ImagePaths", "Restrict write access to service directories"],
        "poc_references": ["https://book.hacktricks.xyz/windows-hardening/windows-local-privilege-escalation#unquoted-service-paths"],
        "research_references": ["https://lolbas-project.github.io/"],
    },
]

PRIVESC_TOOLS: list[dict] = [
    {
        "id": "linpeas",
        "name": "LinPEAS (PEASS-ng)",
        "platform": "linux",
        "category": "enumeration",
        "summary": "The de-facto Linux privilege-escalation enumeration script: colour-coded checks for SUID/SGID, sudo, capabilities, cron, writable files, kernel version and much more.",
        "usage_note": "Run on the target and read the red/yellow highlights first; pairs with linux-exploit-suggester for kernel CVEs.",
        "language": "shell",
        "url": "https://github.com/peass-ng/PEASS-ng",
    },
    {
        "id": "winpeas",
        "name": "WinPEAS (PEASS-ng)",
        "platform": "windows",
        "category": "enumeration",
        "summary": "Windows counterpart of LinPEAS: enumerates services, registry, tokens/privileges, credentials, scheduled tasks and installer misconfig.",
        "usage_note": "Run the .exe/.bat as the low-priv user; review the privilege and service-misconfig sections.",
        "language": "csharp",
        "url": "https://github.com/peass-ng/PEASS-ng",
    },
    {
        "id": "gtfobins",
        "name": "GTFOBins",
        "platform": "linux",
        "category": "reference-db",
        "summary": "A curated reference of Unix binaries that can be abused (via sudo, SUID, capabilities, etc.) to break out restricted environments or escalate privileges.",
        "usage_note": "Look up any binary you can run as root/SUID for a documented escape.",
        "language": "reference",
        "url": "https://gtfobins.github.io/",
    },
    {
        "id": "lolbas",
        "name": "LOLBAS",
        "platform": "windows",
        "category": "reference-db",
        "summary": "Living Off The Land Binaries, Scripts and Libraries: signed Windows binaries abusable for execution, download, and privilege/UAC bypass.",
        "usage_note": "Find a trusted Windows binary that performs the action you need to blend in / escalate.",
        "language": "reference",
        "url": "https://lolbas-project.github.io/",
    },
]
