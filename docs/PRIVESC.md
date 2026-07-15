# MoonMCP — Privilege-Escalation Knowledge Base

> Everything about local **privilege escalation** — across Linux, Windows, containers,
> cloud and Active Directory — plus a catalog of the **tooling** operators use to find
> and exploit it. A *referenced* catalog: conceptual descriptions, benign enumeration
> commands, detection indicators and links to public research — **no** weaponized code.


**129 techniques** across **6 platforms** and **68 tools**. Behind the `privesc_info` (`query=` to search) /
`privesc_tools` tools, the `privesc://all` resource, and — most usefully —
`match_privesc`, which scans pasted enumeration output (`sudo -l`, `id`, a SUID
listing, `getcap -r /`, `whoami /priv`, `systeminfo`) and tells you which escalation
vectors it indicates. Compiled from HackTricks, GTFOBins, LOLBAS, PayloadsAllTheThings,
PEASS-ng, Exploit-DB and vendor advisories / NVD.


## Platforms

| Platform | Techniques |
| --- | --: |
| Linux | 44 |
| Windows | 45 |
| Container / Kubernetes | 5 |
| Cloud (AWS / Azure / GCP) | 4 |
| Active Directory | 28 |
| macOS | 3 |


## Linux privilege escalation

### Linux file capabilities abuse (cap_setuid, cap_dac_read_search, cap_sys_admin, ...)
*id:* `linux-file-capabilities-abuse` · *category:* `capabilities` · *severity:* **critical**

File capabilities grant a binary a subset of root's powers without the SUID bit. Powerful capabilities on interpreters or tools (especially cap_setuid, cap_dac_read_search/override, cap_sys_admin, cap_sys_module, cap_sys_ptrace, cap_chown) allow full privilege escalation.

**How it works —** Capabilities split root into discrete privileges (see capabilities(7)) that can be attached to a file's effective/permitted sets. cap_setuid on an interpreter (python, perl, ruby) lets a program call setuid(0) and become root. cap_dac_read_search bypasses file read permission checks (read /etc/shadow, any file); cap_dac_override bypasses read/write/execute checks entirely. cap_chown lets an attacker re-own sensitive files. cap_sys_ptrace permits injecting into a root process; cap_sys_module permits loading a kernel module; cap_sys_admin is near-root. GTFOBins documents the exact invocation for capability-enabled binaries.

**Prerequisites:** A binary with a dangerous capability in its effective/permitted set; For cap_setuid: an interpreter or tool that can call the setuid syscall

**Enumerate:**
- `getcap -r / 2>/dev/null`
- `/usr/sbin/getcap -r / 2>/dev/null`
- `capsh --print   # capabilities of the current shell`
- `for f in $(getcap -r / 2>/dev/null | cut -d' ' -f1); do ls -la "$f"; done`

**Detection indicators:** `'cap_setuid' in getcap output on python/perl/ruby/php/node or other executables`, `'cap_dac_read_search' or 'cap_dac_override' on any binary`, `'cap_sys_admin', 'cap_sys_module', 'cap_sys_ptrace', 'cap_chown', 'cap_setgid' on non-standard binaries`, `Capability set ending in '+ep' or '+ei' on user-accessible tools`, `cap_setuid`

**Tools:** getcap, capsh, gtfobins, linpeas, linux-smart-enumeration

**Mitigation:** Remove unnecessary capabilities (setcap -r <file>); Never grant cap_setuid/cap_dac_*/cap_sys_admin to interpreters or user-runnable tools; Baseline getcap output and alert on additions; Mount user filesystems nosuid (also strips file capabilities)

**References:** [link](https://gtfobins.github.io/#+capabilities) · [link](https://gtfobins.github.io/gtfobins/python/#capabilities) · [link](https://man7.org/linux/man-pages/man7/capabilities.7.html) · [link](https://book.hacktricks.wiki/en/linux-hardening/privilege-escalation/linux-capabilities.html)

### docker group / Docker socket membership
*id:* `linux-docker-group-socket` · *category:* `container-escape` · *severity:* **critical**

Membership in the docker group (or write access to /var/run/docker.sock) is root-equivalent: the user can start a container that bind-mounts the host filesystem and read/write it as root, or run a privileged container to escape to the host.

**How it works —** The Docker daemon runs as root and exposes a control socket to the docker group. A group member can launch a container mounting the host root filesystem (e.g. '-v /:/host') and, from inside as root, read/modify any host file — dropping a SUID binary, editing /etc/passwd or sudoers, or reading /etc/shadow. Alternatively '--privileged' / '--pid=host' containers permit direct host escape. Access to the socket via HTTP (or a mounted docker.sock inside another container) grants the same power. GTFOBins documents the container-launch primitive.

**Prerequisites:** Membership in the docker group, or read/write access to the Docker API socket; Ability to pull or reference a container image (or use an existing one)

**Enumerate:**
- `id; groups   # look for 'docker'`
- `ls -la /var/run/docker.sock 2>/dev/null`
- `docker ps 2>/dev/null; docker images 2>/dev/null`
- `getent group docker`

**Detection indicators:** `Current user in the 'docker' group (id/groups output)`, `/var/run/docker.sock writable by group/other`, `docker CLI usable without sudo`, `A container with /var/run/docker.sock bind-mounted inside it`

**Tools:** docker, gtfobins, deepce, cdk, linpeas

**Mitigation:** Treat docker group membership as equivalent to root; grant sparingly; Use rootless Docker or Podman where possible; Protect the daemon socket; never bind-mount docker.sock into untrusted containers

**References:** [link](https://gtfobins.github.io/gtfobins/docker/#shell) · [link](https://book.hacktricks.wiki/en/linux-hardening/privilege-escalation/docker-security/index.html) · [link](https://docs.docker.com/engine/security/#docker-daemon-attack-surface) · [link](https://book.hacktricks.wiki/en/linux-hardening/privilege-escalation/interesting-groups-linux-pe/index.html)

### lxd / lxc group membership
*id:* `linux-lxd-lxc-group` · *category:* `container-escape` · *severity:* **critical**

Membership in the lxd (or lxc) group lets a user create a privileged container that mounts the host filesystem, giving root-level read/write to the host without any sudo rights or password.

**How it works —** The LXD daemon runs as root and trusts the lxd group. A member imports a small image (commonly Alpine), launches a container with security.privileged=true, and adds a disk device mapping the host root ('/') into the container. Inside the container the user is root over the mounted host filesystem and can plant a SUID binary, edit /etc/passwd, or read secrets to escalate on the host. The same applies to legacy lxc tooling.

**Prerequisites:** Membership in the lxd or lxc group; LXD initialized (or the ability to run 'lxd init'), and an importable image

**Enumerate:**
- `id; groups   # look for 'lxd' or 'lxc'`
- `lxc list 2>/dev/null; lxc image list 2>/dev/null`
- `getent group lxd lxc`
- `ls -la /var/lib/lxd/unix.socket /var/snap/lxd/common/lxd/unix.socket 2>/dev/null`

**Detection indicators:** `Current user in the 'lxd' or 'lxc' group`, `lxc/lxd CLI usable without sudo`, `Writable LXD unix socket`

**Tools:** lxc, lxd, linpeas, lxd_root (initstring), cdk

**Mitigation:** Treat lxd/lxc group membership as root-equivalent; grant only to trusted admins; Disable privileged containers where feasible; Restrict access to the LXD unix socket

**References:** [link](https://reboare.github.io/lxd/lxd-escape.html) · [link](https://github.com/initstring/lxd_root) · [link](https://hacktricks.wiki/en/linux-hardening/privilege-escalation/interesting-groups-linux-pe/lxd-privilege-escalation.html) · [link](https://shenaniganslabs.io/2019/05/21/LXD-LPE.html)

### Readable or writable /etc/shadow (hash crack or replacement)
*id:* `linux-readable-writable-etc-shadow` · *category:* `credential-harvesting` · *severity:* **critical**

/etc/shadow holds password hashes and must be root-only. If it is readable, root's hash can be extracted and cracked offline; if writable, root's hash can be replaced with a known value for immediate access. Stale backups (shadow-, shadow.bak) leak the same data.

**How it works —** When /etc/shadow (or a backup like /etc/shadow-, /var/backups/shadow.bak) is readable by the attacker — directly, via a permissive mode, or via cap_dac_read_search on a tool — the root hash is dumped and cracked with john/hashcat offline. If /etc/shadow is writable, the attacker replaces root's field with a hash they generated (e.g. via mkpasswd/openssl) and then su/logs in with the corresponding password. Combining a readable /etc/passwd with a readable /etc/shadow enables unshadow+crack.

**Prerequisites:** Read access (crack path) or write access (replace path) to /etc/shadow or an equivalent backup; Offline cracking capability for the read path

**Enumerate:**
- `ls -la /etc/shadow /etc/shadow- /etc/gshadow 2>/dev/null`
- `ls -la /var/backups/*shadow* 2>/dev/null`
- `[ -r /etc/shadow ] && echo 'READABLE /etc/shadow'; [ -w /etc/shadow ] && echo 'WRITABLE /etc/shadow'`
- `find / -name 'shadow*' -readable -type f 2>/dev/null`

**Detection indicators:** `/etc/shadow readable or writable by group/other (mode other than 640/600 root:shadow/root:root)`, `World-readable shadow backups under /var/backups or elsewhere`, `A tool with cap_dac_read_search that can bypass shadow permissions`

**Tools:** john, hashcat, unshadow, linpeas, linux-smart-enumeration

**Mitigation:** /etc/shadow must be mode 640 root:shadow (or 600 root:root); backups equally restricted; Use strong hashing (yescrypt/sha512) and monitor read access; Audit capabilities that can bypass DAC read checks

**References:** [link](https://book.hacktricks.wiki/en/linux-hardening/privilege-escalation/index.html#readable-etcshadow) · [link](https://www.hackingarticles.in/linux-privilege-escalation-using-weak-nfs-permissions/) · [link](https://man7.org/linux/man-pages/man5/shadow.5.html) · [link](https://book.hacktricks.wiki/en/linux-hardening/privilege-escalation/index.html#etcshadow)

### nf_tables double-free (nft_verdict_init NF_DROP)
*id:* `linux-nftables-cve-2024-1086` · *category:* `kernel-exploit` · *severity:* **critical** · *CVE:* CVE-2024-1086

A use-after-free/double-free in nft_verdict_init() where a positive value is accepted as a drop error causes nf_hook_slow() to double-free, yielding a universal local root across kernels ~5.14-6.6; in CISA KEV and used by ransomware.

**How it works —** nft_verdict_init() permits positive values in the hook verdict where NF_DROP is expected. When NF_DROP is issued with a drop error that resembles NF_ACCEPT, nf_hook_slow() frees the skb twice. Notselwyn's 'Flipping Pages' research turned this into a reliable, kernel-version-independent exploit using page-table manipulation and cross-cache techniques that work against hardened kernels (including KernelCTF mitigation kernels) without recompilation, and can run filelessly. Requires unprivileged user namespaces to reach nf_tables.

**Prerequisites:** Unprivileged user namespaces enabled; Vulnerable kernel roughly 5.14 through 6.6.14 (before backported fixes)

**Enumerate:**
- `uname -r`
- `sysctl kernel.unprivileged_userns_clone`
- `lsmod | grep nf_tables`
- `cat /proc/sys/user/max_user_namespaces`

**Detection indicators:** `Kernel ~5.14-6.6 without the Jan/Feb 2024 fix`, `unprivileged userns enabled`, `linux-exploit-suggester flags CVE-2024-1086`, `Listed in CISA Known Exploited Vulnerabilities catalog`

**Tools:** linux-exploit-suggester, linpeas, uname

**Mitigation:** Update to patched stable kernel; Set kernel.unprivileged_userns_clone=0 / restrict user namespaces; Blocklist the nf_tables module if unused

**References:** [link](https://github.com/Notselwyn/CVE-2024-1086) · [link](https://www.openwall.com/lists/oss-security/2024/04/10/22) · [link](https://pwning.tech/nftables/) · [link](https://nvd.nist.gov/vuln/detail/CVE-2024-1086)

### Sudo Baron Samedit (heap overflow)
*id:* `linux-sudo-baron-samedit-cve-2021-3156` · *category:* `sudo` · *severity:* **critical** · *CVE:* CVE-2021-3156

A heap-based buffer overflow in sudo's command-line argument unescaping lets any local user (even without sudo rights) escalate to root on a wide range of default configurations.

**How it works —** When sudo runs in shell mode (sudoedit -s or sudo -s) with a command-line argument ending in a single backslash, the code that removes escape characters reads and writes past the end of a heap buffer because the escaped-character copy loop miscounts the trailing backslash. Attackers control the overflow contents and use it to corrupt adjacent heap structures (such as service_user or a sudoers-related object), ultimately redirecting execution to gain root. The bug does not require the user to be listed in sudoers.

**Prerequisites:** Local unprivileged shell; Vulnerable sudo: 1.8.2 through 1.8.31p2, or 1.9.0 through 1.9.5p1

**Enumerate:**
- `sudo --version`
- `sudoedit -s '\' (vulnerable prints a sudoedit usage/segfault-style error; patched prints 'usage:')`

**Detection indicators:** `sudo version in 1.8.2-1.8.31p2 or 1.9.0-1.9.5p1`, `The `sudoedit -s '\'` probe yields a sudoedit error rather than a clean usage message`, `linux-exploit-suggester flags CVE-2021-3156`, `NOPASSWD`

**Tools:** linpeas, linux-exploit-suggester, searchsploit, sudo

**Mitigation:** Upgrade sudo to 1.9.5p2 or a distro-backported fix; Apply vendor advisories from Jan 26, 2021

**References:** [link](https://github.com/blasty/CVE-2021-3156) · [link](https://github.com/worawit/CVE-2021-3156) · [link](https://www.qualys.com/2021/01/26/cve-2021-3156/baron-samedit-heap-based-overflow-sudo.txt) · [link](https://nvd.nist.gov/vuln/detail/CVE-2021-3156)

### sudo --chroot local root (CVE-2025-32463)
*id:* `linux-sudo-chroot-cve-2025-32463` · *category:* `sudo` · *severity:* **critical** · *CVE:* CVE-2025-32463

In sudo 1.9.14–1.9.17, the -R/--chroot option evaluated paths under the user-supplied root while still processing sudoers, so a local user can plant an /etc/nsswitch.conf there that loads an attacker-controlled shared library, executing code as root — even without any sudoers privileges.

**How it works —** A change in sudo 1.9.14 made sudo call chroot() into the user-specified root directory during sudoers evaluation. Because NSS (name service switch) is consulted during this phase, sudo reads /etc/nsswitch.conf from inside the attacker-controlled chroot; by pointing an NSS database at an attacker-provided module, sudo dlopen()s a malicious shared library while still running as root, giving arbitrary root code execution. Crucially the flaw does not require the invoking user to have any allowed sudo commands — merely the ability to run sudo -R. Rich Mirch (Stratascale CRU) disclosed it; it is fixed in 1.9.17p1, where the 1.9.14 change is reverted and the chroot feature is deprecated.

**Prerequisites:** a local shell on a host with a vulnerable sudo (1.9.14 through 1.9.17, pre-1.9.17p1); a system that consults /etc/nsswitch.conf (standard glibc Linux)

**Enumerate:**
- `sudo --version`
- `sudo -V | head -1`
- `which sudo && sudo -R / true 2>&1 | head`
- `dpkg -l sudo 2>/dev/null || rpm -q sudo`

**Detection indicators:** `Sudo version 1.9.1`, `--chroot`, `-R`, `nsswitch.conf`, `1.9.17`, `chwoot`, `NOPASSWD`

**Tools:** linpeas, sudo-killer

**Mitigation:** Upgrade to sudo 1.9.17p1 or your distro's patched package; Do not enable the (now-deprecated) chroot/runchroot sudoers feature; Monitor for sudo -R usage and unexpected root dlopen of user-writable libraries

**References:** [link](https://www.stratascale.com/resource/cve-2025-32463-sudo-chroot-elevation-of-privilege/) · [link](https://www.sudo.ws/security/advisories/chroot_bug/) · [link](https://github.com/morgenm/sudo-chroot-CVE-2025-32463) · [link](https://nvd.nist.gov/vuln/detail/CVE-2025-32463) · [link](https://seclists.org/oss-sec/2025/q2/288)

### sudo NOPASSWD / permitted-command escape via GTFOBins
*id:* `linux-sudo-nopasswd-gtfobins` · *category:* `sudo` · *severity:* **critical**

sudoers rules that grant a user the ability to run specific commands (often with NOPASSWD) as root can be escaped when the permitted binary offers a shell escape or command-execution feature, turning a narrow grant into full root.

**How it works —** sudo -l reveals which commands the current user may run and as whom. If a permitted binary is a GTFOBins 'sudo' candidate (editors, pagers, interpreters, archivers, service managers, etc.), its built-in shell escape or command hook runs as the target user (root) because sudo already elevated the process. Overly broad rules ('(ALL) ALL', '(ALL) NOPASSWD: ALL') are trivially abused; even a single seemingly harmless tool (e.g. less, vi, awk, tar, systemctl, git, tcpdump) usually provides an escape. Rules that allow running a user-owned or writable script/binary as root are also directly exploitable.

**Prerequisites:** User appears in sudoers with one or more runnable commands; The permitted command exposes a shell escape / command execution, or points at a writable target

**Enumerate:**
- `sudo -l`
- `sudo -ln`
- `cat /etc/sudoers 2>/dev/null; ls -la /etc/sudoers.d/ 2>/dev/null; cat /etc/sudoers.d/* 2>/dev/null`
- `getent group sudo wheel admin`

**Detection indicators:** `'(ALL : ALL) ALL' or 'NOPASSWD: ALL' in sudo -l output`, `NOPASSWD entries pointing at GTFOBins binaries (vi, vim, less, more, awk, python, perl, tar, zip, find, nmap, systemctl, git, ftp, man, tcpdump)`, `sudo rules referencing a script/binary in a user-writable path or the user's home directory`, `Wildcards (*) in permitted command paths`, `NOPASSWD`

**Tools:** gtfobins, linpeas, sudo -l, linenum, linux-smart-enumeration

**Mitigation:** Grant the minimum set of commands; avoid ALL and NOPASSWD: ALL; Never permit interpreters, editors, pagers, or archivers via sudo; Use full absolute paths and avoid wildcards in sudoers command specs; Ensure sudo-permitted binaries/scripts are root-owned and not writable by the grantee

**References:** [link](https://gtfobins.github.io/#+sudo) · [link](https://gtfobins.github.io/gtfobins/less/#sudo) · [link](https://book.hacktricks.wiki/en/linux-hardening/privilege-escalation/index.html#sudo-and-suid) · [link](https://gtfobins.github.io/)

### PwnKit (pkexec argv memory corruption)
*id:* `linux-pwnkit-pkexec-cve-2021-4034` · *category:* `suid-sgid` · *severity:* **critical** · *CVE:* CVE-2021-4034

A memory-corruption flaw in polkit's SUID-root pkexec present since its 2009 introduction allows any unprivileged local user to gain full root, and is exploitable out-of-the-box on default installs of most Linux distributions.

**How it works —** pkexec mishandles calling with an empty argument vector (argc == 0). Its argument-processing loop reads out of bounds and reintroduces an attacker-controlled environment variable into the process environment after the normal environment sanitization has run. By pointing that variable (e.g. via a crafted GCONV_PATH) at an attacker-controlled shared object, arbitrary code executes with root privileges. No exotic timing or race is required, making it extremely reliable and near-universal.

**Prerequisites:** Local unprivileged shell; SUID pkexec binary present (polkit installed, default on most desktops/servers)

**Enumerate:**
- `ls -la $(which pkexec)`
- `pkexec --version`
- `dpkg -l policykit-1 2>/dev/null || rpm -q polkit 2>/dev/null`

**Detection indicators:** `SUID root /usr/bin/pkexec present and unpatched polkit version`, `linux-exploit-suggester / linpeas flags CVE-2021-4034`, `polkit version predating 0.120 vendor fix`

**Tools:** linpeas, linux-exploit-suggester, gtfobins, searchsploit

**Mitigation:** Update polkit to vendor-patched version (fixes shipped Jan 25, 2022); As a stopgap, remove the SUID bit: chmod 0755 /usr/bin/pkexec

**References:** [link](https://github.com/ly4k/PwnKit) · [link](https://github.com/berdav/CVE-2021-4034) · [link](https://www.qualys.com/2022/01/25/cve-2021-4034/pwnkit.txt) · [link](https://nvd.nist.gov/vuln/detail/CVE-2021-4034)

### SUID/SGID binary abuse via GTFOBins
*id:* `linux-suid-sgid-gtfobins-abuse` · *category:* `suid-sgid` · *severity:* **critical**

Binaries with the SUID/SGID bit set run with the file owner's (often root's) privileges regardless of the caller. Many standard utilities can be coerced into spawning a shell, reading/writing arbitrary files, or executing commands while privileged, yielding root.

**How it works —** When a file has the set-user-ID bit and is owned by root, the kernel sets the effective UID to 0 on execution. Any feature of that binary that lets a user run an external command, spawn a shell, or read/write a file therefore does so as root. GTFOBins catalogs the exact feature (e.g. an interpreter's -e/-c flag, a pager's shell escape, an editor's :! escape, a compression tool's command hooks, or 'find -exec') for each Unix binary. Custom SUID wrappers that call other programs by relative name or via system() are additionally vulnerable to PATH hijacking. Non-shell primitives (e.g. reading /etc/shadow, writing /etc/passwd) are equally exploitable.

**Prerequisites:** Low-privileged shell on the host; A SUID/SGID binary owned by root (or a more privileged user) that exposes a shell escape, command execution, or arbitrary file read/write feature

**Enumerate:**
- `find / -perm -4000 -type f 2>/dev/null`
- `find / -perm -2000 -type f 2>/dev/null`
- `find / -perm -6000 -type f 2>/dev/null`
- `find / -perm -u=s -o -perm -g=s -type f 2>/dev/null -exec ls -la {} \;`
- `for f in $(find / -perm -4000 -type f 2>/dev/null); do dpkg -S "$f" 2>/dev/null || rpm -qf "$f" 2>/dev/null; done   # flag files not owned by any package`

**Detection indicators:** `SUID/SGID bit on interpreters or shells (python, python3, perl, ruby, php, bash, dash, lua, node)`, `SUID on GTFOBins-listed tools (nmap, find, vim, view, less, more, awk, gawk, tar, cp, env, nano, ed, tee, dd, base64, xxd, socat, tcpdump, wget, curl, systemctl)`, `SUID root binaries in non-standard paths (/home, /opt, /tmp, /usr/local) not tracked by the package manager`, `'rws' or '-rwsr-xr-x' permission strings in find/ls output on unexpected files`

**Tools:** gtfobins, linpeas, linenum, linux-smart-enumeration, unix-privesc-check, pspy

**Mitigation:** Remove the SUID/SGID bit from binaries that do not require it (chmod u-s / g-s); Audit custom SUID wrappers; avoid system()/relative command invocation; drop privileges early; Mount user-writable filesystems with nosuid; Baseline SUID inventory and alert on new/changed SUID files

**References:** [link](https://gtfobins.github.io/#+suid) · [link](https://gtfobins.github.io/gtfobins/find/#suid) · [link](https://book.hacktricks.wiki/en/linux-hardening/privilege-escalation/index.html) · [link](https://gtfobins.github.io/) · [link](https://github.com/swisskyrepo/PayloadsAllTheThings/blob/master/Methodology%20and%20Resources/Linux%20-%20Privilege%20Escalation.md)

### Writable /etc/passwd (add UID 0 account / clear password field)
*id:* `linux-writable-etc-passwd` · *category:* `writable-file` · *severity:* **critical**

If /etc/passwd is writable by a non-root user, they can append a new UID 0 account with a known password or place a password hash directly in the passwd file, then log in / su to root.

**How it works —** /etc/passwd is world-readable but must be root-only writable. When it is writable, an attacker adds a line defining a second superuser (UID 0, GID 0) with a password hash they control in the second field (the legacy in-passwd hash, still honored when present), then 'su' to that account. A related variant: if the existing root entry's second field is 'x' (hash in /etc/shadow) and passwd is writable, replacing the 'x' with a known hash — or a blank field — can permit password-less/known-password root login on systems that honor the passwd hash.

**Prerequisites:** Write permission on /etc/passwd; A shell and the ability to run su / log in locally

**Enumerate:**
- `ls -la /etc/passwd`
- `[ -w /etc/passwd ] && echo 'WRITABLE /etc/passwd'`
- `awk -F: '($3==0){print $1" has UID 0"}' /etc/passwd   # spot existing UID 0 accounts`

**Detection indicators:** `/etc/passwd permissions grant group/other write (e.g. -rw-rw-r-- or -rw-rw-rw-)`, `More than one entry with UID 0`, `A non-'x', non-'*' value in the password field of an /etc/passwd entry (an inline hash)`, `/etc/passwd`

**Tools:** ls, openssl (passwd), linpeas, linux-smart-enumeration

**Mitigation:** /etc/passwd must be mode 644, owned root:root; Alert on any UID 0 account other than root and on inline password hashes; File-integrity monitoring on /etc/passwd

**References:** [link](https://book.hacktricks.wiki/en/linux-hardening/privilege-escalation/index.html#writable-etcpasswd) · [link](https://www.hackingarticles.in/editing-etc-passwd-file-for-privilege-escalation/) · [link](https://man7.org/linux/man-pages/man5/passwd.5.html) · [link](https://book.hacktricks.wiki/en/linux-hardening/privilege-escalation/index.html#etcpasswd)

### Writable /etc/sudoers or /etc/sudoers.d drop-in
*id:* `linux-writable-sudoers` · *category:* `writable-file` · *severity:* **critical**

If /etc/sudoers or a file/directory under /etc/sudoers.d is writable by a low-privileged user, they can grant themselves passwordless root via sudo.

**How it works —** sudo reads /etc/sudoers and every file in /etc/sudoers.d. When any of these files, or the sudoers.d directory itself, is writable by the attacker, they append a rule granting their user '(ALL) NOPASSWD: ALL' (or add themselves to an admin alias) and then invoke sudo to obtain a root shell. A writable sudoers.d directory lets them drop a new rule file. Improperly permissioned include files ('#includedir') are equally exploitable.

**Prerequisites:** Write access to /etc/sudoers, a file under /etc/sudoers.d, or the sudoers.d directory; sudo installed and honoring the target file

**Enumerate:**
- `ls -la /etc/sudoers /etc/sudoers.d/`
- `[ -w /etc/sudoers ] && echo 'WRITABLE sudoers'; find /etc/sudoers.d -writable 2>/dev/null`
- `sudo -l 2>/dev/null`

**Detection indicators:** `/etc/sudoers or /etc/sudoers.d/* writable by group/other (not mode 440 / 640 root-owned)`, `Writable /etc/sudoers.d directory`, `Recently modified sudoers files with unexpected NOPASSWD rules`, `NOPASSWD`

**Tools:** ls, sudo -l, linpeas, linenum

**Mitigation:** /etc/sudoers and sudoers.d files must be mode 440 (or 640), root-owned; directory 750 root:root; Edit only via visudo (validates syntax and permissions); File-integrity monitoring and alerting on sudoers changes

**References:** [link](https://book.hacktricks.wiki/en/linux-hardening/privilege-escalation/index.html#etcsudoers-etcsudoersd) · [link](https://gtfobins.github.io/#+sudo) · [link](https://www.sudo.ws/docs/man/sudoers.man/) · [link](https://book.hacktricks.wiki/en/linux-hardening/privilege-escalation/index.html#sudo)

### Linux capabilities (cap_setuid / cap_dac_read_search)
*id:* `linux-capabilities-setuid` · *category:* `capabilities` · *severity:* **high**

A binary with a powerful file capability (e.g. cap_setuid+ep) can change its UID to 0 or read protected files without being SUID-root.

**How it works —** `getcap -r /` finds capability-endowed binaries; interpreters with cap_setuid can setuid(0) then exec a shell; cap_dac_read_search bypasses read permission checks.

**Prerequisites:** a binary with an abusable file capability

**Enumerate:**
- `getcap -r / 2>/dev/null`
- `/usr/sbin/getpcaps $$`

**Detection indicators:** `cap_setuid`, `cap_dac_read_search`, `cap_dac_override`, `cap_sys_admin`, `=ep`

**Tools:** gtfobins, linpeas

**Mitigation:** Remove unnecessary file capabilities; Prefer least-privilege capability sets

**References:** [link](https://gtfobins.github.io/#+capabilities) · [link](https://book.hacktricks.xyz/linux-hardening/privilege-escalation#capabilities)

### Looney Tunables (glibc GLIBC_TUNABLES overflow)
*id:* `linux-looney-tunables-cve-2023-4911` · *category:* `credential-harvesting` · *severity:* **high** · *CVE:* CVE-2023-4911

A buffer overflow in the glibc dynamic loader (ld.so) processing of the GLIBC_TUNABLES environment variable lets a local user gain root by exploiting any SUID-root binary, affecting default installs of Fedora, Ubuntu, and Debian.

**How it works —** When ld.so parses GLIBC_TUNABLES it copies tunable name=value tokens into a fixed stack buffer while mishandling the case of a malformed 'tunable=tunable=value' sequence, overflowing the buffer. Because ld.so runs as part of executing any SUID-root binary, an attacker sets a crafted GLIBC_TUNABLES value and executes a setuid binary (e.g. /usr/bin/su) so the overflow corrupts loader state and hijacks execution with root privileges. The bug was introduced with the tunables rewrite in glibc 2.34.

**Prerequisites:** Local unprivileged shell; A SUID-root binary that links glibc; Vulnerable glibc 2.34 through 2.38 before patch

**Enumerate:**
- `ldd --version`
- `ldd /bin/ls | head -1`
- `getconf GNU_LIBC_VERSION`
- `find / -perm -4000 -type f 2>/dev/null`

**Detection indicators:** `glibc version 2.34-2.38 without the Oct 2023 fix`, `Default Fedora 37/38, Ubuntu 22.04/23.04, Debian 12 glibc builds`, `linux-exploit-suggester / linpeas flags CVE-2023-4911`

**Tools:** linpeas, linux-exploit-suggester, searchsploit

**Mitigation:** Update glibc to the patched version (vendor fixes Oct 3, 2023); Temporary: a seccomp/glibc mitigation aborting SUID execution when GLIBC_TUNABLES is malformed

**References:** [link](https://github.com/RootKit-Org/CVE-2023-4911) · [link](https://github.com/leesh3288/CVE-2023-4911) · [link](https://www.qualys.com/2023/10/03/cve-2023-4911/looney-tunables-local-privilege-escalation-glibc-ld-so.txt) · [link](https://nvd.nist.gov/vuln/detail/CVE-2023-4911)

### SSH key and ssh-agent abuse (writable authorized_keys, exposed private keys, agent hijack)
*id:* `linux-ssh-key-and-agent-abuse` · *category:* `credential-harvesting` · *severity:* **high**

Writable authorized_keys files for privileged accounts, readable/unprotected private keys, and hijackable ssh-agent sockets let an attacker authenticate as root or another privileged user.

**How it works —** Three vectors: (1) if root's (or another user's) ~/.ssh/authorized_keys — or the ~/.ssh directory — is writable, the attacker appends their own public key and logs in as that user; (2) private keys stored world-readable, backed up insecurely, or reused across accounts can be harvested and used directly; (3) if a privileged process leaves an ssh-agent socket accessible (SSH_AUTH_SOCK owned by root but reachable, or a shared /tmp/ssh-* socket), an attacker who can access the socket uses the loaded keys to authenticate elsewhere without possessing the key material. Agent forwarding (ForwardAgent yes) into an attacker-controlled host is a related risk.

**Prerequisites:** Write access to a privileged user's authorized_keys/.ssh, OR access to a usable private key, OR access to a live ssh-agent socket with loaded identities

**Enumerate:**
- `ls -la /root/.ssh/ /home/*/.ssh/ 2>/dev/null`
- `find / -name 'authorized_keys' -writable 2>/dev/null`
- `find / -name 'id_rsa' -o -name 'id_ed25519' -o -name '*.pem' 2>/dev/null | xargs -r ls -la 2>/dev/null`
- `env | grep SSH_AUTH_SOCK; ls -la /tmp/ssh-* 2>/dev/null; ss -xlp 2>/dev/null | grep -i agent`

**Detection indicators:** `authorized_keys or ~/.ssh writable by group/other`, `Private keys with permissions readable by others (not 600) or stored in shared/backup locations`, `ssh-agent sockets under /tmp/ssh-* accessible beyond the owner`, `SSH_AUTH_SOCK pointing at a socket reachable by other users; 'ForwardAgent yes' in ssh_config`

**Tools:** ssh, ssh-add, find, linpeas, linenum

**Mitigation:** authorized_keys and ~/.ssh must be owned by and writable only by the account (700/600); Protect private keys (600), rotate exposed keys, avoid key reuse; Avoid agent forwarding to untrusted hosts; restrict agent socket permissions

**References:** [link](https://book.hacktricks.wiki/en/linux-hardening/privilege-escalation/ssh-forward-agent-exploitation.html) · [link](https://www.clockwork.com/insights/ssh-agent-hijacking/) · [link](https://man.openbsd.org/ssh-agent) · [link](https://book.hacktricks.wiki/en/linux-hardening/privilege-escalation/index.html#ssh)

### Cron job abuse: writable scripts, PATH injection, wildcard injection
*id:* `linux-cron-writable-script-path-wildcard` · *category:* `cron-timers` · *severity:* **high**

Root-owned cron jobs that execute a user-writable script, invoke commands by relative name (with a controllable PATH), or expand a wildcard in a directory the user can write, allow arbitrary code execution as root.

**How it works —** Three common flaws: (1) a cron entry runs a script that is world-writable or lives in a user-writable directory, so the user edits it and waits for root to run it; (2) the crontab sets 'PATH=' with a writable directory ahead of system paths, or the job calls a command by bare name, letting the user plant a malicious binary earlier in PATH; (3) the job runs an archiver/command with an unquoted glob (e.g. 'tar czf backup.tar.gz *') in a directory the user controls, so files named like command-line options (e.g. --checkpoint-action) are interpreted as arguments (wildcard/argument injection). pspy observes cron activity without needing root to read crontabs.

**Prerequisites:** A cron job that runs as root (or another privileged user); Write access to the referenced script, a PATH directory, or the directory whose contents are globbed

**Enumerate:**
- `cat /etc/crontab; ls -la /etc/cron.d/ /etc/cron.daily/ /etc/cron.hourly/ /etc/cron.weekly/ /etc/cron.monthly/`
- `cat /etc/cron.d/* 2>/dev/null; ls -la /var/spool/cron/ /var/spool/cron/crontabs/ 2>/dev/null`
- `crontab -l 2>/dev/null`
- `ls -la <path-of-any-script-referenced-by-cron>   # check writability`
- `./pspy64   # observe scheduled processes and their argv as an unprivileged user`

**Detection indicators:** `World/group-writable scripts referenced from crontab (permissions containing 'w' for group/other)`, `'PATH=' line in a crontab that includes a user-writable directory before /usr/bin`, `Cron commands invoking binaries by bare name (no absolute path)`, `Cron command containing an unquoted '*' operating in a user-writable directory (e.g. 'tar ... *', 'chown ... *', 'rsync ... *')`

**Tools:** pspy, linpeas, linenum, unix-privesc-check

**Mitigation:** Root cron scripts must be root-owned and non-writable by others; Set explicit absolute PATH in crontabs; use absolute command paths; Quote and anchor globs, or use 'find ... -print0 | xargs -0' patterns; avoid tar/chown/rsync with bare '*'

**References:** [link](https://www.exploit-db.com/papers/33930) · [link](https://book.hacktricks.wiki/en/linux-hardening/privilege-escalation/index.html#scheduledcron-jobs) · [link](https://book.hacktricks.wiki/en/linux-hardening/privilege-escalation/wildcards-spare-tricks.html) · [link](https://github.com/DominicBreuker/pspy)

### systemd timer / triggered-unit abuse
*id:* `linux-systemd-timer-writable-unit` · *category:* `cron-timers` · *severity:* **high**

A systemd .timer that triggers a .service whose unit file (or the ExecStart target) is writable by a non-root user allows code execution as root when the timer fires.

**How it works —** systemd timers replace cron on modern systems. A .timer unit activates a matching .service. If either the .service unit file, the .timer file, or the executable/script referenced by ExecStart is writable by the attacker, they can point execution at their own payload (or edit the script) and wait for the timer to fire as root (or the unit's User=). Relative ExecStart paths combined with a controllable service environment can also be hijacked. Unit files placed in a writable drop-in directory (/etc/systemd/system/<unit>.d/) are equally abusable.

**Prerequisites:** An active systemd timer triggering a root service; Write access to the .timer/.service unit, a drop-in directory, or the ExecStart target

**Enumerate:**
- `systemctl list-timers --all`
- `systemctl cat <timer>.timer <service>.service 2>/dev/null`
- `ls -la /etc/systemd/system/ /lib/systemd/system/ /run/systemd/system/ 2>/dev/null`
- `find /etc/systemd/ /lib/systemd/ /run/systemd/ -writable 2>/dev/null`
- `for u in $(systemctl list-timers --all --no-legend | awk '{print $NF}'); do systemctl cat "$u" 2>/dev/null; done`

**Detection indicators:** `Unit files (.service/.timer) writable by group/other in find -writable output`, `ExecStart= pointing at a script/binary in a user-writable path`, `Writable systemd drop-in directories (*.service.d)`, `Relative (non-absolute) ExecStart command`

**Tools:** systemctl, linpeas, pspy, linux-smart-enumeration

**Mitigation:** Ensure all unit files and their ExecStart targets are root-owned and non-writable; Use absolute ExecStart paths; Restrict write access to /etc/systemd and drop-in directories

**References:** [link](https://book.hacktricks.wiki/en/linux-hardening/privilege-escalation/index.html#timers) · [link](https://juggernaut-sec.com/systemd-timers-lpe/) · [link](https://www.freedesktop.org/software/systemd/man/systemd.timer.html) · [link](https://book.hacktricks.wiki/en/linux-hardening/privilege-escalation/index.html#systemd-path-relative-paths)

### DirtyCOW (Copy-on-Write race condition)
*id:* `linux-dirtycow-cve-2016-5195` · *category:* `kernel-exploit` · *severity:* **high** · *CVE:* CVE-2016-5195

A race condition in the Linux kernel's copy-on-write (COW) handling of private, read-only memory mappings lets an unprivileged local user write to files they should only be able to read, enabling privilege escalation by overwriting root-owned files (e.g. /etc/passwd) or SUID binaries.

**How it works —** The bug is a race between the memory management dirty-COW path and MADV_DONTNEED. By repeatedly writing to a private mapping of a read-only file via /proc/self/mem while a second thread calls madvise(MADV_DONTNEED) on the same page, the write can land on the original read-only page cache page instead of the private copy, effectively bypassing file permissions. Common escalation targets are overwriting /etc/passwd, a root cron file, or a SUID binary's code. Because it corrupts page cache in memory only, it leaves the on-disk file intact and is hard to detect after the fact.

**Prerequisites:** Local unprivileged shell; Writable page cache target such as a SUID binary or /etc/passwd; Vulnerable kernel (2.6.22 through 4.8.x before patch backports)

**Enumerate:**
- `uname -r`
- `uname -a`
- `cat /etc/os-release`
- `ls -la /usr/bin/passwd (check SUID targets)`

**Detection indicators:** `Kernel version between 2.6.22 and 4.8.2 (fixed in 4.8.3, 4.7.9, 4.4.26 and distro backports)`, `linux-exploit-suggester flags CVE-2016-5195`, `Old distro release predating late 2016 patches`

**Tools:** linux-exploit-suggester, linux-exploit-suggester-2, linpeas, searchsploit, uname

**Mitigation:** Patch to kernel 4.8.3/4.7.9/4.4.26 or distro-backported fix; Apply vendor kernel updates (all major distros shipped fixes Oct 2016)

**References:** [link](https://github.com/dirtycow/dirtycow.github.io/wiki/PoCs) · [link](https://www.exploit-db.com/exploits/40611) · [link](https://dirtycow.ninja/) · [link](https://nvd.nist.gov/vuln/detail/CVE-2016-5195) · [link](https://access.redhat.com/security/vulnerabilities/2706661)

### DirtyCred (credential/file object swap technique)
*id:* `linux-dirtycred-technique` · *category:* `kernel-exploit` · *severity:* **high** · *CVE:* CVE-2022-2588

DirtyCred is a general kernel exploitation technique (not a single CVE) that turns a use-after-free or double-free into root by swapping an unprivileged cred or file struct on the kernel heap for a privileged one, sidestepping data-only overwrite mitigations.

**How it works —** Rather than corrupting a specific field (like modprobe_path), DirtyCred abuses the fact that struct cred and struct file live in dedicated slab caches. Using a UAF/double-free primitive, the attacker frees an unprivileged object and reclaims the same slot with a privileged one allocated by a root context (e.g. by triggering a SUID binary or an open of a root-owned file at the right moment), so an unprivileged task ends up owning privileged credentials or a writable handle to a sensitive file. It generalizes many bugs; the original disclosure paired it with CVE-2022-2588, a double-free in route4_change (net/sched/cls_route.c).

**Prerequisites:** A kernel UAF or double-free primitive on a cred/file-adjacent cache; Ability to allocate/free objects with attacker timing

**Enumerate:**
- `uname -r`
- `linux-exploit-suggester (identify candidate UAF/double-free CVEs)`
- `cat /proc/sys/vm/unprivileged_userfaultfd 2>/dev/null`

**Detection indicators:** `Presence of a UAF/double-free CVE such as CVE-2022-2588 on the running kernel`, `Kernel lacking cred/file cache isolation hardening (CONFIG_KMALLOC_SPLIT_VARSIZE / vendor cred-jar patches)`

**Tools:** linux-exploit-suggester, linpeas, uname

**Mitigation:** Patch the underlying UAF/double-free CVE; Enable slab hardening and cred/file cache isolation (e.g. Google's cred_jar / vendor mitigations)

**References:** [link](https://github.com/Markakd/DirtyCred) · [link](https://github.com/Markakd/CVE-2022-2588) · [link](https://zplin.me/papers/DirtyCred.pdf) · [link](https://nvd.nist.gov/vuln/detail/CVE-2022-2588)

### Dirty Pipe (pipe page-cache overwrite)
*id:* `linux-dirtypipe-cve-2022-0847` · *category:* `kernel-exploit` · *severity:* **high** · *CVE:* CVE-2022-0847

An uninitialized pipe_buffer flag (PIPE_BUF_FLAG_CAN_MERGE) lets an unprivileged user overwrite pages in the page cache of arbitrary read-only files, allowing modification of root-owned files and SUID binaries to gain root.

**How it works —** The flags member of a pipe_buffer struct is not properly cleared on reuse. By splicing a read-only file into a pipe and then writing into that pipe, the stale CAN_MERGE flag causes the write to overwrite the file's page-cache page even though the pipe write should not modify the backing file. Escalation is achieved by overwriting a byte range of a root-owned file such as /etc/passwd, or by patching a SUID binary in the page cache. Unlike DirtyCow it requires no race and is highly reliable.

**Prerequisites:** Local unprivileged shell; Read access to the target file (e.g. a SUID root binary); Kernel 5.8 through 5.16.10 / 5.15.24 / 5.10.101 before backports

**Enumerate:**
- `uname -r`
- `cat /etc/os-release`
- `find / -perm -4000 -type f 2>/dev/null (locate SUID targets)`

**Detection indicators:** `Kernel version 5.8 <= x < 5.16.11 (also < 5.15.25 and < 5.10.102)`, `linux-exploit-suggester flags CVE-2022-0847`, `Distro kernels released between Aug 2020 and Feb 2022 without the fix`

**Tools:** linux-exploit-suggester, linpeas, searchsploit, uname

**Mitigation:** Update to kernel 5.16.11 / 5.15.25 / 5.10.102 or distro backport; Apply vendor kernel patches from Feb/Mar 2022

**References:** [link](https://github.com/AlexisAhmed/CVE-2022-0847-DirtyPipe-Exploits) · [link](https://haxx.in/files/dirtypipez.c) · [link](https://dirtypipe.cm4all.com/) · [link](https://nvd.nist.gov/vuln/detail/CVE-2022-0847)

### eBPF verifier bounds-tracking LPE
*id:* `linux-ebpf-verifier-cve-2021-3490` · *category:* `kernel-exploit` · *severity:* **high** · *CVE:* CVE-2021-3490, CVE-2020-8835, CVE-2021-31440, CVE-2021-4204, CVE-2022-23222

Flaws in the eBPF verifier's register bounds tracking let a user load a program the verifier wrongly accepts as safe, producing kernel out-of-bounds read/write and local root; exploitable only where unprivileged BPF is enabled.

**How it works —** The verifier statically proves eBPF programs are memory-safe by tracking value ranges for each register. Several bugs cause the tracked bounds to diverge from real runtime values: CVE-2021-3490 (Manfred Paul) mishandles 32-bit ALU bounds for AND/OR/XOR, CVE-2020-8835 mistracks 32-bit bounds, CVE-2021-31440 has an off-by-one in bounds adjustment. A crafted program passes verification yet performs out-of-bounds pointer arithmetic at runtime, giving arbitrary kernel read/write that is used to overwrite cred or modprobe_path for root. These require unprivileged eBPF to be permitted.

**Prerequisites:** kernel.unprivileged_bpf_disabled = 0 (unprivileged BPF allowed); Vulnerable kernel for the specific verifier CVE

**Enumerate:**
- `uname -r`
- `sysctl kernel.unprivileged_bpf_disabled`
- `cat /proc/sys/kernel/unprivileged_bpf_disabled`
- `grep BPF /boot/config-$(uname -r) 2>/dev/null`

**Detection indicators:** `kernel.unprivileged_bpf_disabled = 0`, `Kernel version matching a known verifier CVE window`, `linux-exploit-suggester flags CVE-2021-3490 / CVE-2020-8835 etc.`

**Tools:** linux-exploit-suggester, linpeas, uname

**Mitigation:** Patch to a fixed kernel; Set kernel.unprivileged_bpf_disabled=1 (or =2) to block unprivileged BPF program loading

**References:** [link](https://github.com/chompie1337/Linux_LPE_eBPF_CVE-2021-3490) · [link](https://github.com/scwuaptx/CVE/tree/master/CVE-2021-3490) · [link](https://nvd.nist.gov/vuln/detail/CVE-2021-3490) · [link](https://attackerkb.com/topics/3D6SKZ2Hv2/cve-2021-3490)

### GameOver(lay) OverlayFS xattr capability escalation (Ubuntu)
*id:* `linux-gameoverlay-cve-2023-2640-32629` · *category:* `kernel-exploit` · *severity:* **high** · *CVE:* CVE-2023-2640, CVE-2023-32629

Two Ubuntu-specific OverlayFS flaws let files copied from a lower to an upper directory retain extended attributes such as file capabilities, so a non-root user can craft a capability-bearing binary (e.g. cap_setuid) and execute it for root; estimated to affect ~40% of Ubuntu cloud workloads.

**How it works —** Ubuntu's overlayfs modifications mishandle permission checks when copying files (and their security.* extended attributes) from the lower to the upper layer. A file placed in the lower directory with elevated file capabilities has those capabilities carried up to the upper layer, where an unprivileged user can execute it. Because CAP_SETUID / CAP_SYS_ADMIN capabilities survive the copy-up, running the upper-layer binary yields root without any race. The two CVEs cover distinct code paths introduced by Ubuntu-carried patches and mainline changes not properly reconciled.

**Prerequisites:** Ubuntu kernel with the vulnerable overlayfs patches; Ability to create user/mount namespaces or perform overlay mount; Unpatched Ubuntu kernel (fixes July 2023)

**Enumerate:**
- `uname -r`
- `cat /etc/os-release`
- `sysctl kernel.unprivileged_userns_clone`

**Detection indicators:** `Ubuntu kernel released before July 2023 overlayfs fix`, `linux-exploit-suggester flags CVE-2023-2640 / CVE-2023-32629`, `Ubuntu-branded kernel string in uname -a`, `cap_setuid`

**Tools:** linux-exploit-suggester, linpeas, searchsploit, uname

**Mitigation:** Apply Ubuntu kernel updates from July 2023; Restrict unprivileged user namespaces where feasible

**References:** [link](https://github.com/g1vi/CVE-2023-2640-CVE-2023-32629) · [link](https://github.com/Green-Avocado/CVE-2023-2640) · [link](https://www.wiz.io/blog/ubuntu-overlayfs-vulnerability) · [link](https://nvd.nist.gov/vuln/detail/CVE-2023-2640) · [link](https://nvd.nist.gov/vuln/detail/CVE-2023-32629)

### io_uring subsystem LPE (fixed-buffer OOB and related)
*id:* `linux-io-uring-cve-2023-2598` · *category:* `kernel-exploit` · *severity:* **high** · *CVE:* CVE-2023-2598, CVE-2022-1786, CVE-2021-41073, CVE-2022-2602

The io_uring async I/O subsystem has produced multiple memory-corruption LPEs; CVE-2023-2598 is an out-of-bounds access to physical memory via fixed-buffer registration that gives full local root, and the subsystem has had UAFs (e.g. CVE-2022-2602 io_uring+unix GC) exploited for privilege escalation.

**How it works —** io_uring's rich, performance-oriented object lifecycle has repeatedly produced bugs. In CVE-2023-2598, io_sqe_buffer_register() coalesces physically contiguous pages but miscomputes bounds, letting a registered fixed buffer read/write physical memory beyond its intended range, which is escalated to arbitrary kernel R/W and root. CVE-2022-2602 is a use-after-free from the interaction of io_uring registered files and the unix socket garbage collector. Because io_uring is often reachable by unprivileged processes, these are strong LPE primitives. Defenders frequently gate or disable io_uring for untrusted workloads.

**Prerequisites:** io_uring enabled and reachable by unprivileged users; Vulnerable kernel for the specific CVE (e.g. CVE-2023-2598 around 6.x before fix)

**Enumerate:**
- `uname -r`
- `sysctl kernel.io_uring_disabled 2>/dev/null`
- `grep -i io_uring /boot/config-$(uname -r) 2>/dev/null`
- `cat /proc/sys/kernel/io_uring_group 2>/dev/null`

**Detection indicators:** `CONFIG_IO_URING=y and io_uring not disabled by sysctl`, `Kernel version matching a known io_uring CVE window`, `linux-exploit-suggester flags an io_uring CVE`

**Tools:** linux-exploit-suggester, linpeas, uname

**Mitigation:** Patch to a fixed kernel; Set kernel.io_uring_disabled=2 (kernels >= 6.6) or restrict io_uring via seccomp for untrusted workloads

**References:** [link](https://github.com/ysanatomic/io_uring_LPE-CVE-2023-2598) · [link](https://github.com/Ruia-ruia/CVE-2022-2602) · [link](https://anatomic.rip/cve-2023-2598/) · [link](https://nvd.nist.gov/vuln/detail/CVE-2023-2598)

### Netfilter x_tables heap out-of-bounds write
*id:* `linux-netfilter-xtables-oob-cve-2021-22555` · *category:* `kernel-exploit` · *severity:* **high** · *CVE:* CVE-2021-22555

A 15-year-old heap out-of-bounds write in netfilter x_tables (compat setsockopt path) enables kernel memory corruption powerful enough to bypass modern mitigations, giving local root and container escape on kernels 2.6.19 through 5.11.

**How it works —** In net/netfilter/x_tables.c the xt_compat_target_from_user() / IPT_SO_SET_REPLACE compat conversion writes past the end of an allocation because of a size miscalculation when converting 32-bit compat structures. Andy Nguyen (theflow@) leveraged this OOB write against msg_msg heap objects to build a use-after-free and arbitrary read/write, then escalated to root and escaped the kCTF Kubernetes pod isolation. The vulnerability is reachable from an unprivileged user namespace, so unprivileged users can trigger it on affected kernels.

**Prerequisites:** Unprivileged user namespace (for unpriv trigger) or CAP_NET_ADMIN; Vulnerable kernel v2.6.19 through 5.11

**Enumerate:**
- `uname -r`
- `sysctl kernel.unprivileged_userns_clone`
- `lsmod | grep x_tables`

**Detection indicators:** `Kernel <= 5.11 without the April 2021 fix`, `unprivileged userns enabled`, `linux-exploit-suggester / metasploit flag CVE-2021-22555`

**Tools:** metasploit, linux-exploit-suggester, linpeas, uname

**Mitigation:** Update to a patched kernel (fix backported to stable April 2021); Disable unprivileged user namespaces

**References:** [link](https://github.com/google/security-research/tree/master/pocs/linux/cve-2021-22555) · [link](https://github.com/rapid7/metasploit-framework/blob/master/modules/exploits/linux/local/netfilter_xtables_heap_oob_write_priv_esc.rb) · [link](https://google.github.io/security-research/pocs/linux/cve-2021-22555/writeup.html) · [link](https://nvd.nist.gov/vuln/detail/CVE-2021-22555)

### nf_tables use-after-free (NFT_STATEFUL_EXPR)
*id:* `linux-nftables-uaf-cve-2022-32250` · *category:* `kernel-exploit` · *severity:* **high** · *CVE:* CVE-2022-32250

An incorrect NFT_STATEFUL_EXPR check in netfilter nf_tables leads to a use-after-free write, allowing a local user who can create user/network namespaces to escalate to root on kernels through 5.18.1.

**How it works —** In nf_tables_api.c the validation that decides whether an expression is stateful is wrong, so an expression bound to a set can be freed while still referenced. The attacker reclaims the freed object with controlled data (heap grooming with adjacent allocations), builds arbitrary read/write primitives, then typically overwrites modprobe_path or a credential structure to gain root. The nf_tables interface is reachable from an unprivileged user namespace on many distros, so no prior privilege is required beyond namespace creation.

**Prerequisites:** Unprivileged user + network namespace creation allowed; Vulnerable kernel up to and including 5.18.1

**Enumerate:**
- `uname -r`
- `sysctl kernel.unprivileged_userns_clone`
- `lsmod | grep nf_tables`
- `cat /proc/sys/user/max_user_namespaces`

**Detection indicators:** `Kernel <= 5.18.1 without the fix`, `unprivileged userns enabled and nf_tables reachable`, `linux-exploit-suggester flags CVE-2022-32250`

**Tools:** linux-exploit-suggester, linpeas, uname

**Mitigation:** Update to a patched kernel (fix in mid-2022 stable releases); Set kernel.unprivileged_userns_clone=0 to block the namespace reachability

**References:** [link](https://github.com/ysanatomic/CVE-2022-32250-LPE) · [link](https://github.com/theori-io/CVE-2022-32250-exploit) · [link](http://anatomic.rip/cve-2022-32250/) · [link](https://nvd.nist.gov/vuln/detail/CVE-2022-32250)

### nf_tables anonymous-set use-after-free
*id:* `linux-nftables-uaf-cve-2023-32233` · *category:* `kernel-exploit` · *severity:* **high** · *CVE:* CVE-2023-32233

A use-after-free in netfilter nf_tables triggered by mishandling anonymous sets in batch requests gives arbitrary kernel read/write and local root on kernels up to and including 6.3.1.

**How it works —** Anonymous sets are inline sets defined as part of a rule. When a batch request deletes a rule referencing an anonymous set and another operation in the same batch re-references or reactivates that set, nf_tables_deactivate_set() fails to transition the set correctly during the NFT_TRANS_PREPARE phase. The result is a dangling reference the attacker reclaims to obtain arbitrary read/write, which is used to overwrite credential structures and escalate to root. Reachable from an unprivileged user namespace where nf_tables is exposed.

**Prerequisites:** Unprivileged user namespace with nf_tables access; Vulnerable kernel <= 6.3.1

**Enumerate:**
- `uname -r`
- `sysctl kernel.unprivileged_userns_clone`
- `lsmod | grep nf_tables`

**Detection indicators:** `Kernel <= 6.3.1 lacking commit c1592a89942e`, `unprivileged userns enabled`, `linux-exploit-suggester flags CVE-2023-32233`

**Tools:** linux-exploit-suggester, linpeas, uname

**Mitigation:** Apply kernel update containing commit c1592a89942e (nf_tables_activate_set); Disable unprivileged user namespaces

**References:** [link](https://github.com/Liuk3r/CVE-2023-32233) · [link](https://github.com/oferchen/POC-CVE-2023-32233) · [link](https://seclists.org/oss-sec/2023/q2/133) · [link](https://nvd.nist.gov/vuln/detail/CVE-2023-32233)

### OverlayFS SUID copy-up (mainline)
*id:* `linux-overlayfs-copyup-cve-2023-0386` · *category:* `kernel-exploit` · *severity:* **high** · *CVE:* CVE-2023-0386

A mainline OverlayFS bug fails to check uid/gid mapping during copy-up, letting an unprivileged user smuggle a root-owned SUID binary from a lower to an upper layer and execute it as root; actively exploited and in CISA KEV.

**How it works —** When overlayfs copies a file from the lower to the upper directory (copy_up), it preserves ownership without verifying that the setuid file's uid/gid is mapped in the caller's user namespace. Using a FUSE-backed lower directory (owned by root/nobody) combined with an unprivileged user namespace, an attacker presents a root-owned SUID binary in the lower layer; after copy-up the SUID root binary lands in a normal, host-accessible upper directory (e.g. under /tmp) where it can be executed to gain root. Distinct from CVE-2021-3493, this affects mainline kernels, not just Ubuntu.

**Prerequisites:** Unprivileged user namespaces enabled; FUSE available; Vulnerable kernel roughly 5.11 through 6.1 (fixed in 6.2 / backports)

**Enumerate:**
- `uname -r`
- `cat /etc/os-release`
- `modinfo fuse 2>/dev/null; ls -l /dev/fuse`
- `sysctl kernel.unprivileged_userns_clone`

**Detection indicators:** `Kernel roughly 5.11-6.1 without the Jan 2023 copy_up fix`, `FUSE and unprivileged userns both available`, `linux-exploit-suggester / linpeas flags CVE-2023-0386`, `Listed in CISA Known Exploited Vulnerabilities catalog`

**Tools:** linux-exploit-suggester, linpeas, searchsploit, uname

**Mitigation:** Upgrade to kernel 6.2 or apply the backported copy_up fix; Disable unprivileged user namespaces / restrict FUSE where feasible

**References:** [link](https://github.com/xkaneiki/CVE-2023-0386) · [link](https://github.com/sxlmnwb/CVE-2023-0386) · [link](https://securitylabs.datadoghq.com/articles/overlayfs-cve-2023-0386/) · [link](https://nvd.nist.gov/vuln/detail/CVE-2023-0386)

### OverlayFS unprivileged userns capability escalation (Ubuntu)
*id:* `linux-overlayfs-userns-cve-2021-3493` · *category:* `kernel-exploit` · *severity:* **high** · *CVE:* CVE-2021-3493

An Ubuntu-specific OverlayFS flaw fails to validate file capabilities against the user namespace, letting an unprivileged user set file capabilities that are honored in the init namespace and escalate to root.

**How it works —** Upstream Linux forbids mounting overlayfs in an unprivileged user namespace, but Ubuntu carries a patch adding FS_USERNS_MOUNT to overlayfs. When a user in a new user namespace sets file capabilities (e.g. cap_setuid) via setxattr on a file in the overlay, the kernel does not correctly re-validate that the caller lacks those capabilities in the real (init) namespace. The capability xattr persists to a file the attacker then executes in the host namespace, yielding a capability-endowed binary and root. This is essentially the userns/overlayfs analogue of a SUID smuggling bug.

**Prerequisites:** Ubuntu kernel with unprivileged user namespaces enabled; Vulnerable Ubuntu kernel (< 5.11-based / pre-April 2021 patch)

**Enumerate:**
- `uname -r`
- `cat /etc/os-release`
- `sysctl kernel.unprivileged_userns_clone`
- `cat /proc/sys/kernel/unprivileged_userns_clone 2>/dev/null`

**Detection indicators:** `Ubuntu distribution with kernel below the April 2021 fix`, `kernel.unprivileged_userns_clone = 1`, `linux-exploit-suggester flags CVE-2021-3493`, `cap_setuid`

**Tools:** linux-exploit-suggester, linpeas, searchsploit, uname

**Mitigation:** Apply Ubuntu kernel update (USN-4917, April 2021); Set kernel.unprivileged_userns_clone=0 to disable unprivileged user namespaces

**References:** [link](https://github.com/briskets/CVE-2021-3493) · [link](https://www.exploit-db.com/exploits/49933) · [link](https://ubuntu.com/security/CVE-2021-3493) · [link](https://nvd.nist.gov/vuln/detail/CVE-2021-3493)

### ptrace PTRACE_TRACEME credential mishandling
*id:* `linux-ptrace-traceme-cve-2019-13272` · *category:* `kernel-exploit` · *severity:* **high** · *CVE:* CVE-2019-13272

ptrace_link() records the wrong credentials when establishing a ptrace relationship, letting a local user trace a privileged helper (classically pkexec) after a privilege drop and gain root on kernels before 5.1.17.

**How it works —** When a process calls PTRACE_TRACEME, ptrace_link() stores a reference to the tracer's credentials but incorrectly marks the relationship as privileged based on stale credential state. By arranging a parent that drops privileges and then execve()s a SUID helper such as pkexec, an attacker gets the kernel to treat the ptrace relationship as privileged, allowing the unprivileged tracer to influence the privileged process and execute code as root. Jann Horn discovered and reported the flaw.

**Prerequisites:** Local unprivileged shell; A suitable SUID helper (e.g. pkexec) reachable; Vulnerable kernel before 5.1.17

**Enumerate:**
- `uname -r`
- `ls -la $(which pkexec) 2>/dev/null`
- `cat /proc/sys/kernel/yama/ptrace_scope`

**Detection indicators:** `Kernel version 4.10 through < 5.1.17`, `SUID pkexec available`, `linux-exploit-suggester flags CVE-2019-13272`

**Tools:** linux-exploit-suggester, linpeas, searchsploit, uname

**Mitigation:** Update to kernel 5.1.17 or distro backport; Seccomp policies that block ptrace (default in Docker/Podman) mitigate; SELinux deny_ptrace can help

**References:** [link](https://github.com/jas502n/CVE-2019-13272) · [link](https://www.exploit-db.com/exploits/47163) · [link](https://access.redhat.com/articles/4292201) · [link](https://nvd.nist.gov/vuln/detail/CVE-2019-13272)

### Sequoia (seq_file size_t conversion OOB write)
*id:* `linux-sequoia-cve-2021-33909` · *category:* `kernel-exploit` · *severity:* **high** · *CVE:* CVE-2021-33909

An out-of-bounds write in the kernel's seq_file/filesystem layer, reachable by creating a deeply nested directory path, gives local root on default installations of Ubuntu, Debian, and Fedora on kernels since 2014.

**How it works —** When the kernel converts a long file path to a string in the seq_file interface (via the filesystem layer), a size_t length value is improperly cast to a signed int in a size comparison. By creating, mounting, and deleting a directory structure whose path length exceeds 1 GB and then operating on it, an unprivileged user drives the flawed length check to write out of bounds on the kernel heap. Qualys chained this into full arbitrary write and root. It affects essentially all Linux kernels from 3.16 (2014) up to the July 2021 fix and works on stock installs.

**Prerequisites:** Local unprivileged shell (unprivileged user namespace helps on some distros); Vulnerable kernel 3.16 through pre-July-2021 fix

**Enumerate:**
- `uname -r`
- `cat /etc/os-release`
- `sysctl kernel.unprivileged_userns_clone`

**Detection indicators:** `Kernel between 3.16 and the July 2021 fix`, `Default Ubuntu/Debian/Fedora kernel without the patch`, `linux-exploit-suggester flags CVE-2021-33909`

**Tools:** linux-exploit-suggester, linpeas, searchsploit, uname

**Mitigation:** Apply the July 20, 2021 kernel updates from your distro; Set /proc/sys/kernel/unprivileged_userns_clone=0 and user.max_user_namespaces=0 as a temporary mitigation on some distros

**References:** [link](https://www.qualys.com/2021/07/20/cve-2021-33909/sequoia-local-privilege-escalation-linux.txt) · [link](https://www.exploit-db.com/exploits/50134) · [link](https://blog.qualys.com/vulnerabilities-threat-research/2021/07/20/sequoia-a-local-privilege-escalation-vulnerability-in-linuxs-filesystem-layer-cve-2021-33909) · [link](https://nvd.nist.gov/vuln/detail/CVE-2021-33909)

### NFS no_root_squash / no_all_squash misconfiguration
*id:* `linux-nfs-no-root-squash` · *category:* `nfs` · *severity:* **high**

An NFS export configured with no_root_squash lets a client's root map to the server's root over the share. An attacker with root on any client (or on their own machine) writes a root-owned SUID binary into the share, then executes it on the target to become root.

**How it works —** By default NFS 'squashes' remote root to the anonymous user. With no_root_squash, files created as root on the client are owned by root on the server, and the setuid bit is preserved. The attacker mounts the export from a machine where they are root, drops a small root-owned SUID-root helper into the shared directory, then runs it from a low-privileged shell on the server to gain a root shell. no_all_squash enables an analogous attack by matching arbitrary UIDs. A lesser-known local variant forges the client-advertised UID/GID in NFSv3 RPCs to access files as their owner even when the export is IP-restricted.

**Prerequisites:** An NFS export with no_root_squash (or no_all_squash); Root on a client that can mount the share (or ability to forge NFS RPC UIDs), plus a shell on the target to execute the planted binary

**Enumerate:**
- `cat /etc/exports 2>/dev/null`
- `showmount -e <nfs-server>`
- `cat /proc/mounts | grep nfs; mount | grep nfs`
- `grep -i 'no_root_squash\|no_all_squash\|insecure' /etc/exports 2>/dev/null`

**Detection indicators:** `'no_root_squash' or 'no_all_squash' in /etc/exports`, `'insecure' export option (allows non-reserved source ports)`, `Exports readable/writable by broad host ranges (e.g. '*(rw,no_root_squash)')`, `no_root_squash`

**Tools:** showmount, mount, nfs-common, nfsh.py (errno.fr uid-forging poc), linpeas

**Mitigation:** Use root_squash (the default) and all_squash where appropriate; Restrict exports to specific hosts, avoid the 'insecure' option, mount shares nosuid; Prefer NFSv4 with Kerberos (sec=krb5) over UID-based trust

**References:** [link](https://www.errno.fr/nfs_privesc.html) · [link](https://www.hackingarticles.in/linux-privilege-escalation-using-misconfigured-nfs/) · [link](https://book.hacktricks.wiki/en/network-services-pentesting/nfs-service-pentesting.html) · [link](https://man7.org/linux/man-pages/man5/exports.5.html)

### Dynamic linker hijack: writable library path, missing library, RUNPATH, ld.so.conf
*id:* `linux-ld-preload-library-hijack-nonsudo` · *category:* `path-hijack` · *severity:* **high**

Beyond sudo, the dynamic loader can be abused when a privileged binary depends on a library located in (or searched through) a writable directory, when a required library is missing, or when RUNPATH/RPATH or /etc/ld.so.conf.d point at attacker-writable locations.

**How it works —** The loader searches for shared objects via DT_RPATH/DT_RUNPATH embedded in the binary, LD_LIBRARY_PATH (ignored for SUID unless preserved), and the directories in /etc/ld.so.conf(.d) as cached by ldconfig. If a SUID/root binary has a RUNPATH pointing at a writable directory, or requires a library that is missing (ldd reports 'not found') in a directory the attacker can write, they place a malicious .so exporting the needed symbols/constructor there, and the loader loads it into the privileged process. A writable /etc/ld.so.conf.d file (or writable directory listed therein) lets the attacker add a search path globally.

**Prerequisites:** A privileged binary with a hijackable library search path or a missing dependency; Write access to the relevant library directory, RUNPATH target, or ld.so config

**Enumerate:**
- `ldd <suid-or-root-binary>   # look for 'not found' and library directories`
- `readelf -d <binary> | grep -E 'RPATH|RUNPATH'`
- `cat /etc/ld.so.conf; ls -la /etc/ld.so.conf.d/; find /etc/ld.so.conf.d -writable 2>/dev/null`
- `for d in $(readelf -d <binary> | grep -oP '\[\K[^]]+'); do [ -w "$d" ] && echo "writable RUNPATH: $d"; done`

**Detection indicators:** `ldd output containing 'not found' for a SUID/root binary`, `RPATH/RUNPATH entries resolving to user-writable directories (often '.', /tmp, /opt, home)`, `Writable files under /etc/ld.so.conf.d/ or writable directories listed in ld.so.conf`, `Library search directories with group/other write permission`, `NOPASSWD`, `LD_PRELOAD`

**Tools:** ldd, readelf, ldconfig, linpeas, linux-smart-enumeration

**Mitigation:** Build privileged binaries without writable RPATH/RUNPATH; prefer absolute, root-owned library dirs; Ensure all dependencies resolve and all library directories are root-owned/non-writable; Protect /etc/ld.so.conf(.d) from non-root writes

**References:** [link](https://book.hacktricks.wiki/en/linux-hardening/privilege-escalation/index.html#ld_preload-and-ld_library_path) · [link](https://rentoniscoming.medium.com/exploiting-suid-binaries-shared-library-hijacking-4a5f6a1d2eaf) · [link](https://man7.org/linux/man-pages/man8/ld.so.8.html) · [link](https://book.hacktricks.wiki/en/linux-hardening/privilege-escalation/index.html#shared-library)

### PATH hijacking of root-run scripts and SUID wrappers
*id:* `linux-path-hijacking-relative-command` · *category:* `path-hijack` · *severity:* **high**

When a privileged process (SUID binary, root cron/service, or a script run via sudo) invokes another program by a bare/relative name, an attacker who controls an earlier entry in the effective PATH — or a writable PATH directory — can supply a malicious binary that runs with the caller's privileges.

**How it works —** The shell and system()/execlp/execvp resolve unqualified command names against PATH left-to-right. If a privileged script calls e.g. 'service', 'cat', 'ps', or a custom helper without an absolute path, and the process's PATH contains a directory the attacker can write (or the attacker can set PATH before invoking a SUID wrapper that does not sanitize it), the attacker's same-named binary is executed first. A literal '.' or an empty element in PATH (which resolves to the current directory) is a classic instance. strings on a SUID binary often reveals the relative command names it calls.

**Prerequisites:** A privileged program invoking a command by relative name; A writable directory earlier in the effective PATH, or the ability to influence PATH for the privileged process

**Enumerate:**
- `echo $PATH`
- `strings <suid-binary> | grep -iE '^(/|)([a-z0-9_-]+)$'   # spot relative command names`
- `ltrace/strace the SUID binary if permitted to observe execvp/system calls`
- `for d in $(echo $PATH | tr ':' ' '); do [ -w "$d" ] && echo "writable: $d"; done`

**Detection indicators:** `'.' or an empty element ('::', leading/trailing ':') in PATH`, `A world/group-writable directory present in PATH (e.g. /tmp, /usr/local/bin loosely permissioned)`, `SUID binary strings referencing bare command names (e.g. 'system("ps")')`, `Root cron/service scripts calling commands without absolute paths`

**Tools:** strings, ltrace, strace, linpeas, pspy

**Mitigation:** Always call external commands by absolute path in privileged scripts/binaries; Set a sanitized PATH (and use sudo secure_path) for privileged execution; Remove '.' and writable directories from system PATH

**References:** [link](https://book.hacktricks.wiki/en/linux-hardening/privilege-escalation/index.html#writable-path-abuses) · [link](https://gtfobins.github.io/) · [link](https://book.hacktricks.wiki/en/linux-hardening/privilege-escalation/index.html#path) · [link](https://www.cyberciti.biz/faq/unix-linux-bash-append-prepend-path-variable/)

### D-Bus system service method abuse / permissive policy
*id:* `linux-dbus-privileged-method-abuse` · *category:* `service-misconfig` · *severity:* **high**

The system D-Bus exposes methods on root-running services; a permissive bus policy (/etc/dbus-1/system.d) or a service that runs attacker-supplied input as root allows a low-privileged user to invoke privileged methods and escalate.

**How it works —** System-bus services run as root and register interfaces callable over D-Bus. Access is gated by policy XML in /etc/dbus-1/system.d and /usr/share/dbus-1/system.d, and often by polkit. An over-broad '<allow send_destination=...>' policy, or a custom service method that executes a command / writes a file using caller-controlled arguments, lets an unprivileged user call the method (via busctl/gdbus/dbus-send) and cause root-level actions — command injection, file writes, or service manipulation. Enumeration of exposed interfaces reveals candidate methods.

**Prerequisites:** A root D-Bus service reachable by the attacker with a dangerous method or command-injection sink; A bus policy (or polkit rule) that permits the call

**Enumerate:**
- `busctl list; busctl tree <service> 2>/dev/null`
- `busctl introspect <service> <object-path> 2>/dev/null`
- `ls -la /etc/dbus-1/system.d/ /usr/share/dbus-1/system.d/ 2>/dev/null`
- `grep -R 'allow' /etc/dbus-1/system.d/ 2>/dev/null | grep -i 'send_destination\|send_interface'`

**Detection indicators:** `D-Bus policy files with broad '<allow send_destination=...>' / missing polkit checks`, `Custom system services exposing methods that run commands or write files`, `World-writable files under /etc/dbus-1/system.d`, `Root-owned bus names with methods that accept command/path strings`

**Tools:** busctl, gdbus, dbus-send, d-feet, linpeas

**Mitigation:** Default-deny bus policies; scope send_destination/interface narrowly and require polkit for privileged methods; Validate/whitelist all method inputs in root services; never pass to a shell; Restrict write access to D-Bus policy directories

**References:** [link](https://book.hacktricks.wiki/en/linux-hardening/privilege-escalation/d-bus-enumeration-and-command-injection-privilege-escalation.html) · [link](https://vk9-sec.com/d-bus-enumeration-command-injection-privilege-escalation/) · [link](https://dbus.freedesktop.org/doc/dbus-daemon.1.html) · [link](https://www.freedesktop.org/wiki/Software/dbus/)

### polkit / pkexec policy misconfiguration
*id:* `linux-polkit-pkexec-misconfig` · *category:* `service-misconfig` · *severity:* **high** · *CVE:* CVE-2021-4034, CVE-2021-3560

polkit (PolicyKit) mediates privileged actions; permissive local rules or action policies (allowing a user/group to run privileged operations, or pkexec actions, without authentication) let a low-privileged user execute commands as root through pkexec or D-Bus-backed services.

**How it works —** polkit authorization is defined by .policy action files (/usr/share/polkit-1/actions) and JavaScript .rules files (/etc/polkit-1/rules.d, /usr/share/polkit-1/rules.d). A rule that returns polkit.Result.YES for a broad action, or an action whose allow_active/allow_any defaults to 'yes', permits an unprivileged user to invoke that action (e.g. via pkexec, or a D-Bus method such as org.freedesktop.systemd1 / packagekit / NetworkManager) and run code as root without a password. Administrators sometimes add over-broad rules for convenience. (Distinct, exploitation-grade polkit/pkexec bugs — PwnKit CVE-2021-4034 and the polkit auth-bypass CVE-2021-3560 — are widely referenced but are code vulnerabilities rather than pure misconfiguration.)

**Prerequisites:** A polkit rule or action policy that authorizes a privileged operation for the attacker's user/group without auth; A client path to invoke it (pkexec or a privileged D-Bus service)

**Enumerate:**
- `pkexec --version; pkaction 2>/dev/null | head`
- `ls -la /etc/polkit-1/rules.d/ /usr/share/polkit-1/rules.d/ /usr/share/polkit-1/actions/ 2>/dev/null`
- `grep -R 'ResultActive\|ResultAny\|Result.YES\|allow_active\|allow_any' /etc/polkit-1 /usr/share/polkit-1 2>/dev/null`
- `busctl list 2>/dev/null | grep -i 'systemd1\|PackageKit\|NetworkManager'`

**Detection indicators:** `polkit .rules files returning 'polkit.Result.YES' for broad actions or admin groups`, `action .policy files with '<allow_active>yes</allow_active>' or 'allow_any' set to yes for sensitive actions`, `World-writable files under /etc/polkit-1/rules.d`, `pkexec present and SUID (base for related CVEs)`

**Tools:** pkexec, pkaction, busctl, gdbus, linpeas

**Mitigation:** Review custom polkit rules; avoid blanket Result.YES and permissive allow_active/allow_any; Keep polkit/pkexec patched (>= 0.120 for PwnKit); Restrict permissions on polkit rules/action directories

**References:** [link](https://www.qualys.com/2022/01/25/cve-2021-4034/pwnkit.txt) · [link](https://github.blog/security/vulnerability-research/privilege-escalation-polkit-root-on-linux-with-bug/) · [link](https://www.freedesktop.org/software/polkit/docs/latest/polkit.8.html) · [link](https://book.hacktricks.wiki/en/linux-hardening/privilege-escalation/d-bus-enumeration-and-command-injection-privilege-escalation.html)

### polkit authentication bypass (race condition)
*id:* `linux-polkit-race-cve-2021-3560` · *category:* `service-misconfig` · *severity:* **high** · *CVE:* CVE-2021-3560

A race condition in polkit's polkit_system_bus_name_get_creds_sync() lets an unprivileged user bypass authentication and invoke privileged D-Bus methods (e.g. via accountsservice to create an admin user), gaining root on systems with polkit 0.113-0.118.

**How it works —** Polkit authorizes a D-Bus request by asking dbus-daemon for the sender's UID. If the requesting process is killed at the right moment after polkit receives the message but before it resolves the sender's credentials, dbus-daemon returns an error that polkit mishandles by substituting UID 0. Polkit then evaluates the request as if it came from root and allows it. Chaining this with accountsservice/CreateUser and SetPassword methods lets an attacker create a new administrator account. Discovered by Kevin Backhouse (GitHub Security Lab).

**Prerequisites:** Local unprivileged shell; Vulnerable polkit 0.113 through 0.118 (or backports); accountsservice/other privileged D-Bus service present

**Enumerate:**
- `pkaction --version 2>/dev/null`
- `dpkg -l policykit-1 2>/dev/null || rpm -q polkit 2>/dev/null`
- `busctl list | grep -i accounts`

**Detection indicators:** `polkit version 0.113-0.118`, `linpeas / linux-exploit-suggester flags CVE-2021-3560`, `accountsservice reachable over D-Bus`

**Tools:** linpeas, linux-exploit-suggester, searchsploit

**Mitigation:** Update polkit to 0.119 or distro backport; Apply vendor advisories from June 2021

**References:** [link](https://github.com/Almorabea/Polkit-exploit) · [link](https://github.com/secnigma/CVE-2021-3560-Polkit-Privilege-Esclation) · [link](https://seclists.org/oss-sec/2021/q2/180) · [link](https://nvd.nist.gov/vuln/detail/CVE-2021-3560)

### snapd dirty_sock (UNIX socket UID parsing)
*id:* `linux-snapd-dirtysock-cve-2019-7304` · *category:* `service-misconfig` · *severity:* **high** · *CVE:* CVE-2019-7304

snapd's local REST API over a UNIX socket incorrectly parses the client's peer credentials, letting any local user access restricted API functions to create a root user or sideload a malicious snap, gaining root on default Ubuntu and other distros.

**How it works —** snapd restricts privileged API endpoints by checking the UID of the connecting socket peer. A string-parsing loop over the socket peer address lets a client inject characters that overwrite the parsed UID variable, so the attacker's connection is treated as UID 0. With root-equivalent API access, the exploit either calls the user-creation API to add a sudo-capable account or sideloads a snap whose install hooks run as root. Affects snapd 2.28 through 2.37, which ships by default on Ubuntu.

**Prerequisites:** Local unprivileged shell with access to the snapd socket; Vulnerable snapd 2.28 through 2.37

**Enumerate:**
- `snap version`
- `ls -la /run/snapd.socket`
- `dpkg -l snapd 2>/dev/null`

**Detection indicators:** `snapd version 2.28-2.37`, `/run/snapd.socket present`, `linpeas / linux-exploit-suggester flags CVE-2019-7304`

**Tools:** linpeas, linux-exploit-suggester, searchsploit

**Mitigation:** Update snapd to 2.37.1 or later; Apply Ubuntu security update USN-3887-1

**References:** [link](https://github.com/initstring/dirty_sock) · [link](https://www.exploit-db.com/exploits/46362) · [link](https://threatprotect.qualys.com/2019/02/15/snapd-dirty-sock-privilege-escalation-vulnerability/) · [link](https://nvd.nist.gov/vuln/detail/CVE-2019-7304)

### Writable systemd service unit / relative ExecStart hijack
*id:* `linux-writable-systemd-service-unit` · *category:* `service-misconfig` · *severity:* **high**

A systemd service unit file that is writable by a low-privileged user, or that references a writable executable or a relative path, lets that user run arbitrary code as root at the next start/restart or reload.

**How it works —** systemd runs service ExecStart/ExecStartPre commands as root (or the unit's User=). If the unit file itself is writable, an attacker rewrites ExecStart to their payload, runs 'systemctl daemon-reload', and triggers a start/restart (directly if permitted, or by waiting for a reboot/dependency). Even without editing the unit, a writable ExecStart target binary/script, a writable drop-in override directory, or a relative ExecStart resolved against a controllable PATH yields the same result. Being permitted to 'systemctl restart <svc>' via sudo compounds this.

**Prerequisites:** Write access to a service unit, its drop-in directory, or the ExecStart executable; A path to trigger (re)start: sudo systemctl, socket/dependency activation, or reboot

**Enumerate:**
- `find /etc/systemd/system /lib/systemd/system /run/systemd/system -writable -type f 2>/dev/null`
- `systemctl list-unit-files --type=service`
- `systemctl cat <service>.service`
- `ls -la $(systemctl cat <service>.service 2>/dev/null | grep -oP 'ExecStart=\K\S+')`

**Detection indicators:** `Service unit files writable by group/other`, `ExecStart/ExecStartPre pointing at a user-writable file`, `Writable *.service.d drop-in directories`, `Non-absolute ExecStart command`

**Tools:** systemctl, linpeas, linux-smart-enumeration, pspy

**Mitigation:** Unit files and their targets must be root-owned, mode 644/755, non-writable by others; Use absolute paths in ExecStart; Restrict sudo systemctl grants and write access to systemd directories

**References:** [link](https://book.hacktricks.wiki/en/linux-hardening/privilege-escalation/index.html#writable-systemd-path-binaries) · [link](https://juggernaut-sec.com/systemd-lpe/) · [link](https://www.freedesktop.org/software/systemd/man/systemd.service.html) · [link](https://book.hacktricks.wiki/en/linux-hardening/privilege-escalation/index.html#services)

### sudo LD_PRELOAD / LD_LIBRARY_PATH via env_keep / SETENV
*id:* `linux-sudo-ld-preload-env-keep` · *category:* `sudo` · *severity:* **high**

When sudoers preserves LD_PRELOAD or LD_LIBRARY_PATH across the privilege boundary (Defaults env_keep or a SETENV tag), a user can force the dynamic loader to load an attacker-controlled shared object into a root process, executing arbitrary code as root.

**How it works —** The dynamic linker honors LD_PRELOAD (a library loaded before all others) and LD_LIBRARY_PATH (extra library search path). sudo normally strips these 'unsafe' variables. If sudoers contains 'Defaults env_keep += LD_PRELOAD' / 'LD_LIBRARY_PATH', or a command is tagged SETENV, the variables survive into the elevated process. A user builds a shared object exporting a constructor and preloads it while invoking any sudo-permitted command, running their constructor as root. LD_LIBRARY_PATH variants override a legitimate library the target binary depends on.

**Prerequisites:** At least one sudo-runnable command (even a harmless one); sudoers preserves LD_PRELOAD/LD_LIBRARY_PATH via env_keep, or the command carries a SETENV tag

**Enumerate:**
- `sudo -l   # inspect the 'env_keep' and per-command tags`
- `grep -E 'env_keep|env_reset|setenv|SETENV' /etc/sudoers /etc/sudoers.d/* 2>/dev/null`

**Detection indicators:** `'env_keep+=LD_PRELOAD' or 'env_keep+=LD_LIBRARY_PATH' in sudo -l / sudoers`, `'SETENV:' tag on a permitted command`, `Absence of 'env_reset' or presence of 'Defaults !env_reset'`, `NOPASSWD`, `LD_PRELOAD`

**Tools:** sudo -l, linpeas, linenum

**Mitigation:** Keep 'Defaults env_reset' and do not add LD_PRELOAD/LD_LIBRARY_PATH to env_keep; Avoid the SETENV tag on sudo rules; Prefer secure_path and a minimal preserved environment

**References:** [link](https://touhidshaikh.com/blog/2018/04/sudo-ld_preload-linux-privilege-escalation/) · [link](https://www.hackingarticles.in/linux-privilege-escalation-using-ld_preload/) · [link](https://book.hacktricks.wiki/en/linux-hardening/privilege-escalation/index.html#ld_preload-and-ld_library_path) · [link](https://man7.org/linux/man-pages/man8/ld.so.8.html)

### sudo runas negation and cross-user escalation
*id:* `linux-sudo-runas-negation-crossuser` · *category:* `sudo` · *severity:* **high** · *CVE:* CVE-2019-14287, CVE-2019-18634, CVE-2021-3156

Runas specifications that use negation ('!root', 'ALL, !root') or that permit running commands as a non-root but powerful user can be abused: the negation semantics were bypassable, and a permitted intermediate user may itself hold privileges leading to root.

**How it works —** sudoers Runas_Spec controls which target identities a command may assume. A rule intended to permit 'any user except root' (e.g. '(ALL, !root)') was bypassable by requesting an invalid user ID that sudo resolved to root (CVE-2019-14287, via 'sudo -u#-1'). Even without that bug, permitting a user to run commands as a non-root account is dangerous when that account is a member of a privileged group (docker, lxd, disk), owns cron jobs/scripts that run as root, or can read secrets — a chained pivot to root. Related sudo feature-abuse: pwfeedback stack overflow (CVE-2019-18634) and the Baron Samedit heap overflow (CVE-2021-3156) affect old sudo versions.

**Prerequisites:** sudoers Runas_Spec with negation, or permission to run as an intermediate privileged account; For CVE-2019-14287: sudo < 1.8.28 with a '!root' style rule

**Enumerate:**
- `sudo -l   # examine the '(runas)' field, especially negations and non-root targets`
- `sudo -V | head -1   # version check for CVE-2019-14287 / CVE-2021-3156 / CVE-2019-18634`
- `id <target-user>; groups <target-user>   # assess power of a permitted runas account`

**Detection indicators:** `'(ALL, !root)' or any '!' negation in the runas field of sudo -l`, `sudo version < 1.8.28 (CVE-2019-14287)`, `runas target user that belongs to docker/lxd/disk/adm groups or owns root-run scripts`, `NOPASSWD`

**Tools:** sudo -l, linpeas, linenum

**Mitigation:** Never rely on runas negation; explicitly list allowed target users; Keep sudo patched (>= 1.8.28 for CVE-2019-14287; >= 1.9.5p2 for CVE-2021-3156); Treat 'run as non-root X' grants as equivalent to X's full privileges

**References:** [link](https://www.exploit-db.com/exploits/47502) · [link](https://www.qualys.com/2021/01/26/cve-2021-3156/baron-samedit-heap-based-overflow-sudo.txt) · [link](https://www.sudo.ws/security/advisories/minus_1_uid/) · [link](https://book.hacktricks.wiki/en/linux-hardening/privilege-escalation/index.html#sudo)

### Sudoedit arbitrary file edit (EDITOR '--' bypass)
*id:* `linux-sudoedit-cve-2023-22809` · *category:* `sudo` · *severity:* **high** · *CVE:* CVE-2023-22809

A flaw in sudoedit's handling of user-controlled editor environment variables lets a user granted sudoedit rights on specific files edit arbitrary files (including /etc/sudoers or /etc/passwd) as root.

**How it works —** sudoedit derives the editor command from SUDO_EDITOR/VISUAL/EDITOR. The parsing that builds the argument list treats an embedded '--' as an editor argument rather than the end-of-options marker sudoedit uses to separate the editor from the file list. By setting EDITOR='vim -- /path/to/target', an attacker smuggles an extra file path past the sudoers policy check, so the privileged edit is applied to a file the policy never authorized. This turns a narrow 'edit file X' grant into arbitrary root file modification.

**Prerequisites:** A sudoers rule granting the user sudoedit / sudo -e on at least one file; Vulnerable sudo 1.8.0 through 1.9.12p1

**Enumerate:**
- `sudo --version`
- `sudo -l (look for sudoedit / (root) sudoedit entries)`

**Detection indicators:** `sudo version 1.8.0 through 1.9.12p1`, ``sudo -l` shows a sudoedit rule for the current user`, `linux-exploit-suggester / linpeas flags CVE-2023-22809`, `NOPASSWD`

**Tools:** linpeas, sudo, gtfobins, searchsploit

**Mitigation:** Upgrade sudo to 1.9.12p2 or backport; Workaround: add `Defaults!sudoedit env_delete+="SUDO_EDITOR VISUAL EDITOR"` to sudoers

**References:** [link](https://github.com/n3m1dch/CVE-2023-22809) · [link](https://www.exploit-db.com/exploits/51217) · [link](https://www.synacktiv.com/sites/default/files/2023-01/sudo-CVE-2023-22809.pdf) · [link](https://nvd.nist.gov/vuln/detail/CVE-2023-22809) · [link](https://www.sudo.ws/security/advisories/sudoedit_any/)

### sudoedit / sudo path-wildcard and symlink abuse
*id:* `linux-sudoedit-wildcard-symlink` · *category:* `sudo` · *severity:* **high** · *CVE:* CVE-2015-5602, CVE-2023-22809

sudoers rules that use wildcards in file paths for sudoedit, or that let a user edit a file in a directory they control, can be leveraged to edit arbitrary root-owned files (or inject an editor) and escalate to root.

**How it works —** A sudoers entry like 'sudoedit /home/*/report' or 'user ALL=(root) sudoedit /path/*' lets the wildcard match attacker-controlled paths. When the permitted directory component is writable or a symlink can be planted, the user redirects the privileged edit to a sensitive file (e.g. /etc/sudoers, /etc/passwd, an authorized_keys file, or a root cron file). Historically, sudoedit followed symlinks in the final path component when wildcards were present (CVE-2015-5602), and sudoedit honored extra file arguments smuggled through the user-controlled EDITOR/SUDO_EDITOR variable (CVE-2023-22809), each allowing edit of files outside the intended set.

**Prerequisites:** sudoers grants sudoedit/editing with a wildcard path or a writable directory component; Ability to create symlinks or files in the matched directory (or set EDITOR for CVE-2023-22809)

**Enumerate:**
- `sudo -l   # look for sudoedit entries or editor commands with * in the path`
- `sudoedit --version 2>/dev/null; sudo -V | head -1   # version for CVE-2023-22809 (< 1.9.12p2)`
- `grep -R 'sudoedit\|\*' /etc/sudoers /etc/sudoers.d/ 2>/dev/null`

**Detection indicators:** `'sudoedit' rules containing '*' or a directory the user can write to`, `sudo version below 1.9.12p2 (CVE-2023-22809)`, `sudo version 1.8.x with wildcard sudoedit rules (CVE-2015-5602)`, `NOPASSWD`

**Tools:** sudo -l, linpeas

**Mitigation:** Avoid wildcards in sudoedit/editor path specs; enumerate exact files; Upgrade sudo to >= 1.9.12p2; Ensure parent directories of editable files are root-owned and non-writable

**References:** [link](https://www.exploit-db.com/exploits/37710) · [link](https://www.synacktiv.com/en/publications/cve-2023-22809-sudoedit-bypass-in-sudo-versions-before-1912p2.html) · [link](https://www.sudo.ws/security/advisories/sudoedit_escape/) · [link](https://book.hacktricks.wiki/en/linux-hardening/privilege-escalation/index.html#sudo)

### Wildcard / argument injection (tar, rsync, chown, chmod, zip, 7z)
*id:* `linux-wildcard-argument-injection` · *category:* `wildcard-injection` · *severity:* **high**

When a privileged script or cron/service job runs a command with an unquoted shell glob (e.g. '*') in a directory a user can write, filenames crafted to look like command-line options are expanded into arguments, enabling command execution or file-permission changes as root.

**How it works —** The shell expands '*' into the alphabetical list of filenames, which are then passed as arguments. If an attacker can create files in the globbed directory, they create files whose names are option strings. Classic cases: GNU tar's '--checkpoint=1' plus '--checkpoint-action=exec=<cmd>' (or '--use-compress-program') turn a 'tar ... *' backup into arbitrary command execution; rsync's '-e' / '--rsh' does the same; chown/chmod's '--reference=<file>' makes the job copy ownership/permissions from an attacker-chosen file. The privileged job need only run the command with a bare '*' in a writable directory. This is a benign misconfiguration of otherwise-legitimate maintenance scripts.

**Prerequisites:** A privileged job running tar/rsync/chown/chmod/zip with an unquoted glob; Write access to the directory whose contents are globbed

**Enumerate:**
- `cat /etc/crontab /etc/cron.d/* 2>/dev/null   # look for '*' in tar/rsync/chown/chmod lines`
- `./pspy64   # observe the exact argv of scheduled privileged commands`
- `grep -R -- 'tar\|rsync\|chown\|chmod\|zip' /etc/cron* /etc/systemd 2>/dev/null | grep '\*'`
- `ls -la <the-globbed-directory>   # confirm you can create files there`

**Detection indicators:** `A root cron/service command containing an unquoted '*' (e.g. 'tar czf backup.tgz *', 'chown -R app *')`, `The globbed working directory is writable by non-root users`, `Use of tar/rsync without '--' or absolute file lists`

**Tools:** pspy, linpeas, linenum

**Mitigation:** Avoid bare globs in privileged scripts; use absolute file lists or 'find -print0 | xargs -0'; Separate options from operands with '--' and anchor paths (e.g. './*'); Run backups over directories not writable by untrusted users

**References:** [link](https://www.exploit-db.com/papers/33930) · [link](http://blog.defensecode.com/2014/06/back-to-future-unix-wildcards-gone-wild.html) · [link](https://book.hacktricks.wiki/en/linux-hardening/privilege-escalation/wildcards-spare-tricks.html) · [link](https://www.helpnetsecurity.com/2014/06/27/exploiting-wildcards-on-linux/)

### Writable init/rc scripts, MOTD (pam_motd) scripts, and profile/PAM hooks
*id:* `linux-writable-init-motd-pam-profile` · *category:* `writable-file` · *severity:* **high**

Boot/login-time scripts that run as root — SysV init scripts, /etc/rc.local, dynamic MOTD scripts in /etc/update-motd.d, and /etc/profile.d hooks — are code-execution primitives if writable by a low-privileged user; the MOTD scripts in particular run as root on every SSH/console login via pam_motd.

**How it works —** Several files are executed automatically by root or by the login stack. /etc/rc.local and /etc/init.d/* run at boot as root; if writable, an attacker's code runs at the next reboot. On Debian/Ubuntu, the pam_motd module executes every script in /etc/update-motd.d/ as root at each interactive login — a writable script there yields root on the next SSH/console login (the attacker triggers it simply by logging in). /etc/profile, /etc/profile.d/*.sh, and /etc/bash.bashrc run for shells and, if writable, execute in the context of whoever logs in (including root sessions). Writable PAM configuration or module paths similarly permit hijacking authentication flows.

**Prerequisites:** Write access to an init script, /etc/rc.local, an /etc/update-motd.d script, or a profile/PAM hook that root will execute; A trigger: a reboot, an interactive login (for MOTD/profile), or a root shell session

**Enumerate:**
- `ls -la /etc/update-motd.d/ /etc/rc.local /etc/init.d/ 2>/dev/null`
- `ls -la /etc/profile /etc/profile.d/ /etc/bash.bashrc 2>/dev/null`
- `find /etc/update-motd.d /etc/init.d /etc/rc*.d /etc/profile.d -writable 2>/dev/null`
- `ls -la /etc/pam.d/ 2>/dev/null; grep -R 'pam_motd\|pam_exec' /etc/pam.d/ 2>/dev/null`

**Detection indicators:** `Files under /etc/update-motd.d/ writable by group/other (executed as root by pam_motd on login)`, `/etc/rc.local, /etc/init.d/* or /etc/rc*.d links writable by non-root`, `/etc/profile, /etc/profile.d/*.sh or /etc/bash.bashrc writable by non-root`, `pam_exec lines in /etc/pam.d referencing writable scripts`

**Tools:** find, ls, linpeas, linux-smart-enumeration, pspy

**Mitigation:** All boot, MOTD, profile, and PAM scripts must be root-owned and non-writable by others; Audit /etc/update-motd.d permissions (executed as root at every login); File-integrity monitoring on init, rc.local, profile.d, and pam.d

**References:** [link](https://vk9-sec.com/write-to-etc-update-motd-privilege-escalation/) · [link](https://book.hacktricks.wiki/en/linux-hardening/privilege-escalation/index.html#init-init-d-systemd-and-rc-d) · [link](https://man7.org/linux/man-pages/man8/pam_motd.8.html) · [link](https://book.hacktricks.wiki/en/linux-hardening/privilege-escalation/index.html)


## Windows privilege escalation

### LSASS memory dumping (credential extraction)
*id:* `windows-lsass-dumping` · *category:* `credential-harvesting` · *severity:* **critical**

Dumping the memory of the Local Security Authority Subsystem Service (lsass.exe) exposes plaintext passwords, NTLM hashes, Kerberos tickets/keys, and DPAPI master keys for logged-on users, enabling lateral movement and further escalation.

**How it works —** With administrative or SeDebug access to lsass.exe, a memory image is captured (e.g. Task Manager 'Create dump file', procdump -ma, rundll32 comsvcs.dll,MiniDump, or living-off-the-land WerFault paths) and parsed offline with mimikatz/pypykatz to recover credential material cached by SSPs (wdigest, kerberos, tspkg, livessp). In-memory tools like nanodump produce evasive dumps. LSA Protection (PPL) and Credential Guard raise the bar significantly.

**Prerequisites:** Local admin or SeDebugPrivilege; LSASS not protected by RunAsPPL/Credential Guard (or a PPL-bypass driver)

**Enumerate:**
- `whoami /priv (SeDebugPrivilege)`
- `Get-Process lsass`
- `reg query HKLM\SYSTEM\CurrentControlSet\Control\Lsa /v RunAsPPL`

**Detection indicators:** `Handle to lsass.exe with PROCESS_VM_READ (Sysmon Event ID 10, target lsass.exe)`, `comsvcs.dll MiniDump / procdump -ma lsass command lines`, `lsass*.dmp files written to disk`, `Unusual process (not a known EDR/AV) reading lsass memory`

**Tools:** mimikatz, pypykatz, procdump, nanodump, comsvcs.dll (lolbin)

**Mitigation:** Enable LSA Protection (RunAsPPL) and Credential Guard; Disable WDigest credential caching (UseLogonCredential=0); Restrict debug privilege; deploy EDR with lsass-handle telemetry (Sysmon EID 10)

**References:** [link](https://github.com/gentilkiwi/mimikatz) · [link](https://github.com/skelsec/pypykatz) · [link](https://github.com/fortra/nanodump) · [link](https://attack.mitre.org/techniques/T1003/001/) · [link](https://learn.microsoft.com/en-us/windows-server/security/credentials-protection-and-management/configuring-additional-lsa-protection)

### AlwaysInstallElevated MSI
*id:* `windows-alwaysinstallelevated` · *category:* `installer-misconfig` · *severity:* **critical**

When both the HKLM and HKCU AlwaysInstallElevated policy values equal 1, any user can install an MSI package whose actions run with NT AUTHORITY\SYSTEM privileges.

**How it works —** AlwaysInstallElevated instructs Windows Installer to run package installations with elevated (SYSTEM) rights even for non-administrators. If the policy is set to 1 in both the machine and user hives, a low-privileged user launches a crafted MSI (msiexec /i /quiet) whose install action executes an arbitrary command as SYSTEM. Both keys must be enabled; either one alone is not exploitable.

**Prerequisites:** AlwaysInstallElevated = 1 in BOTH HKLM and HKCU

**Enumerate:**
- `reg query HKLM\SOFTWARE\Policies\Microsoft\Windows\Installer /v AlwaysInstallElevated`
- `reg query HKCU\SOFTWARE\Policies\Microsoft\Windows\Installer /v AlwaysInstallElevated`
- `PowerUp: Get-RegistryAlwaysInstallElevated`

**Detection indicators:** `HKLM\SOFTWARE\Policies\Microsoft\Windows\Installer\AlwaysInstallElevated = 0x1`, `HKCU\SOFTWARE\Policies\Microsoft\Windows\Installer\AlwaysInstallElevated = 0x1`, `msiexec installing packages from user-writable paths and spawning SYSTEM child processes`, `AlwaysInstallElevated`

**Tools:** powerup, msfvenom, winpeas, privesccheck, reg.exe

**Mitigation:** disable the policy (set to 0 or remove) in both hives via GPO; never deploy AlwaysInstallElevated in production; restrict who can run msiexec

**References:** [link](https://book.hacktricks.xyz/windows-hardening/windows-local-privilege-escalation#alwaysinstallelevated) · [link](https://www.rapid7.com/db/modules/exploit/windows/local/always_install_elevated/) · [link](https://attack.mitre.org/techniques/T1548/002/) · [link](https://learn.microsoft.com/en-us/windows/win32/msi/alwaysinstallelevated)

### PrintNightmare (CVE-2021-34527 / CVE-2021-1675)
*id:* `windows-printnightmare-cve-2021-34527` · *category:* `service-misconfig` · *severity:* **critical** · *CVE:* CVE-2021-34527, CVE-2021-1675

A flaw in the Windows Print Spooler's RpcAddPrinterDriver/point-and-print handling lets an authenticated user load an attacker-supplied driver DLL that the SYSTEM spooler executes, giving local privilege escalation (and remote code execution) as SYSTEM.

**How it works —** The spooler's driver-installation RPC path fails to properly validate/authorize driver packages, so a low-privileged (or remote authenticated) user can add a printer driver pointing at a malicious DLL. The Print Spooler service, running as SYSTEM, loads and executes the DLL, yielding SYSTEM code execution. Public PoCs implement the RpcAddPrinterDriverEx call; mimikatz integrated the technique. CVE-2021-1675 was the initially-patched LPE and CVE-2021-34527 the follow-on RCE variant.

**Prerequisites:** Print Spooler service running and reachable (local for LPE; MS-RPRN/MS-PAR over SMB for remote); Any authenticated account; Point-and-Print settings often required for the low-priv path

**Enumerate:**
- `sc query spooler / Get-Service Spooler`
- `reg query "HKLM\SOFTWARE\Policies\Microsoft\Windows NT\Printers\PointAndPrint"`
- `rpcdump.py <host> | findstr MS-RPRN`

**Detection indicators:** `New DLL written under C:\Windows\System32\spool\drivers\x64\3\ then loaded by spoolsv.exe`, `spoolsv.exe spawning cmd/powershell or loading an unusual DLL (Sysmon EID 7/1)`, `Event 808/Microsoft-Windows-PrintService admin log 'failed to load' driver entries`, `RpcAddPrinterDriverEx over MS-RPRN from an unexpected host`

**Tools:** cube0x0 cve-2021-1675 (c#/impacket), nemo-wq printnightmare poc, mimikatz misc::printnightmare, impacket

**Mitigation:** Apply the Microsoft patches and set RestrictDriverInstallationToAdministrators=1; Disable the Print Spooler service where not required (esp. on DCs/servers); Restrict Point-and-Print and monitor spooler driver directory writes

**References:** [link](https://github.com/cube0x0/CVE-2021-1675) · [link](https://github.com/nemo-wq/PrintNightmare-CVE-2021-34527) · [link](https://msrc.microsoft.com/update-guide/vulnerability/CVE-2021-34527) · [link](https://www.rapid7.com/blog/post/ra-cve-2021-34527-printnightmare-analysis/)

### Weak Service Object Permissions (SERVICE_CHANGE_CONFIG / binPath)
*id:* `windows-weak-service-permissions-binpath` · *category:* `service-misconfig` · *severity:* **critical**

A service whose SCM security descriptor grants SERVICE_CHANGE_CONFIG (or SERVICE_ALL_ACCESS) to a non-admin principal lets that user rewrite binPath to any command, then start/restart the service to run it as the service identity.

**How it works —** Each service has a DACL controlling rights such as SERVICE_CHANGE_CONFIG, SERVICE_START and SERVICE_STOP. If a low-privileged group (Authenticated Users, Everyone, BUILTIN\Users, INTERACTIVE) holds SERVICE_CHANGE_CONFIG, the binary path can be reconfigured to an arbitrary executable/command; combined with start/stop rights (or a reboot) the command executes in the service's security context, typically LocalSystem.

**Prerequisites:** SERVICE_CHANGE_CONFIG on the target service; SERVICE_START/SERVICE_STOP rights or a reboot to trigger

**Enumerate:**
- `accesschk.exe -accepteula -uwcqv "Authenticated Users" *`
- `accesschk.exe -accepteula -uwcqv %USERNAME% *`
- `sc.exe sdshow <service>`
- `PowerUp: Get-ModifiableService | Invoke-AllChecks`

**Detection indicators:** `accesschk shows SERVICE_ALL_ACCESS or SERVICE_CHANGE_CONFIG for NT AUTHORITY\Authenticated Users / Everyone / BUILTIN\Users`, `sc sdshow SDDL granting CC/DC/RP/WP/DT/LO to AU/BU/IU/WD ACE SIDs`, `non-admin holding both change-config and start rights on a SYSTEM service`

**Tools:** accesschk, powerup, sharpup, privesccheck, sc.exe, winpeas

**Mitigation:** remove change-config/write rights from non-admin principals; audit and reset service SDDLs to defaults; run services under least-privilege accounts

**References:** [link](https://book.hacktricks.xyz/windows-hardening/windows-local-privilege-escalation#permissions) · [link](https://medium.com/r3d-buck3t/privilege-escalation-with-insecure-windows-service-permissions-5d97312db107) · [link](https://attack.mitre.org/techniques/T1543/003/) · [link](https://learn.microsoft.com/en-us/sysinternals/downloads/accesschk)

### EfsPotato / SharpEfsPotato (MS-EFSR coercion)
*id:* `windows-efspotato-sharpefspotato` · *category:* `token-impersonation` · *severity:* **critical**

EfsPotato and the C# SharpEfsPotato abuse the Encrypting File System Remote protocol (MS-EFSR / EfsRpc) over local RPC named pipes to coerce SYSTEM authentication, then impersonate the SYSTEM token via SeImpersonatePrivilege.

**How it works —** The MS-EFSR EfsRpc functions (e.g. EfsRpcOpenFileRaw / EfsRpcEncryptFileSrv) accept a UNC/path argument that triggers the caller (running as SYSTEM inside lsass/efs) to authenticate to a controlled endpoint. Invoked over a local named pipe (lsarpc, efsrpc, samr, lsass, netlogon), this local coercion yields a SYSTEM token which SeImpersonatePrivilege lets the attacker impersonate to launch a SYSTEM process. Related to the PetitPotam coercion family but used locally for privilege escalation.

**Prerequisites:** SeImpersonatePrivilege enabled; EFSRPC endpoint reachable via a local named pipe (default on many builds)

**Enumerate:**
- `whoami /priv`
- `systeminfo`

**Detection indicators:** `SeImpersonatePrivilege Enabled`, `EfsRpc named-pipe activity (\pipe\lsarpc, \pipe\efsrpc) from a service worker`, `EfsPotato.exe / SharpEfsPotato on disk`, `SYSTEM process spawned by MSSQL/IIS worker`, `SeImpersonatePrivilege`

**Tools:** efspotato, sharpefspotato, sweetpotato

**Mitigation:** Apply MS-EFSR / NTLM relay hardening (EPA, SMB signing) and PetitPotam-related patches; Restrict impersonation privileges; Monitor EfsRpc named-pipe usage from non-standard processes

**References:** [link](https://github.com/zcgonvh/EfsPotato) · [link](https://github.com/bugch3ck/SharpEfsPotato) · [link](https://hacktricks.wiki/en/windows-hardening/windows-local-privilege-escalation/roguepotato-and-printspoofer.html) · [link](https://attack.mitre.org/techniques/T1134/)

### GodPotato (RPCSS/DCOM impersonation, broad OS coverage)
*id:* `windows-godpotato` · *category:* `token-impersonation` · *severity:* **critical**

GodPotato exploits flaws in the RPCSS/DCOM implementation to obtain and impersonate a SYSTEM token from any SeImpersonate-capable context. It has very broad coverage (Windows 8 through 11, Server 2012 through 2022) and does not depend on the Print Spooler.

**How it works —** GodPotato abuses the DCOM/RPC (RPCSS) activation path so a SYSTEM object authenticates to a local endpoint under the attacker's control; the returned SYSTEM token is impersonated via SeImpersonatePrivilege and used to run an arbitrary command as SYSTEM. It generalizes the potato technique across a wide range of builds without the version-specific CLSID hunting JuicyPotato required, using .NET.

**Prerequisites:** SeImpersonatePrivilege enabled; .NET runtime present; Windows 8/Server 2012 through Windows 11/Server 2022

**Enumerate:**
- `whoami /priv`
- `systeminfo`

**Detection indicators:** `SeImpersonatePrivilege Enabled on almost any modern build`, `GodPotato.exe / GodPotato-Net*.exe on disk`, `rpcss/DCOM activation from a worker account preceding a SYSTEM child`, `unmanaged->managed .NET process from a service account spawning cmd/powershell as SYSTEM`, `SeImpersonatePrivilege`

**Tools:** godpotato, deadpotato, rustpotato

**Mitigation:** Remove impersonation privileges from application/service accounts where feasible; Keep systems patched; EDR detections for potato binaries and SYSTEM spawn from service accounts

**References:** [link](https://github.com/BeichenDream/GodPotato) · [link](https://github.com/lypd0/DeadPotato) · [link](https://github.com/safedv/RustPotato) · [link](https://hacktricks.wiki/en/windows-hardening/windows-local-privilege-escalation/roguepotato-and-printspoofer.html) · [link](https://attack.mitre.org/techniques/T1134/001/)

### JuicyPotato (DCOM/BITS OXID abuse)
*id:* `windows-juicypotato` · *category:* `token-impersonation` · *severity:* **critical**

JuicyPotato weaponizes the RottenPotato local NTLM reflection technique against DCOM/BITS by letting the attacker choose the CLSID and listening port, coercing a SYSTEM DCOM object to authenticate to a local malicious OXID resolver and impersonating the resulting SYSTEM token.

**How it works —** A DCOM server activation (e.g. BITS or other CLSIDs running as SYSTEM) is triggered and pointed at an attacker-controlled OXID resolver on 127.0.0.1. The activation performs local NTLM authentication which is reflected/relayed to a local RPC endpoint, and the SYSTEM token produced is captured via SeImpersonatePrivilege and used to launch a SYSTEM process. JuicyPotato exposes CLSID and port selection so different SYSTEM COM servers can be tried per Windows version.

**Prerequisites:** SeImpersonatePrivilege or SeAssignPrimaryTokenPrivilege enabled; Windows <= 10 1803 / Server 2016 (Microsoft hardened DCOM local activation on 1809/Server 2019, breaking the original OXID trick); A working SYSTEM CLSID for the target OS/build

**Enumerate:**
- `whoami /priv`
- `systeminfo (identify OS build to pick a compatible CLSID)`

**Detection indicators:** `SeImpersonatePrivilege Enabled + OS build 1803/Server2016 or older`, `DCOM/BITS activation from a service-account process`, `Loopback RPC/DCOM traffic to 127.0.0.1:135 shortly before a SYSTEM process spawns`, `Sysmon process-create where a service account parent spawns cmd.exe/powershell.exe as SYSTEM`, `SeImpersonatePrivilege`

**Tools:** juicypotato, juicypotatong

**Mitigation:** Patch to 1809/Server 2019+ where the classic OXID activation is blocked (note JuicyPotatoNG revives it via a different CLSID/trick); Restrict DCOM activation permissions; Minimize impersonation privileges on service accounts

**References:** [link](https://github.com/ohpe/juicy-potato) · [link](https://github.com/antonioCoco/JuicyPotatoNG) · [link](https://ohpe.it/juicy-potato/) · [link](https://hacktricks.wiki/en/windows-hardening/windows-local-privilege-escalation/juicypotato.html) · [link](https://attack.mitre.org/techniques/T1134/002/)

### PrintSpoofer (Print Spooler named-pipe coercion)
*id:* `windows-printspoofer` · *category:* `token-impersonation` · *severity:* **critical**

PrintSpoofer abuses the Print Spooler service's RpcRemoteFindFirstPrinterChangeNotificationEx to force the SYSTEM spooler to connect to an attacker-controlled named pipe, capturing and impersonating its SYSTEM token. It is fully local (no network redirector) and works on Windows 10 / Server 2019.

**How it works —** The tool creates a named pipe and calls into the spooler RPC interface (spoolss) requesting a change notification whose callback path points at the controlled pipe. The Print Spooler, running as SYSTEM, connects to the pipe; the tool calls ImpersonateNamedPipeClient under SeImpersonatePrivilege to assume the SYSTEM context, then launches a SYSTEM process. Because it uses the local spooler rather than DCOM/OXID it needs no external resolver.

**Prerequisites:** SeImpersonatePrivilege or SeAssignPrimaryTokenPrivilege enabled; Print Spooler service (spoolsv) running

**Enumerate:**
- `whoami /priv`
- `sc query spooler`
- `Get-Service Spooler`

**Detection indicators:** `SeImpersonatePrivilege Enabled and Spooler running`, `Named pipe creation \pipe\spoolss followed by SYSTEM process spawn`, `spoolsv.exe connecting to an unusual local named pipe`, `Sysmon Event ID 17/18 (pipe created/connected) tied to a service worker process`, `SeImpersonatePrivilege`

**Tools:** printspoofer, sweetpotato

**Mitigation:** Disable Print Spooler on servers that do not print; Restrict impersonation privileges on service accounts; Monitor \pipe\spoolss connections by non-spooler contexts

**References:** [link](https://github.com/itm4n/PrintSpoofer) · [link](https://itm4n.github.io/printspoofer-abusing-impersonate-privileges/) · [link](https://hacktricks.wiki/en/windows-hardening/windows-local-privilege-escalation/roguepotato-and-printspoofer.html)

### RoguePotato (remote OXID resolver revival)
*id:* `windows-roguepotato` · *category:* `token-impersonation` · *severity:* **critical**

RoguePotato revives the potato technique on Windows 10 1809 / Server 2019+ (where JuicyPotato was patched) by redirecting the DCOM OXID resolution to a remote/redirected resolver on TCP 135, restoring the local NTLM reflection path to SYSTEM.

**How it works —** After Microsoft blocked the local (127.0.0.1) OXID resolver trick, RoguePotato uses a fake OXID resolver reachable on port 135 (typically via a socket redirector so the resolver runs remotely or is port-forwarded back to the host). The coerced SYSTEM DCOM activation resolves the OXID against the rogue resolver, which steers the authentication to a local named pipe the tool controls; the SYSTEM token is impersonated via SeImpersonatePrivilege to spawn a SYSTEM process.

**Prerequisites:** SeImpersonatePrivilege enabled; Ability to reach/redirect TCP 135 (a redirector on a second host or a local socket redirect); Windows 10 1809 / Server 2019 and later

**Enumerate:**
- `whoami /priv`
- `systeminfo`

**Detection indicators:** `SeImpersonatePrivilege Enabled on a modern build (1809/Server2019+)`, `Outbound/loopback RPC to an unusual OXID resolver on 135`, `socat/redirector process or unexpected listener on 135`, `Service account spawning SYSTEM shell`, `SeImpersonatePrivilege`

**Tools:** roguepotato

**Mitigation:** Block/monitor unexpected outbound TCP 135; Restrict impersonation privileges; EDR alerting on OXID resolver redirection patterns

**References:** [link](https://github.com/antonioCoco/RoguePotato) · [link](https://decoder.cloud/2020/05/11/no-more-juicypotato-old-story-welcome-roguepotato/) · [link](https://hacktricks.wiki/en/windows-hardening/windows-local-privilege-escalation/roguepotato-and-printspoofer.html)

### Service-Account Token Impersonation (Potato family)
*id:* `windows-seimpersonate-potato` · *category:* `token-impersonation` · *severity:* **critical**

A service context holding SeImpersonatePrivilege (default for IIS, MSSQL, and the *SERVICE accounts) can coerce a SYSTEM token via named-pipe/RPC tricks and impersonate it to become SYSTEM — the standard last hop from a service foothold gained through the service misconfigs above.

**How it works —** SeImpersonatePrivilege permits creating a process in another security context once its token is obtained. The Potato family (JuicyPotato, RoguePotato, PrintSpoofer, SharpEfsPotato, GodPotato) coerces a SYSTEM component (DCOM/OXID resolver, Print Spooler, EFSRPC) into authenticating to an attacker-controlled RPC or named-pipe endpoint, captures/impersonates the SYSTEM token, and spawns a SYSTEM process. Tool choice depends on the Windows build.

**Prerequisites:** current context holds SeImpersonatePrivilege (or SeAssignPrimaryTokenPrivilege)

**Enumerate:**
- `whoami /priv`
- `whoami /groups`
- `whoami /all`

**Detection indicators:** `whoami /priv shows SeImpersonatePrivilege or SeAssignPrimaryTokenPrivilege Enabled in a non-admin service context`, `unexpected local named-pipe creation followed by SYSTEM token impersonation`, `spoolsv.exe / rpcss connecting to a local rogue RPC endpoint`, `SeImpersonatePrivilege`

**Tools:** printspoofer, roguepotato, juicypotato, sharpefspotato, godpotato, whoami

**Mitigation:** remove SeImpersonatePrivilege where not required; patch and restrict Spooler/RPC coercion vectors; isolate service accounts; use virtual/managed service accounts with least privilege

**References:** [link](https://itm4n.github.io/printspoofer-abusing-impersonate-privileges/) · [link](https://github.com/itm4n/PrintSpoofer) · [link](https://attack.mitre.org/techniques/T1134/001/) · [link](https://hacktricks.wiki/en/windows-hardening/windows-local-privilege-escalation/roguepotato-and-printspoofer.html)

### SweetPotato (combined potato toolkit)
*id:* `windows-sweetpotato` · *category:* `token-impersonation` · *severity:* **critical**

SweetPotato by CCob is a consolidated collection of service-account-to-SYSTEM potato techniques (Rotten/Juicy-style DCOM, PrintSpoofer spooler coercion, and EfsRpc) packaged for in-memory use with C2 frameworks such as Cobalt Strike via execute-assembly.

**How it works —** SweetPotato bundles multiple SYSTEM-token capture primitives behind one .NET assembly and lets the operator select the exploit method appropriate to the target build (e.g. the PrintSpoofer/spoolss path or the EfsRpc path). All rely on SeImpersonatePrivilege to impersonate the coerced SYSTEM token and then execute a chosen command as SYSTEM. Its value is packaging and C2 integration rather than a new primitive.

**Prerequisites:** SeImpersonatePrivilege enabled; A working sub-technique for the target OS build

**Enumerate:**
- `whoami /priv`
- `systeminfo`

**Detection indicators:** `SeImpersonatePrivilege Enabled`, `In-memory .NET assembly load (execute-assembly) from a service worker`, `spoolss/efsrpc named-pipe coercion patterns`, `SYSTEM child of a beacon/worker process`, `SeImpersonatePrivilege`

**Tools:** sweetpotato

**Mitigation:** Same as underlying techniques: patch, remove impersonation privileges, disable spooler; AMSI/EDR .NET assembly-load telemetry

**References:** [link](https://github.com/CCob/SweetPotato) · [link](https://hacktricks.wiki/en/windows-hardening/windows-local-privilege-escalation/roguepotato-and-printspoofer.html) · [link](https://attack.mitre.org/techniques/T1134/)

### SeImpersonatePrivilege / SeAssignPrimaryTokenPrivilege token impersonation (named-pipe potato mechanism)
*id:* `windows-token-impersonation-seimpersonate-namedpipe` · *category:* `token-impersonation` · *severity:* **critical**

Service accounts (IIS AppPool, MSSQL, NETWORK SERVICE, LOCAL SERVICE) hold SeImpersonatePrivilege/SeAssignPrimaryTokenPrivilege, which allow a process to impersonate the security context of any token it receives. Coercing a SYSTEM process to authenticate to a controlled named pipe or RPC endpoint yields a SYSTEM token, giving full local escalation.

**How it works —** Windows lets a thread holding SeImpersonatePrivilege call ImpersonateNamedPipeClient (or duplicate a token and CreateProcessWithToken) to run in the security context of a client that connects to it. The universal 'potato' pattern is: stand up a listener (named pipe such as \\.\pipe\spoolss or an RPC/DCOM/OXID endpoint), then trick a highly-privileged SYSTEM service into connecting/authenticating to it (NTLM local reflection, RPC callback, or spooler/EFSRPC coercion). The service's SYSTEM token is captured and impersonated, then used to spawn a new SYSTEM process. SeAssignPrimaryTokenPrivilege enables the CreateProcessAsUser primary-token variant when SeImpersonate alone is insufficient. This is a design-level abuse of impersonation, not a single CVE.

**Prerequisites:** Foothold as a Windows service account or any user whose token has SeImpersonatePrivilege or SeAssignPrimaryTokenPrivilege enabled; Ability to run a binary/assembly on the host

**Enumerate:**
- `whoami /priv`
- `whoami /all`
- `whoami /groups`

**Detection indicators:** `"SeImpersonatePrivilege" State=Enabled in whoami /priv output`, `"SeAssignPrimaryTokenPrivilege" Enabled`, `Running as NT AUTHORITY\NETWORK SERVICE / LOCAL SERVICE / IIS APPPOOL\ / a *$ or svc_ service account`, `Security event 4673 (privileged service called) and 4624 logon type 9 (NewCredentials) followed by a SYSTEM child process from a service account parent`, `Anomalous named-pipe creation (\pipe\spoolss, \pipe\lsarpc) by a web/db worker process`, `SeImpersonatePrivilege`

**Tools:** juicypotato, roguepotato, printspoofer, godpotato, efspotato, sweetpotato, juicypotatong, rottenpotatong, privesccheck, winpeas, seatbelt

**Mitigation:** Do not grant service accounts more privilege than required; prefer virtual/gMSA accounts scoped tightly; Keep hosts patched (RPC/OXID and spooler mitigations narrow the coercion primitives); Disable Print Spooler where not needed; Monitor event 4673/4674 and unusual SYSTEM child processes spawned by worker accounts

**References:** [link](https://github.com/ohpe/juicy-potato) · [link](https://github.com/antonioCoco/RoguePotato) · [link](https://github.com/itm4n/PrintSpoofer) · [link](https://github.com/foxglovesec/RottenPotato) · [link](https://attack.mitre.org/techniques/T1134/) · [link](https://hacktricks.wiki/en/windows-hardening/windows-local-privilege-escalation/privilege-escalation-abusing-tokens.html) · [link](https://foxglovesecurity.com/2016/09/26/rotten-potato-privilege-escalation-from-service-accounts-to-system/) · [link](https://powerofcommunity.net/assets/v0/poc2023/AntonioCocomazzi.pdf)

### Weak Registry ACLs on Service Keys (ImagePath)
*id:* `windows-weak-service-registry-acl-imagepath` · *category:* `writable-registry` · *severity:* **critical**

A weak DACL on a service's registry key lets a non-admin rewrite ImagePath (or the failure-recovery command / Parameters) directly, running an arbitrary command as the service account without needing SCM change-config rights.

**How it works —** The SCM launches a service from the ImagePath value under HKLM\SYSTEM\CurrentControlSet\Services\<svc>. If the registry key grants a low-privileged principal KEY_SET_VALUE / KEY_WRITE, the user edits ImagePath (or FailureCommand, or a Parameters value used by the service) to an attacker-controlled command. On start, restart, reboot, or a triggered failure action the SCM executes it in the service identity, commonly LocalSystem.

**Prerequisites:** registry write on the service key; ability to trigger service start/restart/failure

**Enumerate:**
- `accesschk.exe -accepteula -kvuqsw "HKLM\System\CurrentControlSet\Services"`
- `accesschk.exe -accepteula -kvuqsw "HKLM\System\CurrentControlSet\Services\<svc>"`
- `Get-Acl "HKLM:\SYSTEM\CurrentControlSet\Services\<svc>" | Format-List`
- `reg query "HKLM\SYSTEM\CurrentControlSet\Services\<svc>" /v ImagePath`

**Detection indicators:** `accesschk -k shows KEY_ALL_ACCESS / KEY_SET_VALUE / KEY_WRITE for Users/Authenticated Users/Everyone/INTERACTIVE on a Services subkey`, `Get-Acl on a Services key showing SetValue for a non-admin SID`, `modified ImagePath pointing to a non-standard/user path`

**Tools:** accesschk, privesccheck, powerup, reg.exe, winpeas

**Mitigation:** restore default registry DACLs on Services keys; deny write to non-admins on HKLM Services hive; audit registry ACLs with accesschk regularly

**References:** [link](https://book.hacktricks.xyz/windows-hardening/windows-local-privilege-escalation#registry-modify-services) · [link](https://github.com/itm4n/PrivescCheck) · [link](https://attack.mitre.org/techniques/T1574/011/) · [link](https://learn.microsoft.com/en-us/sysinternals/downloads/accesschk)

### Bring-Your-Own-Vulnerable-Driver (BYOVD)
*id:* `windows-byovd-vulnerable-driver` · *category:* `byovd` · *severity:* **high** · *CVE:* CVE-2021-21551, CVE-2019-16098, CVE-2018-19320

An admin-level attacker loads a legitimately signed but vulnerable kernel driver (catalogued at loldrivers.io) and abuses its IOCTLs for arbitrary kernel read/write — disabling EDR, clearing protections, or achieving SYSTEM/kernel code execution without a kernel 0-day.

**How it works —** Many WHQL/vendor-signed drivers expose dangerous IOCTLs (physical-memory mapping, arbitrary MSR/CR writes, process-handle stripping). BYOVD drops such a driver — e.g. Dell dbutil_2_3.sys (CVE-2021-21551), MSI Afterburner RTCore64.sys (CVE-2019-16098), Gigabyte gdrv.sys (CVE-2018-19320), or gaming/anti-cheat drivers — installs it as a kernel service (loading a driver requires local admin/SeLoadDriverPrivilege, but Secure Boot/DSE still trusts its valid signature), then sends crafted IOCTLs to gain kernel read/write. That primitive is used to null out EDR callback routines and remove Protected-Process-Light on security processes ('EDR killers' like some ransomware crews use), map an unsigned payload into the kernel (kdmapper-style manual mapping bypassing DSE), or read/write EPROCESS to elevate. The technique is a signature/trust abuse rather than a code-execution vuln, which is why it survives even on patched, Secure-Boot systems until the driver is blocklisted.

**Prerequisites:** local administrator (ability to create/start a kernel service and load a driver); a vulnerable signed driver not yet on the Microsoft vulnerable-driver blocklist / HVCI blocklist

**Enumerate:**
- `sc query type= driver`
- `driverquery /v`
- `Get-CimInstance Win32_SystemDriver`
- `reg query HKLM\SYSTEM\CurrentControlSet\Control\CI\Config`
- `bcdedit /enum  (check test-signing / integrity)`

**Detection indicators:** `RTCore64.sys`, `dbutil_2_3.sys`, `gdrv.sys`, `\Device\PhysicalMemory`, `SeLoadDriverPrivilege`, `loldrivers`

**Tools:** loldrivers, kdmapper, byovdkit, backstab, spyboy

**Mitigation:** Enable the Microsoft vulnerable driver blocklist and HVCI/Memory Integrity; Enforce Secure Boot; use WDAC/App Control to allow only approved drivers; Alert on new kernel service creation and known-abused driver hashes; Restrict local admin; monitor EDR tamper / callback removal

**References:** [link](https://www.loldrivers.io/) · [link](https://www.rapid7.com/blog/post/2021/12/13/driver-based-attacks-past-and-present/) · [link](https://github.com/TheCruZ/kdmapper) · [link](https://blog.talosintelligence.com/exploring-vulnerable-windows-drivers/) · [link](https://learn.microsoft.com/en-us/windows/security/application-security/application-control/windows-defender-application-control/design/microsoft-recommended-driver-block-rules)

### Windows Credential Manager / Vault harvesting
*id:* `windows-credential-manager-vault` · *category:* `credential-harvesting` · *severity:* **high**

Windows Credential Manager (the Vault) stores saved domain, web, RDP, and generic credentials (DPAPI-protected) that an attacker in the user's context can enumerate and decrypt, and 'runas /savecred' entries can be reused directly to run commands as another user.

**How it works —** Saved credentials live in the Web and Windows Vaults under %LOCALAPPDATA%\Microsoft\{Vault,Credentials} and are DPAPI-protected to the user. In the user's session they are enumerated (cmdkey /list, vaultcmd) and decrypted with the user's DPAPI keys (mimikatz vault::cred, SharpDPAPI, LaZagne). Where a credential was stored with runas /savecred, an attacker can invoke runas /savecred to execute as that (often privileged) account without knowing the password.

**Prerequisites:** Execution in the context of the user who saved the credentials (for DPAPI decryption), or that user's DPAPI keys

**Enumerate:**
- `cmdkey /list`
- `vaultcmd /list`
- `vaultcmd /listcreds:"Windows Credentials" /all`

**Detection indicators:** `cmdkey /list revealing saved DOMAIN/TERMSRV credentials`, `runas /savecred usage`, `access to %LOCALAPPDATA%\Microsoft\Credentials and \Vault blobs`, `vault::cred / SharpDPAPI / LaZagne execution`

**Tools:** cmdkey, vaultcmd, mimikatz vault::cred, sharpdpapi, lazagne

**Mitigation:** Discourage saving credentials/runas savecred for privileged accounts; Enable Credential Guard; use least-privilege service accounts; Audit Credential Manager reads and runas /savecred launches

**References:** [link](https://github.com/AlessandroZ/LaZagne) · [link](https://github.com/GhostPack/SharpDPAPI) · [link](https://attack.mitre.org/techniques/T1555/004/) · [link](https://hacktricks.wiki/en/windows-hardening/windows-local-privilege-escalation/index.html)

### DPAPI secret & masterkey extraction
*id:* `windows-dpapi-secrets` · *category:* `credential-harvesting` · *severity:* **high**

The Data Protection API protects browser passwords, saved RDP/credential-manager secrets, Wi-Fi keys, and app secrets using per-user master keys; recovering the master keys (via the user password/hash, LSASS, or the domain DPAPI backup key) decrypts all of a user's DPAPI blobs.

**How it works —** DPAPI-protected blobs are decrypted with a user master key stored under %APPDATA%\Microsoft\Protect\<SID>\, itself encrypted from the user's password/NTLM hash. Attackers decrypt master keys using the plaintext/hash (offline), by extracting keys from a running LSASS (mimikatz sekurlsa::dpapi), or—domain-wide—with the DPAPI domain backup key exported from a DC, which decrypts every user's master keys. SharpDPAPI/mimikatz then decrypt Credential Manager blobs, Chrome/Edge logins, RDP passwords, and vault entries.

**Prerequisites:** Access to the target user's DPAPI blobs and one of: the user's password/NTLM hash, LSASS access, or the domain DPAPI backup key (Domain Admin on a DC)

**Enumerate:**
- `dir /a %APPDATA%\Microsoft\Protect`
- `dir /a %LOCALAPPDATA%\Microsoft\Credentials`
- `cmdkey /list`

**Detection indicators:** `Access to %APPDATA%\Microsoft\Protect\<SID> masterkey files by another user/context`, `SharpDPAPI/mimikatz dpapi module usage`, `LSADUMP::backupkeys or DC backup-key export (Directory Service access to the domain backup key)`, `Reads of Credentials/Vault blob files`

**Tools:** sharpdpapi (ghostpack), mimikatz dpapi::/sekurlsa::dpapi, donpapi, impacket dpapi.py

**Mitigation:** Protect the domain DPAPI backup key (Tier-0 DC hardening); Enable Credential Guard and strong user passwords; Monitor access to Protect/Credentials/Vault directories and DC backup-key retrieval

**References:** [link](https://github.com/GhostPack/SharpDPAPI) · [link](https://github.com/gentilkiwi/mimikatz) · [link](https://attack.mitre.org/techniques/T1555/) · [link](https://www.harmj0y.net/blog/redteaming/operational-guidance-for-offensive-user-dpapi-abuse/)

### Group Policy Preferences cpassword
*id:* `windows-gpp-cpassword` · *category:* `credential-harvesting` · *severity:* **high** · *CVE:* CVE-2014-1812

Group Policy Preferences that set local account passwords store an AES-encrypted cpassword in domain-readable SYSVOL XML; Microsoft published the AES key, so any domain user can read and decrypt these (often local-admin) credentials.

**How it works —** GPP for local users, services, scheduled tasks, data sources and drive maps writes a cpassword attribute into XML (Groups.xml, Services.xml, ScheduledTasks.xml, DataSources.xml, Drives.xml) under \\<domain>\SYSVOL\...\Policies. The 32-byte AES key was documented on MSDN, so the value decrypts trivially, exposing reusable local-admin credentials for lateral movement and local privilege escalation. MS14-025 (CVE-2014-1812) blocks creating new GPP passwords but does not delete existing files.

**Prerequisites:** any authenticated domain user (SYSVOL read access); existing GPP XML containing a cpassword value

**Enumerate:**
- `findstr /S /I cpassword \\<domain>\SYSVOL\<domain>\Policies\*.xml`
- `Get-GPPPassword   (PowerSploit)`
- `dir /s \\<domain>\SYSVOL\*.xml  then inspect for cpassword`
- `nxc smb <dc> -u <user> -p <pass> -M gpp_password   (NetExec)`

**Detection indicators:** `cpassword="..." attribute inside any XML under SYSVOL\...\Preferences`, `read access to Groups.xml / Services.xml / ScheduledTasks.xml on a Domain Controller`, `SMB reads of \\*\SYSVOL\*\Preferences\*.xml`

**Tools:** powersploit-get-gpppassword, metasploit-smb_enum_gpp, gpp-decrypt, netexec, impacket-get-gpppassword.py

**Mitigation:** apply MS14-025; delete existing GPP XML files containing cpassword; use LAPS/Windows LAPS to manage local admin passwords

**References:** [link](https://dirteam.com/sander/2014/05/23/security-thoughts-passwords-in-group-policy-preferences-cve-2014-1812/) · [link](https://www.microsoft.com/en-us/msrc/blog/2014/05/ms14-025-an-update-for-group-policy-preferences) · [link](https://attack.mitre.org/techniques/T1552/006/) · [link](https://adsecurity.org/?p=2288)

### SAM/SYSTEM/SECURITY hive dumping (local account hashes & LSA secrets)
*id:* `windows-sam-system-hive-dump` · *category:* `credential-harvesting` · *severity:* **high**

Copying the SAM, SYSTEM, and SECURITY registry hives lets an attacker extract local account NTLM hashes (SAM+SYSTEM bootkey), LSA secrets, and cached domain credentials offline for cracking, pass-the-hash, and lateral movement.

**How it works —** The SAM hive stores local password hashes encrypted with the bootkey held in SYSTEM; SECURITY holds LSA secrets and cached domain logon verifiers. With admin (or SeBackup/shadow-copy access) the hives are exported (reg save HKLM\SAM / HKLM\SYSTEM / HKLM\SECURITY, or copied from a VSS snapshot) and parsed offline with impacket-secretsdump or mimikatz lsadump to yield NTLM hashes, machine account secrets, service-account passwords stored as LSA secrets, and DCC2 cached hashes.

**Prerequisites:** Local admin, or SeBackupPrivilege/shadow-copy read access to the hive files

**Enumerate:**
- `reg save HKLM\SAM %TEMP%\sam.save`
- `reg save HKLM\SYSTEM %TEMP%\system.save`
- `vssadmin list shadows`

**Detection indicators:** `reg save/reg export of HKLM\SAM, HKLM\SYSTEM, HKLM\SECURITY`, `Access to \Windows\System32\config\SAM via a shadow copy path`, `secretsdump.py / lsadump usage`, `Event 4688 for reg.exe saving sensitive hives`

**Tools:** reg.exe, impacket-secretsdump, mimikatz lsadump::sam, creddump7

**Mitigation:** Restrict local admin and Backup Operators; Use unique local admin passwords (LAPS/Windows LAPS); Audit reg save of SAM/SYSTEM/SECURITY and shadow-copy creation

**References:** [link](https://github.com/fortra/impacket) · [link](https://github.com/gentilkiwi/mimikatz) · [link](https://attack.mitre.org/techniques/T1003/002/) · [link](https://attack.mitre.org/techniques/T1003/004/)

### Credentials in unattend.xml / sysprep / Group Policy Preferences
*id:* `windows-unattend-sysprep-gpp-cpassword` · *category:* `credential-harvesting` · *severity:* **high** · *CVE:* CVE-2014-1812

Automated-deployment and GPO artifacts frequently embed local administrator or service passwords: unattend.xml/sysprep.inf/autounattend.xml store base64 admin passwords, and Group Policy Preferences XML on SYSVOL contains AES-encrypted cpassword whose key Microsoft publicly disclosed (MS14-025).

**How it works —** Unattended-install answer files leave AdministratorPassword (base64-encoded) in Panther/sysprep locations readable to users. Group Policy Preferences (Groups.xml, Services.xml, ScheduledTasks.xml, Drives.xml, DataSources.xml) on \\domain\SYSVOL store a 'cpassword' encrypted with a static AES key Microsoft published, so any authenticated domain user can decrypt embedded local-admin/service passwords. Both are simple file reads plus a known decryption.

**Prerequisites:** Read access to the answer file locally, or authenticated domain access to SYSVOL for GPP

**Enumerate:**
- `dir /s /b C:\unattend.xml C:\Windows\Panther\Unattend.xml C:\Windows\System32\sysprep\unattend.xml`
- `findstr /si password *.xml *.ini *.txt`
- `findstr /S cpassword \\<domain>\SYSVOL\<domain>\Policies\*.xml`

**Detection indicators:** `Presence of unattend.xml/autounattend.xml/sysprep.inf with a <Password> value`, `cpassword= attribute in SYSVOL GPP XML`, `Get-GPPPassword / gpp-decrypt execution`, `Enumeration of SYSVOL Policies for *.xml`

**Tools:** powerup get-gpppassword, gpp-decrypt, metasploit smb_enum_gpp, winpeas

**Mitigation:** Delete answer files (or scrub passwords) after imaging; do not store secrets in unattend.xml; Apply MS14-025 and remove existing GPP cpassword XML from SYSVOL; Use LAPS/Windows LAPS for local admin passwords

**References:** [link](https://github.com/PowerShellMafia/PowerSploit) · [link](https://github.com/peass-ng/PEASS-ng) · [link](https://attack.mitre.org/techniques/T1552/006/) · [link](https://support.microsoft.com/en-us/topic/ms14-025-vulnerability-in-group-policy-preferences-could-allow-elevation-of-privilege-8b0d6c4e-8e4a-1e6a-3c8a-6a1a8b0f2c9c)

### Weak Scheduled Task Permissions
*id:* `windows-weak-scheduled-task-permissions` · *category:* `cron-timers` · *severity:* **high**

A scheduled task that runs as SYSTEM or an admin but references a user-writable program, script, or working directory (or whose task definition file is writable) lets a low-privileged user gain execution at the task's privilege on next trigger.

**How it works —** Task Scheduler tasks define an action (program + arguments) and a principal (RunLevel/user). If the action target, a script it calls, or a folder in the resolution chain is writable, or the task XML under C:\Windows\System32\Tasks is writable, the attacker overwrites the payload path. When the trigger fires (schedule, logon, event) the task executes the attacker's code at the configured privilege level.

**Prerequisites:** write access to the task target/script/working dir or the task XML; the task triggers while running as a higher-privileged principal

**Enumerate:**
- `schtasks /query /fo LIST /v`
- `Get-ScheduledTask | % { $_.TaskName; $_.Actions.Execute }`
- `accesschk.exe -accepteula -quv "C:\path\to\task-target.exe"`
- `accesschk.exe -accepteula -dqv "C:\Windows\System32\Tasks"`
- `PowerUp: Get-ModifiableScheduledTaskFile`

**Detection indicators:** `task Principal RunLevel=HighestAvailable or SYSTEM with an action path in a user-writable directory`, `writable ACL on C:\Windows\System32\Tasks\<task> or on the referenced binary/script`, `task authored by a non-admin account`

**Tools:** schtasks, accesschk, icacls, powerup, winpeas, privesccheck

**Mitigation:** run tasks from protected, admin-only paths; restrict DACLs on task files, target binaries and called scripts; use least-privilege task principals

**References:** [link](https://book.hacktricks.xyz/windows-hardening/windows-local-privilege-escalation#scheduled-tasks) · [link](https://github.com/PowerShellMafia/PowerSploit/blob/master/Privesc/PowerUp.ps1) · [link](https://attack.mitre.org/techniques/T1053/005/) · [link](https://learn.microsoft.com/en-us/sysinternals/downloads/accesschk)

### DLL Search Order Hijacking
*id:* `windows-dll-search-order-hijacking` · *category:* `dll-hijack` · *severity:* **high**

A privileged application loads a DLL by bare name and resolves it from an earlier, attacker-writable directory in the Windows DLL search order, running attacker code in the target process context.

**How it works —** LoadLibrary without a full path walks a defined search order (application directory, System32, System, Windows dir, current directory, PATH). If a privileged process loads a non-KnownDLL from a location the attacker can write (its own writable install folder, or the current working directory), planting a same-named DLL there executes attacker code with that process's privileges. SafeDllSearchMode and the KnownDLLs list reduce but do not eliminate the surface.

**Prerequisites:** a privileged process that loads a non-fully-qualified, non-KnownDLL; write access to an earlier directory in the search order

**Enumerate:**
- `Process Monitor filter: Result is NAME NOT FOUND AND Path ends with .dll`
- `accesschk.exe -accepteula -quv "<application install directory>"`
- `PowerUp: Find-ProcessDLLHijack ; Find-PathDLLHijack`
- `cross-reference hijacklibs.net for known-vulnerable DLL names`

**Detection indicators:** `Process Monitor: DLL CreateFile with NAME NOT FOUND across earlier search paths before a successful load in a writable dir`, `unsigned DLL sitting next to a signed, privileged EXE`, `DLL loaded from a user-writable application folder or CWD`

**Tools:** procmon, spartacus, robber, powerup, hijacklibs, winpeas

**Mitigation:** load DLLs with a fully-qualified path; call SetDefaultDllDirectories(LOAD_LIBRARY_SEARCH_SYSTEM32); set SafeDllSearchMode=1, remove CWD from search, lock install-dir DACLs, deploy WDAC/AppLocker

**References:** [link](https://book.hacktricks.xyz/windows-hardening/windows-local-privilege-escalation/dll-hijacking) · [link](https://hijacklibs.net/) · [link](https://attack.mitre.org/techniques/T1574/001/) · [link](https://learn.microsoft.com/en-us/windows/win32/dlls/dynamic-link-library-search-order)

### Phantom (Missing) DLL Hijacking
*id:* `windows-phantom-dll-hijacking` · *category:* `dll-hijack` · *severity:* **high**

Some Windows binaries attempt to load DLLs that do not exist on the system; planting a same-named DLL in a searched writable location grants code execution when the (often auto-elevated or SYSTEM) host process runs.

**How it works —** Phantom DLLs are referenced-but-absent modules (optional plugins, debug helpers, removed components). Because the file is missing, the loader continues down the search path; if any searched directory is writable, an attacker-supplied DLL of that name is loaded. It re-triggers each time the host process starts, providing both privilege escalation and persistence. Coined by Hexacorn; classic examples historically include wlbsctrl.dll, WptsExtensions.dll and TSMSISrv.dll.

**Prerequisites:** a host process referencing a nonexistent DLL; write access to a searched directory

**Enumerate:**
- `Process Monitor filter: Result is NAME NOT FOUND AND Path ends with .dll, correlated to elevated processes`
- `cross-reference the hijacklibs.net phantom-DLL catalog`
- `accesschk.exe -accepteula -uwdq "<candidate search directory>"`

**Detection indicators:** `Process Monitor NAME NOT FOUND for a DLL that never resolves in any search path`, `a new DLL appearing in System32 or an app dir matching a known phantom name`, `high-integrity/auto-elevated process probing for a nonexistent DLL`

**Tools:** procmon, hijacklibs, spartacus, powerup, winpeas

**Mitigation:** place a legitimate signed stub or repair the reference; restrict DACLs on search directories; monitor DLL creation in System32 and application folders; WDAC/AppLocker DLL rules

**References:** [link](https://www.hexacorn.com/blog/2013/12/08/beyond-good-ol-run-key-part-5/) · [link](https://hijacklibs.net/) · [link](https://attack.mitre.org/techniques/T1574/001/) · [link](https://learn.microsoft.com/en-us/windows/win32/dlls/dynamic-link-library-search-order)

### Service DLL Hijacking (ServiceDll / missing dependency)
*id:* `windows-service-dll-hijacking` · *category:* `dll-hijack` · *severity:* **high**

Shared-process (svchost) services load logic from a ServiceDll registry value or resolve dependent/absent DLLs via search order; a writable ServiceDll path or writable search directory yields code execution in the SYSTEM service.

**How it works —** Many services run inside svchost.exe and load their DLL from HKLM\SYSTEM\CurrentControlSet\Services\<svc>\Parameters\ServiceDll. If that DLL file or its directory is user-writable, or the service loads a dependent DLL that is missing and resolvable in a writable directory (search-order / phantom), replacing or planting the DLL runs attacker code in the service (typically SYSTEM) context at start.

**Prerequisites:** writable ServiceDll or a writable search directory for a missing dependency; service restart or reboot

**Enumerate:**
- `reg query "HKLM\SYSTEM\CurrentControlSet\Services\<svc>\Parameters" /v ServiceDll`
- `Process Monitor filter: Result is NAME NOT FOUND AND Path ends with .dll`
- `accesschk.exe -accepteula -quv "<ServiceDll path>"`

**Detection indicators:** `Process Monitor CreateFile on a *.dll returning NAME NOT FOUND / PATH NOT FOUND from a writable directory for svchost/service`, `writable ACL on the ServiceDll file or its folder`, `ServiceDll path pointing outside System32`

**Tools:** procmon, accesschk, winpeas, powerup, privesccheck

**Mitigation:** restrict DLL and directory DACLs to admins/SYSTEM; keep service DLLs in System32 / KnownDLLs; use fully-qualified DLL loads and SafeDllSearchMode

**References:** [link](https://book.hacktricks.xyz/windows-hardening/windows-local-privilege-escalation/dll-hijacking) · [link](https://hijacklibs.net/) · [link](https://attack.mitre.org/techniques/T1574/001/) · [link](https://learn.microsoft.com/en-us/windows/win32/dlls/dynamic-link-library-search-order)

### Kerberos ticket theft & pass-the-ticket
*id:* `windows-kerberos-ticket-theft-ptt` · *category:* `kerberos` · *severity:* **high**

Kerberos TGTs and service tickets held in LSASS or on disk can be extracted and reinjected (pass-the-ticket) to impersonate users without their password; harvesting a privileged TGT enables lateral movement and domain escalation.

**How it works —** With admin/SeDebug access, cached Kerberos tickets are extracted from LSASS (mimikatz sekurlsa::tickets /export, Rubeus dump) or requested (Rubeus tgtdeleg/asktgt). A stolen TGT/TGS is then injected into a logon session (kerberos::ptt / Rubeus ptt) to authenticate as the victim. Related abuses include capturing a computer/service account TGT for delegation attacks and reusing tickets across hosts. Ticket harvesting complements Kerberoasting/AS-REP roasting for offline cracking of service passwords.

**Prerequisites:** Local admin/SeDebug to read other sessions' tickets, or possession of an exported ticket (.kirbi/.ccache)

**Enumerate:**
- `klist`
- `klist sessions`
- `whoami /priv (SeDebugPrivilege for cross-session extraction)`

**Detection indicators:** `sekurlsa::tickets / Rubeus dump/ptt execution`, `TGS/TGT requests with anomalous encryption types (RC4) or from unusual hosts (Event 4768/4769)`, `.kirbi/.ccache files on disk`, `Logon session with an injected ticket not matching the account's normal auth`

**Tools:** rubeus (ghostpack), mimikatz kerberos::/sekurlsa::tickets, impacket (ticketer, gettgt)

**Mitigation:** Enable Credential Guard to protect tickets in LSASS; Enforce AES, disable RC4; use strong service-account passwords and gMSA; Monitor 4768/4769 for RC4/anomalous ticket requests; limit local admin

**References:** [link](https://github.com/GhostPack/Rubeus) · [link](https://github.com/gentilkiwi/mimikatz) · [link](https://attack.mitre.org/techniques/T1558/) · [link](https://attack.mitre.org/techniques/T1550/003/)

### HiveNightmare / SeriousSAM (CVE-2021-36934)
*id:* `windows-hivenightmare-serioussam-cve-2021-36934` · *category:* `kernel-exploit` · *severity:* **high** · *CVE:* CVE-2021-36934

Overly permissive ACLs on the SAM, SYSTEM, and SECURITY registry hives on affected Windows 10/11 builds let any non-admin user read them from a Volume Shadow Copy, extracting local account hashes and LSA secrets to escalate to admin/SYSTEM.

**How it works —** On vulnerable builds the config hive files (\Windows\System32\config\SAM etc.) grant BUILTIN\Users read access. While the live files are locked, a pre-existing VSS shadow copy (\\?\GLOBALROOT\Device\HarddiskVolumeShadowCopyN\Windows\System32\config\SAM) is readable by unprivileged users, so the hives are copied and parsed offline (impacket-secretsdump) to recover the local admin hash for pass-the-hash or offline cracking. Requires at least one existing System Restore/shadow copy.

**Prerequisites:** Affected Windows 10 (1809+)/11 build before the fix; At least one Volume Shadow Copy exists (e.g. from a system restore point / update); Any interactive user account

**Enumerate:**
- `icacls %windir%\System32\config\SAM (BUILTIN\Users:(I)(RX) indicates vulnerable)`
- `vssadmin list shadows`

**Detection indicators:** `icacls shows BUILTIN\Users read on SAM/SYSTEM/SECURITY`, `Non-admin process reading \\?\GLOBALROOT\Device\HarddiskVolumeShadowCopy*\Windows\System32\config\SAM`, `HiveNightmare.exe/hivenightmare on disk; SAM/SECURITY/SYSTEM copies in a user-writable dir`

**Tools:** hivenightmare (gossithedog), hivenightmare (firefart), impacket-secretsdump

**Mitigation:** Apply the Microsoft patch and run the mitigation: restrict ACLs on %windir%\System32\config\* and delete existing shadow copies (VSS); Rotate local admin passwords after exposure; Monitor unprivileged access to shadow-copy hive paths

**References:** [link](https://github.com/GossiTheDog/HiveNightmare) · [link](https://github.com/firefart/hivenightmare) · [link](https://msrc.microsoft.com/update-guide/vulnerability/CVE-2021-36934) · [link](https://www.exploit-db.com/docs/50245)

### Windows win32k / GDI kernel LPE to SYSTEM
*id:* `windows-win32k-gdi-kernel-lpe` · *category:* `kernel-exploit` · *severity:* **high** · *CVE:* CVE-2021-1732, CVE-2022-21882

Memory-corruption bugs in the win32k.sys / GDI kernel-mode subsystem (e.g. CVE-2021-1732, CVE-2022-21882) give a low-privileged local process arbitrary kernel read/write, which is used to steal the SYSTEM token and run code as SYSTEM. HackSys Extreme Vulnerable Driver (HEVD) is the standard training target.

**How it works —** The win32k window-manager runs in kernel mode and historically exposes a large attack surface. CVE-2021-1732 and its patch-bypass CVE-2022-21882 abuse xxxClientAllocWindowClassExtraBytes / NtUserConsoleControl: by desynchronizing the kernel and user-mode views of a window's cbWndExtra size, the exploit corrupts an adjacent window object to build an arbitrary write, then constructs a fake spmenu and uses GetMenuBarInfo for an arbitrary read. With read/write it walks EPROCESS structures to copy the SYSTEM process token into the exploiting process (token stealing), yielding SYSTEM. The same primitives are practiced against HEVD (stack overflow, UAF, type confusion, arbitrary write) in a controlled driver. These are memory-corruption LPEs distinct from file-disclosure bugs like HiveNightmare/SeriousSAM.

**Prerequisites:** local low-privileged code execution (interactive or service context); an unpatched vulnerable win32k/GDI build (or HEVD installed for lab use)

**Enumerate:**
- `systeminfo`
- `wmic qfe list`
- `Get-HotFix`
- `whoami /priv`
- `[System.Environment]::OSVersion.Version`
- `wes.py --update  (Windows Exploit Suggester - Next Generation)`

**Detection indicators:** `win32k`, `win32kfull.sys`, `NtUserConsoleControl`, `cbwndextra`, `tagWND`, `KB5009543`

**Tools:** windows-exploit-suggester-ng, watson, winpeas, hevd, metasploit

**Mitigation:** Apply monthly cumulative updates promptly (win32k fixes); Enable win32k syscall filtering / Win32k lockdown for suitable processes; Use HVCI / VBS and exploit-guard mitigations; run least-privilege; Restrict local logon and monitor for token-manipulation behavior

**References:** [link](https://unit42.paloaltonetworks.com/win32k-analysis-part-2/) · [link](https://github.com/KaLendsi/CVE-2021-1732-Exploit) · [link](https://github.com/L4ys/CVE-2022-21882) · [link](https://github.com/hacksysteam/HackSysExtremeVulnerableDriver) · [link](https://connormcgarr.github.io/)

### LLMNR / NBT-NS / mDNS poisoning & NTLM capture (Responder)
*id:* `network-llmnr-nbtns-mdns-poisoning-responder` · *category:* `network-poisoning` · *severity:* **high**

Windows falls back to broadcast/multicast name resolution (LLMNR, NBT-NS, mDNS) when DNS fails; an attacker on the LAN answers those queries, coercing victims to authenticate to them and capturing NetNTLM hashes to crack or relay.

**How it works —** When a host cannot resolve a name via DNS (typos, missing WPAD, stale shares), Windows broadcasts LLMNR (UDP 5355), NBT-NS (UDP 137) and mDNS (UDP 5353) requests. A poisoner such as Responder replies 'that name is me', so the victim connects and performs NTLM authentication (often for SMB/HTTP/WPAD). The attacker captures the NTLMv1/v2 challenge-response, which is either cracked offline (hashcat) to recover the plaintext, or — if SMB signing is not enforced — relayed live (ntlmrelayx) to another host to authenticate as the victim. WPAD auto-discovery and automatic share access make coercion frequent and reliable, and this is one of the most common initial internal-network privilege footholds.

**Prerequisites:** attacker on the same broadcast/L2 segment as victims; LLMNR/NBT-NS/mDNS enabled (default) and name-resolution failures occurring; for relay: SMB signing not required on the target

**Enumerate:**
- `Get-ItemProperty 'HKLM:\Software\Policies\Microsoft\Windows NT\DNSClient' -Name EnableMulticast`
- `reg query HKLM\SYSTEM\CurrentControlSet\Services\NetBT\Parameters\Interfaces`
- `nmap --script broadcast-dns-service-discovery`
- `Responder.py -I eth0 -A  (analyze-only, passive)`

**Detection indicators:** `LLMNR`, `NBT-NS`, `mDNS`, `EnableMulticast`, `WPAD`, `NetNTLMv2`

**Tools:** responder, inveigh, ntlmrelayx, hashcat, pcredz

**Mitigation:** Disable LLMNR (GPO: Turn off multicast name resolution) and NBT-NS on all interfaces; Disable mDNS where not needed; deploy a proper WPAD DNS record (or disable WPAD); Enforce SMB signing (and LDAP signing/channel binding) to defeat relay; Network segmentation and 802.1x; monitor for poisoning responders

**References:** [link](https://github.com/lgandx/Responder) · [link](https://www.thehacker.recipes/ad/movement/mitm-and-coerced-authentications/llmnr-nbtns-mdns) · [link](https://book.hacktricks.xyz/windows-hardening/active-directory-methodology/spoofing-llmnr-nbt-ns-mdns-dns-and-wpad-and-relay-attacks) · [link](https://en.hackndo.com/ntlm-relay/)

### Writable %PATH% Directory Hijacking
*id:* `windows-writable-path-directory` · *category:* `path-hijack` · *severity:* **high**

A directory writable by low-privileged users that appears in the machine %PATH% lets an attacker plant an EXE or DLL that hijacks unqualified command/DLL resolution for privileged processes, services and admin sessions.

**How it works —** When a service, scheduled task or administrator invokes a program or loads a DLL by bare name, Windows searches PATH directories in order. A user-writable directory listed in the machine PATH (especially an early entry) lets the attacker plant a same-named binary that shadows a system tool or dependency; it then runs with the caller's privileges. This is path interception via the PATH environment variable.

**Prerequisites:** a user-writable directory present in the machine PATH; a privileged caller invoking an unqualified program or DLL name

**Enumerate:**
- `reg query "HKLM\SYSTEM\CurrentControlSet\Control\Session Manager\Environment" /v Path`
- `$env:Path -split ';' | % { icacls $_ } 2>$null`
- `accesschk.exe -accepteula -uwdq <each PATH directory>`
- `PowerUp: Get-ModifiablePath -Path ($env:Path -split ';')`

**Detection indicators:** `a machine PATH entry whose DACL grants write to Users/Authenticated Users/Everyone`, `a non-default, user-writable directory prepended to the system PATH`, `an EXE in a PATH directory shadowing a System32 tool name`

**Tools:** accesschk, icacls, powerup, winpeas, privesccheck

**Mitigation:** remove user-writable directories from the machine PATH; restrict DACLs on all PATH directories to admins; avoid placing the current directory in PATH

**References:** [link](https://book.hacktricks.xyz/windows-hardening/windows-local-privilege-escalation#dll-hijacking) · [link](https://github.com/PowerShellMafia/PowerSploit/blob/master/Privesc/PowerUp.ps1) · [link](https://attack.mitre.org/techniques/T1574/007/) · [link](https://learn.microsoft.com/en-us/sysinternals/downloads/accesschk)

### SeBackupPrivilege / SeRestorePrivilege abuse
*id:* `windows-sebackup-serestore` · *category:* `privileges` · *severity:* **high**

SeBackupPrivilege bypasses file ACLs for read (backup semantics) and SeRestorePrivilege bypasses them for write, letting a non-admin read protected files (SAM/SYSTEM hives, other users' data) or overwrite protected files/registry to escalate.

**How it works —** SeBackupPrivilege opens files with FILE_FLAG_BACKUP_SEMANTICS, ignoring the DACL, so an attacker can copy the SAM and SYSTEM registry hives (e.g. via a shadow copy created with diskshadow, or robocopy /b) and extract local hashes offline. SeRestorePrivilege conversely allows writing to normally-protected locations, enabling overwrite of a service binary, a privileged DLL, or registry values (e.g. an IFEO debugger or service ImagePath) to gain SYSTEM. These map to the legitimate Backup/Restore Operators rights being over-assigned.

**Prerequisites:** Token with SeBackupPrivilege (read) and/or SeRestorePrivilege (write) enabled, e.g. Backup Operators membership

**Enumerate:**
- `whoami /priv`
- `whoami /groups (look for Backup Operators)`
- `reg save HKLM\SAM sam.hive (succeeds with SeBackup)`

**Detection indicators:** `"SeBackupPrivilege"/"SeRestorePrivilege" Enabled in whoami /priv`, `Membership in BUILTIN\Backup Operators`, `diskshadow.exe / vssadmin shadow-copy creation by non-backup software`, `reg save/robocopy /b of SAM,SYSTEM,SECURITY hives`, `Event 4674/4985 around backup-semantics file access`

**Tools:** sebackupprivilege (giuliano108) powershell cmdlets, diskshadow, robocopy, impacket-secretsdump

**Mitigation:** Restrict Backup Operators membership; avoid granting these rights to service/user accounts; Monitor shadow-copy creation and SAM/SYSTEM hive access; Use least-privilege backup solutions with auditing

**References:** [link](https://github.com/giuliano108/SeBackupPrivilege) · [link](https://github.com/fortra/impacket) · [link](https://ppn.snovvcrash.rocks/pentest/infrastructure/ad/privileges-abuse/sebackup-serestore) · [link](https://www.ired.team/offensive-security-experiments/active-directory-kerberos-abuse/privileged-accounts-and-token-privileges)

### SeDebugPrivilege abuse (LSASS access & process injection)
*id:* `windows-sedebugprivilege` · *category:* `privileges` · *severity:* **high**

SeDebugPrivilege lets a token open any process (including SYSTEM/protected-adjacent processes) with full access, enabling LSASS memory dumping for credential theft and code injection/token theft into SYSTEM processes.

**How it works —** With SeDebugPrivilege, OpenProcess against arbitrary PIDs succeeds, allowing a debugger-class actor to read/write another process's memory. Offensively this is used to (a) call MiniDumpWriteDump on lsass.exe and harvest credentials offline, or (b) inject into or duplicate the token of an existing SYSTEM process and spawn a SYSTEM child. It does not bypass full PPL protection on LSASS by itself, but grants the access needed for classic dumping and token-manipulation primitives.

**Prerequisites:** Token with SeDebugPrivilege enabled (typically already Administrator; sometimes granted to service/backup accounts)

**Enumerate:**
- `whoami /priv`
- `tasklist /v`
- `Get-Process lsass`

**Detection indicators:** `"SeDebugPrivilege" State=Enabled in whoami /priv`, `Process opening lsass.exe with PROCESS_VM_READ/QUERY (Sysmon Event ID 10 targeting lsass.exe)`, `Security Event 4703 (token privilege adjusted) enabling SeDebugPrivilege`, `MiniDump/comsvcs usage against lsass`

**Tools:** mimikatz, procdump, nanodump, seatbelt, privesccheck

**Mitigation:** Enable LSA Protection (RunAsPPL) and Credential Guard; Restrict the 'Debug programs' user right to Administrators only; Alert on non-EDR handles to lsass.exe (Sysmon EID 10)

**References:** [link](https://github.com/gentilkiwi/mimikatz) · [link](https://github.com/fortra/nanodump) · [link](https://attack.mitre.org/techniques/T1003/001/) · [link](https://learn.microsoft.com/en-us/windows/security/threat-protection/security-policy-settings/debug-programs) · [link](https://www.ired.team/offensive-security-experiments/active-directory-kerberos-abuse/privileged-accounts-and-token-privileges)

### SeLoadDriverPrivilege abuse (vulnerable/kernel driver load)
*id:* `windows-seloaddriver` · *category:* `privileges` · *severity:* **high**

SeLoadDriverPrivilege lets a token load kernel drivers via NtLoadDriver from an HKCU-referenced registry path, enabling a BYOVD (bring-your-own-vulnerable-driver) chain such as loading Capcom.sys and executing attacker code in kernel mode for SYSTEM/kernel escalation.

**How it works —** The privilege allows calling NtLoadDriver. The attacker creates a driver-service registry key under HKEY_CURRENT_USER (writable without admin) pointing ImagePath at a chosen driver, enables the privilege, and loads it. Loading a known-vulnerable but validly-signed driver (e.g. Capcom.sys, which exposes an IOCTL to run arbitrary code in kernel context) then lets a second-stage exploit execute kernel code to elevate. EoPLoadDriver automates the privilege enable + registry key + NtLoadDriver steps.

**Prerequisites:** Token with SeLoadDriverPrivilege enabled; A vulnerable signed driver available on disk (or loadable) plus a second-stage exploit for it; Ability to write the HKCU driver-service registry key

**Enumerate:**
- `whoami /priv`
- `reg query HKCU (to confirm write access for the driver key)`

**Detection indicators:** `"SeLoadDriverPrivilege" Enabled in whoami /priv`, `NtLoadDriver / new driver-service key under HKU\<SID> ImagePath`, `Capcom.sys or other known-vulnerable driver on disk`, `Event 4697/7045 or Sysmon EID 6 (driver load) of an unsigned-by-vendor or blocklisted driver`, `EoPLoadDriver.exe / ExploitCapcom.exe artifacts`

**Tools:** eoploaddriver (tarlogicsecurity), capcom.sys, dsefix

**Mitigation:** Restrict 'Load and unload device drivers' right to Administrators; Enable Microsoft vulnerable-driver blocklist and HVCI/Memory Integrity; Monitor new kernel driver loads (Sysmon EID 6) against a known-good allowlist

**References:** [link](https://github.com/TarlogicSecurity/EoPLoadDriver) · [link](https://www.tarlogic.com/blog/seloaddriverprivilege-privilege-escalation/) · [link](https://learn.microsoft.com/en-us/windows-hardware/drivers/dashboard/microsoft-recommended-driver-block-rules)

### SeManageVolumePrivilege abuse
*id:* `windows-semanagevolume` · *category:* `privileges` · *severity:* **high**

SeManageVolumePrivilege (Perform volume maintenance tasks) can be abused via FSCTL_SD_GLOBAL_CHANGE to alter the global security descriptor on the volume, effectively granting broad write access to C:\ that enables planting a DLL a SYSTEM service will load.

**How it works —** The privilege permits low-level volume operations. A public technique issues FSCTL_SD_GLOBAL_CHANGE to rewrite SIDs in security descriptors across the volume, granting standard users write access to normally-protected directories. With write access to C:\Windows\System32 (or a spooler/wbem drivers path), the attacker drops a malicious DLL that a SYSTEM process loads (e.g. via a Print Spooler PrintConfig.dll load), yielding SYSTEM.

**Prerequisites:** Token with SeManageVolumePrivilege enabled; A SYSTEM process that will load a DLL from a now-writable path

**Enumerate:**
- `whoami /priv`
- `icacls C:\Windows\System32`

**Detection indicators:** `"SeManageVolumePrivilege" Enabled in whoami /priv`, `SeManageVolumeExploit.exe on disk`, `FSCTL_SD_GLOBAL_CHANGE volume operations by a non-admin`, `New DLL written to System32/spool/wbem by a standard user, followed by SYSTEM DLL load (Sysmon EID 7)`

**Tools:** semanagevolumeexploit (csenox)

**Mitigation:** Restrict 'Perform volume maintenance tasks' to Administrators; File integrity monitoring on System32 and driver directories; Application allow-listing to block untrusted DLL loads

**References:** [link](https://github.com/CsEnox/SeManageVolumeExploit) · [link](https://hackfa.st/Offensive-Security/Windows-Environment/Privilege-Escalation/Token-Impersonation/SeManageVolumePrivilege/) · [link](https://github.com/gtworek/Priv2Admin)

### SeTakeOwnershipPrivilege abuse
*id:* `windows-setakeownership` · *category:* `privileges` · *severity:* **high**

SeTakeOwnershipPrivilege lets a token take ownership of any securable object without WRITE_OWNER being granted, after which the new owner can rewrite the DACL to grant full control over a privileged file, registry key, or service and escalate to SYSTEM.

**How it works —** The privilege allows setting oneself as the owner of an object (file, registry key, service) regardless of its DACL. Once owner, the attacker edits the DACL to grant themselves full control, then modifies a SYSTEM-executed resource: replace or hijack a DLL/binary loaded by a SYSTEM service, alter a service's configuration, or edit a privileged registry key. Native takeown.exe and icacls can perform the ownership/ACL changes.

**Prerequisites:** Token with SeTakeOwnershipPrivilege enabled; A SYSTEM-executed file/registry target that can be triggered after modification

**Enumerate:**
- `whoami /priv`
- `icacls C:\Path\To\service.exe`
- `sc qc <service>`

**Detection indicators:** `"SeTakeOwnershipPrivilege" Enabled in whoami /priv`, `takeown.exe / SetSecurityInfo ownership changes on system32/service binaries`, `Event 4670 (permissions on an object were changed) on privileged files/keys`, `New owner set on a service binary or DLL by a non-admin SID`

**Tools:** takeown.exe, icacls, powerup, accesschk

**Mitigation:** Restrict the 'Take ownership of files or other objects' user right to Administrators; File integrity monitoring / audit object-access on system binaries and services; Alert on ownership changes to protected paths

**References:** [link](https://github.com/PowerShellMafia/PowerSploit) · [link](https://github.com/gtworek/Priv2Admin) · [link](https://github.com/gtworek/Priv2Admin) · [link](https://learn.microsoft.com/en-us/windows/security/threat-protection/security-policy-settings/take-ownership-of-files-or-other-objects)

### Unquoted Service Path
*id:* `windows-unquoted-service-path` · *category:* `service-misconfig` · *severity:* **high**

A service whose ImagePath is unquoted and contains spaces lets a low-privileged user drop a binary at an intermediate path token that the SCM launches as the service account (often SYSTEM).

**How it works —** The Service Control Manager parses an unquoted ImagePath left-to-right, splitting on spaces. For C:\Program Files\Some App\svc.exe it attempts C:\Program.exe, then C:\Program Files\Some.exe, before the real target. If any intermediate directory in that chain is user-writable, planting a same-named executable there causes it to run at the service's privilege level on next start/restart or reboot.

**Prerequisites:** write access to an intermediate directory in the unquoted path; ability to restart the service or reboot

**Enumerate:**
- `wmic service get name,displayname,pathname,startmode | findstr /i /v "\"" | findstr /i /v "C:\\Windows\\"`
- `Get-CimInstance Win32_Service | ? { $_.PathName -notmatch '^\"' -and $_.PathName -match ' ' -and $_.PathName -notmatch 'C:\\Windows' } | Select Name,PathName,StartName,StartMode`
- `sc.exe qc <service>`
- `PowerUp: Get-UnquotedService  (or Invoke-AllChecks)`
- `accesschk.exe -accepteula -uwdq "<intermediate directory>"  (test write access)`

**Detection indicators:** `BINARY_PATH_NAME / ImagePath value not wrapped in quotes AND containing a space`, `service binary path resolving into a user-writable directory (e.g. under C:\ or a writable Program Files subfolder)`, `StartMode Auto with a non-System32 unquoted path`, `unquoted`

**Tools:** winpeas, powerup, privesccheck, sharpup, sc.exe, wmic, accesschk

**Mitigation:** quote every ImagePath containing spaces; restrict write DACLs on Program Files subdirectories and C:\ root; install services into protected, non-writable locations

**References:** [link](https://book.hacktricks.xyz/windows-hardening/windows-local-privilege-escalation#unquoted-service-paths) · [link](https://github.com/PowerShellMafia/PowerSploit/blob/master/Privesc/PowerUp.ps1) · [link](https://attack.mitre.org/techniques/T1574/009/) · [link](https://learn.microsoft.com/en-us/sysinternals/downloads/accesschk)

### WSUS over-HTTP abuse (WSUSpendu / PyWSUS)
*id:* `windows-wsus-http-abuse` · *category:* `service-misconfig` · *severity:* **high** · *CVE:* CVE-2020-1013

When domain clients pull Windows updates from a WSUS server over cleartext HTTP, a man-in-the-middle (or a compromised WSUS server) can inject a signed-but-legitimate Microsoft binary plus attacker arguments as a fake 'update', which the SYSTEM-level update agent installs — yielding local SYSTEM code execution.

**How it works —** WSUS clients are configured via HKLM\SOFTWARE\Policies\Microsoft\Windows\WindowsUpdate (WUServer/WUStatusServer, UseWUServer). If WUServer is an http:// URL, update metadata and approvals travel unencrypted. WSUS only requires that the deployed binary be Microsoft-signed — not that it be an actual update — so tools like PyWSUS (MITM the HTTP channel and serve a crafted approval) or WSUSpendu (inject an update directly on a compromised WSUS server) deliver a legitimately-signed LOLBIN such as PsExec with attacker-controlled command-line arguments. The Windows Update agent, running as SYSTEM, executes it, giving local privilege escalation (and lateral movement to every client of that WSUS). CVE-2020-1013 covered a related WSUS/proxy LPE.

**Prerequisites:** target uses WSUS over HTTP (no TLS pinning), AND; a MITM position on the client-WSUS path (e.g. via ARP/DNS/NBNS spoofing), OR admin on the WSUS server

**Enumerate:**
- `reg query HKLM\SOFTWARE\Policies\Microsoft\Windows\WindowsUpdate`
- `reg query HKLM\SOFTWARE\Policies\Microsoft\Windows\WindowsUpdate\AU`
- `Get-ItemProperty HKLM:\SOFTWARE\Policies\Microsoft\Windows\WindowsUpdate`
- `gpresult /h report.html`

**Detection indicators:** `WUServer`, `UseWUServer`, `http://`, `WindowsUpdate\AU`, `WSUS`

**Tools:** pywsus, wsuspendu, responder, mitm6

**Mitigation:** Configure WSUS to use HTTPS (TLS) for the WUServer URL; Segment and harden WSUS servers; restrict who can approve updates; Prevent local MITM (802.1x, disable LLMNR/NBT-NS, dynamic ARP inspection); Consider signed-metadata/ESU controls and monitor for rogue approvals

**References:** [link](https://github.com/GoSecure/pywsus) · [link](https://github.com/AlsidOfficial/WSUSpendu) · [link](https://www.gosecure.net/blog/2020/09/03/wsus-attacks-part-1-introducing-pywsus/) · [link](https://www.gosecure.net/blog/2020/10/29/wsus-attacks-part-2-cve-2020-1013-a-windows-10-local-privilege-escalation-1-day/) · [link](https://book.hacktricks.xyz/windows-hardening/windows-local-privilege-escalation#wsus)

### UAC Bypass via eventvwr.exe
*id:* `windows-uac-bypass-eventvwr` · *category:* `uac-bypass` · *severity:* **high**

eventvwr.exe auto-elevates and opens its .msc via the HKCU mscfile\shell\open\command handler; hijacking that per-user key runs an arbitrary command at high integrity without a UAC prompt.

**How it works —** eventvwr.exe (auto-elevate) launches eventvwr.msc using the mscfile file association, resolved from HKCU\Software\Classes\mscfile\shell\open\command before HKLM. A medium-integrity administrator sets that key to an arbitrary command; running eventvwr.exe then executes it at high integrity. The technique is fileless (registry only). Discovered by Matt Nelson (enigma0x3) and Matt Graeber.

**Prerequisites:** member of local Administrators in Admin Approval Mode

**Enumerate:**
- `reg query "HKCU\Software\Classes\mscfile\shell\open\command"  (absence is normal)`
- `monitor that key for writes`

**Detection indicators:** `creation/modification of HKCU\Software\Classes\mscfile\shell\open\command`, `eventvwr.exe spawning non-mmc.exe children`, `Sigma/Splunk 'eventvwr UAC bypass' registry rules firing`

**Tools:** uacme, metasploit-bypassuac_eventvwr, reg.exe

**Mitigation:** set UAC to Always Notify; remove admin rights from daily accounts; alert on mscfile\shell\open\command writes

**References:** [link](https://enigma0x3.net/2016/08/15/fileless-uac-bypass-using-eventvwr-exe-and-registry-hijacking/) · [link](https://pentestlab.blog/2017/05/02/uac-bypass-event-viewer/) · [link](https://attack.mitre.org/techniques/T1548/002/) · [link](https://lolbas-project.github.io/lolbas/Binaries/Eventvwr/)

### UAC Bypass via fodhelper.exe
*id:* `windows-uac-bypass-fodhelper` · *category:* `uac-bypass` · *severity:* **high**

fodhelper.exe auto-elevates and reads a per-user ms-settings shell command key that is absent by default; creating it under HKCU runs an attacker command at high integrity with no UAC prompt.

**How it works —** On Windows 10+, fodhelper.exe is a Microsoft-signed auto-elevating binary that queries HKCU\Software\Classes\ms-settings\Shell\Open\command (honoring a DelegateExecute value). A medium-integrity administrator creates that key, sets its default command, and runs fodhelper.exe; the command executes at high integrity. This bypasses UAC for an admin-in-Admin-Approval-Mode (medium to high integrity) — it is not a cross-user escalation. computerdefaults.exe behaves similarly.

**Prerequisites:** member of local Administrators running in Admin Approval Mode (default UAC)

**Enumerate:**
- `reg query "HKCU\Software\Classes\ms-settings\Shell\Open\command"  (absence is normal)`
- `reg query HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System /v ConsentPromptBehaviorAdmin  (check UAC level)`
- `monitor the ms-settings command key for creation`

**Detection indicators:** `creation of HKCU\Software\Classes\ms-settings\Shell\Open\command, especially a DelegateExecute value`, `fodhelper.exe spawning cmd.exe/powershell.exe or other children`, `Sysmon RegSetValue on ms-settings\shell\open\command`

**Tools:** uacme, metasploit-bypassuac_fodhelper, reg.exe

**Mitigation:** set UAC to Always Notify; remove administrator rights from daily-use accounts; alert on ms-settings\shell\open\command creation

**References:** [link](https://winscripting.blog/2017/05/12/first-entry-welcome-and-uac-bypass/) · [link](https://pentestlab.blog/2017/06/07/uac-bypass-fodhelper/) · [link](https://attack.mitre.org/techniques/T1548/002/) · [link](https://github.com/hfiref0x/UACME)

### UAC Bypass via sdclt.exe
*id:* `windows-uac-bypass-sdclt` · *category:* `uac-bypass` · *severity:* **high**

The auto-elevating sdclt.exe (Backup and Restore) can be abused through HKCU App Paths or its IsolatedCommand key so a per-user registry entry executes an arbitrary command at high integrity without prompting.

**How it works —** On Windows 10, sdclt.exe auto-elevates. Two documented, fileless registry hijacks exist: (a) the App Paths / control.exe route via HKCU\Software\Classes\Folder\shell\open\command, and (b) the IsolatedCommand route via HKCU\Software\Classes\exefile\shell\runas\command\IsolatedCommand. Setting the per-user key and launching sdclt.exe (e.g. with /KickOffElev) runs the command at high integrity. Both discovered by enigma0x3.

**Prerequisites:** member of local Administrators in Admin Approval Mode

**Enumerate:**
- `reg query "HKCU\Software\Classes\Folder\shell\open\command"`
- `reg query "HKCU\Software\Classes\exefile\shell\runas\command"`
- `monitor those keys for creation`

**Detection indicators:** `writes to HKCU\Software\Classes\Folder\shell\open\command`, `writes to HKCU\Software\Classes\exefile\shell\runas\command\IsolatedCommand`, `sdclt.exe spawning cmd.exe/powershell.exe`

**Tools:** uacme, metasploit, reg.exe

**Mitigation:** set UAC to Always Notify; remove admin rights from daily accounts; alert on the sdclt-related HKCU key writes

**References:** [link](https://enigma0x3.net/2017/03/17/fileless-uac-bypass-using-sdclt-exe/) · [link](https://enigma0x3.net/2017/03/14/bypassing-uac-using-app-paths/) · [link](https://attack.mitre.org/techniques/T1548/002/) · [link](https://pentestlab.blog/2017/06/09/uac-bypass-sdclt/)

### UAC Bypass via SilentCleanup / DiskCleanup Scheduled Task
*id:* `windows-uac-bypass-silentcleanup` · *category:* `uac-bypass` · *severity:* **high**

The built-in SilentCleanup scheduled task runs cleanmgr.exe with highest privileges and is startable by unprivileged users; because its action expands the user-controllable %windir% variable, redirecting windir in HKCU\Environment runs an attacker binary elevated.

**How it works —** \Microsoft\Windows\DiskCleanup\SilentCleanup is configured RunLevel=Highest but its principal lets Users start it. Its action path uses %windir%\system32\cleanmgr.exe, and environment variables resolve from the invoking user; windir can be overridden via HKCU\Environment. Setting windir to an attacker launcher and starting the task executes it auto-elevated with no prompt. Unlike binary/DLL hijacks this abuses environment-variable expansion inside an auto-elevated task, a class documented by James Forshaw (Tyranid's Lair).

**Prerequisites:** member of local Administrators in Admin Approval Mode (SilentCleanup auto-elevates for admins)

**Enumerate:**
- `schtasks /query /tn "\Microsoft\Windows\DiskCleanup\SilentCleanup" /fo LIST /v`
- `reg query "HKCU\Environment" /v windir   (absence is normal)`
- `Get-ScheduledTask -TaskName SilentCleanup | Select -ExpandProperty Principal`

**Detection indicators:** `HKCU\Environment 'windir' set to a non-default value`, `SilentCleanup task started by a non-SYSTEM user`, `cleanmgr.exe or its child spawned from an unusual path`

**Tools:** schtasks, uacme, metasploit-bypassuac_silentcleanup, reg.exe

**Mitigation:** reconfigure the task to not use environment variables; set UAC to Always Notify; alert on HKCU\Environment windir being set; remove admin rights from daily accounts

**References:** [link](https://www.tiraniddo.dev/2017/05/exploiting-environment-variables-in.html) · [link](https://www.rapid7.com/db/modules/exploit/windows/local/bypassuac_silentcleanup/) · [link](https://attack.mitre.org/techniques/T1548/002/) · [link](https://github.com/hfiref0x/UACME)

### Weak Service Executable File Permissions
*id:* `windows-weak-service-binary-file-permissions` · *category:* `writable-file` · *severity:* **high**

When the on-disk executable a service runs (or its containing folder) is writable by a low-privileged user, the user replaces the binary and it executes as the service account at next start.

**How it works —** Independent of SCM object rights, the NTFS DACL on the service's EXE (or a parent folder that permits create/rename/delete) can allow a non-admin to overwrite or swap the binary. On the next service start or reboot the SCM launches the trojanized file at the service's privilege (commonly SYSTEM). Folder write can enable a delete-and-recreate replacement even when the file itself is locked.

**Prerequisites:** write access to the service binary or its containing folder; ability to restart the service or reboot

**Enumerate:**
- `accesschk.exe -accepteula -quv "C:\Path\service.exe"`
- `icacls "C:\Path\service.exe"`
- `Get-Acl "C:\Path\service.exe" | Format-List`
- `PowerUp: Get-ModifiableServiceFile`

**Detection indicators:** `icacls/accesschk shows (F)/(M)/(W) or WRITE_DAC/FILE_WRITE_DATA for Users/Authenticated Users/Everyone on a service binary or its folder`, `service executable located outside %WinDir% in a user-writable path`, `service binary with non-inherited weak ACE`

**Tools:** accesschk, icacls, powerup, winpeas, privesccheck

**Mitigation:** restrict binary and folder DACLs to Administrators/SYSTEM; store service binaries in protected system locations; enable file integrity monitoring on service EXEs

**References:** [link](https://book.hacktricks.xyz/windows-hardening/windows-local-privilege-escalation#services-binaries-weak-permissions) · [link](https://github.com/PowerShellMafia/PowerSploit/blob/master/Privesc/PowerUp.ps1) · [link](https://attack.mitre.org/techniques/T1574/010/) · [link](https://learn.microsoft.com/en-us/sysinternals/downloads/accesschk)

### Autoruns / Startup Folder & Run Keys
*id:* `windows-autoruns-startup-runkeys` · *category:* `autoruns` · *severity:* **medium**

Writable HKLM Run/RunOnce keys, the all-users Startup folder, or Winlogon Userinit/Shell values let a low-privileged user plant a payload that executes in the context of the next (often administrative) user to log on.

**How it works —** Programs referenced by HKLM\Software\Microsoft\Windows\CurrentVersion\Run[Once], the common Startup folder (C:\ProgramData\Microsoft\Windows\Start Menu\Programs\StartUp), and Winlogon Userinit/Shell run automatically at logon. If those keys, folders, or the binaries they reference are writable by a non-admin, the attacker adds or overwrites an entry; it executes when an administrator logs on, escalating to that user. It doubles as persistence.

**Prerequisites:** write access to an autorun location and/or the binary it references; a higher-privileged user subsequently logs on

**Enumerate:**
- `reg query HKLM\Software\Microsoft\Windows\CurrentVersion\Run`
- `reg query HKLM\Software\Microsoft\Windows\CurrentVersion\RunOnce`
- `reg query "HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon" /v Userinit`
- `autorunsc.exe -accepteula -a * -c`
- `accesschk.exe -accepteula -kvuqsw HKLM\Software\Microsoft\Windows\CurrentVersion\Run`

**Detection indicators:** `writable DACL on an HKLM Run/RunOnce key or on a binary it references`, `unexpected value under Run/RunOnce or a modified Winlogon Shell/Userinit`, `user-writable ProgramData Startup folder`, `autorunsc flags unsigned/user-writable autostart entries`

**Tools:** autoruns, autorunsc, reg.exe, powerup, accesschk, winpeas

**Mitigation:** restrict DACLs on autorun keys, folders and referenced binaries; monitor with Sysinternals Autoruns; deploy application allow-listing (WDAC/AppLocker)

**References:** [link](https://book.hacktricks.xyz/windows-hardening/windows-local-privilege-escalation#run-at-startup) · [link](https://www.hexacorn.com/blog/2013/12/08/beyond-good-ol-run-key-part-5/) · [link](https://attack.mitre.org/techniques/T1547/001/) · [link](https://learn.microsoft.com/en-us/sysinternals/downloads/autoruns)

### COM Hijacking (HKCU CLSID)
*id:* `windows-com-hijacking` · *category:* `com-hijack` · *severity:* **medium**

Because HKCU is searched before HKLM for COM class registrations, populating a per-user CLSID InprocServer32/LocalServer32 that shadows or fills an abandoned system CLSID causes a privileged or auto-elevated process to load attacker code.

**How it works —** COM resolves a CLSID by checking HKCU\Software\Classes\CLSID first, then HKLM. A non-admin can register an HKCU entry for a CLSID that a higher-privileged, auto-elevated, or scheduled process instantiates, pointing InprocServer32 at a malicious DLL — or abuse an orphaned CLSID whose server is missing. The code then runs in the consuming process's context, frequently combined with UAC bypass and persistence.

**Prerequisites:** a privileged/auto-elevated process instantiates a CLSID hijackable via HKCU

**Enumerate:**
- `Process Monitor filter: Operation=RegOpenKey AND Path contains \CLSID\ AND Result=NAME NOT FOUND`
- `reg query "HKCU\Software\Classes\CLSID" /s   (inspect InprocServer32 values)`
- `OleViewDotNet to enumerate registered/hijackable CLSIDs`

**Detection indicators:** `Process Monitor: privileged process RegOpenKey on HKCU\Software\Classes\CLSID\{...}\InprocServer32 with NAME NOT FOUND then HKLM fallback`, `new HKCU CLSID InprocServer32 entries referencing user-writable DLLs`, `references to abandoned/orphaned CLSIDs`

**Tools:** procmon, oleviewdotnet, accomplice, sharpup, winpeas

**Mitigation:** monitor HKCU CLSID InprocServer32 writes; prefer HKLM registration and full DLL paths; remove orphaned CLSID references; deploy WDAC/AppLocker DLL rules

**References:** [link](https://github.com/tyranid/oleviewdotnet) · [link](https://book.hacktricks.xyz/windows-hardening/windows-local-privilege-escalation#com-hijacking) · [link](https://attack.mitre.org/techniques/T1546/015/) · [link](https://learn.microsoft.com/en-us/windows/win32/com/com-registration)

### Cached domain credentials (MSCache/DCC2) extraction
*id:* `windows-cached-domain-credentials-dcc2` · *category:* `credential-harvesting` · *severity:* **medium**

Windows caches domain logon verifiers (MS-Cache v2 / DCC2) so users can log on when a domain controller is unreachable; these can be dumped from the SECURITY hive and cracked offline to recover domain account passwords.

**How it works —** Cached domain logon information is stored under HKLM\SECURITY\Cache as a salted PBKDF2/HMAC-derived verifier (DCC2, aka mscash2). It cannot be used directly in pass-the-hash, but is recovered from the SECURITY+SYSTEM hives (secretsdump, mimikatz lsadump::cache) and subjected to offline password cracking (hashcat mode 2100). Number of cached accounts is governed by the CachedLogonsCount policy.

**Prerequisites:** Local admin or SeBackup access to SECURITY and SYSTEM hives

**Enumerate:**
- `reg query "HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon" /v CachedLogonsCount`
- `reg save HKLM\SECURITY / HKLM\SYSTEM`

**Detection indicators:** `Access/export of HKLM\SECURITY hive`, `lsadump::cache or secretsdump usage`, `hashcat -m 2100 ($DCC2$) artifacts`

**Tools:** impacket-secretsdump, mimikatz lsadump::cache, hashcat

**Mitigation:** Lower CachedLogonsCount (e.g. to 0-1) on servers where offline logon is unnecessary; Enforce strong/long passwords to resist offline cracking; Restrict local admin; monitor SECURITY hive access

**References:** [link](https://github.com/fortra/impacket) · [link](https://github.com/gentilkiwi/mimikatz) · [link](https://attack.mitre.org/techniques/T1003/005/) · [link](https://hashcat.net/wiki/doku.php?id=example_hashes)

### Stored credentials in registry, files & apps (autologon, PuTTY, Wi-Fi, VNC)
*id:* `windows-registry-app-wifi-stored-creds` · *category:* `credential-harvesting` · *severity:* **medium**

Passwords are commonly left in cleartext or trivially-recoverable form in the registry (Winlogon AutoAdminLogon DefaultPassword), application configs (PuTTY, WinSCP, VNC, OpenVPN), and Wi-Fi profiles, providing easy credential wins for lateral movement or escalation.

**How it works —** Automatic-logon configuration stores DefaultPassword under HKLM\...\Winlogon in cleartext. Third-party apps store credentials weakly: PuTTY proxy passwords and stored sessions, WinSCP saved sessions (obfuscated, reversible), VNC password (fixed-key DES), OpenVPN, and SNMP/PuTTY registry entries. Wi-Fi PSKs are recoverable with netsh wlan show profile key=clear. Tools like LaZagne and winPEAS automate scraping all of these locations.

**Prerequisites:** Read access to the relevant registry keys/files (often standard-user readable)

**Enumerate:**
- `reg query "HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon" /v DefaultPassword`
- `reg query "HKCU\Software\SimonTatham\PuTTY\Sessions" /s`
- `netsh wlan show profile`
- `netsh wlan show profile name="SSID" key=clear`
- `findstr /si password *.xml *.ini *.config *.txt`

**Detection indicators:** `AutoAdminLogon=1 with a DefaultPassword value present`, `netsh wlan show profile key=clear execution`, `LaZagne/winPEAS scraping app-credential registry/files`, `cleartext password strings in config files under user/app directories`

**Tools:** lazagne, winpeas, seatbelt, netsh

**Mitigation:** Never use AutoAdminLogon with a stored DefaultPassword (use gMSA/scheduled logon alternatives); Avoid saving credentials in app configs; use credential managers/key vaults; Restrict who can read Wi-Fi profiles; audit config files for secrets

**References:** [link](https://github.com/AlessandroZ/LaZagne) · [link](https://github.com/peass-ng/PEASS-ng) · [link](https://attack.mitre.org/techniques/T1552/002/) · [link](https://attack.mitre.org/techniques/T1552/001/)

### Image File Execution Options (IFEO) Debugger Hijack
*id:* `windows-ifeo-debugger-hijack` · *category:* `writable-registry` · *severity:* **medium**

A Debugger value under an executable's IFEO key makes Windows launch that debugger instead of the target; write access to IFEO lets an attacker run code when a higher-privileged context launches the target EXE (classic sethc.exe / utilman.exe SYSTEM shell at the logon screen).

**How it works —** HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Image File Execution Options\<exe>\Debugger is honored by the loader, which runs the named program with the original as an argument; the related SilentProcessExit\MonitorProcess achieves a similar effect. Targeting an EXE that a higher-privileged process launches (or the accessibility binaries sethc.exe/utilman.exe reachable pre-authentication) yields code execution in that elevated/SYSTEM context. Writing IFEO normally needs admin/offline access, so this is chiefly a persistence and elevation-holding primitive.

**Prerequisites:** write access to the IFEO key (typically admin/offline); the target EXE is later launched by a higher-privileged context

**Enumerate:**
- `reg query "HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Image File Execution Options" /s /v Debugger`
- `autorunsc.exe -accepteula -t`
- `Get-ChildItem 'HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Image File Execution Options' | Get-ItemProperty | ? { $_.Debugger }`

**Detection indicators:** `a Debugger value present under an IFEO subkey for a common EXE (cmd, sethc, utilman, magnify)`, `SilentProcessExit MonitorProcess entries`, `Autoruns 'Image Hijacks' tab populated`

**Tools:** reg.exe, autoruns, autorunsc, gflags, get-acl

**Mitigation:** restrict the IFEO key DACL to Administrators; monitor creation of Debugger / MonitorProcess values; set an SLA on unexpected IFEO entries; use Autoruns to review

**References:** [link](https://book.hacktricks.xyz/windows-hardening/windows-local-privilege-escalation#image-file-execution-options) · [link](https://learn.microsoft.com/en-us/windows-hardware/drivers/debugger/how-to-launch-a-debugger-automatically) · [link](https://attack.mitre.org/techniques/T1546/012/) · [link](https://learn.microsoft.com/en-us/sysinternals/downloads/autoruns)


## Container / Kubernetes privilege escalation

### cgroups v1 release_agent container escape (CVE-2022-0492)
*id:* `container-cgroup-release-agent-cve-2022-0492` · *category:* `container-escape` · *severity:* **critical** · *CVE:* CVE-2022-0492

A container that can mount the cgroup v1 filesystem (privileged, or with CAP_SYS_ADMIN and no seccomp/AppArmor) can write to the release_agent file to run an attacker binary in the host namespace as root.

**How it works —** The cgroup v1 release_agent is a host path executed by the kernel (in the initial namespace, as root) when the last task leaves a cgroup that has notify_on_release=1. An escapee mounts a fresh cgroup hierarchy, sets release_agent to a script placed on a host-visible path (resolved via the container's /proc/<pid>/root overlay path), enables notify_on_release, then empties the cgroup so the kernel runs the script on the host. CVE-2022-0492 made this reachable from an unprivileged user namespace because the kernel did not check CAP_SYS_ADMIN in the correct namespace when writing release_agent, so even non-privileged containers were affected on unpatched kernels.

**Prerequisites:** ability to mount a cgroup v1 filesystem (privileged container, or CAP_SYS_ADMIN); no seccomp/AppArmor profile blocking mount() (default Docker seccomp blocks it; --privileged or --security-opt seccomp=unconfined re-enables it); unpatched kernel for the unprivileged (user-namespace) variant

**Enumerate:**
- `cat /proc/self/status | grep CapEff`
- `capsh --print`
- `cat /proc/1/cgroup`
- `ls -la /sys/fs/cgroup`
- `grep -i cgroup /proc/filesystems`
- `cat /proc/self/mountinfo | grep cgroup`

**Detection indicators:** `release_agent`, `notify_on_release`, `CapEff:	0000003fffffffff`, `cap_sys_admin`, `rdma`, `unprivileged_userns_clone`

**Tools:** amicontained, deepce, cdk, linpeas

**Mitigation:** Patch the kernel (fix restores CAP_SYS_ADMIN check in the correct user namespace); Do not run privileged containers; drop CAP_SYS_ADMIN; Keep the default Docker/containerd seccomp profile (blocks mount); Use AppArmor/SELinux and cgroup v2 (release_agent removed); Set kernel.unprivileged_userns_clone=0 where feasible

**References:** [link](https://unit42.paloaltonetworks.com/cve-2022-0492-cgroups/) · [link](https://sysdig.com/blog/detecting-mitigating-cve-2021-0492-sysdig/) · [link](https://blog.aquasec.com/cve-2022-0492-cgroups-container-escape) · [link](https://nvd.nist.gov/vuln/detail/CVE-2022-0492) · [link](https://book.hacktricks.xyz/linux-hardening/privilege-escalation/docker-security/docker-breakout-privilege-escalation/release_agent-exploit-relative-paths-to-pids)

### Mounted Docker socket container escape
*id:* `container-docker-socket` · *category:* `container-escape` · *severity:* **critical**

Access to /var/run/docker.sock (or membership of the docker group) is root-equivalent: it lets you start a container that mounts the host filesystem.

**How it works —** The Docker API on the socket can launch a privileged container bind-mounting the host root, giving full read/write on the host and thus root.

**Prerequisites:** readable/writable docker.sock or docker group membership

**Enumerate:**
- `id`
- `ls -la /var/run/docker.sock`
- `docker ps`

**Detection indicators:** `docker.sock`, `docker`, `/var/run/docker.sock`

**Tools:** linpeas, deepce, cdk

**Mitigation:** Never expose docker.sock to untrusted workloads; Restrict docker group membership

**References:** [link](https://book.hacktricks.xyz/linux-hardening/privilege-escalation/docker-security) · [link](https://docs.docker.com/engine/security/)

### runc /proc/self/exe host binary overwrite (CVE-2019-5736)
*id:* `container-runc-procselfexe-cve-2019-5736` · *category:* `container-escape` · *severity:* **critical** · *CVE:* CVE-2019-5736

A malicious image or a compromised container that can control an entered process can overwrite the host runc binary via /proc/self/exe, so the next 'docker exec'/container start runs attacker code on the host as root.

**How it works —** When runc executes as PID 1 in a container (or during docker exec), the container process can open the host runc via /proc/self/exe (a magic symlink to the running binary), then hold a writable file descriptor to it (e.g. by replacing the container's own /bin/sh entrypoint with #!/proc/self/exe and re-opening the fd O_WRONLY once runc re-execs through it). Writing a new ELF over that descriptor overwrites the runc binary on the host filesystem. The next invocation of runc by the container engine executes the attacker payload with host root privileges, breaking out of the container. Affects Docker, containerd, CRI-O, Kubernetes and any runc-based runtime prior to the patched 1.0-rc7.

**Prerequisites:** run a malicious image, OR docker exec into an already-attacker-controlled container; runc / container runtime older than the CVE-2019-5736 fix

**Enumerate:**
- `runc --version`
- `docker version`
- `ls -la /proc/self/exe`
- `cat /etc/os-release`

**Detection indicators:** `runc version 1.0.0-rc6`, `/proc/self/exe`, `libcontainer`, `ETXTBSY`

**Tools:** deepce

**Mitigation:** Upgrade runc to >= 1.0.0-rc7 / patched distro packages (fix seals /proc/self/exe with a memfd copy); Do not run or exec into untrusted images; Run containers as non-root users and with user namespaces; Use read-only root filesystems and SELinux/AppArmor confinement

**References:** [link](https://github.com/Frichetten/CVE-2019-5736-PoC) · [link](https://unit42.paloaltonetworks.com/breaking-docker-via-runc-explaining-cve-2019-5736/) · [link](https://seclists.org/oss-sec/2019/q1/119) · [link](https://nvd.nist.gov/vuln/detail/CVE-2019-5736) · [link](https://blog.dragonsector.pl/2019/02/cve-2019-5736-escape-from-docker-and.html)

### Sensitive host mounts / exposed sockets / core_pattern escape
*id:* `container-sensitive-host-mounts-corepattern` · *category:* `container-escape` · *severity:* **critical**

Containers that expose host paths or sockets — a bind-mounted host filesystem, /var/run/docker.sock or a runtime socket, host /proc, or a writable /proc/sys/kernel/core_pattern — let the workload read/modify the host or execute host-side code and escape to node root.

**How it works —** Several distinct-but-related misconfigurations grant host reach: (1) a bind mount of the host root or of host directories like /, /etc, /root, or /var/log lets you read/write host files (add SSH keys, edit crontabs); (2) a mounted docker.sock or containerd/CRI socket exposes the runtime API, letting you launch a new privileged container that mounts the host root (see container-docker-socket); (3) with host /proc mounted (or in a --privileged container that can see the real /proc), writing a pipe handler (|/path/to/payload) into /proc/sys/kernel/core_pattern causes the host kernel to execute that program as root the next time any process core-dumps — deliberately crashing a process triggers host code execution; (4) exposed /dev block devices allow reading/writing the host disk directly. Each path collapses the container boundary to node root.

**Prerequisites:** a host-sensitive mount, exposed runtime socket, or writable core_pattern (typically --privileged, or explicit -v/hostPath mounts)

**Enumerate:**
- `cat /proc/self/mountinfo`
- `mount`
- `findmnt`
- `ls -la /var/run/docker.sock /run/containerd/containerd.sock`
- `cat /proc/sys/kernel/core_pattern`
- `ls -la /host /rootfs 2>/dev/null`
- `ls -la /dev | grep -E 'sd|nvme|xvd'`

**Detection indicators:** `/proc/sys/kernel/core_pattern`, `docker.sock`, `containerd.sock`, `hostPath`, `/host/proc`, `rw,relatime - ext4`

**Tools:** amicontained, deepce, cdk, linpeas, kubeletctl

**Mitigation:** Never bind-mount the host filesystem, /proc, or runtime sockets into untrusted containers; Mask /proc/sys and set core_pattern only on the host; keep default masked paths; Drop privileges and capabilities; avoid --privileged; Use read-only mounts and Pod Security admission / OPA policies to forbid hostPath and privileged

**References:** [link](https://blog.trailofbits.com/2019/07/19/understanding-docker-container-escapes/) · [link](https://book.hacktricks.xyz/linux-hardening/privilege-escalation/docker-security/sensitive-mounts) · [link](https://book.hacktricks.xyz/linux-hardening/privilege-escalation/docker-security) · [link](https://docs.docker.com/engine/security/)

### Kubernetes SA token / RBAC abuse & privileged pod node escape
*id:* `kubernetes-sa-token-rbac-privileged-pod` · *category:* `kubernetes` · *severity:* **critical**

A pod's mounted service-account token plus over-permissive RBAC (create pods/exec, get secrets, escalate/bind) lets an attacker schedule a hostPID/hostPath/privileged pod that reaches the node's filesystem and kubelet, taking over the worker and often the cluster.

**How it works —** Every pod (unless opted out) mounts a service-account JWT at /var/run/secrets/kubernetes.io/serviceaccount/token, usable against the API server. If the bound role grants powerful verbs — create/patch pods, pods/exec, pods/attach, get/list secrets, create rolebindings (bind/escalate), or access to nodes/proxy — the attacker abuses them: (a) create a pod with hostPID, hostNetwork, privileged:true or a hostPath volume mounting the node's / to read node secrets, kubelet certs and other pods' SA tokens; (b) exec into existing privileged pods; (c) read cluster secrets to pivot; (d) use 'escalate'/'bind' to grant themselves cluster-admin. Reaching a control-plane node or the kubelet (often on tokenless port 10250) yields cluster-wide compromise. Cloud clusters additionally let a node-level foothold hit the instance metadata service for the node IAM role.

**Prerequisites:** a reachable/stolen service-account token, or code execution in a pod; over-permissive RBAC (create pods, exec, get secrets, escalate/bind, nodes/proxy), or a namespace allowing privileged/hostPath pods

**Enumerate:**
- `cat /var/run/secrets/kubernetes.io/serviceaccount/token`
- `kubectl auth can-i --list`
- `kubectl auth can-i create pods`
- `kubectl get secrets -A`
- `kubectl get pods -o yaml | grep -i 'privileged\|hostPath\|hostPID'`
- `curl -sk https://<node-ip>:10250/pods`
- `kubectl get clusterrolebindings -o wide`

**Detection indicators:** `serviceaccount/token`, `kubernetes.io/serviceaccount`, `system:serviceaccount:`, `privileged: true`, `hostPID`, `hostPath`, `can-i`

**Tools:** kube-hunter, kubeletctl, peirates, kubesploit, kube-bench, rbac-tool

**Mitigation:** Enable Pod Security admission (restricted) to forbid privileged/hostPath/hostPID; Follow least-privilege RBAC; avoid wildcard verbs, 'escalate', 'bind', pods/exec broadly; Set automountServiceAccountToken: false where tokens are unneeded; use bound, short-lived tokens; Restrict kubelet (authn/authz on 10250), and block pod access to the instance metadata service; Use network policy and separate node pools for sensitive workloads

**References:** [link](https://github.com/inguardians/peirates) · [link](https://github.com/aquasecurity/kube-hunter) · [link](https://book.hacktricks.xyz/pentesting-cloud/kubernetes-security) · [link](https://kubernetes.io/docs/concepts/security/rbac-good-practices/) · [link](https://kubernetes.io/docs/concepts/security/pod-security-standards/)


## Cloud (AWS / Azure / GCP) privilege escalation

### AWS IAM privilege escalation (PassRole / policy / key abuse)
*id:* `aws-iam-privilege-escalation` · *category:* `cloud-iam` · *severity:* **critical**

A principal holding a single over-broad IAM permission — iam:PassRole to a service, CreatePolicyVersion, AttachUserPolicy/PutUserPolicy, CreateAccessKey, UpdateAssumeRolePolicy, or CreateLoginProfile — can escalate to administrator through documented permission-misconfiguration chains.

**How it works —** Rhino Security Labs catalogued ~20+ IAM escalation methods that turn a narrow permission into admin. Examples: iam:CreatePolicyVersion with --set-as-default rewrites an attached policy to grant *:* ; iam:AttachUserPolicy / PutUserPolicy attaches AdministratorAccess to yourself; iam:CreateAccessKey or CreateLoginProfile / UpdateLoginProfile hijacks another (privileged) user; iam:AddUserToGroup joins an admin group; iam:UpdateAssumeRolePolicy lets you assume a high-priv role; and the PassRole family (iam:PassRole plus a compute service) launches an EC2/Lambda/Glue/CloudFormation/SageMaker/Data Pipeline resource that runs with a powerful role you pass to it, then reads that role's STS credentials. Because service-linked and compute roles are frequently over-privileged, a passrole chain commonly lands on full account admin.

**Prerequisites:** valid AWS credentials (access key, SSO/role session, or SSRF-obtained token); one of the escalation permissions on the caller (or on a role it can assume); an existing higher-privileged role to pass, for the PassRole variants

**Enumerate:**
- `aws sts get-caller-identity`
- `aws iam get-account-authorization-details`
- `aws iam list-attached-user-policies --user-name <u>`
- `aws iam list-user-policies --user-name <u>`
- `aws iam list-roles`
- `aws iam simulate-principal-policy`

**Detection indicators:** `iam:PassRole`, `iam:CreatePolicyVersion`, `iam:AttachUserPolicy`, `iam:PutUserPolicy`, `iam:CreateAccessKey`, `iam:UpdateAssumeRolePolicy`, `AdministratorAccess`, `"Resource": "*"`

**Tools:** pacu, enumerate-iam, cloudsplaining, scoutsuite, prowler, aws-cli

**Mitigation:** Scope iam:PassRole with a resource ARN and iam:PassedToService condition; Avoid wildcard iam:* permissions; deny self-policy-attachment via permission boundaries/SCPs; Restrict CreatePolicyVersion/AttachUserPolicy/CreateAccessKey to break-glass admins; Right-size compute/service roles; monitor CloudTrail for policy and key mutations; Use IAM Access Analyzer and require MFA for sensitive IAM actions

**References:** [link](https://rhinosecuritylabs.com/aws/aws-privilege-escalation-methods-mitigation/) · [link](https://github.com/RhinoSecurityLabs/pacu) · [link](https://hackingthe.cloud/aws/exploitation/iam_privilege_escalation/) · [link](https://cloud.hacktricks.xyz/pentesting-cloud/aws-security/aws-privilege-escalation) · [link](https://docs.aws.amazon.com/IAM/latest/UserGuide/id_roles_use_passrole.html)

### EC2 IMDSv1 SSRF role-credential theft (169.254.169.254)
*id:* `aws-imds-ssrf-credential-theft` · *category:* `cloud-iam` · *severity:* **high**

The unauthenticated IMDSv1 link-local endpoint at 169.254.169.254 returns the instance role's temporary STS credentials to anything that can make an HTTP request from the host — including SSRF in an app — letting an attacker assume the EC2 instance role.

**How it works —** EC2 instances expose the Instance Metadata Service at http://169.254.169.254/. IMDSv1 is a simple, credential-less GET, so any request originating from the instance (app-layer SSRF, a compromised container sharing the host network, or local code) can fetch the role name from /latest/meta-data/iam/security-credentials/ and then the AccessKeyId/SecretAccessKey/Token from /latest/meta-data/iam/security-credentials/<role>. Those STS creds are exported and used against the AWS API with the instance role's permissions, which are frequently broad enough to read S3/secrets or chain into IAM privilege escalation. This was the mechanism in the 2019 Capital One breach. IMDSv2 mitigates it by requiring a PUT-obtained session token with a hop limit, which most SSRF cannot satisfy.

**Prerequisites:** an SSRF primitive on an EC2-hosted app, or code execution on the instance / a host-networked container; IMDSv1 enabled (or IMDSv2 with a permissive hop limit); an instance profile / role attached to the instance

**Enumerate:**
- `curl http://169.254.169.254/latest/meta-data/iam/security-credentials/`
- `curl http://169.254.169.254/latest/meta-data/iam/info`
- `curl http://169.254.169.254/latest/dynamic/instance-identity/document`
- `TOKEN=$(curl -s -X PUT 'http://169.254.169.254/latest/api/token' -H 'X-aws-ec2-metadata-token-ttl-seconds: 60')`

**Detection indicators:** `169.254.169.254`, `meta-data/iam/security-credentials`, `instance-identity/document`, `AccessKeyId`, `ASIA`, `X-aws-ec2-metadata-token`

**Tools:** pacu, aws-cli, ec2-metadata, smuggler, gopherus

**Mitigation:** Enforce IMDSv2 (HttpTokens=required) and set HttpPutResponseHopLimit=1; Fix SSRF (allowlist egress, block link-local 169.254.0.0/16); Right-size the instance role; monitor for STS use from unexpected sources (GuardDuty InstanceCredentialExfiltration); Disable IMDS entirely where not needed

**References:** [link](https://hackingthe.cloud/aws/exploitation/ec2-metadata-ssrf/) · [link](https://docs.aws.amazon.com/AWSEC2/latest/UserGuide/configuring-instance-metadata-service.html) · [link](https://blog.appsecco.com/an-ssrf-privileged-aws-keys-and-the-capital-one-breach-4c3c2cded3af) · [link](https://cloud.hacktricks.xyz/pentesting-cloud/aws-security/aws-unauthenticated-enum-access/aws-metadata-ssrf)

### Azure/Entra managed identity & privileged role abuse
*id:* `azure-managed-identity-directory-role-abuse` · *category:* `cloud-iam` · *severity:* **high**

An attacker on an Azure VM/App can steal its managed-identity token from IMDS and act as that identity, and in Entra ID can abuse privileged directory roles (Global Admin, Privileged Role Administrator), Owner/User Access Administrator RBAC, or application owner / OAuth consent grants to escalate to tenant control.

**How it works —** Two overlapping surfaces. (1) Managed identities: a VM/Function/App Service with an attached system- or user-assigned identity exposes a token endpoint at http://169.254.169.254/metadata/identity/oauth2/token (IMDS, requiring the Metadata:true header) or the App Service MSI endpoint; code exec or SSRF there yields an AAD access token for ARM/Graph/Key Vault with the identity's permissions. (2) Entra/RBAC role abuse: holders of User Access Administrator or Owner on a subscription can grant themselves any role (including over the tenant root management group via 'elevate access'); directory roles like Privileged Role Administrator can assign Global Admin; Application Administrator / app Owners can add credentials (a new client secret/certificate) to a service principal that itself holds high Graph permissions and authenticate as it; and illicit OAuth consent grants (Application.ReadWrite.All, RoleManagement.ReadWrite.Directory) let an app self-escalate. Chaining a stolen MSI token with an over-privileged SP commonly reaches Global Admin.

**Prerequisites:** code exec/SSRF on an Azure resource with a managed identity, OR; a foothold principal holding Owner/User Access Administrator, a privileged Entra role, app ownership, or dangerous Graph app-roles

**Enumerate:**
- `curl -H 'Metadata:true' 'http://169.254.169.254/metadata/identity/oauth2/token?api-version=2018-02-01&resource=https://management.azure.com/'`
- `az account get-access-token`
- `az role assignment list --assignee <id> --all`
- `az ad sp list --show-mine`
- `Get-MgServicePrincipalAppRoleAssignment`
- `az rest --url https://graph.microsoft.com/v1.0/me/memberOf`

**Detection indicators:** `identity/oauth2/token`, `169.254.169.254/metadata`, `IDENTITY_ENDPOINT`, `User Access Administrator`, `Privileged Role Administrator`, `RoleManagement.ReadWrite.Directory`, `Application.ReadWrite.All`

**Tools:** microburst, roadtools, roadrecon, azurehound, stormspotter, az-cli, graphrunner

**Mitigation:** Restrict which identities are assigned to Azure resources; least-privilege the identity's RBAC/Graph roles; Enforce IMDS access controls and fix SSRF; monitor token requests; Use PIM (just-in-time) for privileged Entra roles; alert on 'elevate access' and role assignments; Review app credentials and consent grants; block risky OAuth consent; require MFA/Conditional Access

**References:** [link](https://github.com/NetSPI/MicroBurst) · [link](https://github.com/dirkjanm/ROADtools) · [link](https://learn.microsoft.com/en-us/entra/identity/managed-identities-azure-resources/how-to-use-vm-token) · [link](https://cloud.hacktricks.xyz/pentesting-cloud/azure-security) · [link](https://dirkjanm.io/azure-managed-identity-privilege-escalation/)

### GCP service-account impersonation / actAs abuse
*id:* `gcp-service-account-impersonation-actas` · *category:* `cloud-iam` · *severity:* **high**

A principal with iam.serviceAccounts.getAccessToken / signJwt / signBlob / getOpenIdToken on a higher-privileged service account — or iam.serviceAccounts.actAs plus a deploy permission (Cloud Functions, Compute, Cloud Run, Deployment Manager, Cloud Build) — can mint that SA's tokens or run code as it, escalating toward project/organization owner.

**How it works —** GCP grants many escalation paths short of Owner. Direct impersonation: with iam.serviceAccounts.getAccessToken on a target SA you request an OAuth2 access token for it; signJwt/signBlob let you self-sign assertions the SA would accept; getOpenIdToken yields an OIDC identity. Indirect (actAs) chains: iam.serviceAccounts.actAs binds an SA to a resource you create, so create-permissions on a compute service run your code as that SA — e.g. deploy a Cloud Function/Cloud Run/GCE instance/Deployment Manager config/Cloud Build job with a more-privileged attached SA and read its metadata token. Additional IAM-mutation paths (setIamPolicy on a project/SA, create/upload SA keys via iam.serviceAccountKeys.create, updating custom roles) let a low-priv principal grant itself Owner. Rhino Security Labs enumerated the full set.

**Prerequisites:** authenticated GCP credentials (gcloud, SA key, or metadata token); one of the impersonation/actAs/IAM-mutation permissions on a higher-privileged SA or resource

**Enumerate:**
- `gcloud auth list`
- `gcloud projects get-iam-policy <project>`
- `gcloud iam service-accounts list`
- `gcloud iam service-accounts get-iam-policy <sa-email>`
- `gcloud iam roles describe <role>`
- `curl -H 'Metadata-Flavor: Google' 'http://metadata.google.internal/computeMetadata/v1/instance/service-accounts/default/token'`

**Detection indicators:** `iam.serviceAccounts.getAccessToken`, `iam.serviceAccounts.actAs`, `iam.serviceAccounts.signJwt`, `iam.serviceAccountKeys.create`, `roles/iam.serviceAccountTokenCreator`, `roles/owner`, `metadata.google.internal`, `SeImpersonatePrivilege`

**Tools:** gcp-iam-privilege-escalation, scoutsuite, prowler, gcloud, gcpwn

**Mitigation:** Grant roles/iam.serviceAccountTokenCreator and actAs sparingly and per-SA; Disable SA key creation (org policy iam.disableServiceAccountKeyCreation); Avoid attaching high-privilege SAs to broadly-deployable resources; Audit setIamPolicy and impersonation in Cloud Audit Logs; use least-privilege custom roles

**References:** [link](https://rhinosecuritylabs.com/gcp/privilege-escalation-google-cloud-platform-part-1/) · [link](https://github.com/RhinoSecurityLabs/GCP-IAM-Privilege-Escalation) · [link](https://cloud.google.com/iam/docs/impersonating-service-accounts) · [link](https://cloud.hacktricks.xyz/pentesting-cloud/gcp-security/gcp-privilege-escalation) · [link](https://hackingthe.cloud/gcp/exploitation/)


## Active Directory privilege escalation

### AD CS Certificate Template & Enrollment Abuse (ESC1-ESC8)
*id:* `ad-adcs-esc1-esc8-certificate-abuse` · *category:* `adcs` · *severity:* **critical** · *CVE:* CVE-2022-26923

Misconfigured Active Directory Certificate Services templates and endpoints let low-privileged users enroll certificates that authenticate as arbitrary users (including Domain Admins) or relay machine authentication to the CA, providing durable domain-privilege escalation and persistence.

**How it works —** From SpecterOps 'Certified Pre-Owned': ESC1 = enrollee-supplies-subject template with client-auth EKU (request a cert as any user via SAN); ESC2 = Any Purpose/no-EKU template usable for auth; ESC3 = Certificate Request Agent (enrollment agent) enroll-on-behalf-of; ESC4 = attacker has write access to a template's ACL (turn it into ESC1); ESC5 = vulnerable PKI object ACLs (CA/CA object); ESC6 = CA has EDITF_ATTRIBUTESUBJECTALTNAME2 (SAN in any request); ESC7 = attacker holds ManageCA/ManageCertificates rights (approve requests, enable SAN, add officers); ESC8 = NTLM relay to the CA HTTP/RPC web-enrollment endpoint (relay a coerced DC to obtain a DC auth cert). Certificates for authentication can then be used for PKINIT to get a TGT (and the NT hash via UnPAC-the-hash). Related: CVE-2022-26923 'Certifried' (dNSHostName machine cert spoofing).

**Prerequisites:** An enterprise CA is present; A vulnerable template/CA configuration or write access to PKI objects; For ESC8: ability to coerce machine authentication (PetitPotam/PrinterBug) plus a relay position

**Enumerate:**
- `Certipy: certipy find -u <user>@<domain> -p <pass> -dc-ip <dc> -vulnerable -stdout`
- `Certify.exe find /vulnerable`
- `PSPKIAudit: Invoke-PKIAudit`
- `Enumerate CA web enrollment endpoints (http://<ca>/certsrv, /CertSrv/mscep) for ESC8`

**Detection indicators:** `Templates with mspki-certificate-name-flag ENROLLEE_SUPPLIES_SUBJECT + client-auth EKU + low-priv enroll rights`, `CA flag EDITF_ATTRIBUTESUBJECTALTNAME2 enabled (ESC6)`, `Event 4886/4887 (cert requested/issued) where SAN != requester; certificate logons (4768 with certificate) for admins`, `NTLM relay signatures against CA web endpoints; DC machine account requesting client-auth certs unexpectedly`

**Tools:** certipy, certify, pspkiaudit, ntlmrelayx (esc8), rubeus (pkinit/asktgt with cert), bloodhound (adcs support)

**Mitigation:** Remove ENROLLEE_SUPPLIES_SUBJECT where not required; restrict enroll/autoenroll rights and require manager approval; Disable EDITF_ATTRIBUTESUBJECTALTNAME2; harden CA and template ACLs; Enable EPA/require signing and disable NTLM on CA web enrollment (ESC8); apply KB5014754 strong certificate mapping; Audit AD CS with Certipy/PSPKIAudit; monitor 4886/4887 for SAN mismatches

**References:** [link](https://github.com/ly4k/Certipy) · [link](https://github.com/GhostPack/Certify) · [link](https://posts.specterops.io/certified-pre-owned-d95910965cd2) · [link](https://attack.mitre.org/techniques/T1649/)

### Certifried — AD CS machine-account cert impersonation (CVE-2022-26923)
*id:* `adcs-certifried-cve-2022-26923` · *category:* `adcs` · *severity:* **critical** · *CVE:* CVE-2022-26923

Any authenticated user who can create or control a computer account can set its dNSHostName to that of a Domain Controller and enroll in the default Machine certificate template, obtaining a certificate that authenticates as the DC — escalating to domain compromise.

**How it works —** The default Machine/Computer certificate template builds the certificate identity from the account's dNSHostName rather than an immutable identifier. By default MachineAccountQuota lets any domain user create computer accounts, and the creator can edit that account's dNSHostName. The attacker creates a computer account, sets its dNSHostName to a DC's FQDN (removing the conflicting value on the real DC object or exploiting the lack of uniqueness enforcement), then requests a certificate from the Machine template. AD CS issues a cert whose SAN/identity maps to the DC, so the attacker can PKINIT-authenticate as the Domain Controller machine account and, e.g., perform DCSync to dump domain hashes. Certipy automates the account creation, dNSHostName manipulation, enrollment and Kerberos authentication.

**Prerequisites:** an AD CS enterprise CA with the default Machine template published; an authenticated domain user with MachineAccountQuota > 0 (or write over a computer object); unpatched DCs / CA (pre-May-2022 fix, before strong certificate mapping enforcement)

**Enumerate:**
- `certipy find -u user@domain -p pass -dc-ip <ip>`
- `Get-ADObject -Filter 'ms-DS-MachineAccountQuota -like "*"'`
- `Get-DomainComputer -Properties dnshostname`
- `certutil -catemplates`

**Detection indicators:** `dNSHostName`, `ms-DS-MachineAccountQuota`, `Machine template`, `PKINIT`, `Certifried`, `szOID_NTDS_CA_SECURITY_EXT`, `SeImpersonatePrivilege`

**Tools:** certipy, certi, bloodhound, impacket

**Mitigation:** Apply the May 2022 updates (KB5014754) and enable Full/strong certificate mapping enforcement; Set MachineAccountQuota to 0; restrict who can create/modify computer accounts; Harden AD CS templates; enable the szOID_NTDS_CA_SECURITY_EXT (SID) extension; Monitor certificate enrollments and dNSHostName changes

**References:** [link](https://research.ifcr.dk/certifried-active-directory-domain-privilege-escalation-cve-2022-26923-9e098fe298f4) · [link](https://github.com/ly4k/Certipy) · [link](https://nvd.nist.gov/vuln/detail/CVE-2022-26923) · [link](https://posts.specterops.io/certified-pre-owned-d95910965cd2)

### DCShadow
*id:* `ad-dcshadow-rogue-dc-injection` · *category:* `dcshadow` · *severity:* **critical**

An attacker with high privileges temporarily registers a rogue domain controller in the directory and pushes malicious replication changes (e.g., SID history, group membership, primaryGroupID) that propagate to legitimate DCs while bypassing normal change-audit logs.

**How it works —** DCShadow abuses the same MS-DRSR replication used by DCSync but in the opposite direction: instead of pulling, it pushes. The attacker creates the nTDSDSA object and required SPNs to make a controlled host appear as a DC, then triggers replication so target attribute changes (backdoor ACLs, SIDHistory, GPO links) are accepted by real DCs. Because the changes arrive as normal replication, they evade many object-modification audit controls. Requires domain/enterprise admin (or equivalent replication + object creation rights) to register the fake DC.

**Prerequisites:** Domain Admin / Enterprise Admin (or rights to create nTDSDSA objects and required SPNs in the Configuration NC); SYSTEM on the pushing host

**Enumerate:**
- `Audit Configuration NC 'Sites' container for unexpected nTDSDSA/server objects`
- `Compare list of DCs (Get-ADDomainController -Filter *) against expected inventory`
- `Repadmin /showrepl to spot unexpected replication partners`

**Detection indicators:** `Security Event 4742 (computer account changed) adding SPNs like GC/ or E3514235-4B06-11D1-AB04-00C04FC2DCD2/`, `Event 5137 (directory object created) / 4929 (AD replica source removed) around nTDSDSA objects`, `Replication from a host not in the authorized DC list; short-lived server objects in Sites`

**Tools:** mimikatz (lsadump::dcshadow), impacket (dcsync-style tooling)

**Mitigation:** Restrict who can create objects in the Configuration partition (Sites/Servers); Monitor for new nTDSDSA objects and replication from non-DC hosts; Enforce tiered admin and privileged access workstations to limit DA compromise

**References:** [link](https://www.dcshadow.com/) · [link](https://github.com/gentilkiwi/mimikatz) · [link](https://attack.mitre.org/techniques/T1207/)

### DCSync
*id:* `ad-dcsync-replication-abuse` · *category:* `dcsync` · *severity:* **critical**

A principal holding directory replication rights (DS-Replication-Get-Changes and DS-Replication-Get-Changes-All) can impersonate a domain controller and pull password hashes (including krbtgt) for any account via the MS-DRSR replication protocol, without touching a DC's disk.

**How it works —** Using the Directory Replication Service Remote Protocol (DRSUAPI GetNCChanges), a client with replication extended rights requests secret attributes (unicodePwd, ntPwdHistory, supplementalCredentials) for target objects. Domain Admins, Enterprise Admins, and DCs hold these rights by default, but any user/group granted them via a misconfigured ACL can DCSync. Extracting the krbtgt hash enables Golden Tickets; extracting a target admin's hash enables Pass-the-Hash. It is a primary post-exploitation objective identified by BloodHound's 'DCSync' edge.

**Prerequisites:** A principal with GetChanges + GetChangesAll (or GetChangesInFilteredSet) rights on the domain naming context; Network access to a DC's RPC endpoints

**Enumerate:**
- `PowerView: Get-DomainObjectAcl -SearchBase 'DC=corp,DC=local' -ResolveGUIDs | ? { $_.ObjectAceType -match 'Replication-Get-Changes' }`
- `BloodHound: query for the DCSync edge / 'Find Principals with DCSync Rights'`
- `Impacket (perform): secretsdump.py -just-dc <domain>/<user>@<dc>`

**Detection indicators:** `Security Event 4662 with property GUID 1131f6aa-9c07-11d1-f79f-00c04fc2dcd2 (Get-Changes) or 1131f6ad-9c07-11d1-f79f-00c04fc2dcd2 (Get-Changes-All)`, `Replication (DRSUAPI GetNCChanges) requests sourced from an IP that is not a domain controller`, `Accounts other than DCs/known replication service accounts triggering replication`

**Tools:** mimikatz (lsadump::dcsync), impacket secretsdump.py, bloodhound, powerview

**Mitigation:** Audit and remove non-DC principals holding replication rights on the domain head; Monitor 4662 for replication GUIDs and alert on non-DC source IPs; Segment DC RPC access; use tiered administration

**References:** [link](https://github.com/gentilkiwi/mimikatz) · [link](https://github.com/fortra/impacket/blob/master/examples/secretsdump.py) · [link](https://attack.mitre.org/techniques/T1003/006/) · [link](https://adsecurity.org/?p=1729)

### Unconstrained Delegation Abuse
*id:* `ad-unconstrained-delegation-tgt-capture` · *category:* `delegation` · *severity:* **critical**

Computers/accounts trusted for unconstrained delegation cache the TGTs of any user that authenticates to them; an attacker controlling such a host (often combined with authentication coercion) can extract a Domain Controller's or Domain Admin's TGT and impersonate them.

**How it works —** With unconstrained delegation (TRUSTED_FOR_DELEGATION UAC flag), when a user authenticates to the service, the KDC embeds the user's forwardable TGT inside the service ticket; the service caches it in LSASS to act on the user's behalf. An attacker who compromises such a server dumps cached TGTs. Weaponized, the attacker coerces a Domain Controller to authenticate to the unconstrained host (via PrinterBug/PetitPotam), capturing the DC's TGT, then uses it (e.g., for DCSync). Any authenticated user can also create a computer object (see MachineAccountQuota) and set delegation in some scenarios.

**Prerequisites:** Control of a host/account with TRUSTED_FOR_DELEGATION; Ability to coerce a privileged principal to authenticate (optional but common); SYSTEM/admin on the delegation host to read LSASS tickets

**Enumerate:**
- `PowerView: Get-DomainComputer -Unconstrained -Properties dnshostname,useraccountcontrol`
- `AD module: Get-ADComputer -Filter {TrustedForDelegation -eq $true}`
- `BloodHound: 'Find Computers with Unconstrained Delegation'`
- `Rubeus.exe monitor /interval:5  (watch for incoming TGTs)`

**Detection indicators:** `Non-DC computer objects with TrustedForDelegation set (userAccountControl 0x80000)`, `Coercion signatures: MS-RPRN/MS-EFSRPC calls to a delegation host followed by DC authentication`, `Event 4769/4768 showing a DC machine account obtaining a forwardable TGT to an unusual host`

**Tools:** rubeus, mimikatz (sekurlsa::tickets), impacket, spoolsample/petitpotam (coercion), bloodhound, powerview

**Mitigation:** Eliminate unconstrained delegation; use constrained or RBCD where delegation is needed; Add privileged accounts to Protected Users and set 'Account is sensitive and cannot be delegated' (NOT_DELEGATED); Patch/mitigate coercion vectors (PetitPotam, PrinterBug); Place DCs and Tier-0 accounts so they never authenticate to non-Tier-0 hosts

**References:** [link](https://github.com/GhostPack/Rubeus) · [link](https://github.com/leechristensen/SpoolSample) · [link](https://shenaniganslabs.io/2019/01/28/Wagging-the-Dog.html) · [link](https://adsecurity.org/?p=1667)

### Golden Ticket
*id:* `ad-golden-ticket-krbtgt-forgery` · *category:* `golden-ticket` · *severity:* **critical**

With the krbtgt account's hash/AES key, an attacker forges arbitrary TGTs (Ticket Granting Tickets) with any user identity and group memberships, granting persistent domain-wide access that survives password resets of normal accounts.

**How it works —** TGTs are encrypted and signed with the krbtgt key. Possessing that key (obtained via DCSync, NTDS.dit dump, or DC compromise) lets an attacker mint self-signed TGTs offline for any SID/username with fabricated PAC group memberships (e.g., Domain/Enterprise Admins) and arbitrary lifetime. Because the KDC trusts anything signed by krbtgt, these tickets are accepted domain-wide. Golden tickets provide long-term persistence; only resetting krbtgt (twice) invalidates them. Modern forgeries should set realistic lifetimes/PAC fields to evade detection (see Diamond Ticket).

**Prerequisites:** krbtgt account NT hash or AES key; Domain SID; Effective domain compromise to obtain the krbtgt secret

**Enumerate:**
- `Detection-focused: audit for krbtgt key exposure events and unusual TGT lifetimes`
- `Get-ADUser krbtgt -Properties pwdLastSet  (assess rotation hygiene)`
- `Rubeus.exe describe /ticket:<ticket>  (inspect a suspicious ticket's PAC/lifetime)`

**Detection indicators:** `Event 4769 (service ticket request) with no preceding 4768 (TGT request) for the account`, `TGTs with abnormal lifetimes (e.g., 10 years) or RC4 when AES is expected`, `PAC anomalies: account name/SID mismatch, non-existent accounts, all-groups membership`, `Kerberos activity for accounts that do not exist in AD`

**Tools:** mimikatz (kerberos::golden), rubeus (golden), impacket ticketer.py

**Mitigation:** Reset the krbtgt password twice (with replication between) after any suspected Tier-0 compromise, and rotate periodically; Protect DCs and NTDS.dit; enforce Tier-0 isolation; Deploy detections for TGT/PAC anomalies and 4769-without-4768; Enforce AES-only Kerberos to make RC4 forgeries stand out

**References:** [link](https://github.com/gentilkiwi/mimikatz) · [link](https://github.com/fortra/impacket/blob/master/examples/ticketer.py) · [link](https://attack.mitre.org/techniques/T1558/001/) · [link](https://adsecurity.org/?p=1640)

### Zerologon (CVE-2020-1472)
*id:* `ad-zerologon-netlogon-cve-2020-1472` · *category:* `netlogon-exploit` · *severity:* **critical** · *CVE:* CVE-2020-1472

A cryptographic flaw in the Netlogon (MS-NRPC) AES-CFB8 authentication allowed an unauthenticated attacker with network access to a DC to set the DC's machine account password to empty, then use it to DCSync every credential — instant domain compromise from network access alone.

**How it works —** Netlogon's ComputeNetlogonCredential used AES-CFB8 with a fixed all-zero IV. Because AES-CFB8 with an all-zero plaintext and all-zero IV yields an all-zero ciphertext with probability ~1/256, an attacker could repeatedly attempt NetrServerAuthenticate3 with all-zero challenge/ciphertext until authentication succeeded (~256 tries), without knowing any key. They then called NetrServerPasswordSet2 to reset the DC computer account's password in AD to empty. With the DC machine account controlled, they DCSync the krbtgt and admin hashes (then restore the original password to avoid breaking the DC). Discovered by Tom Tervoort (Secura).

**Prerequisites:** Network access to a Domain Controller's Netlogon RPC endpoint; Unpatched DC (before Aug 2020 patch / enforcement Feb 2021)

**Enumerate:**
- `Secura tester: zerologon_tester.py <DC-NETBIOS> <DC-IP>  (non-destructive check)`
- `Impacket-based scanners that stop before resetting the password`
- `Verify DC patch level (KB4557222 and Feb 2021 enforcement)`

**Detection indicators:** `Numerous Netlogon NetrServerAuthenticate3 attempts with all-zero data from a single source (~256 tries)`, `Event 4742 machine account (a DC's) password change from an unexpected source`, `Netlogon events 5827/5828 (denied vulnerable connections) after enforcement; 5829 (allowed vulnerable) pre-enforcement`, `DC machine account authentication anomalies immediately followed by replication/DCSync (4662)`

**Tools:** impacket (secretsdump.py after exploit), secura cve-2020-1472 tester, mimikatz (zerologon module)

**Mitigation:** Apply the August 2020 patch and enable enforcement mode (Feb 2021 update); ensure DC secure-channel enforcement; Monitor Netlogon events 5827/5828/5829 and 4742 DC password changes; If exploited, the DC's AD password and local secret desynchronize — reset the DC machine account password to remediate; Restrict RPC/Netlogon exposure and segment DCs

**References:** [link](https://github.com/SecuraBV/CVE-2020-1472) · [link](https://github.com/fortra/impacket/blob/master/examples/secretsdump.py) · [link](https://www.secura.com/uploads/whitepapers/Zerologon.pdf) · [link](https://msrc.microsoft.com/update-guide/vulnerability/CVE-2020-1472)

### mitm6 IPv6 DNS takeover + NTLM relay to LDAP
*id:* `ad-mitm6-ipv6-dns-takeover-ntlm-relay` · *category:* `ntlm-relay` · *severity:* **critical**

Windows prefers IPv6 and auto-requests a DHCPv6 lease; mitm6 answers as the rogue DHCPv6 server and sets itself as the client's DNS, then coerces NTLM authentication and relays it (via ntlmrelayx) to LDAP/LDAPS on a Domain Controller to grant delegation rights or create a computer account, escalating in the domain.

**How it works —** Even on IPv4-only networks, Windows sends DHCPv6 solicitations. mitm6 (dirkjanm) replies with the attacker as the primary DNS server (and optionally a WPAD entry). Victims then resolve names through the attacker, who serves a malicious WPAD/proxy or an intranet name to coerce NTLM authentication. That authentication is relayed with impacket's ntlmrelayx to LDAP/LDAPS on a DC (LDAP signing/channel binding is often not enforced). With a relayed machine or user account the attacker can: grant Resource-Based Constrained Delegation on a victim computer object (then impersonate a privileged user to it), add a new computer account (default MachineAccountQuota=10) to use as the delegation target, or dump domain info. Chained, this is a classic unauthenticated-to-domain-privilege path.

**Prerequisites:** attacker on the LAN (L2 reach to victims for DHCPv6/DNS); IPv6 enabled on clients (default) and DHCPv6 not otherwise served/guarded; LDAP signing / channel binding not enforced on the DC; MachineAccountQuota > 0 for the computer-creation variant

**Enumerate:**
- `mitm6 -d <domain>  (rogue DHCPv6, observe solicitations)`
- `nmap -6 --script dhcpv6`
- `Get-ADObject -SearchBase (Get-ADRootDSE).defaultNamingContext -Filter 'ms-DS-MachineAccountQuota -like "*"'`
- `netsh interface ipv6 show interfaces`

**Detection indicators:** `DHCPv6`, `mitm6`, `WPAD`, `ms-DS-MachineAccountQuota`, `ntlmrelayx`, `rbcd`

**Tools:** mitm6, ntlmrelayx, impacket, krbrelayx, bloodhound

**Mitigation:** Disable IPv6 where unused, or block rogue DHCPv6 (RA Guard / DHCPv6 Guard on switches); Enforce LDAP signing and LDAP channel binding on Domain Controllers; Enforce SMB signing; set MachineAccountQuota to 0; Disable WPAD; monitor for RBCD writes and new computer accounts

**References:** [link](https://github.com/dirkjanm/mitm6) · [link](https://blog.fox-it.com/2018/01/11/mitm6-compromising-ipv4-networks-via-ipv6/) · [link](https://dirkjanm.io/worst-of-both-worlds-ntlm-relaying-and-kerberos-delegation/) · [link](https://www.thehacker.recipes/ad/movement/mitm-and-coerced-authentications/dhcpv6-spoofing) · [link](https://github.com/fortra/impacket)

### Authentication Coercion + NTLM Relay (PetitPotam, PrinterBug/SpoolSample, DFSCoerce, Coercer)
*id:* `ad-ntlm-relay-coercion-petitpotam-printerbug` · *category:* `ntlm-relay` · *severity:* **critical** · *CVE:* CVE-2021-36942

Attackers force a target (often a Domain Controller) to authenticate to an attacker-controlled host over MS-EFSRPC/MS-RPRN/MS-DFSNM, then relay that NTLM authentication to a privileged service (LDAP, AD CS web enrollment, SMB) to act as the coerced machine — commonly ending in domain compromise.

**How it works —** Several RPC interfaces let a remote, sometimes unauthenticated caller trigger the server to authenticate outbound: PetitPotam (MS-EFSRPC EfsRpcOpenFileRaw, CVE-2021-36942), PrinterBug/SpoolSample (MS-RPRN RpcRemoteFindFirstPrinterChangeNotification), DFSCoerce (MS-DFSNM NetrDfsAddStdRoot), and Coercer (multi-protocol). The coerced NTLM is captured by ntlmrelayx and relayed: to LDAP/LDAPS on a DC to configure RBCD or shadow credentials against the DC's computer object; to AD CS web enrollment (ESC8) to obtain a DC authentication certificate; or to SMB for command execution. Because a DC's machine account is Tier-0, relaying it yields domain takeover. Relay requires the destination to lack signing/EPA (e.g., LDAP without signing, HTTP enrollment without EPA).

**Prerequisites:** Network path to trigger coercion (sometimes pre-auth for PetitPotam); A relay target lacking signing/channel binding (LDAP without signing, AD CS HTTP enrollment, SMB without signing); Often MachineAccountQuota > 0 to add a computer for the RBCD/shadow-cred follow-on

**Enumerate:**
- `Coercer: coercer scan -u <user> -p <pass> -t <target>  (identify exposed coercion methods)`
- `Check LDAP signing / channel binding posture and SMB signing on relay targets (nxc smb <t> --gen-relay-list)`
- `Enumerate AD CS web enrollment endpoints for ESC8 relay`
- `Assess Get-ADObject ms-DS-MachineAccountQuota`

**Detection indicators:** `Inbound MS-EFSRPC/MS-RPRN/MS-DFSNM calls to non-file-server hosts; DC machine account authenticating outbound to a workstation`, `Event 4624 Logon Type 3 NTLM where the source is a DC machine account authenticating to an unexpected host`, `NTLM authentications to LDAP/HTTP CA endpoints from a relay host; new RBCD/shadow-credential attributes on the DC object shortly after`, `4741 (computer created) via MachineAccountQuota near relay activity`

**Tools:** petitpotam, spoolsample/dementor, dfscoerce, coercer, impacket ntlmrelayx.py, certipy (relay to esc8), krbrelayx (printerbug)

**Mitigation:** Enforce SMB signing everywhere, LDAP signing + channel binding on DCs (require, don't just enable); Enable EPA and disable NTLM on AD CS web enrollment; consider disabling NTLM broadly; Patch/mitigate coercion (KB for PetitPotam, disable Print Spooler on DCs, restrict RPC), block outbound SMB from DCs; Set MachineAccountQuota to 0; monitor coercion RPC and DC outbound auth

**References:** [link](https://github.com/topotam/PetitPotam) · [link](https://github.com/leechristensen/SpoolSample) · [link](https://github.com/Wh04m1001/DFSCoerce) · [link](https://github.com/p0dalirius/Coercer) · [link](https://attack.mitre.org/techniques/T1187/) · [link](https://dirkjanm.io/worst-of-both-worlds-ntlm-relaying-and-kerberos-delegation/)

### sAMAccountName Spoofing / noPac (CVE-2021-42278 + CVE-2021-42287)
*id:* `ad-nopac-samaccountname-spoofing` · *category:* `samaccountname-spoofing` · *severity:* **critical** · *CVE:* CVE-2021-42278, CVE-2021-42287

Chaining CVE-2021-42278 (no sAMAccountName validation) with CVE-2021-42287 (KDC S4U2self PAC fallback) lets any user who can create/rename a computer account impersonate a Domain Controller and obtain a Kerberos service ticket as a domain admin, yielding full domain compromise.

**How it works —** An attacker creates a machine account (via MachineAccountQuota) and renames its sAMAccountName to match a DC's name without the trailing '$' (CVE-2021-42278: AD failed to enforce that machine account names end in $). They request a TGT for that name, then rename the account back. When they present the TGT for S4U2self/service ticket, the KDC can't find the exact principal and falls back to appending '$' (CVE-2021-42287), matching the real DC's machine account — issuing a service ticket in the security context of the DC. The result is a ticket impersonating a privileged account to services like CIFS/LDAP on the DC (effectively domain admin). Automated end-to-end by noPac/sam_the_admin.

**Prerequisites:** Any authenticated domain user with the ability to create a computer account (MachineAccountQuota > 0) or write to an existing controlled computer's sAMAccountName/servicePrincipalName; Unpatched DCs (missing Nov 2021 KB5008380/KB5008602)

**Enumerate:**
- `Assess patch level of DCs (KB5008380 / KB5008602) and ms-DS-MachineAccountQuota`
- `noPac: check reachability and MAQ (scanner mode)`
- `PowerView: Get-DomainObject -Properties ms-ds-machineaccountquota`

**Detection indicators:** `Event 4741 (computer created) followed by 4781 (account name changed) for a machine account, then TGT requests`, `A computer account whose sAMAccountName collides with a DC name (missing $), transiently`, `Event 4768/4769 for a machine account renamed to a DC name; S4U2self activity from a new machine account`, `Microsoft-added events (KDC PAC) on patched DCs when the fix rejects such requests`

**Tools:** nopac (cube0x0), sam_the_admin (impacket-based), impacket (addcomputer.py, renamemachine.py, getst.py), powermad

**Mitigation:** Apply Microsoft patches KB5008380 and KB5008602 (Nov 2021) on all DCs; Set MachineAccountQuota to 0 and restrict machine-account creation; Monitor 4741 + 4781 sequences and machine-name collisions with DCs; Enforce PAC validation post-patch (registry PacRequestorEnforcement)

**References:** [link](https://github.com/cube0x0/noPac) · [link](https://github.com/WazeHell/sam-the-admin) · [link](https://www.thehacker.recipes/ad/movement/kerberos/samaccountname-spoofing) · [link](https://www.secureworks.com/blog/nopac-a-tale-of-two-vulnerabilities-that-could-end-in-ransomware)

### SID History Injection
*id:* `ad-sid-history-injection` · *category:* `sid-history` · *severity:* **critical**

The sIDHistory attribute — designed to preserve access during domain migrations — can be injected with the SID of a privileged group (e.g., Enterprise/Domain Admins), so a low-privileged account silently gains those privileges since access checks honor SID history.

**How it works —** sIDHistory lets a migrated account retain its former SIDs so ACLs referencing the old SID still grant access. Because Windows authorization includes sIDHistory SIDs in the token/PAC, writing a privileged SID (e.g., the domain Enterprise Admins RID-519 or Domain Admins RID-512) into a controlled account's sIDHistory effectively makes that account a member of the privileged group without visible group membership. Injection requires DC-level access (Mimikatz sid::add/misc, DCShadow, or DsAddSidHistory with the right privileges) and is a stealthy persistence/escalation primitive. Cross-forest, SID Filtering normally strips foreign SIDs unless disabled.

**Prerequisites:** High privilege / DC access to write sIDHistory (e.g., via DCShadow or SYSTEM on a DC); Knowledge of the target privileged group SID

**Enumerate:**
- `PowerView: Get-DomainUser -Properties samaccountname,sidhistory | ? {$_.sidhistory}`
- `AD module: Get-ADUser -Filter {SIDHistory -like '*'} -Properties SIDHistory`
- `Audit for accounts whose sIDHistory contains privileged RIDs (512/516/518/519)`

**Detection indicators:** `Event 4765/4766 (SID History added / add failed) on accounts`, `Event 4738 (user changed) with SidHistory modification`, `Non-migration accounts possessing sIDHistory, especially with high-privilege RIDs`, `Authorization/PAC showing privileged group access without corresponding group membership`

**Tools:** mimikatz (sid::add, misc::addsid), dcshadow, powerview, bloodhound

**Mitigation:** Audit and clear illegitimate sIDHistory entries after migrations complete; Enable SID Filtering on trusts to block foreign privileged SIDs; Monitor 4765/4766 and 4738 SidHistory changes; protect DCs (Tier-0); Restrict who can write sIDHistory

**References:** [link](https://github.com/gentilkiwi/mimikatz) · [link](https://attack.mitre.org/techniques/T1134/005/) · [link](https://adsecurity.org/?p=1772)

### AD Object ACL Abuse (GenericAll/GenericWrite/WriteDACL/WriteOwner)
*id:* `ad-acl-abuse-generic-write-owner-dacl` · *category:* `acl-abuse` · *severity:* **high**

Excessive or misconfigured discretionary ACL entries on AD objects let an attacker escalate: WriteOwner/WriteDACL to grant themselves rights, GenericWrite to set SPNs (targeted Kerberoast) or shadow credentials, GenericAll to reset passwords, and control over groups to add members.

**How it works —** Every AD object has a security descriptor. Dangerous ACEs create attack edges: WriteOwner lets an attacker become object owner then rewrite the DACL (WriteDACL) to grant GenericAll; GenericAll/ForceChangePassword allows resetting a user's password or setting msDS-KeyCredentialLink (shadow credentials) or an SPN (targeted Kerberoasting); GenericWrite/WriteProperty on a group allows self-add to privileged groups; write on a computer enables RBCD. BloodHound maps these as edges to find shortest paths to Domain Admin. Abusing 'AddMember' on a high-value group or GenericAll on an OU (with GPO/inheritance) cascades to domain compromise.

**Prerequisites:** An identity holding a dangerous ACE (GenericAll, GenericWrite, WriteDacl, WriteOwner, ForceChangePassword, AddMember, etc.) over a higher-value object

**Enumerate:**
- `BloodHound/SharpHound: collect ACLs, then 'Shortest Path to Domain Admins' / inbound object control`
- `PowerView: Get-DomainObjectAcl -Identity <obj> -ResolveGUIDs | ? {$_.ActiveDirectoryRights -match 'GenericAll|WriteDacl|WriteOwner|WriteProperty'}`
- `PowerView: Find-InterestingDomainAcl -ResolveGUIDs`
- `AD module: (Get-Acl "AD:\<DN>").Access`

**Detection indicators:** `Event 5136 (directory object modified) on DACL/owner/member attributes of privileged objects`, `Event 4738/4728/4756 (user/group membership changes) for sensitive groups`, `Password resets (4724) on privileged accounts by non-help-desk principals`, `Additions to msDS-KeyCredentialLink or servicePrincipalName on user objects`

**Tools:** bloodhound/sharphound, powerview (add-domainobjectacl, set-domainobject), impacket (dacledit.py), aclpwn/invoke-aclpwn

**Mitigation:** Regularly audit ACLs on Tier-0 objects, OUs, and the domain head; remove non-inherited risky ACEs; Enforce least privilege and AdminSDHolder/SDProp protection of privileged groups; Monitor 5136 for DACL/owner/member changes on sensitive objects; Use BloodHound proactively to find and prune attack paths

**References:** [link](https://github.com/PowerShellMafia/PowerSploit/tree/master/Recon) · [link](https://github.com/fortra/impacket/blob/master/examples/dacledit.py) · [link](https://www.harmj0y.net/blog/redteaming/abusing-active-directory-permissions-with-powerview/) · [link](https://specterops.io/wp-content/uploads/sites/3/2022/06/an_ace_up_the_sleeve.pdf)

### AD CS Advanced Abuses (ESC9-ESC11, ESC13-ESC16)
*id:* `ad-adcs-esc9-esc16-mapping-abuse` · *category:* `adcs` · *severity:* **high** · *CVE:* CVE-2024-49019

Later-discovered AD CS escalations abuse weak certificate-to-account mappings, RPC enrollment relay, group-linked issuance policies, schema/EKU manipulation, and strong-mapping enforcement gaps to authenticate as privileged principals.

**How it works —** ESC9 = template with no-security-extension flag (CT_FLAG_NO_SECURITY_EXTENSION) lets a cert omit the SID, enabling weak-mapping impersonation when combined with control of a target's userPrincipalName. ESC10 = weak certificate mapping registry settings (StrongCertificateBindingEnforcement/UPN mapping) allow UPN-based impersonation. ESC11 = relay of RPC-based ICertPassage (ICPR) enrollment when IF_ENFORCEENCRYPTICERTREQUEST is off. ESC13 = a certificate template linked to an issuance policy that maps to a privileged AD group (msDS-OIDToGroupLink) grants that group membership on logon. ESC14 = write access to altSecurityIdentities enables explicit certificate mapping to a victim. ESC15 (CVE-2024-49019, 'EKUwu') = schema v1 templates allow injecting arbitrary application policies/EKUs into a request. ESC16 = CA-wide disabling of the SID security extension weakens all mappings. Certs are used via PKINIT/Schannel to authenticate as the impersonated principal.

**Prerequisites:** Enterprise CA present; The specific misconfiguration (weak mapping, OID-to-group link, writable altSecurityIdentities, v1 schema template, or CA-level SID-extension disablement); Often control over a low-priv account whose UPN/attributes can be edited

**Enumerate:**
- `Certipy: certipy find -vulnerable -stdout  (flags ESC9-ESC16 in recent versions)`
- `Inspect StrongCertificateBindingEnforcement (KDC) and CertificateMappingMethods (Schannel) registry values`
- `Enumerate templates with msDS-OIDToGroupLink issuance policies (ESC13)`
- `Check altSecurityIdentities write access on target objects (ESC14)`

**Detection indicators:** `Certificate logons mapped to accounts via UPN/altSecurityIdentities rather than strong SID mapping`, `Post-KB5014754 events 39/41 (KDC) about certificates without the SID extension or weak mapping`, `Issuance-policy OIDs linked to privileged groups; unexpected group membership acquired at logon (ESC13)`, `v1 template requests carrying injected application policies (ESC15)`

**Tools:** certipy, certify, rubeus, bloodhound (adcs edges)

**Mitigation:** Deploy KB5014754 and set StrongCertificateBindingEnforcement to Full (strong SID mapping) to close ESC9/ESC10/ESC16; Enable IF_ENFORCEENCRYPTICERTREQUEST (ESC11); retire schema v1 templates and patch CVE-2024-49019 (ESC15); Restrict msDS-OIDToGroupLink issuance policies and altSecurityIdentities write access; Continuously audit AD CS with Certipy and monitor certificate mapping events

**References:** [link](https://github.com/ly4k/Certipy) · [link](https://research.ifcr.dk/certipy-4-0-esc9-esc10-bloodhound-and-new-path-of-least-resistance-7bf96d0dc73f) · [link](https://posts.specterops.io/adcs-esc13-abuse-technique-fda4272fbd53) · [link](https://www.trustedsec.com/blog/ekuwu-not-just-another-ad-cs-esc)

### AS-REP Roasting
*id:* `ad-asrep-roasting-nopreauth` · *category:* `asrep-roasting` · *severity:* **high**

Accounts configured with 'Do not require Kerberos preauthentication' (DONT_REQ_PREAUTH) allow anyone to request an AS-REP whose encrypted portion is derived from the user's password, enabling offline cracking without any credentials.

**How it works —** Normally Kerberos preauthentication requires the client to prove knowledge of the password (an encrypted timestamp) before the KDC issues an AS-REP. When preauth is disabled on an account, the KDC returns an AS-REP containing material encrypted with the account's password-derived key to any requester. Attackers harvest these for flagged accounts and crack them offline. Unlike Kerberoasting, this needs no authenticated context (only the list of usernames) when targeting no-preauth accounts. GenericWrite over an account can be abused to toggle the DONT_REQ_PREAUTH UAC flag (targeted AS-REP roasting).

**Prerequisites:** A list of valid usernames (or authenticated enumeration); Target account has userAccountControl flag DONT_REQ_PREAUTH (0x400000) set; Weak account password for cracking

**Enumerate:**
- `PowerView: Get-DomainUser -PreauthNotRequired -Properties samaccountname,useraccountcontrol`
- `Impacket: GetNPUsers.py <domain>/ -usersfile users.txt -dc-ip <dc> -no-pass -format hashcat`
- `AD module: Get-ADUser -Filter {DoesNotRequirePreAuth -eq $true}`
- `Rubeus.exe asreproast /format:hashcat`

**Detection indicators:** `Security Event 4768 (TGT requested) with Pre-Authentication Type 0 and RC4 encryption (0x17)`, `Accounts with userAccountControl containing DONT_REQ_PREAUTH`, `AS-REQ from unusual hosts for accounts lacking preauth`

**Tools:** rubeus, impacket getnpusers.py, hashcat (mode 18200), john the ripper, powerview, bloodhound

**Mitigation:** Remove DONT_REQ_PREAUTH from all accounts unless strictly required; Enforce strong passwords and AES-only encryption; Alert on 4768 events with pre-auth type 0

**References:** [link](https://github.com/GhostPack/Rubeus) · [link](https://github.com/fortra/impacket/blob/master/examples/GetNPUsers.py) · [link](https://attack.mitre.org/techniques/T1558/004/) · [link](https://www.harmj0y.net/blog/activedirectory/roasting-as-reps/)

### gMSA managed-password read (READ_GMSA / msDS-ManagedPassword)
*id:* `ad-gmsa-password-read` · *category:* `credential-harvesting` · *severity:* **high**

Principals listed in a group-Managed Service Account's msDS-GroupMSAMembership (or with the READ_GMSA_PASSWORD right) can retrieve the account's msDS-ManagedPassword blob, derive its NTLM hash, and authenticate as that service account; with the KDS root key, the password can even be computed offline (Golden gMSA).

**How it works —** A gMSA's password is generated by the domain from the KDS root key and exposed via the constructed LDAP attribute msDS-ManagedPassword to accounts allowed by msDS-GroupMSAMembership (the 'PrincipalsAllowedToRetrieveManagedPassword'). An attacker who controls such an allowed principal reads that blob over LDAP and computes the account's NTLM hash from the current password field — no cracking needed — then uses it for pass-the-hash / service authentication as the (often privileged) service account. gMSADumper and DSInternals automate the read-and-derive. Separately, the Golden gMSA attack (GoldenGMSA) recovers the domain KDS root key (readable by Domain/Enterprise Admins) and computes any gMSA's password entirely offline, across time, without further DC contact. BloodHound flags ReadGMSAPassword edges to find the abusable principals.

**Prerequisites:** control of a principal in the target gMSA's msDS-GroupMSAMembership / READ_GMSA_PASSWORD right, OR; read access to the KDS root key (Domain/Enterprise Admin) for the Golden gMSA variant

**Enumerate:**
- `Get-ADServiceAccount -Filter * -Properties PrincipalsAllowedToRetrieveManagedPassword`
- `python3 gMSADumper.py -u user -p pass -d domain`
- `Get-ADObject -Filter 'objectClass -eq "msDS-GroupManagedServiceAccount"' -Properties *`
- `GoldenGMSA.exe kdsinfo`

**Detection indicators:** `msDS-ManagedPassword`, `msDS-GroupMSAMembership`, `ReadGMSAPassword`, `msDS-GroupManagedServiceAccount`, `KDS root key`, `PrincipalsAllowedToRetrieveManagedPassword`

**Tools:** gmsadumper, goldengmsa, dsinternals, bloodhound, netexec

**Mitigation:** Tightly scope PrincipalsAllowedToRetrieveManagedPassword to required hosts only; Protect the KDS root key; treat Domain/Enterprise Admin as tier-0; Audit gMSA membership and msDS-ManagedPassword reads; Rotate/limit privileges of gMSA-run services; monitor BloodHound ReadGMSAPassword edges

**References:** [link](https://github.com/micahvandeusen/gMSADumper) · [link](https://github.com/Semperis/GoldenGMSA) · [link](https://www.semperis.com/blog/golden-gmsa-attack/) · [link](https://www.thehacker.recipes/ad/movement/dacl/readgmsapassword) · [link](https://simondotsh.com/infosec/2022/12/12/gmsa.html)

### LAPS Password Read Abuse
*id:* `ad-laps-password-read-abuse` · *category:* `credential-harvesting` · *severity:* **high**

The Local Administrator Password Solution stores each machine's randomized local admin password in an AD attribute; principals granted read access to ms-Mcs-AdmPwd (legacy LAPS) or msLAPS-Password/EncryptedPassword (Windows LAPS) can retrieve cleartext local admin passwords for lateral movement.

**How it works —** LAPS randomizes and rotates the local Administrator password and stores it in a confidential AD attribute on the computer object, readable only by delegated principals. If ACLs over-grant read (All Extended Rights, GenericAll, or explicit read of the password attribute) to broad groups, an attacker who compromises such a principal reads the plaintext local admin password directly from AD and moves laterally. Over-broad delegation, or compromise of the intended reader group, converts LAPS from a control into a credential store. Windows LAPS adds encrypted storage and can protect with DPAPI, but read-access misconfiguration still applies.

**Prerequisites:** LAPS deployed; An identity with read access to the LAPS password attribute (ms-Mcs-AdmPwd or msLAPS-Password) on target computers; For Windows LAPS encrypted mode: decryption rights

**Enumerate:**
- `PowerView: Get-DomainComputer -Properties ms-Mcs-AdmPwd,samaccountname | ? {$_.'ms-mcs-admpwd'}`
- `Find readers: Find-LAPSDelegatedGroups / Find-AdmPwdExtendedRights (LAPSToolkit)`
- `BloodHound: 'ReadLAPSPassword' edges`
- `pyLAPS: pyLAPS.py --action get -d <domain> -u <user> -p <pass>`

**Detection indicators:** `Event 4662 read access to the LAPS password attribute by non-standard principals`, `Bulk queries of ms-Mcs-AdmPwd/msLAPS-Password across many computer objects`, `Local admin logons using the LAPS-managed account from unexpected source hosts`

**Tools:** lapstoolkit, pylaps, sharplaps, powerview, bloodhound, get-admpwdpassword (admpwd.ps)

**Mitigation:** Tightly scope who can read LAPS passwords; audit ms-Mcs-AdmPwd/msLAPS ACLs regularly; Migrate to Windows LAPS with encrypted passwords and DPAPI protection; shorten rotation; Monitor 4662 reads of the LAPS attribute and alert on bulk reads; Enforce Tier-0 separation so LAPS readers are not broadly reachable

**References:** [link](https://github.com/leoloobeek/LAPSToolkit) · [link](https://github.com/p0dalirius/pyLAPS) · [link](https://www.thehacker.recipes/ad/movement/dacl/read-laps-password) · [link](https://learn.microsoft.com/en-us/windows-server/identity/laps/laps-overview)

### Constrained Delegation Abuse (S4U2Proxy)
*id:* `ad-constrained-delegation-s4u` · *category:* `delegation` · *severity:* **high**

An account configured for constrained delegation (msDS-AllowedToDelegateTo) can use S4U2Self/S4U2Proxy to obtain service tickets impersonating arbitrary users to the allowed services — and, because only the SPN's service class is validated, the ticket can often be reused against other services on the same host.

**How it works —** Kerberos constrained delegation lets a service request tickets to a fixed list of downstream SPNs on behalf of a user (S4U2Proxy), first minting a forwardable ticket to itself via S4U2Self. If an attacker controls a delegating account, they can impersonate any non-protected user (including domain admins) to the target service. When protocol transition (TRUSTED_TO_AUTH_FOR_DELEGATION) is enabled, no prior user authentication is needed. Because the KDC only checks the service class portion of the SPN and not the exact service, an allowed 'HOST/server' ticket can be rewritten for 'CIFS/server', 'LDAP/server', etc., expanding impact.

**Prerequisites:** Control of an account with msDS-AllowedToDelegateTo populated; The delegated-to service is valuable (e.g., LDAP on a DC enables DCSync-style access)

**Enumerate:**
- `PowerView: Get-DomainUser -TrustedToAuth ; Get-DomainComputer -TrustedToAuth`
- `AD module: Get-ADObject -Filter {msDS-AllowedToDelegateTo -like '*'} -Properties msDS-AllowedToDelegateTo`
- `BloodHound: 'AllowedToDelegate' edges`
- `Rubeus.exe s4u  (to request; use /altservice to swap service class)`

**Detection indicators:** `Event 4769 with Transited Services populated (S4U2Proxy) for sensitive target SPNs`, `Service tickets impersonating admin accounts to LDAP/CIFS/HOST on DCs`, `Accounts with TRUSTED_TO_AUTH_FOR_DELEGATION (protocol transition) set`

**Tools:** rubeus, impacket getst.py, mimikatz, bloodhound, powerview

**Mitigation:** Minimize constrained delegation; avoid protocol transition; Protect Tier-0 accounts with 'sensitive and cannot be delegated' and Protected Users group; Prefer resource-based constrained delegation so target owners control who may delegate; Never allow delegation to DC services

**References:** [link](https://github.com/GhostPack/Rubeus) · [link](https://github.com/fortra/impacket/blob/master/examples/getST.py) · [link](https://www.harmj0y.net/blog/activedirectory/s4u2pwnage/) · [link](https://shenaniganslabs.io/2019/01/28/Wagging-the-Dog.html)

### Resource-Based Constrained Delegation (RBCD) Abuse
*id:* `ad-rbcd-msds-allowedtoactonbehalf` · *category:* `delegation` · *severity:* **high**

If an attacker can write the msDS-AllowedToActOnBehalfOfOtherIdentity attribute on a target computer (via GenericWrite/GenericAll/WriteDACL), they configure an attacker-controlled account as a permitted delegate and then use S4U to impersonate any user — including local admins — to that computer.

**How it works —** RBCD moves delegation control from the source service to the target resource. The target's security descriptor (msDS-AllowedToActOnBehalfOfOtherIdentity) lists SIDs allowed to delegate to it. An attacker with write access to a computer object adds a controlled principal (frequently a new machine account created via MachineAccountQuota) to that attribute, then performs S4U2Self+S4U2Proxy to obtain a service ticket for e.g. CIFS/target impersonating a Domain Admin, yielding SYSTEM on the target. This is the classic 'Wagging the Dog' primitive and a common BloodHound-identified path.

**Prerequisites:** Write access (GenericWrite/GenericAll/WriteDACL/WriteProperty) to the target computer object; Control of an account with an SPN (create one via MAQ if none available)

**Enumerate:**
- `PowerView: Get-DomainComputer <target> -Properties 'msds-allowedtoactonbehalfofotheridentity'`
- `BloodHound: nodes with GenericWrite/GenericAll/WriteDacl to computers; 'AllowedToAct' edges`
- `Get-ADComputer <target> -Properties PrincipalsAllowedToDelegateToAccount`
- `PowerView: Get-DomainObjectAcl to find writeable computer ACLs`

**Detection indicators:** `Security Event 5136 modification of msDS-AllowedToActOnBehalfOfOtherIdentity`, `Creation of a new computer account (Event 4741) shortly before a delegation change`, `4769 with Transited Services impersonating privileged users to a workstation/server`

**Tools:** rubeus, impacket (rbcd.py, getst.py, addcomputer.py), powerview (set-domainrbcd), powermad, bloodhound

**Mitigation:** Set MachineAccountQuota to 0 so users cannot create attacker machine accounts; Tighten computer object ACLs; remove excessive GenericWrite/WriteDACL grants; Add Tier-0 accounts to Protected Users / mark as sensitive-cannot-be-delegated; Monitor 5136 changes to msDS-AllowedToActOnBehalfOfOtherIdentity

**References:** [link](https://github.com/fortra/impacket/blob/master/examples/rbcd.py) · [link](https://github.com/GhostPack/Rubeus) · [link](https://shenaniganslabs.io/2019/01/28/Wagging-the-Dog.html) · [link](https://www.thehacker.recipes/ad/movement/kerberos/delegations/rbcd)

### Diamond Ticket
*id:* `ad-diamond-ticket-pac-modification` · *category:* `diamond-ticket` · *severity:* **high**

Instead of forging a TGT from scratch (Golden), the attacker requests a legitimate TGT with the krbtgt key, decrypts it, modifies the PAC (e.g., adds Domain Admins), and re-encrypts it — producing a ticket with authentic KDC-issued fields that evades golden-ticket detections.

**How it works —** Golden tickets are detectable because their fields (lifetime, PAC contents, request pattern) are attacker-fabricated and often unrealistic. A Diamond ticket starts from a real AS-REQ TGT for a low-priv account, then uses the krbtgt key to decrypt it, alter the PAC's group SIDs/user identity, and re-sign it. The result carries genuine KDC-issued timestamps and structure, matching what a 4768 shows, so it blends in far better while still granting elevated access. Still requires the krbtgt key.

**Prerequisites:** krbtgt key (as with Golden Ticket); A valid TGT obtainable for some account (real AS-REQ)

**Enumerate:**
- `Rubeus.exe diamond /...  (research/perform)`
- `Defenders: correlate 4768 TGT issuance with later privileged use inconsistent with the account's real group membership`
- `Rubeus.exe describe /ticket:<ticket> to inspect PAC`

**Detection indicators:** `A user authenticating with privileges (group SIDs) that do not match their actual AD group membership`, `PAC group memberships inconsistent with directory state for the account`, `Same detection difficulty as golden — focus on privilege-vs-membership mismatch`

**Tools:** rubeus (diamond), mimikatz, impacket ticketer.py

**Mitigation:** Same as Golden Ticket: rotate krbtgt twice after Tier-0 compromise; protect the krbtgt secret; Detect authorization decisions where PAC group SIDs exceed the account's real membership; Enable PAC validation and Kerberos AES enforcement

**References:** [link](https://github.com/GhostPack/Rubeus) · [link](https://www.trustedsec.com/blog/a-diamond-in-the-ruff/)

### GPO Abuse (Group Policy Object Modification)
*id:* `ad-gpo-abuse-modification` · *category:* `gpo-abuse` · *severity:* **high**

An attacker with edit rights on a Group Policy Object (or write access to a linked OU) can push malicious settings — scheduled tasks, immediate tasks, local admin group membership, startup scripts — to every computer/user the GPO applies to, enabling mass code execution or privilege grants.

**How it works —** GPOs are stored as files in SYSVOL plus AD objects, and are applied by clients on refresh. If an attacker can write to a GPO (WriteProperty on gpc-file-sys-path / GP-Options, or edit rights) or link a GPO to an OU, they can add an immediate scheduled task, a startup script, or a Restricted Groups / Group Policy Preferences membership change that makes a controlled account local administrator on all affected machines. Because GPO scope can be huge (e.g., a GPO linked to the Domain Controllers OU or the domain root), impact reaches domain compromise. SharpGPOAbuse automates injecting tasks/rights into an editable GPO.

**Prerequisites:** Edit rights on a GPO (WriteDACL/WriteProperty/GenericWrite on the GPC) or the ability to link GPOs to a target OU; Target OU/domain contains valuable computers or users

**Enumerate:**
- `BloodHound: 'GPO' control edges and 'affected objects' of a GPO`
- `PowerView: Get-DomainGPO | Get-DomainObjectAcl -ResolveGUIDs ; Get-DomainOU | select gplink`
- `PowerView: Get-DomainGPOUserLocalGroupMapping / Get-DomainGPOComputerLocalGroupMapping`
- `GPMC / Get-GPO -All for delegation review`

**Detection indicators:** `Event 5136/5137 changes to GPO objects (gPCFileSysPath, versionNumber) and new gPLink on OUs`, `SYSVOL file changes (ScheduledTasks.xml, GptTmpl.inf, scripts) by non-admin editors`, `Unexpected scheduled tasks/startup scripts appearing on many hosts simultaneously`, `New members added to local Administrators via GPP/Restricted Groups`

**Tools:** sharpgpoabuse, powerview, bloodhound, pygpoabuse, group3r/grouper2 (audit)

**Mitigation:** Restrict GPO edit and OU link delegation to Tier-0 admins; audit GPO ACLs; Monitor SYSVOL and GPO object changes (5136/5137, file integrity on SYSVOL); Use Group3r/Grouper2 to find over-permissive GPOs; Separate DC and Tier-0 GPOs; least-privilege delegation

**References:** [link](https://github.com/FSecureLABS/SharpGPOAbuse) · [link](https://github.com/Hackndo/pyGPOAbuse) · [link](https://wald0.com/?p=179) · [link](https://attack.mitre.org/techniques/T1484/001/)

### Kerberoasting
*id:* `ad-kerberoasting-spn-tgs-crack` · *category:* `kerberoast` · *severity:* **high**

Any authenticated domain user can request Kerberos service tickets (TGS-REP) for accounts with a Service Principal Name (SPN) and crack them offline to recover the service account's plaintext password, because the ticket is encrypted with the service account's password-derived key.

**How it works —** In Kerberos, a client requests a TGS for a target SPN; the KDC returns a ticket encrypted with the service account's NTLM/AES key. An attacker requests tickets for user accounts that have SPNs set (i.e., service accounts, not machine accounts) and cracks them offline with hashcat/John. RC4 (etype 0x17) tickets are derived directly from the NT hash and crack fastest; requesting RC4 explicitly ('downgrade') speeds attacks. Targeted Kerberoasting can be combined with GenericWrite/GenericAll to set an SPN on a victim account temporarily. No elevated privileges are required to request the tickets — only a valid domain account.

**Prerequisites:** Any valid domain user credentials; Target user accounts with servicePrincipalName set; Weak/guessable service account password for offline cracking to succeed

**Enumerate:**
- `PowerView: Get-DomainUser -SPN -Properties samaccountname,serviceprincipalname`
- `Impacket: GetUserSPNs.py <domain>/<user>:<pass> -dc-ip <dc> -request`
- `Rubeus.exe kerberoast /stats  (and /rc4opsec to find AES-only)`
- `AD module: Get-ADUser -Filter {ServicePrincipalName -like '*'} -Properties ServicePrincipalName`

**Detection indicators:** `Windows Security Event 4769 (Kerberos service ticket requested) with Ticket Encryption Type 0x17 (RC4-HMAC)`, `High volume of 4769 events for many SPNs from a single account in a short window`, `4769 Ticket Options flag 0x40810000 combined with RC4 for accounts that normally use AES`, `Requests for SPNs of low-value/decoy (honeypot) service accounts`

**Tools:** rubeus, impacket getuserspns.py, powerview, hashcat (mode 13100), john the ripper (krb5tgs), targetedkerberoast, bloodhound

**Mitigation:** Use Group Managed Service Accounts (gMSA) with 120-char auto-rotated passwords; Enforce long (25+ char) random passwords on service accounts and disable RC4 (set msDS-SupportedEncryptionTypes to AES-only); Deploy honeypot SPN accounts and alert on 4769 for them; Remove unnecessary SPNs; audit for user accounts with SPNs

**References:** [link](https://github.com/GhostPack/Rubeus) · [link](https://github.com/fortra/impacket/blob/master/examples/GetUserSPNs.py) · [link](https://attack.mitre.org/techniques/T1558/003/) · [link](https://adsecurity.org/?p=2293) · [link](https://www.harmj0y.net/blog/powershell/kerberoasting-without-mimikatz/)

### Overpass-the-Hash / Pass-the-Key
*id:* `ad-overpass-the-hash-key` · *category:* `overpass-the-hash` · *severity:* **high**

An attacker uses a stolen NT hash (or AES key) to request a legitimate Kerberos TGT, converting NTLM material into full Kerberos authentication and thereby accessing Kerberos-only services and blending into normal Kerberos traffic.

**How it works —** Because the Kerberos AS-REQ preauth key is derived from the account password (NT hash for RC4, or AES key), an attacker who has the hash/key can request a real TGT (AS-REQ) for the account without the plaintext. This 'overpasses' the hash: the resulting TGT is used for standard Kerberos service ticket requests. Requesting RC4 reveals the RC4/NT-derived path; using the account's AES256 key (Pass-the-Key) avoids RC4 downgrade detections. The TGT can then be injected into a logon session (Pass-the-Ticket).

**Prerequisites:** NT hash or Kerberos AES/DES key for the target account; Network reachability to the KDC (a DC)

**Enumerate:**
- `Extract keys: secretsdump.py output includes aes256/aes128/rc4 keys per account`
- `Rubeus.exe asktgt /user:<u> /rc4:<hash>  (or /aes256:<key>) to obtain a TGT`
- `Validate resulting access with klist and Kerberos-only service access`

**Detection indicators:** `Event 4768 (TGT request) using RC4 (0x17) for an account/host that should use AES`, `TGT requests originating from a workstation IP that does not match the account's normal host`, `Mismatch between logon session NTLM secrets and Kerberos activity`

**Tools:** rubeus (asktgt), mimikatz (sekurlsa::pth with /aes256), impacket gettgt.py, crackmapexec/netexec

**Mitigation:** Disable RC4 Kerberos etypes domain-wide to force AES and improve detection; Protect credential stores (Credential Guard, LSASS PPL); Protected Users group forces AES and blocks RC4/NTLM for members; Alert on RC4 4768 events and geographically/host-anomalous TGT requests

**References:** [link](https://github.com/GhostPack/Rubeus) · [link](https://github.com/fortra/impacket/blob/master/examples/getTGT.py) · [link](https://attack.mitre.org/techniques/T1550/002/) · [link](https://adsecurity.org/?p=2362)

### Pass-the-Hash (PtH)
*id:* `ad-pass-the-hash-ntlm` · *category:* `pass-the-hash` · *severity:* **high**

The NTLM authentication protocol proves identity with the NT hash rather than the plaintext, so an attacker who obtains a user's NT hash can authenticate to remote services as that user without ever cracking the password.

**How it works —** NTLM challenge-response uses the NT hash directly as the key. After dumping hashes from LSASS, the SAM, NTDS.dit, or via DCSync, an attacker supplies the hash to tools that speak SMB/WMI/RPC and authenticates over the network without the cleartext. Local admin hash reuse across machines enables lateral movement; a domain admin hash yields domain-wide access. PtH is limited to NTLM-authenticated services (SMB, WMI, WinRM); Kerberos-only paths require Overpass-the-Hash instead.

**Prerequisites:** An NT hash for a target account; Network access to services accepting NTLM; Target account has privileges on the destination host

**Enumerate:**
- `BloodHound: 'AdminTo' / local admin reuse mapping across hosts`
- `CrackMapExec/NetExec: nxc smb <targets> -u <user> -H <nthash> (validation of where a hash works)`
- `Identify hash sources: SAM/LSASS/NTDS access rights on hosts`

**Detection indicators:** `Event 4624 Logon Type 3 with Authentication Package NTLM for accounts that normally use Kerberos`, `4776 (NTLM credential validation) spikes from workstation-to-workstation`, `Same account authenticating to many hosts in a short window (lateral movement)`, `Use of built-in local Administrator (RID 500) across multiple machines`

**Tools:** mimikatz (sekurlsa::pth), impacket (psexec.py/wmiexec.py -hashes), crackmapexec/netexec, evil-winrm

**Mitigation:** Enable LSASS protection (RunAsPPL/Credential Guard) to prevent hash theft; Use unique local admin passwords (LAPS/Windows LAPS) to stop hash reuse; Add privileged accounts to Protected Users (removes NTLM), enforce tiering; Restrict lateral SMB/WMI with host firewall and 'Deny access from network' for admin accounts

**References:** [link](https://github.com/gentilkiwi/mimikatz) · [link](https://github.com/fortra/impacket) · [link](https://attack.mitre.org/techniques/T1550/002/)

### Pass-the-Ticket (PtT)
*id:* `ad-pass-the-ticket-ptt` · *category:* `pass-the-ticket` · *severity:* **high**

An attacker extracts existing Kerberos tickets (TGTs or service tickets) from a host's memory (or a forged ticket) and injects them into their own logon session to impersonate the ticket's owner without needing the password or hash.

**How it works —** Kerberos tickets live in LSASS and can be exported (e.g., sekurlsa::tickets, Rubeus dump) or written to .kirbi/.ccache files. An attacker with local admin/SYSTEM harvests a privileged user's TGT and injects it (ptt) into a new session, then accesses any resource the ticket permits. Forged Golden/Silver/Diamond tickets are a special case of PtT. Cross-platform, ccache files harvested from Linux/keytabs or from KRB5CCNAME can likewise be reused.

**Prerequisites:** Access to a host holding a valid ticket (local admin/SYSTEM to read LSASS) OR a forged ticket; The ticket is still within its lifetime/renew window

**Enumerate:**
- `klist  (enumerate cached tickets in current session)`
- `Rubeus.exe triage / Rubeus.exe dump  (list/export tickets)`
- `Mimikatz: sekurlsa::tickets /export`
- `Impacket: reuse of exported ccache via KRB5CCNAME`

**Detection indicators:** `Ticket used from a host different from the one it was issued to (source host mismatch)`, `4624 Logon Type 3 with Kerberos for accounts on unexpected endpoints`, `TGS requests (4769) using a TGT whose lifetime/flags are anomalous`, `LSASS read/handle events preceding remote Kerberos logons`

**Tools:** mimikatz (kerberos::ptt), rubeus (ptt/dump/triage), impacket (ccache reuse)

**Mitigation:** Protect LSASS (Credential Guard, RunAsPPL) to prevent ticket theft; Reduce TGT lifetime/renewal; enforce Protected Users (4-hour TGT, no delegation); Detect ticket-host mismatches and abnormal ticket lifetimes; Reset krbtgt twice to invalidate forged golden tickets after compromise

**References:** [link](https://github.com/GhostPack/Rubeus) · [link](https://github.com/gentilkiwi/mimikatz) · [link](https://attack.mitre.org/techniques/T1550/003/)

### SCCM / ConfigMgr abuse (NAA creds, PXE, site takeover)
*id:* `ad-sccm-configmgr-abuse` · *category:* `sccm` · *severity:* **high**

Microsoft Configuration Manager (SCCM/MECM) deployments leak Network Access Account credentials via policy/DPAPI, expose crackable PXE boot media, and permit NTLM-relay to the management point / site database — paths that yield domain credentials and full site (and often domain) takeover.

**How it works —** SCCM's tiered design exposes several abuses catalogued in the Misconfiguration-Manager project. (1) Credential recovery: any domain-joined client requests machine policy from the management point and can decrypt the embedded Network Access Account (and other) credentials protected by client DPAPI (CRED-class, e.g. SharpSCCM gets NAA creds) — those accounts are frequently over-privileged. (2) PXE abuse: if OS-deployment PXE is enabled, an attacker requests a boot image; a blank or weak PXE password lets the media be cracked (pxethiefy/PXEThief) to extract deployed credentials and task-sequence variables. (3) Relay/coercion: NTLM relay of a site-server or client machine account to the management point, SMB, or the site SQL database (via automatic client push authentication or coercion) grants Full Administrator over the site (ELEVATE/TAKEOVER classes), from which application deployment pushes SYSTEM code to any managed host. (4) CMPivot/AdminService and application deployment let a Full Admin run commands across the estate. Together these move from an unprivileged client to domain-wide compromise.

**Prerequisites:** a domain-joined SCCM client or network access to a management point / distribution point; for relay: automatic client push or coercible machine accounts and no SMB/LDAP signing enforced; for PXE: OS deployment enabled, weak/absent PXE password

**Enumerate:**
- `SharpSCCM.exe get naa`
- `SharpSCCM.exe local site-info`
- `nslookup -type=srv _mssms_mp_<sitecode>._tcp.<domain>`
- `python3 pxethiefy.py`
- `Get-WmiObject -Namespace root\ccm -Class SMS_Authority`

**Detection indicators:** `Network Access Account`, `SMS_Authority`, `CCM_NetworkAccessAccount`, `root\ccm`, `PXE`, `management point`, `_mssms_mp_`

**Tools:** sharpsccm, misconfiguration-manager, cmloot, pxethief, malsccm, ntlmrelayx

**Mitigation:** Do not use a Network Access Account (use Enhanced HTTP / PKI); if used, make it minimally privileged; Set a strong PXE password and restrict OS deployment; secure DPs; Disable automatic client push; enforce SMB and LDAP signing to block relay; Harden the site server/DB as tier-0; apply the Misconfiguration-Manager preventions/detections

**References:** [link](https://github.com/Mayyhem/SharpSCCM) · [link](https://github.com/subat0mik/Misconfiguration-Manager) · [link](https://github.com/csandker/pxethiefy) · [link](https://www.thehacker.recipes/ad/movement/sccm-mecm) · [link](https://posts.specterops.io/site-takeover-via-sccms-adminservice-api-d932e22b2bf)

### Shadow Credentials (msDS-KeyCredentialLink)
*id:* `ad-shadow-credentials-keycredentiallink` · *category:* `shadow-credentials` · *severity:* **high**

An attacker with write access to a target user/computer's msDS-KeyCredentialLink attribute adds an attacker-controlled key pair (Key Trust), then uses PKINIT to obtain a TGT and the target's NT hash — a password-less account takeover requiring no password reset.

**How it works —** Windows Hello for Business / Key Trust stores public keys in the target's msDS-KeyCredentialLink attribute; possession of the matching private key lets the holder authenticate via PKINIT and receive a TGT. If an attacker holds GenericWrite/GenericAll/WriteProperty (often surfaced by BloodHound) over a victim object, they append their own KeyCredential, then request a TGT for the victim using PKINIT and can UnPAC-the-hash to recover the victim's NT hash. Unlike a password reset, it is quiet and reversible (remove the added key). Whisker/pyWhisker automate adding the KeyCredential; Rubeus/gettgtpkinit perform PKINIT. Requires the domain to support PKINIT (a CA/DC certificate).

**Prerequisites:** Write access (GenericWrite/GenericAll/WriteProperty on msDS-KeyCredentialLink) over the target object; Domain supports PKINIT (functional DC certificates / AD CS present); DC functional level 2016+ for key trust

**Enumerate:**
- `PowerView/AD module: read msDS-KeyCredentialLink on target objects (Get-ADComputer <t> -Properties msDS-KeyCredentialLink)`
- `BloodHound: inbound GenericWrite/GenericAll/AddKeyCredentialLink edges to targets`
- `Whisker.exe list /target:<victim>  ;  pywhisker --action list`

**Detection indicators:** `Event 5136 modification of the msDS-KeyCredentialLink attribute on user/computer objects`, `PKINIT TGT requests (4768 with certificate/pre-auth type PKINIT) for accounts that don't use WHfB`, `KeyCredentials added to accounts that shouldn't have device keys, followed by immediate authentication`

**Tools:** whisker, pywhisker, rubeus (asktgt /getcredentials via pkinit), gettgtpkinit.py (pkinittools), certipy shadow, bloodhound

**Mitigation:** Restrict write access to msDS-KeyCredentialLink; audit object ACLs; Monitor 5136 changes to msDS-KeyCredentialLink and alert on additions; Enforce strong certificate mapping (KB5014754) and Tier-0 isolation; Where WHfB Key Trust is unused, watch for any KeyCredential additions as anomalies

**References:** [link](https://github.com/eladshamir/Whisker) · [link](https://github.com/ShutdownRepo/pywhisker) · [link](https://posts.specterops.io/shadow-credentials-abusing-key-trust-account-mapping-for-takeover-8ee1a53566ab) · [link](https://www.thehacker.recipes/ad/movement/kerberos/shadow-credentials)

### Silver Ticket
*id:* `ad-silver-ticket-service-forgery` · *category:* `silver-ticket` · *severity:* **high**

With a service account's (or computer account's) password hash, an attacker forges service tickets (TGS) for that specific service, impersonating any user to it without ever contacting the KDC — a stealthier, service-scoped alternative to a Golden Ticket.

**How it works —** A TGS is encrypted with the target service account's key. Knowing that key (e.g., a machine account hash for CIFS/HOST, or a SQL service account hash) lets an attacker craft a valid TGS with a forged PAC directly, bypassing the DC entirely. Because no 4768/4769 is generated at the DC, silver tickets are quieter than golden tickets. Scope is limited to the one service on the one host, but that can be SYSTEM-level (CIFS, HOST, RPCSS for WMI, LDAP for a DC). Prior to PAC validation hardening, forged PACs went unchecked.

**Prerequisites:** Password hash/AES key of the target service or computer account; Domain SID; Knowledge of the target SPN

**Enumerate:**
- `Obtain machine/service account keys via secretsdump/DCSync (post-compromise)`
- `Rubeus.exe describe /ticket:<ticket>  (inspect forged service tickets)`
- `Inventory high-value SPNs (CIFS/HOST/MSSQLSvc/LDAP) to understand impact`

**Detection indicators:** `Service access (4624/4634) with Kerberos but no corresponding 4769 at the DC`, `PAC signature/validation failures where PAC validation is enforced`, `Anomalous TGS with mismatched user/host or excessive privileges to a single service`

**Tools:** mimikatz (kerberos::golden with /service), rubeus (silver), impacket ticketer.py

**Mitigation:** Rotate machine account passwords regularly (default 30 days) and service account passwords/gMSA; Enable PAC validation / Kerberos hardening; force AES; Detect Kerberos service access lacking corresponding DC TGS issuance; Limit exposure of service/computer account secrets

**References:** [link](https://github.com/gentilkiwi/mimikatz) · [link](https://github.com/fortra/impacket/blob/master/examples/ticketer.py) · [link](https://attack.mitre.org/techniques/T1558/002/) · [link](https://adsecurity.org/?p=2011)

### MachineAccountQuota Abuse
*id:* `ad-machineaccountquota-abuse` · *category:* `machineaccountquota` · *severity:* **medium**

The default domain attribute ms-DS-MachineAccountQuota = 10 lets any authenticated user create up to ten computer accounts, which attackers leverage as controlled principals for RBCD, shadow-credential, sAMAccountName-spoofing (noPac), and relay follow-on attacks.

**How it works —** MachineAccountQuota (MAQ) governs how many machine accounts a non-admin user may join to the domain. At the default of 10, any user can create a computer object they fully control (they are its creator/owner with write to key attributes). That attacker-owned machine account with a known password/SPN is the missing puzzle piece for many escalations: it is the delegate added to a target's msDS-AllowedToActOnBehalfOfOtherIdentity (RBCD), the account whose sAMAccountName is renamed to a DC name in noPac, or the principal used in shadow-credential/relay chains. MAQ abuse itself is not escalation, but it removes a key prerequisite for several critical attacks.

**Prerequisites:** Any authenticated domain user; ms-DS-MachineAccountQuota > 0 (default 10); No GPO/ACL restricting who can add workstations to the domain

**Enumerate:**
- `Get-ADObject -Identity ((Get-ADDomain).DistinguishedName) -Properties ms-DS-MachineAccountQuota`
- `PowerView: Get-DomainObject -Identity 'DC=corp,DC=local' -Properties ms-ds-machineaccountquota`
- `Powermad: Get-MachineAccountQuota`
- `Impacket addcomputer.py (to test creation rights)`

**Detection indicators:** `Event 4741 (computer account created) sourced from a normal user rather than a provisioning/help-desk account`, `New computer objects whose creator/ms-DS-CreatorSID is a standard user`, `A burst of machine account creations preceding RBCD/noPac/relay activity`

**Tools:** powermad (new-machineaccount), impacket addcomputer.py, bloodhound, powerview

**Mitigation:** Set ms-DS-MachineAccountQuota to 0 and delegate machine-join to a specific group via 'Add workstations to domain' rights; Monitor 4741 for user-initiated computer creation; Remove the default Authenticated Users 'create computer object' capability where feasible

**References:** [link](https://github.com/Kevin-Robertson/Powermad) · [link](https://github.com/fortra/impacket/blob/master/examples/addcomputer.py) · [link](https://www.netspi.com/blog/technical-blog/network-penetration-testing/machineaccountquota-is-useful-sometimes/) · [link](https://www.thehacker.recipes/ad/movement/domain-settings/machineaccountquota)


## macOS privilege escalation

### macOS dylib hijacking / DYLD_INSERT_LIBRARIES injection
*id:* `macos-dylib-hijacking-dyld-insert` · *category:* `dylib-hijack` · *severity:* **high**

A privileged or entitled Mach-O process that searches a writable path for a missing/weak-linked dylib, or that does not enforce hardened runtime/library validation, can be made to load an attacker library — running code in its (higher-privilege or entitled) context.

**How it works —** Two related primitives. (1) Dylib hijacking (Patrick Wardle): a binary with an LC_LOAD_WEAK_DYLIB for a library that is absent, or with an @rpath search order where an earlier rpath entry is attacker-writable, will load a planted dylib at that path. Placing a malicious library there causes the target to load and execute it on launch, inheriting the target's privileges/entitlements. (2) DYLD_INSERT_LIBRARIES: the dynamic loader force-loads libraries named in this environment variable — for any process the attacker can spawn with a controlled environment that is not protected by hardened runtime (which strips DYLD_* vars) or library validation. Hijacking an entitled or root/SUID process this way yields privilege escalation, TCC-grant inheritance, or persistence. dylibhijack/DylibHijack tooling finds vulnerable @rpath binaries automatically.

**Prerequisites:** a target Mach-O that weak-links or @rpath-searches a writable location, OR; a launchable process lacking hardened runtime / library validation to use DYLD_INSERT_LIBRARIES; write access to the relevant search path

**Enumerate:**
- `otool -l /path/to/binary | grep -A3 LC_RPATH`
- `otool -L /path/to/binary`
- `codesign -dv --verbose=4 /path/to/App.app`
- `codesign -d --entitlements - /path/to/binary`
- `DYLD_PRINT_LIBRARIES=1 /path/to/binary`

**Detection indicators:** `DYLD_INSERT_LIBRARIES`, `LC_LOAD_WEAK_DYLIB`, `@rpath`, `LC_RPATH`, `library validation`, `com.apple.security.cs.disable-library-validation`

**Tools:** dylibhijackscanner, insert_dylib, otool, codesign, objective-see-utilities

**Mitigation:** Ship apps with hardened runtime enabled (strips DYLD_* and enforces library validation); Avoid weak/@rpath dylib references pointing at user-writable locations; Enforce code-signing and notarization; set restricted segment where appropriate; Monitor for unexpected dylib loads in privileged processes

**References:** [link](https://www.virusbulletin.com/virusbulletin/2015/03/dylib-hijacking-os-x) · [link](https://github.com/objective-see/DHS) · [link](https://book.hacktricks.xyz/macos-hardening/macos-security-and-privilege-escalation/macos-dyld-hijacking-and-dyld_insert_libraries) · [link](https://theevilbit.github.io/posts/dyld_insert_libraries_dylib_injection_in_macos_osx_deep_dive/)

### macOS SUID / AuthorizationDB / PackageKit local root
*id:* `macos-suid-authorizationdb-packagekit-root` · *category:* `privilege-escalation` · *severity:* **high** · *CVE:* CVE-2021-30657, CVE-2022-26688, CVE-2024-23275

Local root on macOS via abusable SUID/setuid binaries, sudo misconfig, tampering with the Authorization database rules, or logic bugs in privileged installer components (PackageKit / system_installd, shared-file-list) that run attacker-influenced code as root and can bypass SIP.

**How it works —** Several classic local-root avenues. (1) SUID/sudo: GTFOBins-style abuse of setuid binaries or sudo rules, same as Linux, applies to macOS-specific SUID binaries. (2) Authorization database: /var/db/auth.db (backed by /System/Library/Security/authorization.plist) maps rights like system.privilege.admin to rules; a process able to edit auth rules (or an XPC helper with weak client validation) can lower the requirement for a privileged operation and then invoke it. (3) PackageKit / system_installd: the system_installd daemon runs Apple-signed packages as root with the com.apple.rootless.install.heritable entitlement (CS_INSTALLER), so a logic flaw letting an attacker influence a post-install script or a path it touches yields root and SIP bypass — Apple issued a long chain of patches (CVE-2022-26688, CVE-2023-23497, CVE-2024-23275, CVE-2024-44178, and related). (4) Gatekeeper/quarantine bypasses such as CVE-2021-30657 let unsigned code run as the user without prompts, a common first stage. Csaba Fitzl's research documents shared-file-list and installer-based root escalations in depth.

**Prerequisites:** local code execution as a normal user; an abusable SUID/sudo rule, writable auth rule / weak XPC helper, or an unpatched PackageKit/installd logic bug

**Enumerate:**
- `find / -perm -4000 -type f 2>/dev/null`
- `sudo -l`
- `security authorizationdb read system.privilege.admin`
- `ls -la /var/db/auth.db`
- `csrutil status`
- `codesign -d --entitlements - /System/Library/PrivateFrameworks/PackageKit.framework`

**Detection indicators:** `-rwsr-xr-x`, `system.privilege.admin`, `authorizationdb`, `com.apple.rootless.install.heritable`, `system_installd`, `CS_INSTALLER`

**Tools:** gtfobins, swiftbelt, knockout, codesign, objective-see-utilities

**Mitigation:** Keep macOS patched (installer/PackageKit and Gatekeeper fixes ship regularly); Minimize SUID binaries and permissive sudoers; protect /var/db/auth.db (SIP); Validate XPC clients (audit token) in privileged helpers; Enable SIP and Gatekeeper; require notarization

**References:** [link](https://khronokernel.com/macos/2024/06/03/CVE-2024-27822.html) · [link](https://jhftss.github.io/Endless-Exploits/) · [link](https://cedowens.medium.com/macos-gatekeeper-bypass-2021-edition-5256a2955508) · [link](https://book.hacktricks.xyz/macos-hardening/macos-security-and-privilege-escalation) · [link](https://theevilbit.github.io/posts/)

### macOS TCC privacy database bypass
*id:* `macos-tcc-privacy-bypass` · *category:* `tcc-bypass` · *severity:* **high** · *CVE:* CVE-2021-30970, CVE-2020-9934, CVE-2021-30713

Transparency, Consent and Control (TCC) gates access to protected data (files, camera, mic, automation, full disk). Attackers bypass it by riding a Full-Disk-Access-granted app, injecting into entitled/injectable processes (e.g. non-hardened Electron apps), or directly manipulating the TCC.db when protection is weak.

**How it works —** TCC stores per-app grants in SQLite (~/Library/Application Support/com.apple.TCC/TCC.db for the user, /Library/... for the system). Bypasses: (1) piggyback on an app already granted Full Disk Access (e.g. Terminal, a backup or EDR agent) to read protected paths its permission covers; (2) inject code into a process that holds a privacy entitlement (com.apple.private.tcc.allow) or is not hardened-runtime/library-validation protected — many Electron and third-party apps allow DYLD injection or plugin loading, inheriting the host's TCC grants; (3) directly read/modify TCC.db if the attacker already has FDA or the DB is not SIP-protected, adding a fake ALLOW row; (4) abuse specific Apple bugs such as PowerDir (CVE-2021-30970, changing the target of the user TCC dir), CVE-2020-9934 (env-var path confusion in tccd), and XCSSET's CVE-2021-30713. The result is access to Documents, Photos, Messages, camera/mic, or full disk without a consent prompt.

**Prerequisites:** local code execution as a user, or an injectable/entitled app to hijack; for direct TCC.db edits: existing Full Disk Access or an unpatched SIP/tccd bug

**Enumerate:**
- `sqlite3 ~/Library/Application\ Support/com.apple.TCC/TCC.db 'select service,client,auth_value from access'`
- `tccutil reset All`
- `codesign -d --entitlements - /path/to/App.app`
- `csrutil status`
- `ls -la /Library/Application\ Support/com.apple.TCC/`

**Detection indicators:** `com.apple.TCC`, `TCC.db`, `kTCCService`, `com.apple.private.tcc.allow`, `SystemPolicyAllFiles`, `hardened runtime`

**Tools:** tccutil, objective-see-utilities, codesign, swiftbelt

**Mitigation:** Keep macOS patched; enable SIP (protects the system TCC.db); Enable hardened runtime + library validation on distributed apps; avoid injectable Electron builds; Limit which apps receive Full Disk Access; audit TCC grants; Use MDM PPPC profiles to control automation/privacy entitlements

**References:** [link](https://www.microsoft.com/en-us/security/blog/2022/01/10/new-macos-vulnerability-powerdir-could-lead-to-unauthorized-user-data-access/) · [link](https://theevilbit.github.io/posts/tcc_a_deep_dive/) · [link](https://book.hacktricks.xyz/macos-hardening/macos-security-and-privilege-escalation/macos-security-protections/macos-tcc) · [link](https://objective-see.org/blog.html)


## Tooling catalog


### Reference Db

| Tool | Platform | What it does | Link |
| --- | --- | --- | --- |
| **GTFOBins** | linux | Curated database of Unix binaries that can be abused to bypass local security restrictions. Maps standard utilities (tar, find, vim, awk, less, etc.) to the functions they can be coerced into: SUID exploitation, sudo abuse, capabilities, shell escapes, file read/write, and reverse shells. The canonical reference for turning a misconfigured sudoers entry or a SUID root binary into a privesc. | [gtfobins.github.io/](https://gtfobins.github.io/) |
| **HackTricks** | cross-platform | Large community-maintained knowledge base of pentesting and privilege-escalation methodology across Linux, Windows, Active Directory, cloud, and containers. Contains dedicated Linux and Windows local-privesc checklists enumerating misconfiguration classes (sudo, SUID, cron, capabilities, kernel exploits, service/registry perms, token privileges) with links to relevant PoCs. | [book.hacktricks.wiki/](https://book.hacktricks.wiki/) |
| **LOLBAS (Living Off The Land Binaries, Scripts and Libraries)** | windows | Windows counterpart to GTFOBins. Catalogs signed, Microsoft-shipped binaries, scripts and libraries (certutil, rundll32, regsvr32, mshta, msbuild, bitsadmin, etc.) abusable for execution, download, UAC bypass, credential theft, and defense evasion while appearing legitimate. Each entry lists the abuse function, sample command, MITRE ATT&CK mapping, and detection notes. | [lolbas-project.github.io/](https://lolbas-project.github.io/) |
| **LOLDrivers (Living Off The Land Drivers)** | windows | Consolidated database of known vulnerable and malicious Windows drivers used in BYOVD (Bring Your Own Vulnerable Driver) attacks. Provides hashes, signatures, and Sigma/YARA detection artifacts for drivers attackers load to gain kernel-level code execution, disable EDR, or escalate from admin to SYSTEM/kernel. | [www.loldrivers.io/](https://www.loldrivers.io/) |
| **PayloadsAllTheThings** | cross-platform | Comprehensive repository of payloads, bypasses, and methodology notes for web and infrastructure security testing, including dedicated Linux and Windows privilege-escalation sections that document enumeration steps, common misconfigurations, and references to public exploits. | [github.com/swisskyrepo/PayloadsA](https://github.com/swisskyrepo/PayloadsAllTheThings) |
| **WADComs** | active-directory | Interactive cheat-sheet matrix of offensive-security commands for Windows/Active Directory environments. Cross-references common tooling (Impacket, NetExec, Rubeus, Certipy, etc.) against attack scenarios and the credential material held (password, hash, ticket), producing ready command syntax for enumeration and AD attack paths. | [wadcoms.github.io/](https://wadcoms.github.io/) |

### Enumeration

| Tool | Platform | What it does | Link |
| --- | --- | --- | --- |
| **AccessChk (Sysinternals)** | windows | Official Microsoft Sysinternals utility that reports the effective permissions users and groups have on files, directories, registry keys, services, processes, and other securable objects. | [learn.microsoft.com/en-us/sysint](https://learn.microsoft.com/en-us/sysinternals/downloads/accesschk) |
| **BeRoot** | cross-platform | Multi-platform privesc path detector (Windows, Linux, macOS) that checks common misconfigurations which could allow local escalation, reporting potential paths rather than exploiting them. | [github.com/AlessandroZ/BeRoot](https://github.com/AlessandroZ/BeRoot) |
| **enum4linux-ng** | linux | Modern rewrite of enum4linux for enumerating information from Windows/Samba SMB services (users, groups, shares, password policy, OS/domain info) from a Linux attacker host, with structured JSON/YAML output. | [github.com/cddmp/enum4linux-ng](https://github.com/cddmp/enum4linux-ng) |
| **JAWS (Just Another Windows (Enum) Script)** | windows | Dependency-light PowerShell enumeration script for Windows privilege escalation, written to run on default PowerShell v2+ found on stripped-down or legacy hosts. | [github.com/411Hall/JAWS](https://github.com/411Hall/JAWS) |
| **kerbrute** | active-directory | Fast Kerberos pre-authentication tool (ropnop) for username enumeration and password spraying against AD. Uses AS-REQ responses to validate usernames without logging failed logons the way SMB does, and to spray candidate passwords, the enumeration/initial-access step that precedes escalation. | [github.com/ropnop/kerbrute](https://github.com/ropnop/kerbrute) |
| **LinEnum** | linux | Classic, widely-referenced Linux local enumeration script that collects system, user, and configuration data relevant to privilege escalation. Largely superseded by LinPEAS/LSE but still common in training material. | [github.com/rebootuser/LinEnum](https://github.com/rebootuser/LinEnum) |
| **LinPEAS (PEASS-ng)** | linux | Comprehensive Linux/Unix privilege-escalation enumeration script that automatically searches for known local privesc vectors and highlights the most promising ones with a color-coded (red/yellow) likelihood scheme. The de facto standard first-run enumerator on Linux hosts. | [github.com/peass-ng/PEASS-ng/tre](https://github.com/peass-ng/PEASS-ng/tree/master/linPEAS) |
| **linuxprivchecker** | linux | Python enumeration script that inventories the host and attempts to correlate discovered software/kernel versions with candidate local privilege-escalation exploits. | [github.com/sleventyeleven/linuxp](https://github.com/sleventyeleven/linuxprivchecker) |
| **linux-smart-enumeration (LSE)** | linux | Linux enumeration script optimized for signal-to-noise, with selectable verbosity levels (0-2) that progressively reveal more detail. Designed to point out concrete privesc paths rather than dumping raw data like older scripts. | [github.com/diego-treitos/linux-s](https://github.com/diego-treitos/linux-smart-enumeration) |
| **PowerUp** | windows | PowerShell privilege-escalation checker (the Privesc module of PowerSploit) that enumerates common Windows misconfigurations and flags abusable service/registry/path weaknesses, with optional abuse helper functions. | [github.com/PowerShellMafia/Power](https://github.com/PowerShellMafia/PowerSploit/tree/master/Privesc) |
| **PowerView** | active-directory | PowerShell AD reconnaissance toolkit (part of PowerSploit's Recon module). Enumerates domain users, groups, ACLs, trusts, GPOs, local admin access, sessions, and delegation without native RSAT tools, the manual counterpart to SharpHound for discovering privesc-relevant misconfigurations. | [github.com/PowerShellMafia/Power](https://github.com/PowerShellMafia/PowerSploit) |
| **PrivescCheck** | windows | Actively maintained PowerShell script that enumerates a wide range of Windows configuration weaknesses for privilege escalation, producing severity-ranked, readable, and export-friendly output. | [github.com/itm4n/PrivescCheck](https://github.com/itm4n/PrivescCheck) |
| **pspy** | linux | Unprivileged process-snooping tool that watches process creation and filesystem events without root by combining procfs polling with inotify. Reveals cron jobs and scheduled/automated commands run by other users (including root). | [github.com/DominicBreuker/pspy](https://github.com/DominicBreuker/pspy) |
| **Seatbelt** | windows | GhostPack C# host-survey tool that runs a broad set of grouped safety checks enumerating security-relevant configuration and defensive posture on Windows for situational awareness and privesc triage. | [github.com/GhostPack/Seatbelt](https://github.com/GhostPack/Seatbelt) |
| **SharpUp** | windows | GhostPack C# port of PowerUp's core checks for identifying common Windows privilege-escalation misconfigurations without invoking PowerShell. | [github.com/GhostPack/SharpUp](https://github.com/GhostPack/SharpUp) |
| **SwiftBelt** | macos | macOS host situational-awareness and enumeration tool (inspired by harmj0y's Seatbelt) that gathers privilege-escalation-relevant context — running processes, installed security products, browser history, SSH/AWS config, TCC database and installed apps — using native Swift APIs to avoid noisy shell commands. First macOS entry for the KB. | [github.com/cedowens/SwiftBelt](https://github.com/cedowens/SwiftBelt) |
| **WinPEAS (PEASS-ng)** | windows | Windows counterpart of LinPEAS; enumerates local privilege-escalation vectors on Windows and highlights likely-exploitable misconfigurations. Part of the actively maintained peass-ng project. | [github.com/peass-ng/PEASS-ng/tre](https://github.com/peass-ng/PEASS-ng/tree/master/winPEAS) |

### Kernel Suggester

| Tool | Platform | What it does | Link |
| --- | --- | --- | --- |
| **linux-exploit-suggester (LES)** | linux | Kernel/userspace exploit suggester that compares the host kernel version and exposed packages against a curated database of known local privesc CVEs/exploits, and also flags relevant hardening (grsecurity, kptr_restrict, etc.) that affects exploitability. | [github.com/mzet-/linux-exploit-s](https://github.com/mzet-/linux-exploit-suggester) |
| **linux-exploit-suggester-2 (LES2)** | linux | Alternative/rewrite of LES that maps the running kernel version to a smaller, higher-signal set of well-known kernel privesc exploits (e.g., Dirty COW-class and classic CVEs). | [github.com/jondonas/linux-exploi](https://github.com/jondonas/linux-exploit-suggester-2) |
| **Metasploit local_exploit_suggester** | cross-platform | Metasploit post module that, given an existing session, checks the compromised host against Metasploit's catalog of local exploit modules and reports which are likely applicable to the target's OS/patch level. | [github.com/rapid7/metasploit-fra](https://github.com/rapid7/metasploit-framework/blob/master/modules/post/multi/recon/local_exploit_suggester.rb) |
| **Sherlock** | windows | Legacy PowerShell script that quickly checks a Windows host against a curated set of common privilege-escalation vulnerabilities. Archived and superseded by Watson but still referenced in training. | [github.com/rasta-mouse/Sherlock](https://github.com/rasta-mouse/Sherlock) |
| **Watson** | windows | .NET tool that enumerates missing KB patches on a Windows host and identifies known privilege-escalation vulnerabilities addressable by those patches (successor to Sherlock). | [github.com/rasta-mouse/Watson](https://github.com/rasta-mouse/Watson) |
| **Windows-Exploit-Suggester-NG (WES-NG)** | windows | Offline Windows missing-patch exploit suggester that parses systeminfo output and cross-references it against a locally-updatable Microsoft security-bulletin database to list missing patches that have public exploits. | [github.com/bitsadmin/wesng](https://github.com/bitsadmin/wesng) |

### Exploitation

| Tool | Platform | What it does | Link |
| --- | --- | --- | --- |
| **DirtyPipe / PwnKit public PoCs** | linux | Two widely-referenced Linux local privilege-escalation vulnerabilities with public PoCs. PwnKit (CVE-2021-4034) is a memory-corruption flaw in Polkit's pkexec SUID binary giving instant root on most distros; DirtyPipe (CVE-2022-0847) is a Linux kernel page-cache flaw (5.8+) letting an unprivileged user overwrite read-only files (e.g. /etc/passwd) to gain root. Both are staple kernel/SUID exploit checks after a Linux foothold. | [github.com/berdav/CVE-2021-4034](https://github.com/berdav/CVE-2021-4034) |
| **Potato family (PrintSpoofer / JuicyPotato / RoguePotato / GodPotato)** | windows | Family of local privilege-escalation PoCs that convert Windows SeImpersonatePrivilege / SeAssignPrimaryTokenPrivilege (commonly held by service accounts like IIS/MSSQL) into a SYSTEM token by abusing NTLM/DCOM/RPC authentication relay to local RPC. GodPotato (BeichenDream) works on modern Windows 8-11 / Server 2012-2022; PrintSpoofer (itm4n) abuses the print spooler named pipe; RoguePotato (antonioCoco) and the original JuicyPotato (ohpe) cover earlier OS versions and DCOM/OXID resolution. | [github.com/BeichenDream/GodPotat](https://github.com/BeichenDream/GodPotato) |
| **PowerUpSQL** | windows | PowerShell toolkit (NetSPI) for discovering and attacking Microsoft SQL Server. Enumerates instances across a domain and escalates via login impersonation (EXECUTE AS), xp_cmdshell OS command execution and linked-server crawl chains to reach sysadmin or host-level code execution — a common Windows/AD privilege-escalation pivot. | [github.com/NetSPI/PowerUpSQL](https://github.com/NetSPI/PowerUpSQL) |
| **sudo / SUID / capabilities abuse (GTFOBins-style local privesc technique)** | linux | Core Linux local-privesc technique class rather than a single tool: abusing overly permissive sudoers rules, SUID-root binaries, and Linux file capabilities (cap_setuid, cap_dac_read_search) to execute code as root. Also covers writable cron jobs, PATH hijacking, LD_PRELOAD via env_keep, and wildcard/tar injection. GTFOBins is the lookup index mapping each binary to its abuse primitive. | [gtfobins.github.io/#+sudo](https://gtfobins.github.io/#+sudo) |

### Credential

| Tool | Platform | What it does | Link |
| --- | --- | --- | --- |
| **DonPAPI** | windows | Remote, mass-scale DPAPI credential-harvesting tool (login-securité) that collects and decrypts DPAPI-protected secrets — Windows credentials, browser passwords/cookies, Wi-Fi keys, vaults and masterkeys — across many hosts via impacket, without dropping binaries. The remote complement to SharpDPAPI for post-compromise credential sweeps. | [github.com/login-securite/DonPAP](https://github.com/login-securite/DonPAPI) |
| **hashcat** | cross-platform | GPU-accelerated password-recovery tool supporting hundreds of hash modes central to privilege escalation: Kerberoast TGS-REP (-m 13100), AS-REP roast (18200), NTLM (1000), NetNTLMv2 (5600), domain cached credentials DCC2/mscash2 (2100) and Linux shadow (1800/500). Turns captured hashes into plaintext for credential reuse and elevation. | [github.com/hashcat/hashcat](https://github.com/hashcat/hashcat) |
| **John the Ripper (jumbo)** | cross-platform | CPU-focused password cracker (Openwall jumbo edition) with an extensive format list and a family of *2john helper tools (unshadow, kirbi2john, etc.). Cracks Kerberoast/AS-REP, NTLM, DCC2 and Unix shadow hashes and is often the easiest way to extract and normalize hashes into a crackable form. | [github.com/openwall/john](https://github.com/openwall/john) |
| **LaZagne** | cross-platform | Broad local credential-recovery tool that harvests stored secrets from a wide range of software — browsers, mail clients, Wi-Fi profiles, databases, sysadmin tools (WinSCP, PuTTY, FileZilla), chats, git/svn and OS keyrings/DPAPI — on Windows and Linux. Discovered passwords are frequently reusable for privilege escalation and lateral movement. | [github.com/AlessandroZ/LaZagne](https://github.com/AlessandroZ/LaZagne) |
| **mimikatz** | windows | The seminal Windows credential-extraction and Kerberos-abuse toolkit by Benjamin Delpy. Dumps plaintext passwords, NTLM hashes, and Kerberos tickets from LSASS memory, and implements pass-the-hash, pass-the-ticket, overpass-the-hash, Golden/Silver ticket forging, DCSync, and token/privilege manipulation, several of which escalate from local admin to domain-wide control. | [github.com/gentilkiwi/mimikatz](https://github.com/gentilkiwi/mimikatz) |
| **pypykatz** | cross-platform | Pure-Python reimplementation of Mimikatz for OFFLINE credential extraction: parses LSASS memory dumps, SAM/SYSTEM/SECURITY registry hives and DPAPI blobs/masterkeys to recover plaintext passwords, NT hashes and Kerberos tickets without running native code on the target. Central to privilege escalation because recovered SYSTEM/admin secrets are reused for lateral movement and elevation. | [github.com/skelsec/pypykatz](https://github.com/skelsec/pypykatz) |
| **Responder** | cross-platform | LLMNR/NBT-NS/mDNS poisoner and rogue authentication server. Answers broadcast name-resolution queries to coerce victims into authenticating, capturing NetNTLMv1/v2 hashes for offline cracking or relaying. A primary initial-foothold and privesc-enabling tool on Windows networks (often paired with ntlmrelayx). | [github.com/lgandx/Responder](https://github.com/lgandx/Responder) |
| **SharpDPAPI** | windows | C# port of Mimikatz DPAPI functionality (GhostPack) that decrypts Windows Data Protection API-protected secrets — saved credentials, Credential Manager/vaults, RDP, browser cookies/passwords and masterkeys — locally, or across a domain using the DPAPI backup/domain key. Yields reusable creds for lateral movement and elevation. | [github.com/GhostPack/SharpDPAPI](https://github.com/GhostPack/SharpDPAPI) |
| **Snaffler** | windows | Credential/secret discovery tool that crawls accessible network shares across an Active Directory environment, hunting for files likely to contain secrets (private keys, config files, scripts, password stores) using tunable match rules. | [github.com/SnaffCon/Snaffler](https://github.com/SnaffCon/Snaffler) |

### Ad

| Tool | Platform | What it does | Link |
| --- | --- | --- | --- |
| **BloodHound / SharpHound** | active-directory | Attack-path-mapping platform for Active Directory (and Azure AD/Entra). The SharpHound collector enumerates users, groups, sessions, ACLs, GPOs, delegation, and cert services; BloodHound ingests this into a graph and computes shortest paths from any owned principal to high-value targets (e.g. Domain Admins), surfacing privesc chains invisible to manual review. | [github.com/SpecterOps/BloodHound](https://github.com/SpecterOps/BloodHound) |
| **bloodyAD** | active-directory | Fast Active Directory privilege-escalation framework (Python) that abuses AD objects and ACLs directly from Linux — add computer accounts, set RBCD, edit DACLs (genericAll/owner), change passwords, toggle UAC flags and manage shadow credentials — over LDAP(S). Enacts the abuse paths that BloodHound identifies without a Windows host. | [github.com/CravateRouge/bloodyAD](https://github.com/CravateRouge/bloodyAD) |
| **Certify** | active-directory | C# tool (GhostPack) to enumerate and abuse Active Directory Certificate Services (AD CS). Finds vulnerable certificate templates and exploits the ESC1–ESC8 misconfigurations to request certificates that impersonate high-privilege users (e.g. Domain Admin) for PKINIT authentication — the Windows counterpart to Certipy. | [github.com/GhostPack/Certify](https://github.com/GhostPack/Certify) |
| **Certipy (and Certify)** | active-directory | AD Certificate Services (AD CS) enumeration and abuse toolkit. Identifies and exploits vulnerable certificate templates and CA misconfigurations (the ESC1-ESC17 attack classes), enabling low-privileged users to obtain certificates that authenticate as high-privileged principals, a direct path from user to Domain Admin. Certipy is the Python/cross-platform tool by ly4k; Certify (github.com/GhostPack/Certify) is the original C#/Windows equivalent. | [github.com/ly4k/Certipy](https://github.com/ly4k/Certipy) |
| **Coercer** | active-directory | Automated authentication-coercion tool (p0dalirius) that sweeps many known vulnerable RPC methods across multiple interfaces (MS-EFSR, MS-RPRN, MS-FSRVP, MS-DFSNM, etc.) to force a remote Windows host to authenticate to an attacker. Generalizes PetitPotam/PrinterBug into a single fuzzing-and-trigger tool, feeding NTLM relay chains toward domain compromise. | [github.com/p0dalirius/Coercer](https://github.com/p0dalirius/Coercer) |
| **KrbRelayUp** | active-directory | Universal no-fix local privilege escalation (user-to-SYSTEM) for domain-joined Windows hosts where LDAP signing/channel binding is not enforced (the default). Wraps a Kerberos relay (KrbRelay) with RBCD, Shadow Credentials, or AD CS methods to relay the machine's own authentication and gain SYSTEM on the local box. | [github.com/Dec0ne/KrbRelayUp](https://github.com/Dec0ne/KrbRelayUp) |
| **mitm6** | active-directory | IPv6/DHCPv6 DNS-takeover primitive (dirkjanm) that abuses Windows' default preference for IPv6 to become the network's DNS server via rogue DHCPv6 replies, then supplies spoofed name resolution that funnels victim authentication into ntlmrelayx for NTLM/LDAP(S) relay attacks against Active Directory. | [github.com/dirkjanm/mitm6](https://github.com/dirkjanm/mitm6) |
| **PetitPotam** | active-directory | Coercion PoC (CVE-2021-36942) abusing MS-EFSRPC EfsRpcOpenFileRaw and related methods to force a Windows host, notably a Domain Controller, to authenticate to an attacker-controlled machine. Chained with ntlmrelayx to AD CS (ESC8), it enables domain compromise without any credentials. | [github.com/topotam/PetitPotam](https://github.com/topotam/PetitPotam) |
| **Purple Knight (Semperis)** | active-directory | Free Semperis assessment tool that scans Active Directory (and Entra ID / Okta) for security indicators of exposure and compromise, including privilege-escalation paths and misconfigurations, and scores overall posture with remediation guidance. | [www.purple-knight.com/](https://www.purple-knight.com/) |
| **Rubeus** | active-directory | C# toolset (GhostPack) for raw Kerberos interaction and abuse: ticket requesting/renewal, Kerberoasting, AS-REP roasting, pass-the-ticket, overpass-the-hash, S4U (constrained-delegation) abuse, and unconstrained-delegation ticket harvesting. Core tool for escalating within AD by abusing Kerberos delegation and roastable accounts. | [github.com/GhostPack/Rubeus](https://github.com/GhostPack/Rubeus) |
| **Whisker** | active-directory | C# shadow-credentials attack tool (Elad Shamir) that writes a key to a target user or computer's msDS-KeyCredentialLink attribute when you hold write privileges over the object, enabling PKINIT/Kerberos authentication as that account without changing its password — a stealthy takeover primitive in Key Trust / AD CS environments. | [github.com/eladshamir/Whisker](https://github.com/eladshamir/Whisker) |

### Container Cloud

| Tool | Platform | What it does | Link |
| --- | --- | --- | --- |
| **amicontained** | container | Container introspection tool (genuinetools) that reports, from inside a container, the runtime in use, effective Linux capabilities, seccomp/AppArmor status, namespace configuration and blocked/allowed syscalls. Used to gauge how confined a container is and where a breakout or privilege escalation is feasible. | [github.com/genuinetools/amiconta](https://github.com/genuinetools/amicontained) |
| **CDK (Container DupKit)** | container | Zero-dependency container penetration toolkit (Go) combining information-gathering, exploitation and lateral-movement modules to evaluate and escape Docker, Kubernetes and containerd — covering capability abuse, mount/host-namespace escapes and cloud-metadata/service-account token theft to move from container to host or cluster. | [github.com/cdk-team/CDK](https://github.com/cdk-team/CDK) |
| **DEEPCE** | container | Dependency-free shell script (Docker Enumeration, Escalation of Privileges and Container Escapes) that enumerates a container's mounts, capabilities, sockets, environment and credentials and can automate common Docker breakouts (mounted docker.sock, privileged mode, sensitive host mounts) to escalate to the host. | [github.com/stealthcopter/deepce](https://github.com/stealthcopter/deepce) |
| **kube-hunter** | container | Kubernetes attack-surface discovery tool (Aqua Security) that scans clusters remotely, on the network, or from inside a pod for exposed components — open/anonymous kubelet (10250/10255), unauthenticated API server, dashboard, etcd — and reports weaknesses that can lead to RCE and privilege escalation. Now archived but a widely cited reference. | [github.com/aquasecurity/kube-hun](https://github.com/aquasecurity/kube-hunter) |
| **kubeletctl** | container | CLI client for the kubelet API (CyberArk) that enumerates and interacts with an exposed/anonymous-auth kubelet on port 10250 — listing pods and running commands inside running containers. Turns an unauthenticated kubelet into RCE and a privilege-escalation foothold by executing in pods and harvesting their service-account tokens. | [github.com/cyberark/kubeletctl](https://github.com/cyberark/kubeletctl) |
| **Pacu** | cloud | Modular AWS exploitation framework (Rhino Security Labs) for offensive testing of Amazon Web Services environments. Includes IAM privilege-escalation enumeration and abuse modules that map a principal's effective permissions and identify/exploit misconfigurations (iam:PassRole, policy version rollback, CreatePolicyVersion, Lambda/EC2 role abuse) to elevate from a low-privileged identity. | [github.com/RhinoSecurityLabs/pac](https://github.com/RhinoSecurityLabs/pacu) |
| **Peirates** | container | Kubernetes penetration-testing and privilege-escalation toolkit (InGuardians) that automates service-account token abuse, secret harvesting, pod-to-node escape (privileged/hostPath pod creation) and cloud-metadata credential theft from a compromised pod, chaining a foothold up to node or cluster-admin control. | [github.com/inguardians/peirates](https://github.com/inguardians/peirates) |
| **Prowler** | cloud | Open-source multi-cloud security tool for AWS, Azure, GCP and Kubernetes that runs hundreds of read-only checks against CIS benchmarks and provider best practices, flagging misconfigurations, weak/over-permissive IAM and privilege-escalation exposure. Complements ScoutSuite with a checks-and-compliance orientation. | [github.com/prowler-cloud/prowler](https://github.com/prowler-cloud/prowler) |
| **Scout Suite** | cloud | Multi-cloud security-auditing tool (NCC Group) for AWS, Azure, GCP, Oracle Cloud and Alibaba. Reads provider APIs read-only and produces an HTML report highlighting misconfigurations, over-permissive IAM roles/policies and privilege-escalation paths — used defensively to find the same weaknesses an attacker would abuse to elevate. | [github.com/nccgroup/ScoutSuite](https://github.com/nccgroup/ScoutSuite) |

### Post Exploitation

| Tool | Platform | What it does | Link |
| --- | --- | --- | --- |
| **chisel / ligolo-ng (pivoting & tunneling)** | cross-platform | Network pivoting/tunneling tools used to reach internal segments from a compromised host and thereby escalate reach across a network. Ligolo-ng (nicocha30) creates a userland TUN interface for transparent routing without SOCKS/proxychains; Chisel (jpillora/chisel) is a fast TCP/UDP tunnel over HTTP with SSH-encrypted transport for port-forwarding and SOCKS. | [github.com/nicocha30/ligolo-ng](https://github.com/nicocha30/ligolo-ng) |
| **Evil-WinRM** | windows | Feature-rich WinRM (Windows Remote Management) shell client for authenticated remote access to Windows hosts using passwords, NTLM hashes (pass-the-hash), or Kerberos tickets. Adds in-memory PowerShell script/loader execution, file upload/download, and AMSI-bypass helpers, the standard interactive shell once valid credentials or a hash are obtained. | [github.com/Hackplayers/evil-winr](https://github.com/Hackplayers/evil-winrm) |
| **Impacket (secretsdump, psexec, ntlmrelayx, GetUserSPNs)** | cross-platform | Foundational Python library and example-script collection for low-level network protocols (SMB, MSRPC, Kerberos, LDAP). Key privesc/lateral scripts: secretsdump.py (remote SAM/LSA/NTDS.dit extraction incl. DCSync), psexec.py/wmiexec.py/smbexec.py (remote code execution as SYSTEM), ntlmrelayx.py (NTLM relay to LDAP/AD CS/SMB), and GetUserSPNs.py (Kerberoasting). | [github.com/fortra/impacket](https://github.com/fortra/impacket) |
| **NetExec (successor to CrackMapExec)** | cross-platform | Network execution / swiss-army tool for assessing and exploiting AD and network services (SMB, WinRM, LDAP, MSSQL, RDP, SSH, WMI, FTP). Automates credential spraying, hash/ticket authentication, share and session enumeration, remote command execution, LSA/SAM dumping, and a large module ecosystem, used to move laterally and escalate across a domain at scale. | [github.com/Pennyw0rth/NetExec](https://github.com/Pennyw0rth/NetExec) |
| **PowerSploit** | windows | Archived but highly influential PowerShell post-exploitation framework whose modules (Privesc/PowerUp, Recon/PowerView, CodeExecution, Exfiltration, Persistence) are widely reused for enumeration and privilege escalation. | [github.com/PowerShellMafia/Power](https://github.com/PowerShellMafia/PowerSploit) |
| **pwncat** | linux | Post-exploitation reverse/bind-shell handler and framework (Caleb Stewart). Upgrades a raw shell to a managed session and provides modules for host enumeration, persistence, and Linux privilege-escalation checks (SUID, sudo, capabilities, writable paths), automating the recon-to-escalation workflow after initial access. | [github.com/calebstewart/pwncat](https://github.com/calebstewart/pwncat) |

