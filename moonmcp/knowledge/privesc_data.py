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
cross-platform.  Compiled from authoritative public sources: HackTricks, GTFOBins,
LOLBAS, PayloadsAllTheThings, PEASS-ng, Exploit-DB, vendor advisories and NVD.
"""

from __future__ import annotations

PRIVESC: list[dict] = [   {   'id': 'ad-adcs-esc1-esc8-certificate-abuse',
        'name': 'AD CS Certificate Template & Enrollment Abuse (ESC1-ESC8)',
        'platform': 'active-directory',
        'category': 'adcs',
        'severity': 'critical',
        'summary': 'Misconfigured Active Directory Certificate Services templates and endpoints '
                   'let low-privileged users enroll certificates that authenticate as arbitrary '
                   'users (including Domain Admins) or relay machine authentication to the CA, '
                   'providing durable domain-privilege escalation and persistence.',
        'technique': "From SpecterOps 'Certified Pre-Owned': ESC1 = enrollee-supplies-subject "
                     'template with client-auth EKU (request a cert as any user via SAN); ESC2 = '
                     'Any Purpose/no-EKU template usable for auth; ESC3 = Certificate Request '
                     'Agent (enrollment agent) enroll-on-behalf-of; ESC4 = attacker has write '
                     "access to a template's ACL (turn it into ESC1); ESC5 = vulnerable PKI object "
                     'ACLs (CA/CA object); ESC6 = CA has EDITF_ATTRIBUTESUBJECTALTNAME2 (SAN in '
                     'any request); ESC7 = attacker holds ManageCA/ManageCertificates rights '
                     '(approve requests, enable SAN, add officers); ESC8 = NTLM relay to the CA '
                     'HTTP/RPC web-enrollment endpoint (relay a coerced DC to obtain a DC auth '
                     'cert). Certificates for authentication can then be used for PKINIT to get a '
                     'TGT (and the NT hash via UnPAC-the-hash). Related: CVE-2022-26923 '
                     "'Certifried' (dNSHostName machine cert spoofing).",
        'prerequisites': [   'An enterprise CA is present',
                             'A vulnerable template/CA configuration or write access to PKI '
                             'objects',
                             'For ESC8: ability to coerce machine authentication '
                             '(PetitPotam/PrinterBug) plus a relay position'],
        'enumeration': [   'Certipy: certipy find -u <user>@<domain> -p <pass> -dc-ip <dc> '
                           '-vulnerable -stdout',
                           'Certify.exe find /vulnerable',
                           'PSPKIAudit: Invoke-PKIAudit',
                           'Enumerate CA web enrollment endpoints (http://<ca>/certsrv, '
                           '/CertSrv/mscep) for ESC8'],
        'detection_indicators': [   'Templates with mspki-certificate-name-flag '
                                    'ENROLLEE_SUPPLIES_SUBJECT + client-auth EKU + low-priv enroll '
                                    'rights',
                                    'CA flag EDITF_ATTRIBUTESUBJECTALTNAME2 enabled (ESC6)',
                                    'Event 4886/4887 (cert requested/issued) where SAN != '
                                    'requester; certificate logons (4768 with certificate) for '
                                    'admins',
                                    'NTLM relay signatures against CA web endpoints; DC machine '
                                    'account requesting client-auth certs unexpectedly'],
        'tools': [   'certipy',
                     'certify',
                     'pspkiaudit',
                     'ntlmrelayx (esc8)',
                     'rubeus (pkinit/asktgt with cert)',
                     'bloodhound (adcs support)'],
        'cve': ['CVE-2022-26923'],
        'mitigation': [   'Remove ENROLLEE_SUPPLIES_SUBJECT where not required; restrict '
                          'enroll/autoenroll rights and require manager approval',
                          'Disable EDITF_ATTRIBUTESUBJECTALTNAME2; harden CA and template ACLs',
                          'Enable EPA/require signing and disable NTLM on CA web enrollment '
                          '(ESC8); apply KB5014754 strong certificate mapping',
                          'Audit AD CS with Certipy/PSPKIAudit; monitor 4886/4887 for SAN '
                          'mismatches'],
        'poc_references': [   'https://github.com/ly4k/Certipy',
                              'https://github.com/GhostPack/Certify'],
        'research_references': [   'https://posts.specterops.io/certified-pre-owned-d95910965cd2',
                                   'https://attack.mitre.org/techniques/T1649/']},
    {   'id': 'ad-dcshadow-rogue-dc-injection',
        'name': 'DCShadow',
        'platform': 'active-directory',
        'category': 'dcshadow',
        'severity': 'critical',
        'summary': 'An attacker with high privileges temporarily registers a rogue domain '
                   'controller in the directory and pushes malicious replication changes (e.g., '
                   'SID history, group membership, primaryGroupID) that propagate to legitimate '
                   'DCs while bypassing normal change-audit logs.',
        'technique': 'DCShadow abuses the same MS-DRSR replication used by DCSync but in the '
                     'opposite direction: instead of pulling, it pushes. The attacker creates the '
                     'nTDSDSA object and required SPNs to make a controlled host appear as a DC, '
                     'then triggers replication so target attribute changes (backdoor ACLs, '
                     'SIDHistory, GPO links) are accepted by real DCs. Because the changes arrive '
                     'as normal replication, they evade many object-modification audit controls. '
                     'Requires domain/enterprise admin (or equivalent replication + object '
                     'creation rights) to register the fake DC.',
        'prerequisites': [   'Domain Admin / Enterprise Admin (or rights to create nTDSDSA objects '
                             'and required SPNs in the Configuration NC)',
                             'SYSTEM on the pushing host'],
        'enumeration': [   "Audit Configuration NC 'Sites' container for unexpected nTDSDSA/server "
                           'objects',
                           'Compare list of DCs (Get-ADDomainController -Filter *) against '
                           'expected inventory',
                           'Repadmin /showrepl to spot unexpected replication partners'],
        'detection_indicators': [   'Security Event 4742 (computer account changed) adding SPNs '
                                    'like GC/ or E3514235-4B06-11D1-AB04-00C04FC2DCD2/',
                                    'Event 5137 (directory object created) / 4929 (AD replica '
                                    'source removed) around nTDSDSA objects',
                                    'Replication from a host not in the authorized DC list; '
                                    'short-lived server objects in Sites'],
        'tools': ['mimikatz (lsadump::dcshadow)', 'impacket (dcsync-style tooling)'],
        'cve': [],
        'mitigation': [   'Restrict who can create objects in the Configuration partition '
                          '(Sites/Servers)',
                          'Monitor for new nTDSDSA objects and replication from non-DC hosts',
                          'Enforce tiered admin and privileged access workstations to limit DA '
                          'compromise'],
        'poc_references': ['https://www.dcshadow.com/', 'https://github.com/gentilkiwi/mimikatz'],
        'research_references': ['https://attack.mitre.org/techniques/T1207/']},
    {   'id': 'ad-dcsync-replication-abuse',
        'name': 'DCSync',
        'platform': 'active-directory',
        'category': 'dcsync',
        'severity': 'critical',
        'summary': 'A principal holding directory replication rights (DS-Replication-Get-Changes '
                   'and DS-Replication-Get-Changes-All) can impersonate a domain controller and '
                   'pull password hashes (including krbtgt) for any account via the MS-DRSR '
                   "replication protocol, without touching a DC's disk.",
        'technique': 'Using the Directory Replication Service Remote Protocol (DRSUAPI '
                     'GetNCChanges), a client with replication extended rights requests secret '
                     'attributes (unicodePwd, ntPwdHistory, supplementalCredentials) for target '
                     'objects. Domain Admins, Enterprise Admins, and DCs hold these rights by '
                     'default, but any user/group granted them via a misconfigured ACL can DCSync. '
                     'Extracting the krbtgt hash enables Golden Tickets; extracting a target '
                     "admin's hash enables Pass-the-Hash. It is a primary post-exploitation "
                     "objective identified by BloodHound's 'DCSync' edge.",
        'prerequisites': [   'A principal with GetChanges + GetChangesAll (or '
                             'GetChangesInFilteredSet) rights on the domain naming context',
                             "Network access to a DC's RPC endpoints"],
        'enumeration': [   "PowerView: Get-DomainObjectAcl -SearchBase 'DC=corp,DC=local' "
                           "-ResolveGUIDs | ? { $_.ObjectAceType -match 'Replication-Get-Changes' "
                           '}',
                           "BloodHound: query for the DCSync edge / 'Find Principals with DCSync "
                           "Rights'",
                           'Impacket (perform): secretsdump.py -just-dc <domain>/<user>@<dc>'],
        'detection_indicators': [   'Security Event 4662 with property GUID '
                                    '1131f6aa-9c07-11d1-f79f-00c04fc2dcd2 (Get-Changes) or '
                                    '1131f6ad-9c07-11d1-f79f-00c04fc2dcd2 (Get-Changes-All)',
                                    'Replication (DRSUAPI GetNCChanges) requests sourced from an '
                                    'IP that is not a domain controller',
                                    'Accounts other than DCs/known replication service accounts '
                                    'triggering replication'],
        'tools': [   'mimikatz (lsadump::dcsync)',
                     'impacket secretsdump.py',
                     'bloodhound',
                     'powerview'],
        'cve': [],
        'mitigation': [   'Audit and remove non-DC principals holding replication rights on the '
                          'domain head',
                          'Monitor 4662 for replication GUIDs and alert on non-DC source IPs',
                          'Segment DC RPC access; use tiered administration'],
        'poc_references': [   'https://github.com/gentilkiwi/mimikatz',
                              'https://github.com/fortra/impacket/blob/master/examples/secretsdump.py'],
        'research_references': [   'https://attack.mitre.org/techniques/T1003/006/',
                                   'https://adsecurity.org/?p=1729']},
    {   'id': 'ad-golden-ticket-krbtgt-forgery',
        'name': 'Golden Ticket',
        'platform': 'active-directory',
        'category': 'golden-ticket',
        'severity': 'critical',
        'summary': "With the krbtgt account's hash/AES key, an attacker forges arbitrary TGTs "
                   '(Ticket Granting Tickets) with any user identity and group memberships, '
                   'granting persistent domain-wide access that survives password resets of normal '
                   'accounts.',
        'technique': 'TGTs are encrypted and signed with the krbtgt key. Possessing that key '
                     '(obtained via DCSync, NTDS.dit dump, or DC compromise) lets an attacker mint '
                     'self-signed TGTs offline for any SID/username with fabricated PAC group '
                     'memberships (e.g., Domain/Enterprise Admins) and arbitrary lifetime. Because '
                     'the KDC trusts anything signed by krbtgt, these tickets are accepted '
                     'domain-wide. Golden tickets provide long-term persistence; only resetting '
                     'krbtgt (twice) invalidates them. Modern forgeries should set realistic '
                     'lifetimes/PAC fields to evade detection (see Diamond Ticket).',
        'prerequisites': [   'krbtgt account NT hash or AES key',
                             'Domain SID',
                             'Effective domain compromise to obtain the krbtgt secret'],
        'enumeration': [   'Detection-focused: audit for krbtgt key exposure events and unusual '
                           'TGT lifetimes',
                           'Get-ADUser krbtgt -Properties pwdLastSet  (assess rotation hygiene)',
                           "Rubeus.exe describe /ticket:<ticket>  (inspect a suspicious ticket's "
                           'PAC/lifetime)'],
        'detection_indicators': [   'Event 4769 (service ticket request) with no preceding 4768 '
                                    '(TGT request) for the account',
                                    'TGTs with abnormal lifetimes (e.g., 10 years) or RC4 when AES '
                                    'is expected',
                                    'PAC anomalies: account name/SID mismatch, non-existent '
                                    'accounts, all-groups membership',
                                    'Kerberos activity for accounts that do not exist in AD'],
        'tools': ['mimikatz (kerberos::golden)', 'rubeus (golden)', 'impacket ticketer.py'],
        'cve': [],
        'mitigation': [   'Reset the krbtgt password twice (with replication between) after any '
                          'suspected Tier-0 compromise, and rotate periodically',
                          'Protect DCs and NTDS.dit; enforce Tier-0 isolation',
                          'Deploy detections for TGT/PAC anomalies and 4769-without-4768',
                          'Enforce AES-only Kerberos to make RC4 forgeries stand out'],
        'poc_references': [   'https://github.com/gentilkiwi/mimikatz',
                              'https://github.com/fortra/impacket/blob/master/examples/ticketer.py'],
        'research_references': [   'https://attack.mitre.org/techniques/T1558/001/',
                                   'https://adsecurity.org/?p=1640']},
    {   'id': 'ad-mitm6-ipv6-dns-takeover-ntlm-relay',
        'name': 'mitm6 IPv6 DNS takeover + NTLM relay to LDAP',
        'platform': 'active-directory',
        'category': 'ntlm-relay',
        'severity': 'critical',
        'summary': 'Windows prefers IPv6 and auto-requests a DHCPv6 lease; mitm6 answers as the '
                   "rogue DHCPv6 server and sets itself as the client's DNS, then coerces NTLM "
                   'authentication and relays it (via ntlmrelayx) to LDAP/LDAPS on a Domain '
                   'Controller to grant delegation rights or create a computer account, escalating '
                   'in the domain.',
        'technique': 'Even on IPv4-only networks, Windows sends DHCPv6 solicitations. mitm6 '
                     '(dirkjanm) replies with the attacker as the primary DNS server (and '
                     'optionally a WPAD entry). Victims then resolve names through the attacker, '
                     'who serves a malicious WPAD/proxy or an intranet name to coerce NTLM '
                     "authentication. That authentication is relayed with impacket's ntlmrelayx to "
                     'LDAP/LDAPS on a DC (LDAP signing/channel binding is often not enforced). '
                     'With a relayed machine or user account the attacker can: grant '
                     'Resource-Based Constrained Delegation on a victim computer object (then '
                     'impersonate a privileged user to it), add a new computer account (default '
                     'MachineAccountQuota=10) to use as the delegation target, or dump domain '
                     'info. Chained, this is a classic unauthenticated-to-domain-privilege path.',
        'prerequisites': [   'attacker on the LAN (L2 reach to victims for DHCPv6/DNS)',
                             'IPv6 enabled on clients (default) and DHCPv6 not otherwise '
                             'served/guarded',
                             'LDAP signing / channel binding not enforced on the DC; '
                             'MachineAccountQuota > 0 for the computer-creation variant'],
        'enumeration': [   'mitm6 -d <domain>  (rogue DHCPv6, observe solicitations)',
                           'nmap -6 --script dhcpv6',
                           'Get-ADObject -SearchBase (Get-ADRootDSE).defaultNamingContext -Filter '
                           '\'ms-DS-MachineAccountQuota -like "*"\'',
                           'netsh interface ipv6 show interfaces'],
        'detection_indicators': [   'DHCPv6',
                                    'mitm6',
                                    'WPAD',
                                    'ms-DS-MachineAccountQuota',
                                    'ntlmrelayx',
                                    'rbcd'],
        'tools': ['mitm6', 'ntlmrelayx', 'impacket', 'krbrelayx', 'bloodhound'],
        'cve': [],
        'mitigation': [   'Disable IPv6 where unused, or block rogue DHCPv6 (RA Guard / DHCPv6 '
                          'Guard on switches)',
                          'Enforce LDAP signing and LDAP channel binding on Domain Controllers',
                          'Enforce SMB signing; set MachineAccountQuota to 0',
                          'Disable WPAD; monitor for RBCD writes and new computer accounts'],
        'poc_references': [   'https://github.com/dirkjanm/mitm6',
                              'https://blog.fox-it.com/2018/01/11/mitm6-compromising-ipv4-networks-via-ipv6/',
                              'https://dirkjanm.io/worst-of-both-worlds-ntlm-relaying-and-kerberos-delegation/'],
        'research_references': [   'https://www.thehacker.recipes/ad/movement/mitm-and-coerced-authentications/dhcpv6-spoofing',
                                   'https://github.com/fortra/impacket']},
    {   'id': 'ad-nopac-samaccountname-spoofing',
        'name': 'sAMAccountName Spoofing / noPac (CVE-2021-42278 + CVE-2021-42287)',
        'platform': 'active-directory',
        'category': 'samaccountname-spoofing',
        'severity': 'critical',
        'summary': 'Chaining CVE-2021-42278 (no sAMAccountName validation) with CVE-2021-42287 '
                   '(KDC S4U2self PAC fallback) lets any user who can create/rename a computer '
                   'account impersonate a Domain Controller and obtain a Kerberos service ticket '
                   'as a domain admin, yielding full domain compromise.',
        'technique': 'An attacker creates a machine account (via MachineAccountQuota) and renames '
                     "its sAMAccountName to match a DC's name without the trailing '$' "
                     '(CVE-2021-42278: AD failed to enforce that machine account names end in $). '
                     'They request a TGT for that name, then rename the account back. When they '
                     "present the TGT for S4U2self/service ticket, the KDC can't find the exact "
                     "principal and falls back to appending '$' (CVE-2021-42287), matching the "
                     "real DC's machine account — issuing a service ticket in the security context "
                     'of the DC. The result is a ticket impersonating a privileged account to '
                     'services like CIFS/LDAP on the DC (effectively domain admin). Automated '
                     'end-to-end by noPac/sam_the_admin.',
        'prerequisites': [   'Any authenticated domain user with the ability to create a computer '
                             'account (MachineAccountQuota > 0) or write to an existing controlled '
                             "computer's sAMAccountName/servicePrincipalName",
                             'Unpatched DCs (missing Nov 2021 KB5008380/KB5008602)'],
        'enumeration': [   'Assess patch level of DCs (KB5008380 / KB5008602) and '
                           'ms-DS-MachineAccountQuota',
                           'noPac: check reachability and MAQ (scanner mode)',
                           'PowerView: Get-DomainObject -Properties ms-ds-machineaccountquota'],
        'detection_indicators': [   'Event 4741 (computer created) followed by 4781 (account name '
                                    'changed) for a machine account, then TGT requests',
                                    'A computer account whose sAMAccountName collides with a DC '
                                    'name (missing $), transiently',
                                    'Event 4768/4769 for a machine account renamed to a DC name; '
                                    'S4U2self activity from a new machine account',
                                    'Microsoft-added events (KDC PAC) on patched DCs when the fix '
                                    'rejects such requests'],
        'tools': [   'nopac (cube0x0)',
                     'sam_the_admin (impacket-based)',
                     'impacket (addcomputer.py, renamemachine.py, getst.py)',
                     'powermad'],
        'cve': ['CVE-2021-42278', 'CVE-2021-42287'],
        'mitigation': [   'Apply Microsoft patches KB5008380 and KB5008602 (Nov 2021) on all DCs',
                          'Set MachineAccountQuota to 0 and restrict machine-account creation',
                          'Monitor 4741 + 4781 sequences and machine-name collisions with DCs',
                          'Enforce PAC validation post-patch (registry PacRequestorEnforcement)'],
        'poc_references': [   'https://github.com/cube0x0/noPac',
                              'https://github.com/WazeHell/sam-the-admin'],
        'research_references': [   'https://www.thehacker.recipes/ad/movement/kerberos/samaccountname-spoofing',
                                   'https://www.secureworks.com/blog/nopac-a-tale-of-two-vulnerabilities-that-could-end-in-ransomware']},
    {   'id': 'ad-ntlm-relay-coercion-petitpotam-printerbug',
        'name': 'Authentication Coercion + NTLM Relay (PetitPotam, PrinterBug/SpoolSample, '
                'DFSCoerce, Coercer)',
        'platform': 'active-directory',
        'category': 'ntlm-relay',
        'severity': 'critical',
        'summary': 'Attackers force a target (often a Domain Controller) to authenticate to an '
                   'attacker-controlled host over MS-EFSRPC/MS-RPRN/MS-DFSNM, then relay that NTLM '
                   'authentication to a privileged service (LDAP, AD CS web enrollment, SMB) to '
                   'act as the coerced machine — commonly ending in domain compromise.',
        'technique': 'Several RPC interfaces let a remote, sometimes unauthenticated caller '
                     'trigger the server to authenticate outbound: PetitPotam (MS-EFSRPC '
                     'EfsRpcOpenFileRaw, CVE-2021-36942), PrinterBug/SpoolSample (MS-RPRN '
                     'RpcRemoteFindFirstPrinterChangeNotification), DFSCoerce (MS-DFSNM '
                     'NetrDfsAddStdRoot), and Coercer (multi-protocol). The coerced NTLM is '
                     'captured by ntlmrelayx and relayed: to LDAP/LDAPS on a DC to configure RBCD '
                     "or shadow credentials against the DC's computer object; to AD CS web "
                     'enrollment (ESC8) to obtain a DC authentication certificate; or to SMB for '
                     "command execution. Because a DC's machine account is Tier-0, relaying it "
                     'yields domain takeover. Relay requires the destination to lack signing/EPA '
                     '(e.g., LDAP without signing, HTTP enrollment without EPA).',
        'prerequisites': [   'Network path to trigger coercion (sometimes pre-auth for PetitPotam)',
                             'A relay target lacking signing/channel binding (LDAP without '
                             'signing, AD CS HTTP enrollment, SMB without signing)',
                             'Often MachineAccountQuota > 0 to add a computer for the '
                             'RBCD/shadow-cred follow-on'],
        'enumeration': [   'Coercer: coercer scan -u <user> -p <pass> -t <target>  (identify '
                           'exposed coercion methods)',
                           'Check LDAP signing / channel binding posture and SMB signing on relay '
                           'targets (nxc smb <t> --gen-relay-list)',
                           'Enumerate AD CS web enrollment endpoints for ESC8 relay',
                           'Assess Get-ADObject ms-DS-MachineAccountQuota'],
        'detection_indicators': [   'Inbound MS-EFSRPC/MS-RPRN/MS-DFSNM calls to non-file-server '
                                    'hosts; DC machine account authenticating outbound to a '
                                    'workstation',
                                    'Event 4624 Logon Type 3 NTLM where the source is a DC machine '
                                    'account authenticating to an unexpected host',
                                    'NTLM authentications to LDAP/HTTP CA endpoints from a relay '
                                    'host; new RBCD/shadow-credential attributes on the DC object '
                                    'shortly after',
                                    '4741 (computer created) via MachineAccountQuota near relay '
                                    'activity'],
        'tools': [   'petitpotam',
                     'spoolsample/dementor',
                     'dfscoerce',
                     'coercer',
                     'impacket ntlmrelayx.py',
                     'certipy (relay to esc8)',
                     'krbrelayx (printerbug)'],
        'cve': ['CVE-2021-36942'],
        'mitigation': [   'Enforce SMB signing everywhere, LDAP signing + channel binding on DCs '
                          "(require, don't just enable)",
                          'Enable EPA and disable NTLM on AD CS web enrollment; consider disabling '
                          'NTLM broadly',
                          'Patch/mitigate coercion (KB for PetitPotam, disable Print Spooler on '
                          'DCs, restrict RPC), block outbound SMB from DCs',
                          'Set MachineAccountQuota to 0; monitor coercion RPC and DC outbound '
                          'auth'],
        'poc_references': [   'https://github.com/topotam/PetitPotam',
                              'https://github.com/leechristensen/SpoolSample',
                              'https://github.com/Wh04m1001/DFSCoerce',
                              'https://github.com/p0dalirius/Coercer'],
        'research_references': [   'https://attack.mitre.org/techniques/T1187/',
                                   'https://dirkjanm.io/worst-of-both-worlds-ntlm-relaying-and-kerberos-delegation/']},
    {   'id': 'ad-sid-history-injection',
        'name': 'SID History Injection',
        'platform': 'active-directory',
        'category': 'sid-history',
        'severity': 'critical',
        'summary': 'The sIDHistory attribute — designed to preserve access during domain '
                   'migrations — can be injected with the SID of a privileged group (e.g., '
                   'Enterprise/Domain Admins), so a low-privileged account silently gains those '
                   'privileges since access checks honor SID history.',
        'technique': 'sIDHistory lets a migrated account retain its former SIDs so ACLs '
                     'referencing the old SID still grant access. Because Windows authorization '
                     'includes sIDHistory SIDs in the token/PAC, writing a privileged SID (e.g., '
                     'the domain Enterprise Admins RID-519 or Domain Admins RID-512) into a '
                     "controlled account's sIDHistory effectively makes that account a member of "
                     'the privileged group without visible group membership. Injection requires '
                     'DC-level access (Mimikatz sid::add/misc, DCShadow, or DsAddSidHistory with '
                     'the right privileges) and is a stealthy persistence/escalation primitive. '
                     'Cross-forest, SID Filtering normally strips foreign SIDs unless disabled.',
        'prerequisites': [   'High privilege / DC access to write sIDHistory (e.g., via DCShadow '
                             'or SYSTEM on a DC)',
                             'Knowledge of the target privileged group SID'],
        'enumeration': [   'PowerView: Get-DomainUser -Properties samaccountname,sidhistory | ? '
                           '{$_.sidhistory}',
                           "AD module: Get-ADUser -Filter {SIDHistory -like '*'} -Properties "
                           'SIDHistory',
                           'Audit for accounts whose sIDHistory contains privileged RIDs '
                           '(512/516/518/519)'],
        'detection_indicators': [   'Event 4765/4766 (SID History added / add failed) on accounts',
                                    'Event 4738 (user changed) with SidHistory modification',
                                    'Non-migration accounts possessing sIDHistory, especially with '
                                    'high-privilege RIDs',
                                    'Authorization/PAC showing privileged group access without '
                                    'corresponding group membership'],
        'tools': ['mimikatz (sid::add, misc::addsid)', 'dcshadow', 'powerview', 'bloodhound'],
        'cve': [],
        'mitigation': [   'Audit and clear illegitimate sIDHistory entries after migrations '
                          'complete',
                          'Enable SID Filtering on trusts to block foreign privileged SIDs',
                          'Monitor 4765/4766 and 4738 SidHistory changes; protect DCs (Tier-0)',
                          'Restrict who can write sIDHistory'],
        'poc_references': ['https://github.com/gentilkiwi/mimikatz'],
        'research_references': [   'https://attack.mitre.org/techniques/T1134/005/',
                                   'https://adsecurity.org/?p=1772']},
    {   'id': 'ad-unconstrained-delegation-tgt-capture',
        'name': 'Unconstrained Delegation Abuse',
        'platform': 'active-directory',
        'category': 'delegation',
        'severity': 'critical',
        'summary': 'Computers/accounts trusted for unconstrained delegation cache the TGTs of any '
                   'user that authenticates to them; an attacker controlling such a host (often '
                   "combined with authentication coercion) can extract a Domain Controller's or "
                   "Domain Admin's TGT and impersonate them.",
        'technique': 'With unconstrained delegation (TRUSTED_FOR_DELEGATION UAC flag), when a user '
                     "authenticates to the service, the KDC embeds the user's forwardable TGT "
                     'inside the service ticket; the service caches it in LSASS to act on the '
                     "user's behalf. An attacker who compromises such a server dumps cached TGTs. "
                     'Weaponized, the attacker coerces a Domain Controller to authenticate to the '
                     "unconstrained host (via PrinterBug/PetitPotam), capturing the DC's TGT, then "
                     'uses it (e.g., for DCSync). Any authenticated user can also create a '
                     'computer object (see MachineAccountQuota) and set delegation in some '
                     'scenarios.',
        'prerequisites': [   'Control of a host/account with TRUSTED_FOR_DELEGATION',
                             'Ability to coerce a privileged principal to authenticate (optional '
                             'but common)',
                             'SYSTEM/admin on the delegation host to read LSASS tickets'],
        'enumeration': [   'PowerView: Get-DomainComputer -Unconstrained -Properties '
                           'dnshostname,useraccountcontrol',
                           'AD module: Get-ADComputer -Filter {TrustedForDelegation -eq $true}',
                           "BloodHound: 'Find Computers with Unconstrained Delegation'",
                           'Rubeus.exe monitor /interval:5  (watch for incoming TGTs)'],
        'detection_indicators': [   'Non-DC computer objects with TrustedForDelegation set '
                                    '(userAccountControl 0x80000)',
                                    'Coercion signatures: MS-RPRN/MS-EFSRPC calls to a delegation '
                                    'host followed by DC authentication',
                                    'Event 4769/4768 showing a DC machine account obtaining a '
                                    'forwardable TGT to an unusual host'],
        'tools': [   'rubeus',
                     'mimikatz (sekurlsa::tickets)',
                     'impacket',
                     'spoolsample/petitpotam (coercion)',
                     'bloodhound',
                     'powerview'],
        'cve': [],
        'mitigation': [   'Eliminate unconstrained delegation; use constrained or RBCD where '
                          'delegation is needed',
                          "Add privileged accounts to Protected Users and set 'Account is "
                          "sensitive and cannot be delegated' (NOT_DELEGATED)",
                          'Patch/mitigate coercion vectors (PetitPotam, PrinterBug)',
                          'Place DCs and Tier-0 accounts so they never authenticate to non-Tier-0 '
                          'hosts'],
        'poc_references': [   'https://github.com/GhostPack/Rubeus',
                              'https://github.com/leechristensen/SpoolSample'],
        'research_references': [   'https://shenaniganslabs.io/2019/01/28/Wagging-the-Dog.html',
                                   'https://adsecurity.org/?p=1667']},
    {   'id': 'ad-zerologon-netlogon-cve-2020-1472',
        'name': 'Zerologon (CVE-2020-1472)',
        'platform': 'active-directory',
        'category': 'netlogon-exploit',
        'severity': 'critical',
        'summary': 'A cryptographic flaw in the Netlogon (MS-NRPC) AES-CFB8 authentication allowed '
                   "an unauthenticated attacker with network access to a DC to set the DC's "
                   'machine account password to empty, then use it to DCSync every credential — '
                   'instant domain compromise from network access alone.',
        'technique': "Netlogon's ComputeNetlogonCredential used AES-CFB8 with a fixed all-zero IV. "
                     'Because AES-CFB8 with an all-zero plaintext and all-zero IV yields an '
                     'all-zero ciphertext with probability ~1/256, an attacker could repeatedly '
                     'attempt NetrServerAuthenticate3 with all-zero challenge/ciphertext until '
                     'authentication succeeded (~256 tries), without knowing any key. They then '
                     "called NetrServerPasswordSet2 to reset the DC computer account's password in "
                     'AD to empty. With the DC machine account controlled, they DCSync the krbtgt '
                     'and admin hashes (then restore the original password to avoid breaking the '
                     'DC). Discovered by Tom Tervoort (Secura).',
        'prerequisites': [   "Network access to a Domain Controller's Netlogon RPC endpoint",
                             'Unpatched DC (before Aug 2020 patch / enforcement Feb 2021)'],
        'enumeration': [   'Secura tester: zerologon_tester.py <DC-NETBIOS> <DC-IP>  '
                           '(non-destructive check)',
                           'Impacket-based scanners that stop before resetting the password',
                           'Verify DC patch level (KB4557222 and Feb 2021 enforcement)'],
        'detection_indicators': [   'Numerous Netlogon NetrServerAuthenticate3 attempts with '
                                    'all-zero data from a single source (~256 tries)',
                                    "Event 4742 machine account (a DC's) password change from an "
                                    'unexpected source',
                                    'Netlogon events 5827/5828 (denied vulnerable connections) '
                                    'after enforcement; 5829 (allowed vulnerable) pre-enforcement',
                                    'DC machine account authentication anomalies immediately '
                                    'followed by replication/DCSync (4662)'],
        'tools': [   'impacket (secretsdump.py after exploit)',
                     'secura cve-2020-1472 tester',
                     'mimikatz (zerologon module)'],
        'cve': ['CVE-2020-1472'],
        'mitigation': [   'Apply the August 2020 patch and enable enforcement mode (Feb 2021 '
                          'update); ensure DC secure-channel enforcement',
                          'Monitor Netlogon events 5827/5828/5829 and 4742 DC password changes',
                          "If exploited, the DC's AD password and local secret desynchronize — "
                          'reset the DC machine account password to remediate',
                          'Restrict RPC/Netlogon exposure and segment DCs'],
        'poc_references': [   'https://github.com/SecuraBV/CVE-2020-1472',
                              'https://github.com/fortra/impacket/blob/master/examples/secretsdump.py'],
        'research_references': [   'https://www.secura.com/uploads/whitepapers/Zerologon.pdf',
                                   'https://msrc.microsoft.com/update-guide/vulnerability/CVE-2020-1472']},
    {   'id': 'adcs-certifried-cve-2022-26923',
        'name': 'Certifried — AD CS machine-account cert impersonation (CVE-2022-26923)',
        'platform': 'active-directory',
        'category': 'adcs',
        'severity': 'critical',
        'summary': 'Any authenticated user who can create or control a computer account can set '
                   'its dNSHostName to that of a Domain Controller and enroll in the default '
                   'Machine certificate template, obtaining a certificate that authenticates as '
                   'the DC — escalating to domain compromise.',
        'technique': 'The default Machine/Computer certificate template builds the certificate '
                     "identity from the account's dNSHostName rather than an immutable identifier. "
                     'By default MachineAccountQuota lets any domain user create computer '
                     "accounts, and the creator can edit that account's dNSHostName. The attacker "
                     "creates a computer account, sets its dNSHostName to a DC's FQDN (removing "
                     'the conflicting value on the real DC object or exploiting the lack of '
                     'uniqueness enforcement), then requests a certificate from the Machine '
                     'template. AD CS issues a cert whose SAN/identity maps to the DC, so the '
                     'attacker can PKINIT-authenticate as the Domain Controller machine account '
                     'and, e.g., perform DCSync to dump domain hashes. Certipy automates the '
                     'account creation, dNSHostName manipulation, enrollment and Kerberos '
                     'authentication.',
        'prerequisites': [   'an AD CS enterprise CA with the default Machine template published',
                             'an authenticated domain user with MachineAccountQuota > 0 (or write '
                             'over a computer object)',
                             'unpatched DCs / CA (pre-May-2022 fix, before strong certificate '
                             'mapping enforcement)'],
        'enumeration': [   'certipy find -u user@domain -p pass -dc-ip <ip>',
                           'Get-ADObject -Filter \'ms-DS-MachineAccountQuota -like "*"\'',
                           'Get-DomainComputer -Properties dnshostname',
                           'certutil -catemplates'],
        'detection_indicators': [   'dNSHostName',
                                    'ms-DS-MachineAccountQuota',
                                    'Machine template',
                                    'PKINIT',
                                    'Certifried',
                                    'szOID_NTDS_CA_SECURITY_EXT',
                                    'SeImpersonatePrivilege'],
        'tools': ['certipy', 'certi', 'bloodhound', 'impacket'],
        'cve': ['CVE-2022-26923'],
        'mitigation': [   'Apply the May 2022 updates (KB5014754) and enable Full/strong '
                          'certificate mapping enforcement',
                          'Set MachineAccountQuota to 0; restrict who can create/modify computer '
                          'accounts',
                          'Harden AD CS templates; enable the szOID_NTDS_CA_SECURITY_EXT (SID) '
                          'extension',
                          'Monitor certificate enrollments and dNSHostName changes'],
        'poc_references': [   'https://research.ifcr.dk/certifried-active-directory-domain-privilege-escalation-cve-2022-26923-9e098fe298f4',
                              'https://github.com/ly4k/Certipy'],
        'research_references': [   'https://nvd.nist.gov/vuln/detail/CVE-2022-26923',
                                   'https://posts.specterops.io/certified-pre-owned-d95910965cd2']},
    {   'id': 'ad-acl-abuse-generic-write-owner-dacl',
        'name': 'AD Object ACL Abuse (GenericAll/GenericWrite/WriteDACL/WriteOwner)',
        'platform': 'active-directory',
        'category': 'acl-abuse',
        'severity': 'high',
        'summary': 'Excessive or misconfigured discretionary ACL entries on AD objects let an '
                   'attacker escalate: WriteOwner/WriteDACL to grant themselves rights, '
                   'GenericWrite to set SPNs (targeted Kerberoast) or shadow credentials, '
                   'GenericAll to reset passwords, and control over groups to add members.',
        'technique': 'Every AD object has a security descriptor. Dangerous ACEs create attack '
                     'edges: WriteOwner lets an attacker become object owner then rewrite the DACL '
                     '(WriteDACL) to grant GenericAll; GenericAll/ForceChangePassword allows '
                     "resetting a user's password or setting msDS-KeyCredentialLink (shadow "
                     'credentials) or an SPN (targeted Kerberoasting); GenericWrite/WriteProperty '
                     'on a group allows self-add to privileged groups; write on a computer enables '
                     'RBCD. BloodHound maps these as edges to find shortest paths to Domain Admin. '
                     "Abusing 'AddMember' on a high-value group or GenericAll on an OU (with "
                     'GPO/inheritance) cascades to domain compromise.',
        'prerequisites': [   'An identity holding a dangerous ACE (GenericAll, GenericWrite, '
                             'WriteDacl, WriteOwner, ForceChangePassword, AddMember, etc.) over a '
                             'higher-value object'],
        'enumeration': [   "BloodHound/SharpHound: collect ACLs, then 'Shortest Path to Domain "
                           "Admins' / inbound object control",
                           'PowerView: Get-DomainObjectAcl -Identity <obj> -ResolveGUIDs | ? '
                           '{$_.ActiveDirectoryRights -match '
                           "'GenericAll|WriteDacl|WriteOwner|WriteProperty'}",
                           'PowerView: Find-InterestingDomainAcl -ResolveGUIDs',
                           'AD module: (Get-Acl "AD:\\<DN>").Access'],
        'detection_indicators': [   'Event 5136 (directory object modified) on DACL/owner/member '
                                    'attributes of privileged objects',
                                    'Event 4738/4728/4756 (user/group membership changes) for '
                                    'sensitive groups',
                                    'Password resets (4724) on privileged accounts by '
                                    'non-help-desk principals',
                                    'Additions to msDS-KeyCredentialLink or servicePrincipalName '
                                    'on user objects'],
        'tools': [   'bloodhound/sharphound',
                     'powerview (add-domainobjectacl, set-domainobject)',
                     'impacket (dacledit.py)',
                     'aclpwn/invoke-aclpwn'],
        'cve': [],
        'mitigation': [   'Regularly audit ACLs on Tier-0 objects, OUs, and the domain head; '
                          'remove non-inherited risky ACEs',
                          'Enforce least privilege and AdminSDHolder/SDProp protection of '
                          'privileged groups',
                          'Monitor 5136 for DACL/owner/member changes on sensitive objects',
                          'Use BloodHound proactively to find and prune attack paths'],
        'poc_references': [   'https://github.com/PowerShellMafia/PowerSploit/tree/master/Recon',
                              'https://github.com/fortra/impacket/blob/master/examples/dacledit.py'],
        'research_references': [   'https://www.harmj0y.net/blog/redteaming/abusing-active-directory-permissions-with-powerview/',
                                   'https://specterops.io/wp-content/uploads/sites/3/2022/06/an_ace_up_the_sleeve.pdf']},
    {   'id': 'ad-adcs-esc9-esc16-mapping-abuse',
        'name': 'AD CS Advanced Abuses (ESC9-ESC11, ESC13-ESC16)',
        'platform': 'active-directory',
        'category': 'adcs',
        'severity': 'high',
        'summary': 'Later-discovered AD CS escalations abuse weak certificate-to-account mappings, '
                   'RPC enrollment relay, group-linked issuance policies, schema/EKU manipulation, '
                   'and strong-mapping enforcement gaps to authenticate as privileged principals.',
        'technique': 'ESC9 = template with no-security-extension flag '
                     '(CT_FLAG_NO_SECURITY_EXTENSION) lets a cert omit the SID, enabling '
                     "weak-mapping impersonation when combined with control of a target's "
                     'userPrincipalName. ESC10 = weak certificate mapping registry settings '
                     '(StrongCertificateBindingEnforcement/UPN mapping) allow UPN-based '
                     'impersonation. ESC11 = relay of RPC-based ICertPassage (ICPR) enrollment '
                     'when IF_ENFORCEENCRYPTICERTREQUEST is off. ESC13 = a certificate template '
                     'linked to an issuance policy that maps to a privileged AD group '
                     '(msDS-OIDToGroupLink) grants that group membership on logon. ESC14 = write '
                     'access to altSecurityIdentities enables explicit certificate mapping to a '
                     "victim. ESC15 (CVE-2024-49019, 'EKUwu') = schema v1 templates allow "
                     'injecting arbitrary application policies/EKUs into a request. ESC16 = '
                     'CA-wide disabling of the SID security extension weakens all mappings. Certs '
                     'are used via PKINIT/Schannel to authenticate as the impersonated principal.',
        'prerequisites': [   'Enterprise CA present',
                             'The specific misconfiguration (weak mapping, OID-to-group link, '
                             'writable altSecurityIdentities, v1 schema template, or CA-level '
                             'SID-extension disablement)',
                             'Often control over a low-priv account whose UPN/attributes can be '
                             'edited'],
        'enumeration': [   'Certipy: certipy find -vulnerable -stdout  (flags ESC9-ESC16 in recent '
                           'versions)',
                           'Inspect StrongCertificateBindingEnforcement (KDC) and '
                           'CertificateMappingMethods (Schannel) registry values',
                           'Enumerate templates with msDS-OIDToGroupLink issuance policies (ESC13)',
                           'Check altSecurityIdentities write access on target objects (ESC14)'],
        'detection_indicators': [   'Certificate logons mapped to accounts via '
                                    'UPN/altSecurityIdentities rather than strong SID mapping',
                                    'Post-KB5014754 events 39/41 (KDC) about certificates without '
                                    'the SID extension or weak mapping',
                                    'Issuance-policy OIDs linked to privileged groups; unexpected '
                                    'group membership acquired at logon (ESC13)',
                                    'v1 template requests carrying injected application policies '
                                    '(ESC15)'],
        'tools': ['certipy', 'certify', 'rubeus', 'bloodhound (adcs edges)'],
        'cve': ['CVE-2024-49019'],
        'mitigation': [   'Deploy KB5014754 and set StrongCertificateBindingEnforcement to Full '
                          '(strong SID mapping) to close ESC9/ESC10/ESC16',
                          'Enable IF_ENFORCEENCRYPTICERTREQUEST (ESC11); retire schema v1 '
                          'templates and patch CVE-2024-49019 (ESC15)',
                          'Restrict msDS-OIDToGroupLink issuance policies and '
                          'altSecurityIdentities write access',
                          'Continuously audit AD CS with Certipy and monitor certificate mapping '
                          'events'],
        'poc_references': ['https://github.com/ly4k/Certipy'],
        'research_references': [   'https://research.ifcr.dk/certipy-4-0-esc9-esc10-bloodhound-and-new-path-of-least-resistance-7bf96d0dc73f',
                                   'https://posts.specterops.io/adcs-esc13-abuse-technique-fda4272fbd53',
                                   'https://www.trustedsec.com/blog/ekuwu-not-just-another-ad-cs-esc']},
    {   'id': 'ad-asrep-roasting-nopreauth',
        'name': 'AS-REP Roasting',
        'platform': 'active-directory',
        'category': 'asrep-roasting',
        'severity': 'high',
        'summary': "Accounts configured with 'Do not require Kerberos preauthentication' "
                   '(DONT_REQ_PREAUTH) allow anyone to request an AS-REP whose encrypted portion '
                   "is derived from the user's password, enabling offline cracking without any "
                   'credentials.',
        'technique': 'Normally Kerberos preauthentication requires the client to prove knowledge '
                     'of the password (an encrypted timestamp) before the KDC issues an AS-REP. '
                     'When preauth is disabled on an account, the KDC returns an AS-REP containing '
                     "material encrypted with the account's password-derived key to any requester. "
                     'Attackers harvest these for flagged accounts and crack them offline. Unlike '
                     'Kerberoasting, this needs no authenticated context (only the list of '
                     'usernames) when targeting no-preauth accounts. GenericWrite over an account '
                     'can be abused to toggle the DONT_REQ_PREAUTH UAC flag (targeted AS-REP '
                     'roasting).',
        'prerequisites': [   'A list of valid usernames (or authenticated enumeration)',
                             'Target account has userAccountControl flag DONT_REQ_PREAUTH '
                             '(0x400000) set',
                             'Weak account password for cracking'],
        'enumeration': [   'PowerView: Get-DomainUser -PreauthNotRequired -Properties '
                           'samaccountname,useraccountcontrol',
                           'Impacket: GetNPUsers.py <domain>/ -usersfile users.txt -dc-ip <dc> '
                           '-no-pass -format hashcat',
                           'AD module: Get-ADUser -Filter {DoesNotRequirePreAuth -eq $true}',
                           'Rubeus.exe asreproast /format:hashcat'],
        'detection_indicators': [   'Security Event 4768 (TGT requested) with Pre-Authentication '
                                    'Type 0 and RC4 encryption (0x17)',
                                    'Accounts with userAccountControl containing DONT_REQ_PREAUTH',
                                    'AS-REQ from unusual hosts for accounts lacking preauth'],
        'tools': [   'rubeus',
                     'impacket getnpusers.py',
                     'hashcat (mode 18200)',
                     'john the ripper',
                     'powerview',
                     'bloodhound'],
        'cve': [],
        'mitigation': [   'Remove DONT_REQ_PREAUTH from all accounts unless strictly required',
                          'Enforce strong passwords and AES-only encryption',
                          'Alert on 4768 events with pre-auth type 0'],
        'poc_references': [   'https://github.com/GhostPack/Rubeus',
                              'https://github.com/fortra/impacket/blob/master/examples/GetNPUsers.py'],
        'research_references': [   'https://attack.mitre.org/techniques/T1558/004/',
                                   'https://www.harmj0y.net/blog/activedirectory/roasting-as-reps/']},
    {   'id': 'ad-constrained-delegation-s4u',
        'name': 'Constrained Delegation Abuse (S4U2Proxy)',
        'platform': 'active-directory',
        'category': 'delegation',
        'severity': 'high',
        'summary': 'An account configured for constrained delegation (msDS-AllowedToDelegateTo) '
                   'can use S4U2Self/S4U2Proxy to obtain service tickets impersonating arbitrary '
                   "users to the allowed services — and, because only the SPN's service class is "
                   'validated, the ticket can often be reused against other services on the same '
                   'host.',
        'technique': 'Kerberos constrained delegation lets a service request tickets to a fixed '
                     'list of downstream SPNs on behalf of a user (S4U2Proxy), first minting a '
                     'forwardable ticket to itself via S4U2Self. If an attacker controls a '
                     'delegating account, they can impersonate any non-protected user (including '
                     'domain admins) to the target service. When protocol transition '
                     '(TRUSTED_TO_AUTH_FOR_DELEGATION) is enabled, no prior user authentication is '
                     'needed. Because the KDC only checks the service class portion of the SPN and '
                     "not the exact service, an allowed 'HOST/server' ticket can be rewritten for "
                     "'CIFS/server', 'LDAP/server', etc., expanding impact.",
        'prerequisites': [   'Control of an account with msDS-AllowedToDelegateTo populated',
                             'The delegated-to service is valuable (e.g., LDAP on a DC enables '
                             'DCSync-style access)'],
        'enumeration': [   'PowerView: Get-DomainUser -TrustedToAuth ; Get-DomainComputer '
                           '-TrustedToAuth',
                           "AD module: Get-ADObject -Filter {msDS-AllowedToDelegateTo -like '*'} "
                           '-Properties msDS-AllowedToDelegateTo',
                           "BloodHound: 'AllowedToDelegate' edges",
                           'Rubeus.exe s4u  (to request; use /altservice to swap service class)'],
        'detection_indicators': [   'Event 4769 with Transited Services populated (S4U2Proxy) for '
                                    'sensitive target SPNs',
                                    'Service tickets impersonating admin accounts to '
                                    'LDAP/CIFS/HOST on DCs',
                                    'Accounts with TRUSTED_TO_AUTH_FOR_DELEGATION (protocol '
                                    'transition) set'],
        'tools': ['rubeus', 'impacket getst.py', 'mimikatz', 'bloodhound', 'powerview'],
        'cve': [],
        'mitigation': [   'Minimize constrained delegation; avoid protocol transition',
                          "Protect Tier-0 accounts with 'sensitive and cannot be delegated' and "
                          'Protected Users group',
                          'Prefer resource-based constrained delegation so target owners control '
                          'who may delegate',
                          'Never allow delegation to DC services'],
        'poc_references': [   'https://github.com/GhostPack/Rubeus',
                              'https://github.com/fortra/impacket/blob/master/examples/getST.py'],
        'research_references': [   'https://www.harmj0y.net/blog/activedirectory/s4u2pwnage/',
                                   'https://shenaniganslabs.io/2019/01/28/Wagging-the-Dog.html']},
    {   'id': 'ad-diamond-ticket-pac-modification',
        'name': 'Diamond Ticket',
        'platform': 'active-directory',
        'category': 'diamond-ticket',
        'severity': 'high',
        'summary': 'Instead of forging a TGT from scratch (Golden), the attacker requests a '
                   'legitimate TGT with the krbtgt key, decrypts it, modifies the PAC (e.g., adds '
                   'Domain Admins), and re-encrypts it — producing a ticket with authentic '
                   'KDC-issued fields that evades golden-ticket detections.',
        'technique': 'Golden tickets are detectable because their fields (lifetime, PAC contents, '
                     'request pattern) are attacker-fabricated and often unrealistic. A Diamond '
                     'ticket starts from a real AS-REQ TGT for a low-priv account, then uses the '
                     "krbtgt key to decrypt it, alter the PAC's group SIDs/user identity, and "
                     're-sign it. The result carries genuine KDC-issued timestamps and structure, '
                     'matching what a 4768 shows, so it blends in far better while still granting '
                     'elevated access. Still requires the krbtgt key.',
        'prerequisites': [   'krbtgt key (as with Golden Ticket)',
                             'A valid TGT obtainable for some account (real AS-REQ)'],
        'enumeration': [   'Rubeus.exe diamond /...  (research/perform)',
                           'Defenders: correlate 4768 TGT issuance with later privileged use '
                           "inconsistent with the account's real group membership",
                           'Rubeus.exe describe /ticket:<ticket> to inspect PAC'],
        'detection_indicators': [   'A user authenticating with privileges (group SIDs) that do '
                                    'not match their actual AD group membership',
                                    'PAC group memberships inconsistent with directory state for '
                                    'the account',
                                    'Same detection difficulty as golden — focus on '
                                    'privilege-vs-membership mismatch'],
        'tools': ['rubeus (diamond)', 'mimikatz', 'impacket ticketer.py'],
        'cve': [],
        'mitigation': [   'Same as Golden Ticket: rotate krbtgt twice after Tier-0 compromise; '
                          'protect the krbtgt secret',
                          'Detect authorization decisions where PAC group SIDs exceed the '
                          "account's real membership",
                          'Enable PAC validation and Kerberos AES enforcement'],
        'poc_references': ['https://github.com/GhostPack/Rubeus'],
        'research_references': ['https://www.trustedsec.com/blog/a-diamond-in-the-ruff/']},
    {   'id': 'ad-gmsa-password-read',
        'name': 'gMSA managed-password read (READ_GMSA / msDS-ManagedPassword)',
        'platform': 'active-directory',
        'category': 'credential-harvesting',
        'severity': 'high',
        'summary': "Principals listed in a group-Managed Service Account's msDS-GroupMSAMembership "
                   "(or with the READ_GMSA_PASSWORD right) can retrieve the account's "
                   'msDS-ManagedPassword blob, derive its NTLM hash, and authenticate as that '
                   'service account; with the KDS root key, the password can even be computed '
                   'offline (Golden gMSA).',
        'technique': "A gMSA's password is generated by the domain from the KDS root key and "
                     'exposed via the constructed LDAP attribute msDS-ManagedPassword to accounts '
                     'allowed by msDS-GroupMSAMembership (the '
                     "'PrincipalsAllowedToRetrieveManagedPassword'). An attacker who controls such "
                     "an allowed principal reads that blob over LDAP and computes the account's "
                     'NTLM hash from the current password field — no cracking needed — then uses '
                     'it for pass-the-hash / service authentication as the (often privileged) '
                     'service account. gMSADumper and DSInternals automate the read-and-derive. '
                     'Separately, the Golden gMSA attack (GoldenGMSA) recovers the domain KDS root '
                     "key (readable by Domain/Enterprise Admins) and computes any gMSA's password "
                     'entirely offline, across time, without further DC contact. BloodHound flags '
                     'ReadGMSAPassword edges to find the abusable principals.',
        'prerequisites': [   "control of a principal in the target gMSA's msDS-GroupMSAMembership "
                             '/ READ_GMSA_PASSWORD right, OR',
                             'read access to the KDS root key (Domain/Enterprise Admin) for the '
                             'Golden gMSA variant'],
        'enumeration': [   'Get-ADServiceAccount -Filter * -Properties '
                           'PrincipalsAllowedToRetrieveManagedPassword',
                           'python3 gMSADumper.py -u user -p pass -d domain',
                           "Get-ADObject -Filter 'objectClass -eq "
                           '"msDS-GroupManagedServiceAccount"\' -Properties *',
                           'GoldenGMSA.exe kdsinfo'],
        'detection_indicators': [   'msDS-ManagedPassword',
                                    'msDS-GroupMSAMembership',
                                    'ReadGMSAPassword',
                                    'msDS-GroupManagedServiceAccount',
                                    'KDS root key',
                                    'PrincipalsAllowedToRetrieveManagedPassword'],
        'tools': ['gmsadumper', 'goldengmsa', 'dsinternals', 'bloodhound', 'netexec'],
        'cve': [],
        'mitigation': [   'Tightly scope PrincipalsAllowedToRetrieveManagedPassword to required '
                          'hosts only',
                          'Protect the KDS root key; treat Domain/Enterprise Admin as tier-0',
                          'Audit gMSA membership and msDS-ManagedPassword reads',
                          'Rotate/limit privileges of gMSA-run services; monitor BloodHound '
                          'ReadGMSAPassword edges'],
        'poc_references': [   'https://github.com/micahvandeusen/gMSADumper',
                              'https://github.com/Semperis/GoldenGMSA',
                              'https://www.semperis.com/blog/golden-gmsa-attack/'],
        'research_references': [   'https://www.thehacker.recipes/ad/movement/dacl/readgmsapassword',
                                   'https://simondotsh.com/infosec/2022/12/12/gmsa.html']},
    {   'id': 'ad-gpo-abuse-modification',
        'name': 'GPO Abuse (Group Policy Object Modification)',
        'platform': 'active-directory',
        'category': 'gpo-abuse',
        'severity': 'high',
        'summary': 'An attacker with edit rights on a Group Policy Object (or write access to a '
                   'linked OU) can push malicious settings — scheduled tasks, immediate tasks, '
                   'local admin group membership, startup scripts — to every computer/user the GPO '
                   'applies to, enabling mass code execution or privilege grants.',
        'technique': 'GPOs are stored as files in SYSVOL plus AD objects, and are applied by '
                     'clients on refresh. If an attacker can write to a GPO (WriteProperty on '
                     'gpc-file-sys-path / GP-Options, or edit rights) or link a GPO to an OU, they '
                     'can add an immediate scheduled task, a startup script, or a Restricted '
                     'Groups / Group Policy Preferences membership change that makes a controlled '
                     'account local administrator on all affected machines. Because GPO scope can '
                     'be huge (e.g., a GPO linked to the Domain Controllers OU or the domain '
                     'root), impact reaches domain compromise. SharpGPOAbuse automates injecting '
                     'tasks/rights into an editable GPO.',
        'prerequisites': [   'Edit rights on a GPO (WriteDACL/WriteProperty/GenericWrite on the '
                             'GPC) or the ability to link GPOs to a target OU',
                             'Target OU/domain contains valuable computers or users'],
        'enumeration': [   "BloodHound: 'GPO' control edges and 'affected objects' of a GPO",
                           'PowerView: Get-DomainGPO | Get-DomainObjectAcl -ResolveGUIDs ; '
                           'Get-DomainOU | select gplink',
                           'PowerView: Get-DomainGPOUserLocalGroupMapping / '
                           'Get-DomainGPOComputerLocalGroupMapping',
                           'GPMC / Get-GPO -All for delegation review'],
        'detection_indicators': [   'Event 5136/5137 changes to GPO objects (gPCFileSysPath, '
                                    'versionNumber) and new gPLink on OUs',
                                    'SYSVOL file changes (ScheduledTasks.xml, GptTmpl.inf, '
                                    'scripts) by non-admin editors',
                                    'Unexpected scheduled tasks/startup scripts appearing on many '
                                    'hosts simultaneously',
                                    'New members added to local Administrators via GPP/Restricted '
                                    'Groups'],
        'tools': [   'sharpgpoabuse',
                     'powerview',
                     'bloodhound',
                     'pygpoabuse',
                     'group3r/grouper2 (audit)'],
        'cve': [],
        'mitigation': [   'Restrict GPO edit and OU link delegation to Tier-0 admins; audit GPO '
                          'ACLs',
                          'Monitor SYSVOL and GPO object changes (5136/5137, file integrity on '
                          'SYSVOL)',
                          'Use Group3r/Grouper2 to find over-permissive GPOs',
                          'Separate DC and Tier-0 GPOs; least-privilege delegation'],
        'poc_references': [   'https://github.com/FSecureLABS/SharpGPOAbuse',
                              'https://github.com/Hackndo/pyGPOAbuse'],
        'research_references': [   'https://wald0.com/?p=179',
                                   'https://attack.mitre.org/techniques/T1484/001/']},
    {   'id': 'ad-kerberoasting-spn-tgs-crack',
        'name': 'Kerberoasting',
        'platform': 'active-directory',
        'category': 'kerberoast',
        'severity': 'high',
        'summary': 'Any authenticated domain user can request Kerberos service tickets (TGS-REP) '
                   'for accounts with a Service Principal Name (SPN) and crack them offline to '
                   "recover the service account's plaintext password, because the ticket is "
                   "encrypted with the service account's password-derived key.",
        'technique': 'In Kerberos, a client requests a TGS for a target SPN; the KDC returns a '
                     "ticket encrypted with the service account's NTLM/AES key. An attacker "
                     'requests tickets for user accounts that have SPNs set (i.e., service '
                     'accounts, not machine accounts) and cracks them offline with hashcat/John. '
                     'RC4 (etype 0x17) tickets are derived directly from the NT hash and crack '
                     "fastest; requesting RC4 explicitly ('downgrade') speeds attacks. Targeted "
                     'Kerberoasting can be combined with GenericWrite/GenericAll to set an SPN on '
                     'a victim account temporarily. No elevated privileges are required to request '
                     'the tickets — only a valid domain account.',
        'prerequisites': [   'Any valid domain user credentials',
                             'Target user accounts with servicePrincipalName set',
                             'Weak/guessable service account password for offline cracking to '
                             'succeed'],
        'enumeration': [   'PowerView: Get-DomainUser -SPN -Properties '
                           'samaccountname,serviceprincipalname',
                           'Impacket: GetUserSPNs.py <domain>/<user>:<pass> -dc-ip <dc> -request',
                           'Rubeus.exe kerberoast /stats  (and /rc4opsec to find AES-only)',
                           "AD module: Get-ADUser -Filter {ServicePrincipalName -like '*'} "
                           '-Properties ServicePrincipalName'],
        'detection_indicators': [   'Windows Security Event 4769 (Kerberos service ticket '
                                    'requested) with Ticket Encryption Type 0x17 (RC4-HMAC)',
                                    'High volume of 4769 events for many SPNs from a single '
                                    'account in a short window',
                                    '4769 Ticket Options flag 0x40810000 combined with RC4 for '
                                    'accounts that normally use AES',
                                    'Requests for SPNs of low-value/decoy (honeypot) service '
                                    'accounts'],
        'tools': [   'rubeus',
                     'impacket getuserspns.py',
                     'powerview',
                     'hashcat (mode 13100)',
                     'john the ripper (krb5tgs)',
                     'targetedkerberoast',
                     'bloodhound'],
        'cve': [],
        'mitigation': [   'Use Group Managed Service Accounts (gMSA) with 120-char auto-rotated '
                          'passwords',
                          'Enforce long (25+ char) random passwords on service accounts and '
                          'disable RC4 (set msDS-SupportedEncryptionTypes to AES-only)',
                          'Deploy honeypot SPN accounts and alert on 4769 for them',
                          'Remove unnecessary SPNs; audit for user accounts with SPNs'],
        'poc_references': [   'https://github.com/GhostPack/Rubeus',
                              'https://github.com/fortra/impacket/blob/master/examples/GetUserSPNs.py'],
        'research_references': [   'https://attack.mitre.org/techniques/T1558/003/',
                                   'https://adsecurity.org/?p=2293',
                                   'https://www.harmj0y.net/blog/powershell/kerberoasting-without-mimikatz/']},
    {   'id': 'ad-laps-password-read-abuse',
        'name': 'LAPS Password Read Abuse',
        'platform': 'active-directory',
        'category': 'credential-harvesting',
        'severity': 'high',
        'summary': "The Local Administrator Password Solution stores each machine's randomized "
                   'local admin password in an AD attribute; principals granted read access to '
                   'ms-Mcs-AdmPwd (legacy LAPS) or msLAPS-Password/EncryptedPassword (Windows '
                   'LAPS) can retrieve cleartext local admin passwords for lateral movement.',
        'technique': 'LAPS randomizes and rotates the local Administrator password and stores it '
                     'in a confidential AD attribute on the computer object, readable only by '
                     'delegated principals. If ACLs over-grant read (All Extended Rights, '
                     'GenericAll, or explicit read of the password attribute) to broad groups, an '
                     'attacker who compromises such a principal reads the plaintext local admin '
                     'password directly from AD and moves laterally. Over-broad delegation, or '
                     'compromise of the intended reader group, converts LAPS from a control into a '
                     'credential store. Windows LAPS adds encrypted storage and can protect with '
                     'DPAPI, but read-access misconfiguration still applies.',
        'prerequisites': [   'LAPS deployed',
                             'An identity with read access to the LAPS password attribute '
                             '(ms-Mcs-AdmPwd or msLAPS-Password) on target computers',
                             'For Windows LAPS encrypted mode: decryption rights'],
        'enumeration': [   'PowerView: Get-DomainComputer -Properties ms-Mcs-AdmPwd,samaccountname '
                           "| ? {$_.'ms-mcs-admpwd'}",
                           'Find readers: Find-LAPSDelegatedGroups / Find-AdmPwdExtendedRights '
                           '(LAPSToolkit)',
                           "BloodHound: 'ReadLAPSPassword' edges",
                           'pyLAPS: pyLAPS.py --action get -d <domain> -u <user> -p <pass>'],
        'detection_indicators': [   'Event 4662 read access to the LAPS password attribute by '
                                    'non-standard principals',
                                    'Bulk queries of ms-Mcs-AdmPwd/msLAPS-Password across many '
                                    'computer objects',
                                    'Local admin logons using the LAPS-managed account from '
                                    'unexpected source hosts'],
        'tools': [   'lapstoolkit',
                     'pylaps',
                     'sharplaps',
                     'powerview',
                     'bloodhound',
                     'get-admpwdpassword (admpwd.ps)'],
        'cve': [],
        'mitigation': [   'Tightly scope who can read LAPS passwords; audit ms-Mcs-AdmPwd/msLAPS '
                          'ACLs regularly',
                          'Migrate to Windows LAPS with encrypted passwords and DPAPI protection; '
                          'shorten rotation',
                          'Monitor 4662 reads of the LAPS attribute and alert on bulk reads',
                          'Enforce Tier-0 separation so LAPS readers are not broadly reachable'],
        'poc_references': [   'https://github.com/leoloobeek/LAPSToolkit',
                              'https://github.com/p0dalirius/pyLAPS'],
        'research_references': [   'https://www.thehacker.recipes/ad/movement/dacl/read-laps-password',
                                   'https://learn.microsoft.com/en-us/windows-server/identity/laps/laps-overview']},
    {   'id': 'ad-overpass-the-hash-key',
        'name': 'Overpass-the-Hash / Pass-the-Key',
        'platform': 'active-directory',
        'category': 'overpass-the-hash',
        'severity': 'high',
        'summary': 'An attacker uses a stolen NT hash (or AES key) to request a legitimate '
                   'Kerberos TGT, converting NTLM material into full Kerberos authentication and '
                   'thereby accessing Kerberos-only services and blending into normal Kerberos '
                   'traffic.',
        'technique': 'Because the Kerberos AS-REQ preauth key is derived from the account password '
                     '(NT hash for RC4, or AES key), an attacker who has the hash/key can request '
                     "a real TGT (AS-REQ) for the account without the plaintext. This 'overpasses' "
                     'the hash: the resulting TGT is used for standard Kerberos service ticket '
                     'requests. Requesting RC4 reveals the RC4/NT-derived path; using the '
                     "account's AES256 key (Pass-the-Key) avoids RC4 downgrade detections. The TGT "
                     'can then be injected into a logon session (Pass-the-Ticket).',
        'prerequisites': [   'NT hash or Kerberos AES/DES key for the target account',
                             'Network reachability to the KDC (a DC)'],
        'enumeration': [   'Extract keys: secretsdump.py output includes aes256/aes128/rc4 keys '
                           'per account',
                           'Rubeus.exe asktgt /user:<u> /rc4:<hash>  (or /aes256:<key>) to obtain '
                           'a TGT',
                           'Validate resulting access with klist and Kerberos-only service access'],
        'detection_indicators': [   'Event 4768 (TGT request) using RC4 (0x17) for an account/host '
                                    'that should use AES',
                                    'TGT requests originating from a workstation IP that does not '
                                    "match the account's normal host",
                                    'Mismatch between logon session NTLM secrets and Kerberos '
                                    'activity'],
        'tools': [   'rubeus (asktgt)',
                     'mimikatz (sekurlsa::pth with /aes256)',
                     'impacket gettgt.py',
                     'crackmapexec/netexec'],
        'cve': [],
        'mitigation': [   'Disable RC4 Kerberos etypes domain-wide to force AES and improve '
                          'detection',
                          'Protect credential stores (Credential Guard, LSASS PPL)',
                          'Protected Users group forces AES and blocks RC4/NTLM for members',
                          'Alert on RC4 4768 events and geographically/host-anomalous TGT '
                          'requests'],
        'poc_references': [   'https://github.com/GhostPack/Rubeus',
                              'https://github.com/fortra/impacket/blob/master/examples/getTGT.py'],
        'research_references': [   'https://attack.mitre.org/techniques/T1550/002/',
                                   'https://adsecurity.org/?p=2362']},
    {   'id': 'ad-pass-the-hash-ntlm',
        'name': 'Pass-the-Hash (PtH)',
        'platform': 'active-directory',
        'category': 'pass-the-hash',
        'severity': 'high',
        'summary': 'The NTLM authentication protocol proves identity with the NT hash rather than '
                   "the plaintext, so an attacker who obtains a user's NT hash can authenticate to "
                   'remote services as that user without ever cracking the password.',
        'technique': 'NTLM challenge-response uses the NT hash directly as the key. After dumping '
                     'hashes from LSASS, the SAM, NTDS.dit, or via DCSync, an attacker supplies '
                     'the hash to tools that speak SMB/WMI/RPC and authenticates over the network '
                     'without the cleartext. Local admin hash reuse across machines enables '
                     'lateral movement; a domain admin hash yields domain-wide access. PtH is '
                     'limited to NTLM-authenticated services (SMB, WMI, WinRM); Kerberos-only '
                     'paths require Overpass-the-Hash instead.',
        'prerequisites': [   'An NT hash for a target account',
                             'Network access to services accepting NTLM',
                             'Target account has privileges on the destination host'],
        'enumeration': [   "BloodHound: 'AdminTo' / local admin reuse mapping across hosts",
                           'CrackMapExec/NetExec: nxc smb <targets> -u <user> -H <nthash> '
                           '(validation of where a hash works)',
                           'Identify hash sources: SAM/LSASS/NTDS access rights on hosts'],
        'detection_indicators': [   'Event 4624 Logon Type 3 with Authentication Package NTLM for '
                                    'accounts that normally use Kerberos',
                                    '4776 (NTLM credential validation) spikes from '
                                    'workstation-to-workstation',
                                    'Same account authenticating to many hosts in a short window '
                                    '(lateral movement)',
                                    'Use of built-in local Administrator (RID 500) across multiple '
                                    'machines'],
        'tools': [   'mimikatz (sekurlsa::pth)',
                     'impacket (psexec.py/wmiexec.py -hashes)',
                     'crackmapexec/netexec',
                     'evil-winrm'],
        'cve': [],
        'mitigation': [   'Enable LSASS protection (RunAsPPL/Credential Guard) to prevent hash '
                          'theft',
                          'Use unique local admin passwords (LAPS/Windows LAPS) to stop hash reuse',
                          'Add privileged accounts to Protected Users (removes NTLM), enforce '
                          'tiering',
                          "Restrict lateral SMB/WMI with host firewall and 'Deny access from "
                          "network' for admin accounts"],
        'poc_references': [   'https://github.com/gentilkiwi/mimikatz',
                              'https://github.com/fortra/impacket'],
        'research_references': ['https://attack.mitre.org/techniques/T1550/002/']},
    {   'id': 'ad-pass-the-ticket-ptt',
        'name': 'Pass-the-Ticket (PtT)',
        'platform': 'active-directory',
        'category': 'pass-the-ticket',
        'severity': 'high',
        'summary': 'An attacker extracts existing Kerberos tickets (TGTs or service tickets) from '
                   "a host's memory (or a forged ticket) and injects them into their own logon "
                   "session to impersonate the ticket's owner without needing the password or "
                   'hash.',
        'technique': 'Kerberos tickets live in LSASS and can be exported (e.g., sekurlsa::tickets, '
                     'Rubeus dump) or written to .kirbi/.ccache files. An attacker with local '
                     "admin/SYSTEM harvests a privileged user's TGT and injects it (ptt) into a "
                     'new session, then accesses any resource the ticket permits. Forged '
                     'Golden/Silver/Diamond tickets are a special case of PtT. Cross-platform, '
                     'ccache files harvested from Linux/keytabs or from KRB5CCNAME can likewise be '
                     'reused.',
        'prerequisites': [   'Access to a host holding a valid ticket (local admin/SYSTEM to read '
                             'LSASS) OR a forged ticket',
                             'The ticket is still within its lifetime/renew window'],
        'enumeration': [   'klist  (enumerate cached tickets in current session)',
                           'Rubeus.exe triage / Rubeus.exe dump  (list/export tickets)',
                           'Mimikatz: sekurlsa::tickets /export',
                           'Impacket: reuse of exported ccache via KRB5CCNAME'],
        'detection_indicators': [   'Ticket used from a host different from the one it was issued '
                                    'to (source host mismatch)',
                                    '4624 Logon Type 3 with Kerberos for accounts on unexpected '
                                    'endpoints',
                                    'TGS requests (4769) using a TGT whose lifetime/flags are '
                                    'anomalous',
                                    'LSASS read/handle events preceding remote Kerberos logons'],
        'tools': [   'mimikatz (kerberos::ptt)',
                     'rubeus (ptt/dump/triage)',
                     'impacket (ccache reuse)'],
        'cve': [],
        'mitigation': [   'Protect LSASS (Credential Guard, RunAsPPL) to prevent ticket theft',
                          'Reduce TGT lifetime/renewal; enforce Protected Users (4-hour TGT, no '
                          'delegation)',
                          'Detect ticket-host mismatches and abnormal ticket lifetimes',
                          'Reset krbtgt twice to invalidate forged golden tickets after '
                          'compromise'],
        'poc_references': [   'https://github.com/GhostPack/Rubeus',
                              'https://github.com/gentilkiwi/mimikatz'],
        'research_references': ['https://attack.mitre.org/techniques/T1550/003/']},
    {   'id': 'ad-rbcd-msds-allowedtoactonbehalf',
        'name': 'Resource-Based Constrained Delegation (RBCD) Abuse',
        'platform': 'active-directory',
        'category': 'delegation',
        'severity': 'high',
        'summary': 'If an attacker can write the msDS-AllowedToActOnBehalfOfOtherIdentity '
                   'attribute on a target computer (via GenericWrite/GenericAll/WriteDACL), they '
                   'configure an attacker-controlled account as a permitted delegate and then use '
                   'S4U to impersonate any user — including local admins — to that computer.',
        'technique': 'RBCD moves delegation control from the source service to the target '
                     "resource. The target's security descriptor "
                     '(msDS-AllowedToActOnBehalfOfOtherIdentity) lists SIDs allowed to delegate to '
                     'it. An attacker with write access to a computer object adds a controlled '
                     'principal (frequently a new machine account created via MachineAccountQuota) '
                     'to that attribute, then performs S4U2Self+S4U2Proxy to obtain a service '
                     'ticket for e.g. CIFS/target impersonating a Domain Admin, yielding SYSTEM on '
                     "the target. This is the classic 'Wagging the Dog' primitive and a common "
                     'BloodHound-identified path.',
        'prerequisites': [   'Write access (GenericWrite/GenericAll/WriteDACL/WriteProperty) to '
                             'the target computer object',
                             'Control of an account with an SPN (create one via MAQ if none '
                             'available)'],
        'enumeration': [   'PowerView: Get-DomainComputer <target> -Properties '
                           "'msds-allowedtoactonbehalfofotheridentity'",
                           'BloodHound: nodes with GenericWrite/GenericAll/WriteDacl to computers; '
                           "'AllowedToAct' edges",
                           'Get-ADComputer <target> -Properties '
                           'PrincipalsAllowedToDelegateToAccount',
                           'PowerView: Get-DomainObjectAcl to find writeable computer ACLs'],
        'detection_indicators': [   'Security Event 5136 modification of '
                                    'msDS-AllowedToActOnBehalfOfOtherIdentity',
                                    'Creation of a new computer account (Event 4741) shortly '
                                    'before a delegation change',
                                    '4769 with Transited Services impersonating privileged users '
                                    'to a workstation/server'],
        'tools': [   'rubeus',
                     'impacket (rbcd.py, getst.py, addcomputer.py)',
                     'powerview (set-domainrbcd)',
                     'powermad',
                     'bloodhound'],
        'cve': [],
        'mitigation': [   'Set MachineAccountQuota to 0 so users cannot create attacker machine '
                          'accounts',
                          'Tighten computer object ACLs; remove excessive GenericWrite/WriteDACL '
                          'grants',
                          'Add Tier-0 accounts to Protected Users / mark as '
                          'sensitive-cannot-be-delegated',
                          'Monitor 5136 changes to msDS-AllowedToActOnBehalfOfOtherIdentity'],
        'poc_references': [   'https://github.com/fortra/impacket/blob/master/examples/rbcd.py',
                              'https://github.com/GhostPack/Rubeus'],
        'research_references': [   'https://shenaniganslabs.io/2019/01/28/Wagging-the-Dog.html',
                                   'https://www.thehacker.recipes/ad/movement/kerberos/delegations/rbcd']},
    {   'id': 'ad-sccm-configmgr-abuse',
        'name': 'SCCM / ConfigMgr abuse (NAA creds, PXE, site takeover)',
        'platform': 'active-directory',
        'category': 'sccm',
        'severity': 'high',
        'summary': 'Microsoft Configuration Manager (SCCM/MECM) deployments leak Network Access '
                   'Account credentials via policy/DPAPI, expose crackable PXE boot media, and '
                   'permit NTLM-relay to the management point / site database — paths that yield '
                   'domain credentials and full site (and often domain) takeover.',
        'technique': "SCCM's tiered design exposes several abuses catalogued in the "
                     'Misconfiguration-Manager project. (1) Credential recovery: any domain-joined '
                     'client requests machine policy from the management point and can decrypt the '
                     'embedded Network Access Account (and other) credentials protected by client '
                     'DPAPI (CRED-class, e.g. SharpSCCM gets NAA creds) — those accounts are '
                     'frequently over-privileged. (2) PXE abuse: if OS-deployment PXE is enabled, '
                     'an attacker requests a boot image; a blank or weak PXE password lets the '
                     'media be cracked (pxethiefy/PXEThief) to extract deployed credentials and '
                     'task-sequence variables. (3) Relay/coercion: NTLM relay of a site-server or '
                     'client machine account to the management point, SMB, or the site SQL '
                     'database (via automatic client push authentication or coercion) grants Full '
                     'Administrator over the site (ELEVATE/TAKEOVER classes), from which '
                     'application deployment pushes SYSTEM code to any managed host. (4) '
                     'CMPivot/AdminService and application deployment let a Full Admin run '
                     'commands across the estate. Together these move from an unprivileged client '
                     'to domain-wide compromise.',
        'prerequisites': [   'a domain-joined SCCM client or network access to a management point '
                             '/ distribution point',
                             'for relay: automatic client push or coercible machine accounts and '
                             'no SMB/LDAP signing enforced',
                             'for PXE: OS deployment enabled, weak/absent PXE password'],
        'enumeration': [   'SharpSCCM.exe get naa',
                           'SharpSCCM.exe local site-info',
                           'nslookup -type=srv _mssms_mp_<sitecode>._tcp.<domain>',
                           'python3 pxethiefy.py',
                           'Get-WmiObject -Namespace root\\ccm -Class SMS_Authority'],
        'detection_indicators': [   'Network Access Account',
                                    'SMS_Authority',
                                    'CCM_NetworkAccessAccount',
                                    'root\\ccm',
                                    'PXE',
                                    'management point',
                                    '_mssms_mp_'],
        'tools': [   'sharpsccm',
                     'misconfiguration-manager',
                     'cmloot',
                     'pxethief',
                     'malsccm',
                     'ntlmrelayx'],
        'cve': [],
        'mitigation': [   'Do not use a Network Access Account (use Enhanced HTTP / PKI); if used, '
                          'make it minimally privileged',
                          'Set a strong PXE password and restrict OS deployment; secure DPs',
                          'Disable automatic client push; enforce SMB and LDAP signing to block '
                          'relay',
                          'Harden the site server/DB as tier-0; apply the Misconfiguration-Manager '
                          'preventions/detections'],
        'poc_references': [   'https://github.com/Mayyhem/SharpSCCM',
                              'https://github.com/subat0mik/Misconfiguration-Manager',
                              'https://github.com/csandker/pxethiefy'],
        'research_references': [   'https://www.thehacker.recipes/ad/movement/sccm-mecm',
                                   'https://posts.specterops.io/site-takeover-via-sccms-adminservice-api-d932e22b2bf']},
    {   'id': 'ad-shadow-credentials-keycredentiallink',
        'name': 'Shadow Credentials (msDS-KeyCredentialLink)',
        'platform': 'active-directory',
        'category': 'shadow-credentials',
        'severity': 'high',
        'summary': "An attacker with write access to a target user/computer's "
                   'msDS-KeyCredentialLink attribute adds an attacker-controlled key pair (Key '
                   "Trust), then uses PKINIT to obtain a TGT and the target's NT hash — a "
                   'password-less account takeover requiring no password reset.',
        'technique': "Windows Hello for Business / Key Trust stores public keys in the target's "
                     'msDS-KeyCredentialLink attribute; possession of the matching private key '
                     'lets the holder authenticate via PKINIT and receive a TGT. If an attacker '
                     'holds GenericWrite/GenericAll/WriteProperty (often surfaced by BloodHound) '
                     'over a victim object, they append their own KeyCredential, then request a '
                     'TGT for the victim using PKINIT and can UnPAC-the-hash to recover the '
                     "victim's NT hash. Unlike a password reset, it is quiet and reversible "
                     '(remove the added key). Whisker/pyWhisker automate adding the KeyCredential; '
                     'Rubeus/gettgtpkinit perform PKINIT. Requires the domain to support PKINIT (a '
                     'CA/DC certificate).',
        'prerequisites': [   'Write access (GenericWrite/GenericAll/WriteProperty on '
                             'msDS-KeyCredentialLink) over the target object',
                             'Domain supports PKINIT (functional DC certificates / AD CS present)',
                             'DC functional level 2016+ for key trust'],
        'enumeration': [   'PowerView/AD module: read msDS-KeyCredentialLink on target objects '
                           '(Get-ADComputer <t> -Properties msDS-KeyCredentialLink)',
                           'BloodHound: inbound GenericWrite/GenericAll/AddKeyCredentialLink edges '
                           'to targets',
                           'Whisker.exe list /target:<victim>  ;  pywhisker --action list'],
        'detection_indicators': [   'Event 5136 modification of the msDS-KeyCredentialLink '
                                    'attribute on user/computer objects',
                                    'PKINIT TGT requests (4768 with certificate/pre-auth type '
                                    "PKINIT) for accounts that don't use WHfB",
                                    "KeyCredentials added to accounts that shouldn't have device "
                                    'keys, followed by immediate authentication'],
        'tools': [   'whisker',
                     'pywhisker',
                     'rubeus (asktgt /getcredentials via pkinit)',
                     'gettgtpkinit.py (pkinittools)',
                     'certipy shadow',
                     'bloodhound'],
        'cve': [],
        'mitigation': [   'Restrict write access to msDS-KeyCredentialLink; audit object ACLs',
                          'Monitor 5136 changes to msDS-KeyCredentialLink and alert on additions',
                          'Enforce strong certificate mapping (KB5014754) and Tier-0 isolation',
                          'Where WHfB Key Trust is unused, watch for any KeyCredential additions '
                          'as anomalies'],
        'poc_references': [   'https://github.com/eladshamir/Whisker',
                              'https://github.com/ShutdownRepo/pywhisker'],
        'research_references': [   'https://posts.specterops.io/shadow-credentials-abusing-key-trust-account-mapping-for-takeover-8ee1a53566ab',
                                   'https://www.thehacker.recipes/ad/movement/kerberos/shadow-credentials']},
    {   'id': 'ad-silver-ticket-service-forgery',
        'name': 'Silver Ticket',
        'platform': 'active-directory',
        'category': 'silver-ticket',
        'severity': 'high',
        'summary': "With a service account's (or computer account's) password hash, an attacker "
                   'forges service tickets (TGS) for that specific service, impersonating any user '
                   'to it without ever contacting the KDC — a stealthier, service-scoped '
                   'alternative to a Golden Ticket.',
        'technique': "A TGS is encrypted with the target service account's key. Knowing that key "
                     '(e.g., a machine account hash for CIFS/HOST, or a SQL service account hash) '
                     'lets an attacker craft a valid TGS with a forged PAC directly, bypassing the '
                     'DC entirely. Because no 4768/4769 is generated at the DC, silver tickets are '
                     'quieter than golden tickets. Scope is limited to the one service on the one '
                     'host, but that can be SYSTEM-level (CIFS, HOST, RPCSS for WMI, LDAP for a '
                     'DC). Prior to PAC validation hardening, forged PACs went unchecked.',
        'prerequisites': [   'Password hash/AES key of the target service or computer account',
                             'Domain SID',
                             'Knowledge of the target SPN'],
        'enumeration': [   'Obtain machine/service account keys via secretsdump/DCSync '
                           '(post-compromise)',
                           'Rubeus.exe describe /ticket:<ticket>  (inspect forged service tickets)',
                           'Inventory high-value SPNs (CIFS/HOST/MSSQLSvc/LDAP) to understand '
                           'impact'],
        'detection_indicators': [   'Service access (4624/4634) with Kerberos but no corresponding '
                                    '4769 at the DC',
                                    'PAC signature/validation failures where PAC validation is '
                                    'enforced',
                                    'Anomalous TGS with mismatched user/host or excessive '
                                    'privileges to a single service'],
        'tools': [   'mimikatz (kerberos::golden with /service)',
                     'rubeus (silver)',
                     'impacket ticketer.py'],
        'cve': [],
        'mitigation': [   'Rotate machine account passwords regularly (default 30 days) and '
                          'service account passwords/gMSA',
                          'Enable PAC validation / Kerberos hardening; force AES',
                          'Detect Kerberos service access lacking corresponding DC TGS issuance',
                          'Limit exposure of service/computer account secrets'],
        'poc_references': [   'https://github.com/gentilkiwi/mimikatz',
                              'https://github.com/fortra/impacket/blob/master/examples/ticketer.py'],
        'research_references': [   'https://attack.mitre.org/techniques/T1558/002/',
                                   'https://adsecurity.org/?p=2011']},
    {   'id': 'ad-machineaccountquota-abuse',
        'name': 'MachineAccountQuota Abuse',
        'platform': 'active-directory',
        'category': 'machineaccountquota',
        'severity': 'medium',
        'summary': 'The default domain attribute ms-DS-MachineAccountQuota = 10 lets any '
                   'authenticated user create up to ten computer accounts, which attackers '
                   'leverage as controlled principals for RBCD, shadow-credential, '
                   'sAMAccountName-spoofing (noPac), and relay follow-on attacks.',
        'technique': 'MachineAccountQuota (MAQ) governs how many machine accounts a non-admin user '
                     'may join to the domain. At the default of 10, any user can create a computer '
                     'object they fully control (they are its creator/owner with write to key '
                     'attributes). That attacker-owned machine account with a known password/SPN '
                     'is the missing puzzle piece for many escalations: it is the delegate added '
                     "to a target's msDS-AllowedToActOnBehalfOfOtherIdentity (RBCD), the account "
                     'whose sAMAccountName is renamed to a DC name in noPac, or the principal used '
                     'in shadow-credential/relay chains. MAQ abuse itself is not escalation, but '
                     'it removes a key prerequisite for several critical attacks.',
        'prerequisites': [   'Any authenticated domain user',
                             'ms-DS-MachineAccountQuota > 0 (default 10)',
                             'No GPO/ACL restricting who can add workstations to the domain'],
        'enumeration': [   'Get-ADObject -Identity ((Get-ADDomain).DistinguishedName) -Properties '
                           'ms-DS-MachineAccountQuota',
                           "PowerView: Get-DomainObject -Identity 'DC=corp,DC=local' -Properties "
                           'ms-ds-machineaccountquota',
                           'Powermad: Get-MachineAccountQuota',
                           'Impacket addcomputer.py (to test creation rights)'],
        'detection_indicators': [   'Event 4741 (computer account created) sourced from a normal '
                                    'user rather than a provisioning/help-desk account',
                                    'New computer objects whose creator/ms-DS-CreatorSID is a '
                                    'standard user',
                                    'A burst of machine account creations preceding '
                                    'RBCD/noPac/relay activity'],
        'tools': [   'powermad (new-machineaccount)',
                     'impacket addcomputer.py',
                     'bloodhound',
                     'powerview'],
        'cve': [],
        'mitigation': [   'Set ms-DS-MachineAccountQuota to 0 and delegate machine-join to a '
                          "specific group via 'Add workstations to domain' rights",
                          'Monitor 4741 for user-initiated computer creation',
                          "Remove the default Authenticated Users 'create computer object' "
                          'capability where feasible'],
        'poc_references': [   'https://github.com/Kevin-Robertson/Powermad',
                              'https://github.com/fortra/impacket/blob/master/examples/addcomputer.py'],
        'research_references': [   'https://www.netspi.com/blog/technical-blog/network-penetration-testing/machineaccountquota-is-useful-sometimes/',
                                   'https://www.thehacker.recipes/ad/movement/domain-settings/machineaccountquota']},
    {   'id': 'aws-iam-privilege-escalation',
        'name': 'AWS IAM privilege escalation (PassRole / policy / key abuse)',
        'platform': 'cloud',
        'category': 'cloud-iam',
        'severity': 'critical',
        'summary': 'A principal holding a single over-broad IAM permission — iam:PassRole to a '
                   'service, CreatePolicyVersion, AttachUserPolicy/PutUserPolicy, CreateAccessKey, '
                   'UpdateAssumeRolePolicy, or CreateLoginProfile — can escalate to administrator '
                   'through documented permission-misconfiguration chains.',
        'technique': 'Rhino Security Labs catalogued ~20+ IAM escalation methods that turn a '
                     'narrow permission into admin. Examples: iam:CreatePolicyVersion with '
                     '--set-as-default rewrites an attached policy to grant *:* ; '
                     'iam:AttachUserPolicy / PutUserPolicy attaches AdministratorAccess to '
                     'yourself; iam:CreateAccessKey or CreateLoginProfile / UpdateLoginProfile '
                     'hijacks another (privileged) user; iam:AddUserToGroup joins an admin group; '
                     'iam:UpdateAssumeRolePolicy lets you assume a high-priv role; and the '
                     'PassRole family (iam:PassRole plus a compute service) launches an '
                     'EC2/Lambda/Glue/CloudFormation/SageMaker/Data Pipeline resource that runs '
                     "with a powerful role you pass to it, then reads that role's STS credentials. "
                     'Because service-linked and compute roles are frequently over-privileged, a '
                     'passrole chain commonly lands on full account admin.',
        'prerequisites': [   'valid AWS credentials (access key, SSO/role session, or '
                             'SSRF-obtained token)',
                             'one of the escalation permissions on the caller (or on a role it can '
                             'assume)',
                             'an existing higher-privileged role to pass, for the PassRole '
                             'variants'],
        'enumeration': [   'aws sts get-caller-identity',
                           'aws iam get-account-authorization-details',
                           'aws iam list-attached-user-policies --user-name <u>',
                           'aws iam list-user-policies --user-name <u>',
                           'aws iam list-roles',
                           'aws iam simulate-principal-policy'],
        'detection_indicators': [   'iam:PassRole',
                                    'iam:CreatePolicyVersion',
                                    'iam:AttachUserPolicy',
                                    'iam:PutUserPolicy',
                                    'iam:CreateAccessKey',
                                    'iam:UpdateAssumeRolePolicy',
                                    'AdministratorAccess',
                                    '"Resource": "*"'],
        'tools': ['pacu', 'enumerate-iam', 'cloudsplaining', 'scoutsuite', 'prowler', 'aws-cli'],
        'cve': [],
        'mitigation': [   'Scope iam:PassRole with a resource ARN and iam:PassedToService '
                          'condition',
                          'Avoid wildcard iam:* permissions; deny self-policy-attachment via '
                          'permission boundaries/SCPs',
                          'Restrict CreatePolicyVersion/AttachUserPolicy/CreateAccessKey to '
                          'break-glass admins',
                          'Right-size compute/service roles; monitor CloudTrail for policy and key '
                          'mutations',
                          'Use IAM Access Analyzer and require MFA for sensitive IAM actions'],
        'poc_references': [   'https://rhinosecuritylabs.com/aws/aws-privilege-escalation-methods-mitigation/',
                              'https://github.com/RhinoSecurityLabs/pacu',
                              'https://hackingthe.cloud/aws/exploitation/iam_privilege_escalation/'],
        'research_references': [   'https://cloud.hacktricks.xyz/pentesting-cloud/aws-security/aws-privilege-escalation',
                                   'https://docs.aws.amazon.com/IAM/latest/UserGuide/id_roles_use_passrole.html']},
    {   'id': 'aws-imds-ssrf-credential-theft',
        'name': 'EC2 IMDSv1 SSRF role-credential theft (169.254.169.254)',
        'platform': 'cloud',
        'category': 'cloud-iam',
        'severity': 'high',
        'summary': 'The unauthenticated IMDSv1 link-local endpoint at 169.254.169.254 returns the '
                   "instance role's temporary STS credentials to anything that can make an HTTP "
                   'request from the host — including SSRF in an app — letting an attacker assume '
                   'the EC2 instance role.',
        'technique': 'EC2 instances expose the Instance Metadata Service at '
                     'http://169.254.169.254/. IMDSv1 is a simple, credential-less GET, so any '
                     'request originating from the instance (app-layer SSRF, a compromised '
                     'container sharing the host network, or local code) can fetch the role name '
                     'from /latest/meta-data/iam/security-credentials/ and then the '
                     'AccessKeyId/SecretAccessKey/Token from '
                     '/latest/meta-data/iam/security-credentials/<role>. Those STS creds are '
                     "exported and used against the AWS API with the instance role's permissions, "
                     'which are frequently broad enough to read S3/secrets or chain into IAM '
                     'privilege escalation. This was the mechanism in the 2019 Capital One breach. '
                     'IMDSv2 mitigates it by requiring a PUT-obtained session token with a hop '
                     'limit, which most SSRF cannot satisfy.',
        'prerequisites': [   'an SSRF primitive on an EC2-hosted app, or code execution on the '
                             'instance / a host-networked container',
                             'IMDSv1 enabled (or IMDSv2 with a permissive hop limit)',
                             'an instance profile / role attached to the instance'],
        'enumeration': [   'curl http://169.254.169.254/latest/meta-data/iam/security-credentials/',
                           'curl http://169.254.169.254/latest/meta-data/iam/info',
                           'curl http://169.254.169.254/latest/dynamic/instance-identity/document',
                           "TOKEN=$(curl -s -X PUT 'http://169.254.169.254/latest/api/token' -H "
                           "'X-aws-ec2-metadata-token-ttl-seconds: 60')"],
        'detection_indicators': [   '169.254.169.254',
                                    'meta-data/iam/security-credentials',
                                    'instance-identity/document',
                                    'AccessKeyId',
                                    'ASIA',
                                    'X-aws-ec2-metadata-token'],
        'tools': ['pacu', 'aws-cli', 'ec2-metadata', 'smuggler', 'gopherus'],
        'cve': [],
        'mitigation': [   'Enforce IMDSv2 (HttpTokens=required) and set HttpPutResponseHopLimit=1',
                          'Fix SSRF (allowlist egress, block link-local 169.254.0.0/16)',
                          'Right-size the instance role; monitor for STS use from unexpected '
                          'sources (GuardDuty InstanceCredentialExfiltration)',
                          'Disable IMDS entirely where not needed'],
        'poc_references': [   'https://hackingthe.cloud/aws/exploitation/ec2-metadata-ssrf/',
                              'https://docs.aws.amazon.com/AWSEC2/latest/UserGuide/configuring-instance-metadata-service.html'],
        'research_references': [   'https://blog.appsecco.com/an-ssrf-privileged-aws-keys-and-the-capital-one-breach-4c3c2cded3af',
                                   'https://cloud.hacktricks.xyz/pentesting-cloud/aws-security/aws-unauthenticated-enum-access/aws-metadata-ssrf']},
    {   'id': 'azure-managed-identity-directory-role-abuse',
        'name': 'Azure/Entra managed identity & privileged role abuse',
        'platform': 'cloud',
        'category': 'cloud-iam',
        'severity': 'high',
        'summary': 'An attacker on an Azure VM/App can steal its managed-identity token from IMDS '
                   'and act as that identity, and in Entra ID can abuse privileged directory roles '
                   '(Global Admin, Privileged Role Administrator), Owner/User Access Administrator '
                   'RBAC, or application owner / OAuth consent grants to escalate to tenant '
                   'control.',
        'technique': 'Two overlapping surfaces. (1) Managed identities: a VM/Function/App Service '
                     'with an attached system- or user-assigned identity exposes a token endpoint '
                     'at http://169.254.169.254/metadata/identity/oauth2/token (IMDS, requiring '
                     'the Metadata:true header) or the App Service MSI endpoint; code exec or SSRF '
                     "there yields an AAD access token for ARM/Graph/Key Vault with the identity's "
                     'permissions. (2) Entra/RBAC role abuse: holders of User Access Administrator '
                     'or Owner on a subscription can grant themselves any role (including over the '
                     "tenant root management group via 'elevate access'); directory roles like "
                     'Privileged Role Administrator can assign Global Admin; Application '
                     'Administrator / app Owners can add credentials (a new client '
                     'secret/certificate) to a service principal that itself holds high Graph '
                     'permissions and authenticate as it; and illicit OAuth consent grants '
                     '(Application.ReadWrite.All, RoleManagement.ReadWrite.Directory) let an app '
                     'self-escalate. Chaining a stolen MSI token with an over-privileged SP '
                     'commonly reaches Global Admin.',
        'prerequisites': [   'code exec/SSRF on an Azure resource with a managed identity, OR',
                             'a foothold principal holding Owner/User Access Administrator, a '
                             'privileged Entra role, app ownership, or dangerous Graph app-roles'],
        'enumeration': [   "curl -H 'Metadata:true' "
                           "'http://169.254.169.254/metadata/identity/oauth2/token?api-version=2018-02-01&resource=https://management.azure.com/'",
                           'az account get-access-token',
                           'az role assignment list --assignee <id> --all',
                           'az ad sp list --show-mine',
                           'Get-MgServicePrincipalAppRoleAssignment',
                           'az rest --url https://graph.microsoft.com/v1.0/me/memberOf'],
        'detection_indicators': [   'identity/oauth2/token',
                                    '169.254.169.254/metadata',
                                    'IDENTITY_ENDPOINT',
                                    'User Access Administrator',
                                    'Privileged Role Administrator',
                                    'RoleManagement.ReadWrite.Directory',
                                    'Application.ReadWrite.All'],
        'tools': [   'microburst',
                     'roadtools',
                     'roadrecon',
                     'azurehound',
                     'stormspotter',
                     'az-cli',
                     'graphrunner'],
        'cve': [],
        'mitigation': [   'Restrict which identities are assigned to Azure resources; '
                          "least-privilege the identity's RBAC/Graph roles",
                          'Enforce IMDS access controls and fix SSRF; monitor token requests',
                          "Use PIM (just-in-time) for privileged Entra roles; alert on 'elevate "
                          "access' and role assignments",
                          'Review app credentials and consent grants; block risky OAuth consent; '
                          'require MFA/Conditional Access'],
        'poc_references': [   'https://github.com/NetSPI/MicroBurst',
                              'https://github.com/dirkjanm/ROADtools',
                              'https://learn.microsoft.com/en-us/entra/identity/managed-identities-azure-resources/how-to-use-vm-token'],
        'research_references': [   'https://cloud.hacktricks.xyz/pentesting-cloud/azure-security',
                                   'https://dirkjanm.io/azure-managed-identity-privilege-escalation/']},
    {   'id': 'gcp-service-account-impersonation-actas',
        'name': 'GCP service-account impersonation / actAs abuse',
        'platform': 'cloud',
        'category': 'cloud-iam',
        'severity': 'high',
        'summary': 'A principal with iam.serviceAccounts.getAccessToken / signJwt / signBlob / '
                   'getOpenIdToken on a higher-privileged service account — or '
                   'iam.serviceAccounts.actAs plus a deploy permission (Cloud Functions, Compute, '
                   "Cloud Run, Deployment Manager, Cloud Build) — can mint that SA's tokens or run "
                   'code as it, escalating toward project/organization owner.',
        'technique': 'GCP grants many escalation paths short of Owner. Direct impersonation: with '
                     'iam.serviceAccounts.getAccessToken on a target SA you request an OAuth2 '
                     'access token for it; signJwt/signBlob let you self-sign assertions the SA '
                     'would accept; getOpenIdToken yields an OIDC identity. Indirect (actAs) '
                     'chains: iam.serviceAccounts.actAs binds an SA to a resource you create, so '
                     'create-permissions on a compute service run your code as that SA — e.g. '
                     'deploy a Cloud Function/Cloud Run/GCE instance/Deployment Manager '
                     'config/Cloud Build job with a more-privileged attached SA and read its '
                     'metadata token. Additional IAM-mutation paths (setIamPolicy on a project/SA, '
                     'create/upload SA keys via iam.serviceAccountKeys.create, updating custom '
                     'roles) let a low-priv principal grant itself Owner. Rhino Security Labs '
                     'enumerated the full set.',
        'prerequisites': [   'authenticated GCP credentials (gcloud, SA key, or metadata token)',
                             'one of the impersonation/actAs/IAM-mutation permissions on a '
                             'higher-privileged SA or resource'],
        'enumeration': [   'gcloud auth list',
                           'gcloud projects get-iam-policy <project>',
                           'gcloud iam service-accounts list',
                           'gcloud iam service-accounts get-iam-policy <sa-email>',
                           'gcloud iam roles describe <role>',
                           "curl -H 'Metadata-Flavor: Google' "
                           "'http://metadata.google.internal/computeMetadata/v1/instance/service-accounts/default/token'"],
        'detection_indicators': [   'iam.serviceAccounts.getAccessToken',
                                    'iam.serviceAccounts.actAs',
                                    'iam.serviceAccounts.signJwt',
                                    'iam.serviceAccountKeys.create',
                                    'roles/iam.serviceAccountTokenCreator',
                                    'roles/owner',
                                    'metadata.google.internal',
                                    'SeImpersonatePrivilege'],
        'tools': ['gcp-iam-privilege-escalation', 'scoutsuite', 'prowler', 'gcloud', 'gcpwn'],
        'cve': [],
        'mitigation': [   'Grant roles/iam.serviceAccountTokenCreator and actAs sparingly and '
                          'per-SA',
                          'Disable SA key creation (org policy '
                          'iam.disableServiceAccountKeyCreation)',
                          'Avoid attaching high-privilege SAs to broadly-deployable resources',
                          'Audit setIamPolicy and impersonation in Cloud Audit Logs; use '
                          'least-privilege custom roles'],
        'poc_references': [   'https://rhinosecuritylabs.com/gcp/privilege-escalation-google-cloud-platform-part-1/',
                              'https://github.com/RhinoSecurityLabs/GCP-IAM-Privilege-Escalation',
                              'https://cloud.google.com/iam/docs/impersonating-service-accounts'],
        'research_references': [   'https://cloud.hacktricks.xyz/pentesting-cloud/gcp-security/gcp-privilege-escalation',
                                   'https://hackingthe.cloud/gcp/exploitation/']},
    {   'id': 'container-cgroup-release-agent-cve-2022-0492',
        'name': 'cgroups v1 release_agent container escape (CVE-2022-0492)',
        'platform': 'container',
        'category': 'container-escape',
        'severity': 'critical',
        'summary': 'A container that can mount the cgroup v1 filesystem (privileged, or with '
                   'CAP_SYS_ADMIN and no seccomp/AppArmor) can write to the release_agent file to '
                   'run an attacker binary in the host namespace as root.',
        'technique': 'The cgroup v1 release_agent is a host path executed by the kernel (in the '
                     'initial namespace, as root) when the last task leaves a cgroup that has '
                     'notify_on_release=1. An escapee mounts a fresh cgroup hierarchy, sets '
                     'release_agent to a script placed on a host-visible path (resolved via the '
                     "container's /proc/<pid>/root overlay path), enables notify_on_release, then "
                     'empties the cgroup so the kernel runs the script on the host. CVE-2022-0492 '
                     'made this reachable from an unprivileged user namespace because the kernel '
                     'did not check CAP_SYS_ADMIN in the correct namespace when writing '
                     'release_agent, so even non-privileged containers were affected on unpatched '
                     'kernels.',
        'prerequisites': [   'ability to mount a cgroup v1 filesystem (privileged container, or '
                             'CAP_SYS_ADMIN)',
                             'no seccomp/AppArmor profile blocking mount() (default Docker seccomp '
                             'blocks it; --privileged or --security-opt seccomp=unconfined '
                             're-enables it)',
                             'unpatched kernel for the unprivileged (user-namespace) variant'],
        'enumeration': [   'cat /proc/self/status | grep CapEff',
                           'capsh --print',
                           'cat /proc/1/cgroup',
                           'ls -la /sys/fs/cgroup',
                           'grep -i cgroup /proc/filesystems',
                           'cat /proc/self/mountinfo | grep cgroup'],
        'detection_indicators': [   'release_agent',
                                    'notify_on_release',
                                    'CapEff:\t0000003fffffffff',
                                    'cap_sys_admin',
                                    'rdma',
                                    'unprivileged_userns_clone'],
        'tools': ['amicontained', 'deepce', 'cdk', 'linpeas'],
        'cve': ['CVE-2022-0492'],
        'mitigation': [   'Patch the kernel (fix restores CAP_SYS_ADMIN check in the correct user '
                          'namespace)',
                          'Do not run privileged containers; drop CAP_SYS_ADMIN',
                          'Keep the default Docker/containerd seccomp profile (blocks mount)',
                          'Use AppArmor/SELinux and cgroup v2 (release_agent removed)',
                          'Set kernel.unprivileged_userns_clone=0 where feasible'],
        'poc_references': [   'https://unit42.paloaltonetworks.com/cve-2022-0492-cgroups/',
                              'https://sysdig.com/blog/detecting-mitigating-cve-2021-0492-sysdig/',
                              'https://blog.aquasec.com/cve-2022-0492-cgroups-container-escape'],
        'research_references': [   'https://nvd.nist.gov/vuln/detail/CVE-2022-0492',
                                   'https://book.hacktricks.xyz/linux-hardening/privilege-escalation/docker-security/docker-breakout-privilege-escalation/release_agent-exploit-relative-paths-to-pids']},
    {   'id': 'container-docker-socket',
        'name': 'Mounted Docker socket container escape',
        'platform': 'container',
        'category': 'container-escape',
        'severity': 'critical',
        'summary': 'Access to /var/run/docker.sock (or membership of the docker group) is '
                   'root-equivalent: it lets you start a container that mounts the host '
                   'filesystem.',
        'technique': 'The Docker API on the socket can launch a privileged container bind-mounting '
                     'the host root, giving full read/write on the host and thus root.',
        'prerequisites': ['readable/writable docker.sock or docker group membership'],
        'enumeration': ['id', 'ls -la /var/run/docker.sock', 'docker ps'],
        'detection_indicators': ['docker.sock', 'docker', '/var/run/docker.sock'],
        'tools': ['linpeas', 'deepce', 'cdk'],
        'cve': [],
        'mitigation': [   'Never expose docker.sock to untrusted workloads',
                          'Restrict docker group membership'],
        'poc_references': [   'https://book.hacktricks.xyz/linux-hardening/privilege-escalation/docker-security'],
        'research_references': ['https://docs.docker.com/engine/security/']},
    {   'id': 'container-runc-procselfexe-cve-2019-5736',
        'name': 'runc /proc/self/exe host binary overwrite (CVE-2019-5736)',
        'platform': 'container',
        'category': 'container-escape',
        'severity': 'critical',
        'summary': 'A malicious image or a compromised container that can control an entered '
                   'process can overwrite the host runc binary via /proc/self/exe, so the next '
                   "'docker exec'/container start runs attacker code on the host as root.",
        'technique': 'When runc executes as PID 1 in a container (or during docker exec), the '
                     'container process can open the host runc via /proc/self/exe (a magic symlink '
                     'to the running binary), then hold a writable file descriptor to it (e.g. by '
                     "replacing the container's own /bin/sh entrypoint with #!/proc/self/exe and "
                     're-opening the fd O_WRONLY once runc re-execs through it). Writing a new ELF '
                     'over that descriptor overwrites the runc binary on the host filesystem. The '
                     'next invocation of runc by the container engine executes the attacker '
                     'payload with host root privileges, breaking out of the container. Affects '
                     'Docker, containerd, CRI-O, Kubernetes and any runc-based runtime prior to '
                     'the patched 1.0-rc7.',
        'prerequisites': [   'run a malicious image, OR docker exec into an '
                             'already-attacker-controlled container',
                             'runc / container runtime older than the CVE-2019-5736 fix'],
        'enumeration': [   'runc --version',
                           'docker version',
                           'ls -la /proc/self/exe',
                           'cat /etc/os-release'],
        'detection_indicators': [   'runc version 1.0.0-rc6',
                                    '/proc/self/exe',
                                    'libcontainer',
                                    'ETXTBSY'],
        'tools': ['deepce'],
        'cve': ['CVE-2019-5736'],
        'mitigation': [   'Upgrade runc to >= 1.0.0-rc7 / patched distro packages (fix seals '
                          '/proc/self/exe with a memfd copy)',
                          'Do not run or exec into untrusted images',
                          'Run containers as non-root users and with user namespaces',
                          'Use read-only root filesystems and SELinux/AppArmor confinement'],
        'poc_references': [   'https://github.com/Frichetten/CVE-2019-5736-PoC',
                              'https://unit42.paloaltonetworks.com/breaking-docker-via-runc-explaining-cve-2019-5736/',
                              'https://seclists.org/oss-sec/2019/q1/119'],
        'research_references': [   'https://nvd.nist.gov/vuln/detail/CVE-2019-5736',
                                   'https://blog.dragonsector.pl/2019/02/cve-2019-5736-escape-from-docker-and.html']},
    {   'id': 'container-sensitive-host-mounts-corepattern',
        'name': 'Sensitive host mounts / exposed sockets / core_pattern escape',
        'platform': 'container',
        'category': 'container-escape',
        'severity': 'critical',
        'summary': 'Containers that expose host paths or sockets — a bind-mounted host filesystem, '
                   '/var/run/docker.sock or a runtime socket, host /proc, or a writable '
                   '/proc/sys/kernel/core_pattern — let the workload read/modify the host or '
                   'execute host-side code and escape to node root.',
        'technique': 'Several distinct-but-related misconfigurations grant host reach: (1) a bind '
                     'mount of the host root or of host directories like /, /etc, /root, or '
                     '/var/log lets you read/write host files (add SSH keys, edit crontabs); (2) a '
                     'mounted docker.sock or containerd/CRI socket exposes the runtime API, '
                     'letting you launch a new privileged container that mounts the host root (see '
                     'container-docker-socket); (3) with host /proc mounted (or in a --privileged '
                     'container that can see the real /proc), writing a pipe handler '
                     '(|/path/to/payload) into /proc/sys/kernel/core_pattern causes the host '
                     'kernel to execute that program as root the next time any process core-dumps '
                     '— deliberately crashing a process triggers host code execution; (4) exposed '
                     '/dev block devices allow reading/writing the host disk directly. Each path '
                     'collapses the container boundary to node root.',
        'prerequisites': [   'a host-sensitive mount, exposed runtime socket, or writable '
                             'core_pattern (typically --privileged, or explicit -v/hostPath '
                             'mounts)'],
        'enumeration': [   'cat /proc/self/mountinfo',
                           'mount',
                           'findmnt',
                           'ls -la /var/run/docker.sock /run/containerd/containerd.sock',
                           'cat /proc/sys/kernel/core_pattern',
                           'ls -la /host /rootfs 2>/dev/null',
                           "ls -la /dev | grep -E 'sd|nvme|xvd'"],
        'detection_indicators': [   '/proc/sys/kernel/core_pattern',
                                    'docker.sock',
                                    'containerd.sock',
                                    'hostPath',
                                    '/host/proc',
                                    'rw,relatime - ext4'],
        'tools': ['amicontained', 'deepce', 'cdk', 'linpeas', 'kubeletctl'],
        'cve': [],
        'mitigation': [   'Never bind-mount the host filesystem, /proc, or runtime sockets into '
                          'untrusted containers',
                          'Mask /proc/sys and set core_pattern only on the host; keep default '
                          'masked paths',
                          'Drop privileges and capabilities; avoid --privileged',
                          'Use read-only mounts and Pod Security admission / OPA policies to '
                          'forbid hostPath and privileged'],
        'poc_references': [   'https://blog.trailofbits.com/2019/07/19/understanding-docker-container-escapes/',
                              'https://book.hacktricks.xyz/linux-hardening/privilege-escalation/docker-security/sensitive-mounts'],
        'research_references': [   'https://book.hacktricks.xyz/linux-hardening/privilege-escalation/docker-security',
                                   'https://docs.docker.com/engine/security/']},
    {   'id': 'kubernetes-sa-token-rbac-privileged-pod',
        'name': 'Kubernetes SA token / RBAC abuse & privileged pod node escape',
        'platform': 'container',
        'category': 'kubernetes',
        'severity': 'critical',
        'summary': "A pod's mounted service-account token plus over-permissive RBAC (create "
                   'pods/exec, get secrets, escalate/bind) lets an attacker schedule a '
                   "hostPID/hostPath/privileged pod that reaches the node's filesystem and "
                   'kubelet, taking over the worker and often the cluster.',
        'technique': 'Every pod (unless opted out) mounts a service-account JWT at '
                     '/var/run/secrets/kubernetes.io/serviceaccount/token, usable against the API '
                     'server. If the bound role grants powerful verbs — create/patch pods, '
                     'pods/exec, pods/attach, get/list secrets, create rolebindings '
                     '(bind/escalate), or access to nodes/proxy — the attacker abuses them: (a) '
                     'create a pod with hostPID, hostNetwork, privileged:true or a hostPath volume '
                     "mounting the node's / to read node secrets, kubelet certs and other pods' SA "
                     'tokens; (b) exec into existing privileged pods; (c) read cluster secrets to '
                     "pivot; (d) use 'escalate'/'bind' to grant themselves cluster-admin. Reaching "
                     'a control-plane node or the kubelet (often on tokenless port 10250) yields '
                     'cluster-wide compromise. Cloud clusters additionally let a node-level '
                     'foothold hit the instance metadata service for the node IAM role.',
        'prerequisites': [   'a reachable/stolen service-account token, or code execution in a pod',
                             'over-permissive RBAC (create pods, exec, get secrets, escalate/bind, '
                             'nodes/proxy), or a namespace allowing privileged/hostPath pods'],
        'enumeration': [   'cat /var/run/secrets/kubernetes.io/serviceaccount/token',
                           'kubectl auth can-i --list',
                           'kubectl auth can-i create pods',
                           'kubectl get secrets -A',
                           "kubectl get pods -o yaml | grep -i 'privileged\\|hostPath\\|hostPID'",
                           'curl -sk https://<node-ip>:10250/pods',
                           'kubectl get clusterrolebindings -o wide'],
        'detection_indicators': [   'serviceaccount/token',
                                    'kubernetes.io/serviceaccount',
                                    'system:serviceaccount:',
                                    'privileged: true',
                                    'hostPID',
                                    'hostPath',
                                    'can-i'],
        'tools': ['kube-hunter', 'kubeletctl', 'peirates', 'kubesploit', 'kube-bench', 'rbac-tool'],
        'cve': [],
        'mitigation': [   'Enable Pod Security admission (restricted) to forbid '
                          'privileged/hostPath/hostPID',
                          "Follow least-privilege RBAC; avoid wildcard verbs, 'escalate', 'bind', "
                          'pods/exec broadly',
                          'Set automountServiceAccountToken: false where tokens are unneeded; use '
                          'bound, short-lived tokens',
                          'Restrict kubelet (authn/authz on 10250), and block pod access to the '
                          'instance metadata service',
                          'Use network policy and separate node pools for sensitive workloads'],
        'poc_references': [   'https://github.com/inguardians/peirates',
                              'https://github.com/aquasecurity/kube-hunter',
                              'https://book.hacktricks.xyz/pentesting-cloud/kubernetes-security'],
        'research_references': [   'https://kubernetes.io/docs/concepts/security/rbac-good-practices/',
                                   'https://kubernetes.io/docs/concepts/security/pod-security-standards/']},
    {   'id': 'linux-docker-group-socket',
        'name': 'docker group / Docker socket membership',
        'platform': 'linux',
        'category': 'container-escape',
        'severity': 'critical',
        'summary': 'Membership in the docker group (or write access to /var/run/docker.sock) is '
                   'root-equivalent: the user can start a container that bind-mounts the host '
                   'filesystem and read/write it as root, or run a privileged container to escape '
                   'to the host.',
        'technique': 'The Docker daemon runs as root and exposes a control socket to the docker '
                     'group. A group member can launch a container mounting the host root '
                     "filesystem (e.g. '-v /:/host') and, from inside as root, read/modify any "
                     'host file — dropping a SUID binary, editing /etc/passwd or sudoers, or '
                     "reading /etc/shadow. Alternatively '--privileged' / '--pid=host' containers "
                     'permit direct host escape. Access to the socket via HTTP (or a mounted '
                     'docker.sock inside another container) grants the same power. GTFOBins '
                     'documents the container-launch primitive.',
        'prerequisites': [   'Membership in the docker group, or read/write access to the Docker '
                             'API socket',
                             'Ability to pull or reference a container image (or use an existing '
                             'one)'],
        'enumeration': [   "id; groups   # look for 'docker'",
                           'ls -la /var/run/docker.sock 2>/dev/null',
                           'docker ps 2>/dev/null; docker images 2>/dev/null',
                           'getent group docker'],
        'detection_indicators': [   "Current user in the 'docker' group (id/groups output)",
                                    '/var/run/docker.sock writable by group/other',
                                    'docker CLI usable without sudo',
                                    'A container with /var/run/docker.sock bind-mounted inside it'],
        'tools': ['docker', 'gtfobins', 'deepce', 'cdk', 'linpeas'],
        'cve': [],
        'mitigation': [   'Treat docker group membership as equivalent to root; grant sparingly',
                          'Use rootless Docker or Podman where possible',
                          'Protect the daemon socket; never bind-mount docker.sock into untrusted '
                          'containers'],
        'poc_references': [   'https://gtfobins.github.io/gtfobins/docker/#shell',
                              'https://book.hacktricks.wiki/en/linux-hardening/privilege-escalation/docker-security/index.html'],
        'research_references': [   'https://docs.docker.com/engine/security/#docker-daemon-attack-surface',
                                   'https://book.hacktricks.wiki/en/linux-hardening/privilege-escalation/interesting-groups-linux-pe/index.html']},
    {   'id': 'linux-file-capabilities-abuse',
        'name': 'Linux file capabilities abuse (cap_setuid, cap_dac_read_search, cap_sys_admin, '
                '...)',
        'platform': 'linux',
        'category': 'capabilities',
        'severity': 'critical',
        'summary': "File capabilities grant a binary a subset of root's powers without the SUID "
                   'bit. Powerful capabilities on interpreters or tools (especially cap_setuid, '
                   'cap_dac_read_search/override, cap_sys_admin, cap_sys_module, cap_sys_ptrace, '
                   'cap_chown) allow full privilege escalation.',
        'technique': 'Capabilities split root into discrete privileges (see capabilities(7)) that '
                     "can be attached to a file's effective/permitted sets. cap_setuid on an "
                     'interpreter (python, perl, ruby) lets a program call setuid(0) and become '
                     'root. cap_dac_read_search bypasses file read permission checks (read '
                     '/etc/shadow, any file); cap_dac_override bypasses read/write/execute checks '
                     'entirely. cap_chown lets an attacker re-own sensitive files. cap_sys_ptrace '
                     'permits injecting into a root process; cap_sys_module permits loading a '
                     'kernel module; cap_sys_admin is near-root. GTFOBins documents the exact '
                     'invocation for capability-enabled binaries.',
        'prerequisites': [   'A binary with a dangerous capability in its effective/permitted set',
                             'For cap_setuid: an interpreter or tool that can call the setuid '
                             'syscall'],
        'enumeration': [   'getcap -r / 2>/dev/null',
                           '/usr/sbin/getcap -r / 2>/dev/null',
                           'capsh --print   # capabilities of the current shell',
                           'for f in $(getcap -r / 2>/dev/null | cut -d\' \' -f1); do ls -la "$f"; '
                           'done'],
        'detection_indicators': [   "'cap_setuid' in getcap output on python/perl/ruby/php/node or "
                                    'other executables',
                                    "'cap_dac_read_search' or 'cap_dac_override' on any binary",
                                    "'cap_sys_admin', 'cap_sys_module', 'cap_sys_ptrace', "
                                    "'cap_chown', 'cap_setgid' on non-standard binaries",
                                    "Capability set ending in '+ep' or '+ei' on user-accessible "
                                    'tools',
                                    'cap_setuid'],
        'tools': ['getcap', 'capsh', 'gtfobins', 'linpeas', 'linux-smart-enumeration'],
        'cve': [],
        'mitigation': [   'Remove unnecessary capabilities (setcap -r <file>)',
                          'Never grant cap_setuid/cap_dac_*/cap_sys_admin to interpreters or '
                          'user-runnable tools',
                          'Baseline getcap output and alert on additions',
                          'Mount user filesystems nosuid (also strips file capabilities)'],
        'poc_references': [   'https://gtfobins.github.io/#+capabilities',
                              'https://gtfobins.github.io/gtfobins/python/#capabilities'],
        'research_references': [   'https://man7.org/linux/man-pages/man7/capabilities.7.html',
                                   'https://book.hacktricks.wiki/en/linux-hardening/privilege-escalation/linux-capabilities.html']},
    {   'id': 'linux-lxd-lxc-group',
        'name': 'lxd / lxc group membership',
        'platform': 'linux',
        'category': 'container-escape',
        'severity': 'critical',
        'summary': 'Membership in the lxd (or lxc) group lets a user create a privileged container '
                   'that mounts the host filesystem, giving root-level read/write to the host '
                   'without any sudo rights or password.',
        'technique': 'The LXD daemon runs as root and trusts the lxd group. A member imports a '
                     'small image (commonly Alpine), launches a container with '
                     "security.privileged=true, and adds a disk device mapping the host root ('/') "
                     'into the container. Inside the container the user is root over the mounted '
                     'host filesystem and can plant a SUID binary, edit /etc/passwd, or read '
                     'secrets to escalate on the host. The same applies to legacy lxc tooling.',
        'prerequisites': [   'Membership in the lxd or lxc group',
                             "LXD initialized (or the ability to run 'lxd init'), and an "
                             'importable image'],
        'enumeration': [   "id; groups   # look for 'lxd' or 'lxc'",
                           'lxc list 2>/dev/null; lxc image list 2>/dev/null',
                           'getent group lxd lxc',
                           'ls -la /var/lib/lxd/unix.socket /var/snap/lxd/common/lxd/unix.socket '
                           '2>/dev/null'],
        'detection_indicators': [   "Current user in the 'lxd' or 'lxc' group",
                                    'lxc/lxd CLI usable without sudo',
                                    'Writable LXD unix socket'],
        'tools': ['lxc', 'lxd', 'linpeas', 'lxd_root (initstring)', 'cdk'],
        'cve': [],
        'mitigation': [   'Treat lxd/lxc group membership as root-equivalent; grant only to '
                          'trusted admins',
                          'Disable privileged containers where feasible',
                          'Restrict access to the LXD unix socket'],
        'poc_references': [   'https://reboare.github.io/lxd/lxd-escape.html',
                              'https://github.com/initstring/lxd_root'],
        'research_references': [   'https://hacktricks.wiki/en/linux-hardening/privilege-escalation/interesting-groups-linux-pe/lxd-privilege-escalation.html',
                                   'https://shenaniganslabs.io/2019/05/21/LXD-LPE.html']},
    {   'id': 'linux-nftables-cve-2024-1086',
        'name': 'nf_tables double-free (nft_verdict_init NF_DROP)',
        'platform': 'linux',
        'category': 'kernel-exploit',
        'severity': 'critical',
        'summary': 'A use-after-free/double-free in nft_verdict_init() where a positive value is '
                   'accepted as a drop error causes nf_hook_slow() to double-free, yielding a '
                   'universal local root across kernels ~5.14-6.6; in CISA KEV and used by '
                   'ransomware.',
        'technique': 'nft_verdict_init() permits positive values in the hook verdict where NF_DROP '
                     'is expected. When NF_DROP is issued with a drop error that resembles '
                     "NF_ACCEPT, nf_hook_slow() frees the skb twice. Notselwyn's 'Flipping Pages' "
                     'research turned this into a reliable, kernel-version-independent exploit '
                     'using page-table manipulation and cross-cache techniques that work against '
                     'hardened kernels (including KernelCTF mitigation kernels) without '
                     'recompilation, and can run filelessly. Requires unprivileged user namespaces '
                     'to reach nf_tables.',
        'prerequisites': [   'Unprivileged user namespaces enabled',
                             'Vulnerable kernel roughly 5.14 through 6.6.14 (before backported '
                             'fixes)'],
        'enumeration': [   'uname -r',
                           'sysctl kernel.unprivileged_userns_clone',
                           'lsmod | grep nf_tables',
                           'cat /proc/sys/user/max_user_namespaces'],
        'detection_indicators': [   'Kernel ~5.14-6.6 without the Jan/Feb 2024 fix',
                                    'unprivileged userns enabled',
                                    'linux-exploit-suggester flags CVE-2024-1086',
                                    'Listed in CISA Known Exploited Vulnerabilities catalog'],
        'tools': ['linux-exploit-suggester', 'linpeas', 'uname'],
        'cve': ['CVE-2024-1086'],
        'mitigation': [   'Update to patched stable kernel',
                          'Set kernel.unprivileged_userns_clone=0 / restrict user namespaces',
                          'Blocklist the nf_tables module if unused'],
        'poc_references': [   'https://github.com/Notselwyn/CVE-2024-1086',
                              'https://www.openwall.com/lists/oss-security/2024/04/10/22'],
        'research_references': [   'https://pwning.tech/nftables/',
                                   'https://nvd.nist.gov/vuln/detail/CVE-2024-1086']},
    {   'id': 'linux-pwnkit-pkexec-cve-2021-4034',
        'name': 'PwnKit (pkexec argv memory corruption)',
        'platform': 'linux',
        'category': 'suid-sgid',
        'severity': 'critical',
        'summary': "A memory-corruption flaw in polkit's SUID-root pkexec present since its 2009 "
                   'introduction allows any unprivileged local user to gain full root, and is '
                   'exploitable out-of-the-box on default installs of most Linux distributions.',
        'technique': 'pkexec mishandles calling with an empty argument vector (argc == 0). Its '
                     'argument-processing loop reads out of bounds and reintroduces an '
                     'attacker-controlled environment variable into the process environment after '
                     'the normal environment sanitization has run. By pointing that variable (e.g. '
                     'via a crafted GCONV_PATH) at an attacker-controlled shared object, arbitrary '
                     'code executes with root privileges. No exotic timing or race is required, '
                     'making it extremely reliable and near-universal.',
        'prerequisites': [   'Local unprivileged shell',
                             'SUID pkexec binary present (polkit installed, default on most '
                             'desktops/servers)'],
        'enumeration': [   'ls -la $(which pkexec)',
                           'pkexec --version',
                           'dpkg -l policykit-1 2>/dev/null || rpm -q polkit 2>/dev/null'],
        'detection_indicators': [   'SUID root /usr/bin/pkexec present and unpatched polkit '
                                    'version',
                                    'linux-exploit-suggester / linpeas flags CVE-2021-4034',
                                    'polkit version predating 0.120 vendor fix'],
        'tools': ['linpeas', 'linux-exploit-suggester', 'gtfobins', 'searchsploit'],
        'cve': ['CVE-2021-4034'],
        'mitigation': [   'Update polkit to vendor-patched version (fixes shipped Jan 25, 2022)',
                          'As a stopgap, remove the SUID bit: chmod 0755 /usr/bin/pkexec'],
        'poc_references': [   'https://github.com/ly4k/PwnKit',
                              'https://github.com/berdav/CVE-2021-4034'],
        'research_references': [   'https://www.qualys.com/2022/01/25/cve-2021-4034/pwnkit.txt',
                                   'https://nvd.nist.gov/vuln/detail/CVE-2021-4034']},
    {   'id': 'linux-readable-writable-etc-shadow',
        'name': 'Readable or writable /etc/shadow (hash crack or replacement)',
        'platform': 'linux',
        'category': 'credential-harvesting',
        'severity': 'critical',
        'summary': '/etc/shadow holds password hashes and must be root-only. If it is readable, '
                   "root's hash can be extracted and cracked offline; if writable, root's hash can "
                   'be replaced with a known value for immediate access. Stale backups (shadow-, '
                   'shadow.bak) leak the same data.',
        'technique': 'When /etc/shadow (or a backup like /etc/shadow-, /var/backups/shadow.bak) is '
                     'readable by the attacker — directly, via a permissive mode, or via '
                     'cap_dac_read_search on a tool — the root hash is dumped and cracked with '
                     'john/hashcat offline. If /etc/shadow is writable, the attacker replaces '
                     "root's field with a hash they generated (e.g. via mkpasswd/openssl) and then "
                     'su/logs in with the corresponding password. Combining a readable /etc/passwd '
                     'with a readable /etc/shadow enables unshadow+crack.',
        'prerequisites': [   'Read access (crack path) or write access (replace path) to '
                             '/etc/shadow or an equivalent backup',
                             'Offline cracking capability for the read path'],
        'enumeration': [   'ls -la /etc/shadow /etc/shadow- /etc/gshadow 2>/dev/null',
                           'ls -la /var/backups/*shadow* 2>/dev/null',
                           "[ -r /etc/shadow ] && echo 'READABLE /etc/shadow'; [ -w /etc/shadow ] "
                           "&& echo 'WRITABLE /etc/shadow'",
                           "find / -name 'shadow*' -readable -type f 2>/dev/null"],
        'detection_indicators': [   '/etc/shadow readable or writable by group/other (mode other '
                                    'than 640/600 root:shadow/root:root)',
                                    'World-readable shadow backups under /var/backups or elsewhere',
                                    'A tool with cap_dac_read_search that can bypass shadow '
                                    'permissions'],
        'tools': ['john', 'hashcat', 'unshadow', 'linpeas', 'linux-smart-enumeration'],
        'cve': [],
        'mitigation': [   '/etc/shadow must be mode 640 root:shadow (or 600 root:root); backups '
                          'equally restricted',
                          'Use strong hashing (yescrypt/sha512) and monitor read access',
                          'Audit capabilities that can bypass DAC read checks'],
        'poc_references': [   'https://book.hacktricks.wiki/en/linux-hardening/privilege-escalation/index.html#readable-etcshadow',
                              'https://www.hackingarticles.in/linux-privilege-escalation-using-weak-nfs-permissions/'],
        'research_references': [   'https://man7.org/linux/man-pages/man5/shadow.5.html',
                                   'https://book.hacktricks.wiki/en/linux-hardening/privilege-escalation/index.html#etcshadow']},
    {   'id': 'linux-sudo-baron-samedit-cve-2021-3156',
        'name': 'Sudo Baron Samedit (heap overflow)',
        'platform': 'linux',
        'category': 'sudo',
        'severity': 'critical',
        'summary': "A heap-based buffer overflow in sudo's command-line argument unescaping lets "
                   'any local user (even without sudo rights) escalate to root on a wide range of '
                   'default configurations.',
        'technique': 'When sudo runs in shell mode (sudoedit -s or sudo -s) with a command-line '
                     'argument ending in a single backslash, the code that removes escape '
                     'characters reads and writes past the end of a heap buffer because the '
                     'escaped-character copy loop miscounts the trailing backslash. Attackers '
                     'control the overflow contents and use it to corrupt adjacent heap structures '
                     '(such as service_user or a sudoers-related object), ultimately redirecting '
                     'execution to gain root. The bug does not require the user to be listed in '
                     'sudoers.',
        'prerequisites': [   'Local unprivileged shell',
                             'Vulnerable sudo: 1.8.2 through 1.8.31p2, or 1.9.0 through 1.9.5p1'],
        'enumeration': [   'sudo --version',
                           "sudoedit -s '\\' (vulnerable prints a sudoedit usage/segfault-style "
                           "error; patched prints 'usage:')"],
        'detection_indicators': [   'sudo version in 1.8.2-1.8.31p2 or 1.9.0-1.9.5p1',
                                    "The `sudoedit -s '\\'` probe yields a sudoedit error rather "
                                    'than a clean usage message',
                                    'linux-exploit-suggester flags CVE-2021-3156',
                                    'NOPASSWD'],
        'tools': ['linpeas', 'linux-exploit-suggester', 'searchsploit', 'sudo'],
        'cve': ['CVE-2021-3156'],
        'mitigation': [   'Upgrade sudo to 1.9.5p2 or a distro-backported fix',
                          'Apply vendor advisories from Jan 26, 2021'],
        'poc_references': [   'https://github.com/blasty/CVE-2021-3156',
                              'https://github.com/worawit/CVE-2021-3156'],
        'research_references': [   'https://www.qualys.com/2021/01/26/cve-2021-3156/baron-samedit-heap-based-overflow-sudo.txt',
                                   'https://nvd.nist.gov/vuln/detail/CVE-2021-3156']},
    {   'id': 'linux-sudo-chroot-cve-2025-32463',
        'name': 'sudo --chroot local root (CVE-2025-32463)',
        'platform': 'linux',
        'category': 'sudo',
        'severity': 'critical',
        'summary': 'In sudo 1.9.14–1.9.17, the -R/--chroot option evaluated paths under the '
                   'user-supplied root while still processing sudoers, so a local user can plant '
                   'an /etc/nsswitch.conf there that loads an attacker-controlled shared library, '
                   'executing code as root — even without any sudoers privileges.',
        'technique': 'A change in sudo 1.9.14 made sudo call chroot() into the user-specified root '
                     'directory during sudoers evaluation. Because NSS (name service switch) is '
                     'consulted during this phase, sudo reads /etc/nsswitch.conf from inside the '
                     'attacker-controlled chroot; by pointing an NSS database at an '
                     'attacker-provided module, sudo dlopen()s a malicious shared library while '
                     'still running as root, giving arbitrary root code execution. Crucially the '
                     'flaw does not require the invoking user to have any allowed sudo commands — '
                     'merely the ability to run sudo -R. Rich Mirch (Stratascale CRU) disclosed '
                     'it; it is fixed in 1.9.17p1, where the 1.9.14 change is reverted and the '
                     'chroot feature is deprecated.',
        'prerequisites': [   'a local shell on a host with a vulnerable sudo (1.9.14 through '
                             '1.9.17, pre-1.9.17p1)',
                             'a system that consults /etc/nsswitch.conf (standard glibc Linux)'],
        'enumeration': [   'sudo --version',
                           'sudo -V | head -1',
                           'which sudo && sudo -R / true 2>&1 | head',
                           'dpkg -l sudo 2>/dev/null || rpm -q sudo'],
        'detection_indicators': [   'Sudo version 1.9.1',
                                    '--chroot',
                                    '-R',
                                    'nsswitch.conf',
                                    '1.9.17',
                                    'chwoot',
                                    'NOPASSWD'],
        'tools': ['linpeas', 'sudo-killer'],
        'cve': ['CVE-2025-32463'],
        'mitigation': [   "Upgrade to sudo 1.9.17p1 or your distro's patched package",
                          'Do not enable the (now-deprecated) chroot/runchroot sudoers feature',
                          'Monitor for sudo -R usage and unexpected root dlopen of user-writable '
                          'libraries'],
        'poc_references': [   'https://www.stratascale.com/resource/cve-2025-32463-sudo-chroot-elevation-of-privilege/',
                              'https://www.sudo.ws/security/advisories/chroot_bug/',
                              'https://github.com/morgenm/sudo-chroot-CVE-2025-32463'],
        'research_references': [   'https://nvd.nist.gov/vuln/detail/CVE-2025-32463',
                                   'https://seclists.org/oss-sec/2025/q2/288']},
    {   'id': 'linux-sudo-nopasswd-gtfobins',
        'name': 'sudo NOPASSWD / permitted-command escape via GTFOBins',
        'platform': 'linux',
        'category': 'sudo',
        'severity': 'critical',
        'summary': 'sudoers rules that grant a user the ability to run specific commands (often '
                   'with NOPASSWD) as root can be escaped when the permitted binary offers a shell '
                   'escape or command-execution feature, turning a narrow grant into full root.',
        'technique': 'sudo -l reveals which commands the current user may run and as whom. If a '
                     "permitted binary is a GTFOBins 'sudo' candidate (editors, pagers, "
                     'interpreters, archivers, service managers, etc.), its built-in shell escape '
                     'or command hook runs as the target user (root) because sudo already elevated '
                     "the process. Overly broad rules ('(ALL) ALL', '(ALL) NOPASSWD: ALL') are "
                     'trivially abused; even a single seemingly harmless tool (e.g. less, vi, awk, '
                     'tar, systemctl, git, tcpdump) usually provides an escape. Rules that allow '
                     'running a user-owned or writable script/binary as root are also directly '
                     'exploitable.',
        'prerequisites': [   'User appears in sudoers with one or more runnable commands',
                             'The permitted command exposes a shell escape / command execution, or '
                             'points at a writable target'],
        'enumeration': [   'sudo -l',
                           'sudo -ln',
                           'cat /etc/sudoers 2>/dev/null; ls -la /etc/sudoers.d/ 2>/dev/null; cat '
                           '/etc/sudoers.d/* 2>/dev/null',
                           'getent group sudo wheel admin'],
        'detection_indicators': [   "'(ALL : ALL) ALL' or 'NOPASSWD: ALL' in sudo -l output",
                                    'NOPASSWD entries pointing at GTFOBins binaries (vi, vim, '
                                    'less, more, awk, python, perl, tar, zip, find, nmap, '
                                    'systemctl, git, ftp, man, tcpdump)',
                                    'sudo rules referencing a script/binary in a user-writable '
                                    "path or the user's home directory",
                                    'Wildcards (*) in permitted command paths',
                                    'NOPASSWD'],
        'tools': ['gtfobins', 'linpeas', 'sudo -l', 'linenum', 'linux-smart-enumeration'],
        'cve': [],
        'mitigation': [   'Grant the minimum set of commands; avoid ALL and NOPASSWD: ALL',
                          'Never permit interpreters, editors, pagers, or archivers via sudo',
                          'Use full absolute paths and avoid wildcards in sudoers command specs',
                          'Ensure sudo-permitted binaries/scripts are root-owned and not writable '
                          'by the grantee'],
        'poc_references': [   'https://gtfobins.github.io/#+sudo',
                              'https://gtfobins.github.io/gtfobins/less/#sudo'],
        'research_references': [   'https://book.hacktricks.wiki/en/linux-hardening/privilege-escalation/index.html#sudo-and-suid',
                                   'https://gtfobins.github.io/']},
    {   'id': 'linux-suid-sgid-gtfobins-abuse',
        'name': 'SUID/SGID binary abuse via GTFOBins',
        'platform': 'linux',
        'category': 'suid-sgid',
        'severity': 'critical',
        'summary': "Binaries with the SUID/SGID bit set run with the file owner's (often root's) "
                   'privileges regardless of the caller. Many standard utilities can be coerced '
                   'into spawning a shell, reading/writing arbitrary files, or executing commands '
                   'while privileged, yielding root.',
        'technique': 'When a file has the set-user-ID bit and is owned by root, the kernel sets '
                     'the effective UID to 0 on execution. Any feature of that binary that lets a '
                     'user run an external command, spawn a shell, or read/write a file therefore '
                     "does so as root. GTFOBins catalogs the exact feature (e.g. an interpreter's "
                     "-e/-c flag, a pager's shell escape, an editor's :! escape, a compression "
                     "tool's command hooks, or 'find -exec') for each Unix binary. Custom SUID "
                     'wrappers that call other programs by relative name or via system() are '
                     'additionally vulnerable to PATH hijacking. Non-shell primitives (e.g. '
                     'reading /etc/shadow, writing /etc/passwd) are equally exploitable.',
        'prerequisites': [   'Low-privileged shell on the host',
                             'A SUID/SGID binary owned by root (or a more privileged user) that '
                             'exposes a shell escape, command execution, or arbitrary file '
                             'read/write feature'],
        'enumeration': [   'find / -perm -4000 -type f 2>/dev/null',
                           'find / -perm -2000 -type f 2>/dev/null',
                           'find / -perm -6000 -type f 2>/dev/null',
                           'find / -perm -u=s -o -perm -g=s -type f 2>/dev/null -exec ls -la {} '
                           '\\;',
                           'for f in $(find / -perm -4000 -type f 2>/dev/null); do dpkg -S "$f" '
                           '2>/dev/null || rpm -qf "$f" 2>/dev/null; done   # flag files not owned '
                           'by any package'],
        'detection_indicators': [   'SUID/SGID bit on interpreters or shells (python, python3, '
                                    'perl, ruby, php, bash, dash, lua, node)',
                                    'SUID on GTFOBins-listed tools (nmap, find, vim, view, less, '
                                    'more, awk, gawk, tar, cp, env, nano, ed, tee, dd, base64, '
                                    'xxd, socat, tcpdump, wget, curl, systemctl)',
                                    'SUID root binaries in non-standard paths (/home, /opt, /tmp, '
                                    '/usr/local) not tracked by the package manager',
                                    "'rws' or '-rwsr-xr-x' permission strings in find/ls output on "
                                    'unexpected files'],
        'tools': [   'gtfobins',
                     'linpeas',
                     'linenum',
                     'linux-smart-enumeration',
                     'unix-privesc-check',
                     'pspy'],
        'cve': [],
        'mitigation': [   'Remove the SUID/SGID bit from binaries that do not require it (chmod '
                          'u-s / g-s)',
                          'Audit custom SUID wrappers; avoid system()/relative command invocation; '
                          'drop privileges early',
                          'Mount user-writable filesystems with nosuid',
                          'Baseline SUID inventory and alert on new/changed SUID files'],
        'poc_references': [   'https://gtfobins.github.io/#+suid',
                              'https://gtfobins.github.io/gtfobins/find/#suid'],
        'research_references': [   'https://book.hacktricks.wiki/en/linux-hardening/privilege-escalation/index.html',
                                   'https://gtfobins.github.io/',
                                   'https://github.com/swisskyrepo/PayloadsAllTheThings/blob/master/Methodology%20and%20Resources/Linux%20-%20Privilege%20Escalation.md']},
    {   'id': 'linux-writable-etc-passwd',
        'name': 'Writable /etc/passwd (add UID 0 account / clear password field)',
        'platform': 'linux',
        'category': 'writable-file',
        'severity': 'critical',
        'summary': 'If /etc/passwd is writable by a non-root user, they can append a new UID 0 '
                   'account with a known password or place a password hash directly in the passwd '
                   'file, then log in / su to root.',
        'technique': '/etc/passwd is world-readable but must be root-only writable. When it is '
                     'writable, an attacker adds a line defining a second superuser (UID 0, GID 0) '
                     'with a password hash they control in the second field (the legacy in-passwd '
                     "hash, still honored when present), then 'su' to that account. A related "
                     "variant: if the existing root entry's second field is 'x' (hash in "
                     "/etc/shadow) and passwd is writable, replacing the 'x' with a known hash — "
                     'or a blank field — can permit password-less/known-password root login on '
                     'systems that honor the passwd hash.',
        'prerequisites': [   'Write permission on /etc/passwd',
                             'A shell and the ability to run su / log in locally'],
        'enumeration': [   'ls -la /etc/passwd',
                           "[ -w /etc/passwd ] && echo 'WRITABLE /etc/passwd'",
                           'awk -F: \'($3==0){print $1" has UID 0"}\' /etc/passwd   # spot '
                           'existing UID 0 accounts'],
        'detection_indicators': [   '/etc/passwd permissions grant group/other write (e.g. '
                                    '-rw-rw-r-- or -rw-rw-rw-)',
                                    'More than one entry with UID 0',
                                    "A non-'x', non-'*' value in the password field of an "
                                    '/etc/passwd entry (an inline hash)',
                                    '/etc/passwd'],
        'tools': ['ls', 'openssl (passwd)', 'linpeas', 'linux-smart-enumeration'],
        'cve': [],
        'mitigation': [   '/etc/passwd must be mode 644, owned root:root',
                          'Alert on any UID 0 account other than root and on inline password '
                          'hashes',
                          'File-integrity monitoring on /etc/passwd'],
        'poc_references': [   'https://book.hacktricks.wiki/en/linux-hardening/privilege-escalation/index.html#writable-etcpasswd',
                              'https://www.hackingarticles.in/editing-etc-passwd-file-for-privilege-escalation/'],
        'research_references': [   'https://man7.org/linux/man-pages/man5/passwd.5.html',
                                   'https://book.hacktricks.wiki/en/linux-hardening/privilege-escalation/index.html#etcpasswd']},
    {   'id': 'linux-writable-sudoers',
        'name': 'Writable /etc/sudoers or /etc/sudoers.d drop-in',
        'platform': 'linux',
        'category': 'writable-file',
        'severity': 'critical',
        'summary': 'If /etc/sudoers or a file/directory under /etc/sudoers.d is writable by a '
                   'low-privileged user, they can grant themselves passwordless root via sudo.',
        'technique': 'sudo reads /etc/sudoers and every file in /etc/sudoers.d. When any of these '
                     'files, or the sudoers.d directory itself, is writable by the attacker, they '
                     "append a rule granting their user '(ALL) NOPASSWD: ALL' (or add themselves "
                     'to an admin alias) and then invoke sudo to obtain a root shell. A writable '
                     'sudoers.d directory lets them drop a new rule file. Improperly permissioned '
                     "include files ('#includedir') are equally exploitable.",
        'prerequisites': [   'Write access to /etc/sudoers, a file under /etc/sudoers.d, or the '
                             'sudoers.d directory',
                             'sudo installed and honoring the target file'],
        'enumeration': [   'ls -la /etc/sudoers /etc/sudoers.d/',
                           "[ -w /etc/sudoers ] && echo 'WRITABLE sudoers'; find /etc/sudoers.d "
                           '-writable 2>/dev/null',
                           'sudo -l 2>/dev/null'],
        'detection_indicators': [   '/etc/sudoers or /etc/sudoers.d/* writable by group/other (not '
                                    'mode 440 / 640 root-owned)',
                                    'Writable /etc/sudoers.d directory',
                                    'Recently modified sudoers files with unexpected NOPASSWD '
                                    'rules',
                                    'NOPASSWD'],
        'tools': ['ls', 'sudo -l', 'linpeas', 'linenum'],
        'cve': [],
        'mitigation': [   '/etc/sudoers and sudoers.d files must be mode 440 (or 640), root-owned; '
                          'directory 750 root:root',
                          'Edit only via visudo (validates syntax and permissions)',
                          'File-integrity monitoring and alerting on sudoers changes'],
        'poc_references': [   'https://book.hacktricks.wiki/en/linux-hardening/privilege-escalation/index.html#etcsudoers-etcsudoersd',
                              'https://gtfobins.github.io/#+sudo'],
        'research_references': [   'https://www.sudo.ws/docs/man/sudoers.man/',
                                   'https://book.hacktricks.wiki/en/linux-hardening/privilege-escalation/index.html#sudo']},
    {   'id': 'linux-capabilities-setuid',
        'name': 'Linux capabilities (cap_setuid / cap_dac_read_search)',
        'platform': 'linux',
        'category': 'capabilities',
        'severity': 'high',
        'summary': 'A binary with a powerful file capability (e.g. cap_setuid+ep) can change its '
                   'UID to 0 or read protected files without being SUID-root.',
        'technique': '`getcap -r /` finds capability-endowed binaries; interpreters with '
                     'cap_setuid can setuid(0) then exec a shell; cap_dac_read_search bypasses '
                     'read permission checks.',
        'prerequisites': ['a binary with an abusable file capability'],
        'enumeration': ['getcap -r / 2>/dev/null', '/usr/sbin/getpcaps $$'],
        'detection_indicators': [   'cap_setuid',
                                    'cap_dac_read_search',
                                    'cap_dac_override',
                                    'cap_sys_admin',
                                    '=ep'],
        'tools': ['gtfobins', 'linpeas'],
        'cve': [],
        'mitigation': [   'Remove unnecessary file capabilities',
                          'Prefer least-privilege capability sets'],
        'poc_references': ['https://gtfobins.github.io/#+capabilities'],
        'research_references': [   'https://book.hacktricks.xyz/linux-hardening/privilege-escalation#capabilities']},
    {   'id': 'linux-cron-writable-script-path-wildcard',
        'name': 'Cron job abuse: writable scripts, PATH injection, wildcard injection',
        'platform': 'linux',
        'category': 'cron-timers',
        'severity': 'high',
        'summary': 'Root-owned cron jobs that execute a user-writable script, invoke commands by '
                   'relative name (with a controllable PATH), or expand a wildcard in a directory '
                   'the user can write, allow arbitrary code execution as root.',
        'technique': 'Three common flaws: (1) a cron entry runs a script that is world-writable or '
                     'lives in a user-writable directory, so the user edits it and waits for root '
                     "to run it; (2) the crontab sets 'PATH=' with a writable directory ahead of "
                     'system paths, or the job calls a command by bare name, letting the user '
                     'plant a malicious binary earlier in PATH; (3) the job runs an '
                     "archiver/command with an unquoted glob (e.g. 'tar czf backup.tar.gz *') in a "
                     'directory the user controls, so files named like command-line options (e.g. '
                     '--checkpoint-action) are interpreted as arguments (wildcard/argument '
                     'injection). pspy observes cron activity without needing root to read '
                     'crontabs.',
        'prerequisites': [   'A cron job that runs as root (or another privileged user)',
                             'Write access to the referenced script, a PATH directory, or the '
                             'directory whose contents are globbed'],
        'enumeration': [   'cat /etc/crontab; ls -la /etc/cron.d/ /etc/cron.daily/ '
                           '/etc/cron.hourly/ /etc/cron.weekly/ /etc/cron.monthly/',
                           'cat /etc/cron.d/* 2>/dev/null; ls -la /var/spool/cron/ '
                           '/var/spool/cron/crontabs/ 2>/dev/null',
                           'crontab -l 2>/dev/null',
                           'ls -la <path-of-any-script-referenced-by-cron>   # check writability',
                           './pspy64   # observe scheduled processes and their argv as an '
                           'unprivileged user'],
        'detection_indicators': [   'World/group-writable scripts referenced from crontab '
                                    "(permissions containing 'w' for group/other)",
                                    "'PATH=' line in a crontab that includes a user-writable "
                                    'directory before /usr/bin',
                                    'Cron commands invoking binaries by bare name (no absolute '
                                    'path)',
                                    "Cron command containing an unquoted '*' operating in a "
                                    "user-writable directory (e.g. 'tar ... *', 'chown ... *', "
                                    "'rsync ... *')"],
        'tools': ['pspy', 'linpeas', 'linenum', 'unix-privesc-check'],
        'cve': [],
        'mitigation': [   'Root cron scripts must be root-owned and non-writable by others',
                          'Set explicit absolute PATH in crontabs; use absolute command paths',
                          "Quote and anchor globs, or use 'find ... -print0 | xargs -0' patterns; "
                          "avoid tar/chown/rsync with bare '*'"],
        'poc_references': [   'https://www.exploit-db.com/papers/33930',
                              'https://book.hacktricks.wiki/en/linux-hardening/privilege-escalation/index.html#scheduledcron-jobs'],
        'research_references': [   'https://book.hacktricks.wiki/en/linux-hardening/privilege-escalation/wildcards-spare-tricks.html',
                                   'https://github.com/DominicBreuker/pspy']},
    {   'id': 'linux-dbus-privileged-method-abuse',
        'name': 'D-Bus system service method abuse / permissive policy',
        'platform': 'linux',
        'category': 'service-misconfig',
        'severity': 'high',
        'summary': 'The system D-Bus exposes methods on root-running services; a permissive bus '
                   'policy (/etc/dbus-1/system.d) or a service that runs attacker-supplied input '
                   'as root allows a low-privileged user to invoke privileged methods and '
                   'escalate.',
        'technique': 'System-bus services run as root and register interfaces callable over D-Bus. '
                     'Access is gated by policy XML in /etc/dbus-1/system.d and '
                     "/usr/share/dbus-1/system.d, and often by polkit. An over-broad '<allow "
                     "send_destination=...>' policy, or a custom service method that executes a "
                     'command / writes a file using caller-controlled arguments, lets an '
                     'unprivileged user call the method (via busctl/gdbus/dbus-send) and cause '
                     'root-level actions — command injection, file writes, or service '
                     'manipulation. Enumeration of exposed interfaces reveals candidate methods.',
        'prerequisites': [   'A root D-Bus service reachable by the attacker with a dangerous '
                             'method or command-injection sink',
                             'A bus policy (or polkit rule) that permits the call'],
        'enumeration': [   'busctl list; busctl tree <service> 2>/dev/null',
                           'busctl introspect <service> <object-path> 2>/dev/null',
                           'ls -la /etc/dbus-1/system.d/ /usr/share/dbus-1/system.d/ 2>/dev/null',
                           "grep -R 'allow' /etc/dbus-1/system.d/ 2>/dev/null | grep -i "
                           "'send_destination\\|send_interface'"],
        'detection_indicators': [   "D-Bus policy files with broad '<allow send_destination=...>' "
                                    '/ missing polkit checks',
                                    'Custom system services exposing methods that run commands or '
                                    'write files',
                                    'World-writable files under /etc/dbus-1/system.d',
                                    'Root-owned bus names with methods that accept command/path '
                                    'strings'],
        'tools': ['busctl', 'gdbus', 'dbus-send', 'd-feet', 'linpeas'],
        'cve': [],
        'mitigation': [   'Default-deny bus policies; scope send_destination/interface narrowly '
                          'and require polkit for privileged methods',
                          'Validate/whitelist all method inputs in root services; never pass to a '
                          'shell',
                          'Restrict write access to D-Bus policy directories'],
        'poc_references': [   'https://book.hacktricks.wiki/en/linux-hardening/privilege-escalation/d-bus-enumeration-and-command-injection-privilege-escalation.html',
                              'https://vk9-sec.com/d-bus-enumeration-command-injection-privilege-escalation/'],
        'research_references': [   'https://dbus.freedesktop.org/doc/dbus-daemon.1.html',
                                   'https://www.freedesktop.org/wiki/Software/dbus/']},
    {   'id': 'linux-dirtycow-cve-2016-5195',
        'name': 'DirtyCOW (Copy-on-Write race condition)',
        'platform': 'linux',
        'category': 'kernel-exploit',
        'severity': 'high',
        'summary': "A race condition in the Linux kernel's copy-on-write (COW) handling of "
                   'private, read-only memory mappings lets an unprivileged local user write to '
                   'files they should only be able to read, enabling privilege escalation by '
                   'overwriting root-owned files (e.g. /etc/passwd) or SUID binaries.',
        'technique': 'The bug is a race between the memory management dirty-COW path and '
                     'MADV_DONTNEED. By repeatedly writing to a private mapping of a read-only '
                     'file via /proc/self/mem while a second thread calls madvise(MADV_DONTNEED) '
                     'on the same page, the write can land on the original read-only page cache '
                     'page instead of the private copy, effectively bypassing file permissions. '
                     'Common escalation targets are overwriting /etc/passwd, a root cron file, or '
                     "a SUID binary's code. Because it corrupts page cache in memory only, it "
                     'leaves the on-disk file intact and is hard to detect after the fact.',
        'prerequisites': [   'Local unprivileged shell',
                             'Writable page cache target such as a SUID binary or /etc/passwd',
                             'Vulnerable kernel (2.6.22 through 4.8.x before patch backports)'],
        'enumeration': [   'uname -r',
                           'uname -a',
                           'cat /etc/os-release',
                           'ls -la /usr/bin/passwd (check SUID targets)'],
        'detection_indicators': [   'Kernel version between 2.6.22 and 4.8.2 (fixed in 4.8.3, '
                                    '4.7.9, 4.4.26 and distro backports)',
                                    'linux-exploit-suggester flags CVE-2016-5195',
                                    'Old distro release predating late 2016 patches'],
        'tools': [   'linux-exploit-suggester',
                     'linux-exploit-suggester-2',
                     'linpeas',
                     'searchsploit',
                     'uname'],
        'cve': ['CVE-2016-5195'],
        'mitigation': [   'Patch to kernel 4.8.3/4.7.9/4.4.26 or distro-backported fix',
                          'Apply vendor kernel updates (all major distros shipped fixes Oct 2016)'],
        'poc_references': [   'https://github.com/dirtycow/dirtycow.github.io/wiki/PoCs',
                              'https://www.exploit-db.com/exploits/40611'],
        'research_references': [   'https://dirtycow.ninja/',
                                   'https://nvd.nist.gov/vuln/detail/CVE-2016-5195',
                                   'https://access.redhat.com/security/vulnerabilities/2706661']},
    {   'id': 'linux-dirtycred-technique',
        'name': 'DirtyCred (credential/file object swap technique)',
        'platform': 'linux',
        'category': 'kernel-exploit',
        'severity': 'high',
        'summary': 'DirtyCred is a general kernel exploitation technique (not a single CVE) that '
                   'turns a use-after-free or double-free into root by swapping an unprivileged '
                   'cred or file struct on the kernel heap for a privileged one, sidestepping '
                   'data-only overwrite mitigations.',
        'technique': 'Rather than corrupting a specific field (like modprobe_path), DirtyCred '
                     'abuses the fact that struct cred and struct file live in dedicated slab '
                     'caches. Using a UAF/double-free primitive, the attacker frees an '
                     'unprivileged object and reclaims the same slot with a privileged one '
                     'allocated by a root context (e.g. by triggering a SUID binary or an open of '
                     'a root-owned file at the right moment), so an unprivileged task ends up '
                     'owning privileged credentials or a writable handle to a sensitive file. It '
                     'generalizes many bugs; the original disclosure paired it with CVE-2022-2588, '
                     'a double-free in route4_change (net/sched/cls_route.c).',
        'prerequisites': [   'A kernel UAF or double-free primitive on a cred/file-adjacent cache',
                             'Ability to allocate/free objects with attacker timing'],
        'enumeration': [   'uname -r',
                           'linux-exploit-suggester (identify candidate UAF/double-free CVEs)',
                           'cat /proc/sys/vm/unprivileged_userfaultfd 2>/dev/null'],
        'detection_indicators': [   'Presence of a UAF/double-free CVE such as CVE-2022-2588 on '
                                    'the running kernel',
                                    'Kernel lacking cred/file cache isolation hardening '
                                    '(CONFIG_KMALLOC_SPLIT_VARSIZE / vendor cred-jar patches)'],
        'tools': ['linux-exploit-suggester', 'linpeas', 'uname'],
        'cve': ['CVE-2022-2588'],
        'mitigation': [   'Patch the underlying UAF/double-free CVE',
                          "Enable slab hardening and cred/file cache isolation (e.g. Google's "
                          'cred_jar / vendor mitigations)'],
        'poc_references': [   'https://github.com/Markakd/DirtyCred',
                              'https://github.com/Markakd/CVE-2022-2588'],
        'research_references': [   'https://zplin.me/papers/DirtyCred.pdf',
                                   'https://nvd.nist.gov/vuln/detail/CVE-2022-2588']},
    {   'id': 'linux-dirtypipe-cve-2022-0847',
        'name': 'Dirty Pipe (pipe page-cache overwrite)',
        'platform': 'linux',
        'category': 'kernel-exploit',
        'severity': 'high',
        'summary': 'An uninitialized pipe_buffer flag (PIPE_BUF_FLAG_CAN_MERGE) lets an '
                   'unprivileged user overwrite pages in the page cache of arbitrary read-only '
                   'files, allowing modification of root-owned files and SUID binaries to gain '
                   'root.',
        'technique': 'The flags member of a pipe_buffer struct is not properly cleared on reuse. '
                     'By splicing a read-only file into a pipe and then writing into that pipe, '
                     "the stale CAN_MERGE flag causes the write to overwrite the file's page-cache "
                     'page even though the pipe write should not modify the backing file. '
                     'Escalation is achieved by overwriting a byte range of a root-owned file such '
                     'as /etc/passwd, or by patching a SUID binary in the page cache. Unlike '
                     'DirtyCow it requires no race and is highly reliable.',
        'prerequisites': [   'Local unprivileged shell',
                             'Read access to the target file (e.g. a SUID root binary)',
                             'Kernel 5.8 through 5.16.10 / 5.15.24 / 5.10.101 before backports'],
        'enumeration': [   'uname -r',
                           'cat /etc/os-release',
                           'find / -perm -4000 -type f 2>/dev/null (locate SUID targets)'],
        'detection_indicators': [   'Kernel version 5.8 <= x < 5.16.11 (also < 5.15.25 and < '
                                    '5.10.102)',
                                    'linux-exploit-suggester flags CVE-2022-0847',
                                    'Distro kernels released between Aug 2020 and Feb 2022 without '
                                    'the fix'],
        'tools': ['linux-exploit-suggester', 'linpeas', 'searchsploit', 'uname'],
        'cve': ['CVE-2022-0847'],
        'mitigation': [   'Update to kernel 5.16.11 / 5.15.25 / 5.10.102 or distro backport',
                          'Apply vendor kernel patches from Feb/Mar 2022'],
        'poc_references': [   'https://github.com/AlexisAhmed/CVE-2022-0847-DirtyPipe-Exploits',
                              'https://haxx.in/files/dirtypipez.c'],
        'research_references': [   'https://dirtypipe.cm4all.com/',
                                   'https://nvd.nist.gov/vuln/detail/CVE-2022-0847']},
    {   'id': 'linux-ebpf-verifier-cve-2021-3490',
        'name': 'eBPF verifier bounds-tracking LPE',
        'platform': 'linux',
        'category': 'kernel-exploit',
        'severity': 'high',
        'summary': "Flaws in the eBPF verifier's register bounds tracking let a user load a "
                   'program the verifier wrongly accepts as safe, producing kernel out-of-bounds '
                   'read/write and local root; exploitable only where unprivileged BPF is enabled.',
        'technique': 'The verifier statically proves eBPF programs are memory-safe by tracking '
                     'value ranges for each register. Several bugs cause the tracked bounds to '
                     'diverge from real runtime values: CVE-2021-3490 (Manfred Paul) mishandles '
                     '32-bit ALU bounds for AND/OR/XOR, CVE-2020-8835 mistracks 32-bit bounds, '
                     'CVE-2021-31440 has an off-by-one in bounds adjustment. A crafted program '
                     'passes verification yet performs out-of-bounds pointer arithmetic at '
                     'runtime, giving arbitrary kernel read/write that is used to overwrite cred '
                     'or modprobe_path for root. These require unprivileged eBPF to be permitted.',
        'prerequisites': [   'kernel.unprivileged_bpf_disabled = 0 (unprivileged BPF allowed)',
                             'Vulnerable kernel for the specific verifier CVE'],
        'enumeration': [   'uname -r',
                           'sysctl kernel.unprivileged_bpf_disabled',
                           'cat /proc/sys/kernel/unprivileged_bpf_disabled',
                           'grep BPF /boot/config-$(uname -r) 2>/dev/null'],
        'detection_indicators': [   'kernel.unprivileged_bpf_disabled = 0',
                                    'Kernel version matching a known verifier CVE window',
                                    'linux-exploit-suggester flags CVE-2021-3490 / CVE-2020-8835 '
                                    'etc.'],
        'tools': ['linux-exploit-suggester', 'linpeas', 'uname'],
        'cve': [   'CVE-2021-3490',
                   'CVE-2020-8835',
                   'CVE-2021-31440',
                   'CVE-2021-4204',
                   'CVE-2022-23222'],
        'mitigation': [   'Patch to a fixed kernel',
                          'Set kernel.unprivileged_bpf_disabled=1 (or =2) to block unprivileged '
                          'BPF program loading'],
        'poc_references': [   'https://github.com/chompie1337/Linux_LPE_eBPF_CVE-2021-3490',
                              'https://github.com/scwuaptx/CVE/tree/master/CVE-2021-3490'],
        'research_references': [   'https://nvd.nist.gov/vuln/detail/CVE-2021-3490',
                                   'https://attackerkb.com/topics/3D6SKZ2Hv2/cve-2021-3490']},
    {   'id': 'linux-gameoverlay-cve-2023-2640-32629',
        'name': 'GameOver(lay) OverlayFS xattr capability escalation (Ubuntu)',
        'platform': 'linux',
        'category': 'kernel-exploit',
        'severity': 'high',
        'summary': 'Two Ubuntu-specific OverlayFS flaws let files copied from a lower to an upper '
                   'directory retain extended attributes such as file capabilities, so a non-root '
                   'user can craft a capability-bearing binary (e.g. cap_setuid) and execute it '
                   'for root; estimated to affect ~40% of Ubuntu cloud workloads.',
        'technique': "Ubuntu's overlayfs modifications mishandle permission checks when copying "
                     'files (and their security.* extended attributes) from the lower to the upper '
                     'layer. A file placed in the lower directory with elevated file capabilities '
                     'has those capabilities carried up to the upper layer, where an unprivileged '
                     'user can execute it. Because CAP_SETUID / CAP_SYS_ADMIN capabilities survive '
                     'the copy-up, running the upper-layer binary yields root without any race. '
                     'The two CVEs cover distinct code paths introduced by Ubuntu-carried patches '
                     'and mainline changes not properly reconciled.',
        'prerequisites': [   'Ubuntu kernel with the vulnerable overlayfs patches',
                             'Ability to create user/mount namespaces or perform overlay mount',
                             'Unpatched Ubuntu kernel (fixes July 2023)'],
        'enumeration': [   'uname -r',
                           'cat /etc/os-release',
                           'sysctl kernel.unprivileged_userns_clone'],
        'detection_indicators': [   'Ubuntu kernel released before July 2023 overlayfs fix',
                                    'linux-exploit-suggester flags CVE-2023-2640 / CVE-2023-32629',
                                    'Ubuntu-branded kernel string in uname -a',
                                    'cap_setuid'],
        'tools': ['linux-exploit-suggester', 'linpeas', 'searchsploit', 'uname'],
        'cve': ['CVE-2023-2640', 'CVE-2023-32629'],
        'mitigation': [   'Apply Ubuntu kernel updates from July 2023',
                          'Restrict unprivileged user namespaces where feasible'],
        'poc_references': [   'https://github.com/g1vi/CVE-2023-2640-CVE-2023-32629',
                              'https://github.com/Green-Avocado/CVE-2023-2640'],
        'research_references': [   'https://www.wiz.io/blog/ubuntu-overlayfs-vulnerability',
                                   'https://nvd.nist.gov/vuln/detail/CVE-2023-2640',
                                   'https://nvd.nist.gov/vuln/detail/CVE-2023-32629']},
    {   'id': 'linux-io-uring-cve-2023-2598',
        'name': 'io_uring subsystem LPE (fixed-buffer OOB and related)',
        'platform': 'linux',
        'category': 'kernel-exploit',
        'severity': 'high',
        'summary': 'The io_uring async I/O subsystem has produced multiple memory-corruption LPEs; '
                   'CVE-2023-2598 is an out-of-bounds access to physical memory via fixed-buffer '
                   'registration that gives full local root, and the subsystem has had UAFs (e.g. '
                   'CVE-2022-2602 io_uring+unix GC) exploited for privilege escalation.',
        'technique': "io_uring's rich, performance-oriented object lifecycle has repeatedly "
                     'produced bugs. In CVE-2023-2598, io_sqe_buffer_register() coalesces '
                     'physically contiguous pages but miscomputes bounds, letting a registered '
                     'fixed buffer read/write physical memory beyond its intended range, which is '
                     'escalated to arbitrary kernel R/W and root. CVE-2022-2602 is a '
                     'use-after-free from the interaction of io_uring registered files and the '
                     'unix socket garbage collector. Because io_uring is often reachable by '
                     'unprivileged processes, these are strong LPE primitives. Defenders '
                     'frequently gate or disable io_uring for untrusted workloads.',
        'prerequisites': [   'io_uring enabled and reachable by unprivileged users',
                             'Vulnerable kernel for the specific CVE (e.g. CVE-2023-2598 around '
                             '6.x before fix)'],
        'enumeration': [   'uname -r',
                           'sysctl kernel.io_uring_disabled 2>/dev/null',
                           'grep -i io_uring /boot/config-$(uname -r) 2>/dev/null',
                           'cat /proc/sys/kernel/io_uring_group 2>/dev/null'],
        'detection_indicators': [   'CONFIG_IO_URING=y and io_uring not disabled by sysctl',
                                    'Kernel version matching a known io_uring CVE window',
                                    'linux-exploit-suggester flags an io_uring CVE'],
        'tools': ['linux-exploit-suggester', 'linpeas', 'uname'],
        'cve': ['CVE-2023-2598', 'CVE-2022-1786', 'CVE-2021-41073', 'CVE-2022-2602'],
        'mitigation': [   'Patch to a fixed kernel',
                          'Set kernel.io_uring_disabled=2 (kernels >= 6.6) or restrict io_uring '
                          'via seccomp for untrusted workloads'],
        'poc_references': [   'https://github.com/ysanatomic/io_uring_LPE-CVE-2023-2598',
                              'https://github.com/Ruia-ruia/CVE-2022-2602'],
        'research_references': [   'https://anatomic.rip/cve-2023-2598/',
                                   'https://nvd.nist.gov/vuln/detail/CVE-2023-2598']},
    {   'id': 'linux-ld-preload-library-hijack-nonsudo',
        'name': 'Dynamic linker hijack: writable library path, missing library, RUNPATH, '
                'ld.so.conf',
        'platform': 'linux',
        'category': 'path-hijack',
        'severity': 'high',
        'summary': 'Beyond sudo, the dynamic loader can be abused when a privileged binary depends '
                   'on a library located in (or searched through) a writable directory, when a '
                   'required library is missing, or when RUNPATH/RPATH or /etc/ld.so.conf.d point '
                   'at attacker-writable locations.',
        'technique': 'The loader searches for shared objects via DT_RPATH/DT_RUNPATH embedded in '
                     'the binary, LD_LIBRARY_PATH (ignored for SUID unless preserved), and the '
                     'directories in /etc/ld.so.conf(.d) as cached by ldconfig. If a SUID/root '
                     'binary has a RUNPATH pointing at a writable directory, or requires a library '
                     "that is missing (ldd reports 'not found') in a directory the attacker can "
                     'write, they place a malicious .so exporting the needed symbols/constructor '
                     'there, and the loader loads it into the privileged process. A writable '
                     '/etc/ld.so.conf.d file (or writable directory listed therein) lets the '
                     'attacker add a search path globally.',
        'prerequisites': [   'A privileged binary with a hijackable library search path or a '
                             'missing dependency',
                             'Write access to the relevant library directory, RUNPATH target, or '
                             'ld.so config'],
        'enumeration': [   "ldd <suid-or-root-binary>   # look for 'not found' and library "
                           'directories',
                           "readelf -d <binary> | grep -E 'RPATH|RUNPATH'",
                           'cat /etc/ld.so.conf; ls -la /etc/ld.so.conf.d/; find /etc/ld.so.conf.d '
                           '-writable 2>/dev/null',
                           "for d in $(readelf -d <binary> | grep -oP '\\[\\K[^]]+'); do [ -w "
                           '"$d" ] && echo "writable RUNPATH: $d"; done'],
        'detection_indicators': [   "ldd output containing 'not found' for a SUID/root binary",
                                    'RPATH/RUNPATH entries resolving to user-writable directories '
                                    "(often '.', /tmp, /opt, home)",
                                    'Writable files under /etc/ld.so.conf.d/ or writable '
                                    'directories listed in ld.so.conf',
                                    'Library search directories with group/other write permission',
                                    'NOPASSWD',
                                    'LD_PRELOAD'],
        'tools': ['ldd', 'readelf', 'ldconfig', 'linpeas', 'linux-smart-enumeration'],
        'cve': [],
        'mitigation': [   'Build privileged binaries without writable RPATH/RUNPATH; prefer '
                          'absolute, root-owned library dirs',
                          'Ensure all dependencies resolve and all library directories are '
                          'root-owned/non-writable',
                          'Protect /etc/ld.so.conf(.d) from non-root writes'],
        'poc_references': [   'https://book.hacktricks.wiki/en/linux-hardening/privilege-escalation/index.html#ld_preload-and-ld_library_path',
                              'https://rentoniscoming.medium.com/exploiting-suid-binaries-shared-library-hijacking-4a5f6a1d2eaf'],
        'research_references': [   'https://man7.org/linux/man-pages/man8/ld.so.8.html',
                                   'https://book.hacktricks.wiki/en/linux-hardening/privilege-escalation/index.html#shared-library']},
    {   'id': 'linux-looney-tunables-cve-2023-4911',
        'name': 'Looney Tunables (glibc GLIBC_TUNABLES overflow)',
        'platform': 'linux',
        'category': 'credential-harvesting',
        'severity': 'high',
        'summary': 'A buffer overflow in the glibc dynamic loader (ld.so) processing of the '
                   'GLIBC_TUNABLES environment variable lets a local user gain root by exploiting '
                   'any SUID-root binary, affecting default installs of Fedora, Ubuntu, and '
                   'Debian.',
        'technique': 'When ld.so parses GLIBC_TUNABLES it copies tunable name=value tokens into a '
                     'fixed stack buffer while mishandling the case of a malformed '
                     "'tunable=tunable=value' sequence, overflowing the buffer. Because ld.so runs "
                     'as part of executing any SUID-root binary, an attacker sets a crafted '
                     'GLIBC_TUNABLES value and executes a setuid binary (e.g. /usr/bin/su) so the '
                     'overflow corrupts loader state and hijacks execution with root privileges. '
                     'The bug was introduced with the tunables rewrite in glibc 2.34.',
        'prerequisites': [   'Local unprivileged shell',
                             'A SUID-root binary that links glibc',
                             'Vulnerable glibc 2.34 through 2.38 before patch'],
        'enumeration': [   'ldd --version',
                           'ldd /bin/ls | head -1',
                           'getconf GNU_LIBC_VERSION',
                           'find / -perm -4000 -type f 2>/dev/null'],
        'detection_indicators': [   'glibc version 2.34-2.38 without the Oct 2023 fix',
                                    'Default Fedora 37/38, Ubuntu 22.04/23.04, Debian 12 glibc '
                                    'builds',
                                    'linux-exploit-suggester / linpeas flags CVE-2023-4911'],
        'tools': ['linpeas', 'linux-exploit-suggester', 'searchsploit'],
        'cve': ['CVE-2023-4911'],
        'mitigation': [   'Update glibc to the patched version (vendor fixes Oct 3, 2023)',
                          'Temporary: a seccomp/glibc mitigation aborting SUID execution when '
                          'GLIBC_TUNABLES is malformed'],
        'poc_references': [   'https://github.com/RootKit-Org/CVE-2023-4911',
                              'https://github.com/leesh3288/CVE-2023-4911'],
        'research_references': [   'https://www.qualys.com/2023/10/03/cve-2023-4911/looney-tunables-local-privilege-escalation-glibc-ld-so.txt',
                                   'https://nvd.nist.gov/vuln/detail/CVE-2023-4911']},
    {   'id': 'linux-netfilter-xtables-oob-cve-2021-22555',
        'name': 'Netfilter x_tables heap out-of-bounds write',
        'platform': 'linux',
        'category': 'kernel-exploit',
        'severity': 'high',
        'summary': 'A 15-year-old heap out-of-bounds write in netfilter x_tables (compat '
                   'setsockopt path) enables kernel memory corruption powerful enough to bypass '
                   'modern mitigations, giving local root and container escape on kernels 2.6.19 '
                   'through 5.11.',
        'technique': 'In net/netfilter/x_tables.c the xt_compat_target_from_user() / '
                     'IPT_SO_SET_REPLACE compat conversion writes past the end of an allocation '
                     'because of a size miscalculation when converting 32-bit compat structures. '
                     'Andy Nguyen (theflow@) leveraged this OOB write against msg_msg heap objects '
                     'to build a use-after-free and arbitrary read/write, then escalated to root '
                     'and escaped the kCTF Kubernetes pod isolation. The vulnerability is '
                     'reachable from an unprivileged user namespace, so unprivileged users can '
                     'trigger it on affected kernels.',
        'prerequisites': [   'Unprivileged user namespace (for unpriv trigger) or CAP_NET_ADMIN',
                             'Vulnerable kernel v2.6.19 through 5.11'],
        'enumeration': [   'uname -r',
                           'sysctl kernel.unprivileged_userns_clone',
                           'lsmod | grep x_tables'],
        'detection_indicators': [   'Kernel <= 5.11 without the April 2021 fix',
                                    'unprivileged userns enabled',
                                    'linux-exploit-suggester / metasploit flag CVE-2021-22555'],
        'tools': ['metasploit', 'linux-exploit-suggester', 'linpeas', 'uname'],
        'cve': ['CVE-2021-22555'],
        'mitigation': [   'Update to a patched kernel (fix backported to stable April 2021)',
                          'Disable unprivileged user namespaces'],
        'poc_references': [   'https://github.com/google/security-research/tree/master/pocs/linux/cve-2021-22555',
                              'https://github.com/rapid7/metasploit-framework/blob/master/modules/exploits/linux/local/netfilter_xtables_heap_oob_write_priv_esc.rb'],
        'research_references': [   'https://google.github.io/security-research/pocs/linux/cve-2021-22555/writeup.html',
                                   'https://nvd.nist.gov/vuln/detail/CVE-2021-22555']},
    {   'id': 'linux-nfs-no-root-squash',
        'name': 'NFS no_root_squash / no_all_squash misconfiguration',
        'platform': 'linux',
        'category': 'nfs',
        'severity': 'high',
        'summary': "An NFS export configured with no_root_squash lets a client's root map to the "
                   "server's root over the share. An attacker with root on any client (or on their "
                   'own machine) writes a root-owned SUID binary into the share, then executes it '
                   'on the target to become root.',
        'technique': "By default NFS 'squashes' remote root to the anonymous user. With "
                     'no_root_squash, files created as root on the client are owned by root on the '
                     'server, and the setuid bit is preserved. The attacker mounts the export from '
                     'a machine where they are root, drops a small root-owned SUID-root helper '
                     'into the shared directory, then runs it from a low-privileged shell on the '
                     'server to gain a root shell. no_all_squash enables an analogous attack by '
                     'matching arbitrary UIDs. A lesser-known local variant forges the '
                     'client-advertised UID/GID in NFSv3 RPCs to access files as their owner even '
                     'when the export is IP-restricted.',
        'prerequisites': [   'An NFS export with no_root_squash (or no_all_squash)',
                             'Root on a client that can mount the share (or ability to forge NFS '
                             'RPC UIDs), plus a shell on the target to execute the planted binary'],
        'enumeration': [   'cat /etc/exports 2>/dev/null',
                           'showmount -e <nfs-server>',
                           'cat /proc/mounts | grep nfs; mount | grep nfs',
                           "grep -i 'no_root_squash\\|no_all_squash\\|insecure' /etc/exports "
                           '2>/dev/null'],
        'detection_indicators': [   "'no_root_squash' or 'no_all_squash' in /etc/exports",
                                    "'insecure' export option (allows non-reserved source ports)",
                                    'Exports readable/writable by broad host ranges (e.g. '
                                    "'*(rw,no_root_squash)')",
                                    'no_root_squash'],
        'tools': [   'showmount',
                     'mount',
                     'nfs-common',
                     'nfsh.py (errno.fr uid-forging poc)',
                     'linpeas'],
        'cve': [],
        'mitigation': [   'Use root_squash (the default) and all_squash where appropriate',
                          "Restrict exports to specific hosts, avoid the 'insecure' option, mount "
                          'shares nosuid',
                          'Prefer NFSv4 with Kerberos (sec=krb5) over UID-based trust'],
        'poc_references': [   'https://www.errno.fr/nfs_privesc.html',
                              'https://www.hackingarticles.in/linux-privilege-escalation-using-misconfigured-nfs/'],
        'research_references': [   'https://book.hacktricks.wiki/en/network-services-pentesting/nfs-service-pentesting.html',
                                   'https://man7.org/linux/man-pages/man5/exports.5.html']},
    {   'id': 'linux-nftables-uaf-cve-2022-32250',
        'name': 'nf_tables use-after-free (NFT_STATEFUL_EXPR)',
        'platform': 'linux',
        'category': 'kernel-exploit',
        'severity': 'high',
        'summary': 'An incorrect NFT_STATEFUL_EXPR check in netfilter nf_tables leads to a '
                   'use-after-free write, allowing a local user who can create user/network '
                   'namespaces to escalate to root on kernels through 5.18.1.',
        'technique': 'In nf_tables_api.c the validation that decides whether an expression is '
                     'stateful is wrong, so an expression bound to a set can be freed while still '
                     'referenced. The attacker reclaims the freed object with controlled data '
                     '(heap grooming with adjacent allocations), builds arbitrary read/write '
                     'primitives, then typically overwrites modprobe_path or a credential '
                     'structure to gain root. The nf_tables interface is reachable from an '
                     'unprivileged user namespace on many distros, so no prior privilege is '
                     'required beyond namespace creation.',
        'prerequisites': [   'Unprivileged user + network namespace creation allowed',
                             'Vulnerable kernel up to and including 5.18.1'],
        'enumeration': [   'uname -r',
                           'sysctl kernel.unprivileged_userns_clone',
                           'lsmod | grep nf_tables',
                           'cat /proc/sys/user/max_user_namespaces'],
        'detection_indicators': [   'Kernel <= 5.18.1 without the fix',
                                    'unprivileged userns enabled and nf_tables reachable',
                                    'linux-exploit-suggester flags CVE-2022-32250'],
        'tools': ['linux-exploit-suggester', 'linpeas', 'uname'],
        'cve': ['CVE-2022-32250'],
        'mitigation': [   'Update to a patched kernel (fix in mid-2022 stable releases)',
                          'Set kernel.unprivileged_userns_clone=0 to block the namespace '
                          'reachability'],
        'poc_references': [   'https://github.com/ysanatomic/CVE-2022-32250-LPE',
                              'https://github.com/theori-io/CVE-2022-32250-exploit'],
        'research_references': [   'http://anatomic.rip/cve-2022-32250/',
                                   'https://nvd.nist.gov/vuln/detail/CVE-2022-32250']},
    {   'id': 'linux-nftables-uaf-cve-2023-32233',
        'name': 'nf_tables anonymous-set use-after-free',
        'platform': 'linux',
        'category': 'kernel-exploit',
        'severity': 'high',
        'summary': 'A use-after-free in netfilter nf_tables triggered by mishandling anonymous '
                   'sets in batch requests gives arbitrary kernel read/write and local root on '
                   'kernels up to and including 6.3.1.',
        'technique': 'Anonymous sets are inline sets defined as part of a rule. When a batch '
                     'request deletes a rule referencing an anonymous set and another operation in '
                     'the same batch re-references or reactivates that set, '
                     'nf_tables_deactivate_set() fails to transition the set correctly during the '
                     'NFT_TRANS_PREPARE phase. The result is a dangling reference the attacker '
                     'reclaims to obtain arbitrary read/write, which is used to overwrite '
                     'credential structures and escalate to root. Reachable from an unprivileged '
                     'user namespace where nf_tables is exposed.',
        'prerequisites': [   'Unprivileged user namespace with nf_tables access',
                             'Vulnerable kernel <= 6.3.1'],
        'enumeration': [   'uname -r',
                           'sysctl kernel.unprivileged_userns_clone',
                           'lsmod | grep nf_tables'],
        'detection_indicators': [   'Kernel <= 6.3.1 lacking commit c1592a89942e',
                                    'unprivileged userns enabled',
                                    'linux-exploit-suggester flags CVE-2023-32233'],
        'tools': ['linux-exploit-suggester', 'linpeas', 'uname'],
        'cve': ['CVE-2023-32233'],
        'mitigation': [   'Apply kernel update containing commit c1592a89942e '
                          '(nf_tables_activate_set)',
                          'Disable unprivileged user namespaces'],
        'poc_references': [   'https://github.com/Liuk3r/CVE-2023-32233',
                              'https://github.com/oferchen/POC-CVE-2023-32233'],
        'research_references': [   'https://seclists.org/oss-sec/2023/q2/133',
                                   'https://nvd.nist.gov/vuln/detail/CVE-2023-32233']},
    {   'id': 'linux-overlayfs-copyup-cve-2023-0386',
        'name': 'OverlayFS SUID copy-up (mainline)',
        'platform': 'linux',
        'category': 'kernel-exploit',
        'severity': 'high',
        'summary': 'A mainline OverlayFS bug fails to check uid/gid mapping during copy-up, '
                   'letting an unprivileged user smuggle a root-owned SUID binary from a lower to '
                   'an upper layer and execute it as root; actively exploited and in CISA KEV.',
        'technique': 'When overlayfs copies a file from the lower to the upper directory '
                     "(copy_up), it preserves ownership without verifying that the setuid file's "
                     "uid/gid is mapped in the caller's user namespace. Using a FUSE-backed lower "
                     'directory (owned by root/nobody) combined with an unprivileged user '
                     'namespace, an attacker presents a root-owned SUID binary in the lower layer; '
                     'after copy-up the SUID root binary lands in a normal, host-accessible upper '
                     'directory (e.g. under /tmp) where it can be executed to gain root. Distinct '
                     'from CVE-2021-3493, this affects mainline kernels, not just Ubuntu.',
        'prerequisites': [   'Unprivileged user namespaces enabled',
                             'FUSE available',
                             'Vulnerable kernel roughly 5.11 through 6.1 (fixed in 6.2 / '
                             'backports)'],
        'enumeration': [   'uname -r',
                           'cat /etc/os-release',
                           'modinfo fuse 2>/dev/null; ls -l /dev/fuse',
                           'sysctl kernel.unprivileged_userns_clone'],
        'detection_indicators': [   'Kernel roughly 5.11-6.1 without the Jan 2023 copy_up fix',
                                    'FUSE and unprivileged userns both available',
                                    'linux-exploit-suggester / linpeas flags CVE-2023-0386',
                                    'Listed in CISA Known Exploited Vulnerabilities catalog'],
        'tools': ['linux-exploit-suggester', 'linpeas', 'searchsploit', 'uname'],
        'cve': ['CVE-2023-0386'],
        'mitigation': [   'Upgrade to kernel 6.2 or apply the backported copy_up fix',
                          'Disable unprivileged user namespaces / restrict FUSE where feasible'],
        'poc_references': [   'https://github.com/xkaneiki/CVE-2023-0386',
                              'https://github.com/sxlmnwb/CVE-2023-0386'],
        'research_references': [   'https://securitylabs.datadoghq.com/articles/overlayfs-cve-2023-0386/',
                                   'https://nvd.nist.gov/vuln/detail/CVE-2023-0386']},
    {   'id': 'linux-overlayfs-userns-cve-2021-3493',
        'name': 'OverlayFS unprivileged userns capability escalation (Ubuntu)',
        'platform': 'linux',
        'category': 'kernel-exploit',
        'severity': 'high',
        'summary': 'An Ubuntu-specific OverlayFS flaw fails to validate file capabilities against '
                   'the user namespace, letting an unprivileged user set file capabilities that '
                   'are honored in the init namespace and escalate to root.',
        'technique': 'Upstream Linux forbids mounting overlayfs in an unprivileged user namespace, '
                     'but Ubuntu carries a patch adding FS_USERNS_MOUNT to overlayfs. When a user '
                     'in a new user namespace sets file capabilities (e.g. cap_setuid) via '
                     'setxattr on a file in the overlay, the kernel does not correctly re-validate '
                     'that the caller lacks those capabilities in the real (init) namespace. The '
                     'capability xattr persists to a file the attacker then executes in the host '
                     'namespace, yielding a capability-endowed binary and root. This is '
                     'essentially the userns/overlayfs analogue of a SUID smuggling bug.',
        'prerequisites': [   'Ubuntu kernel with unprivileged user namespaces enabled',
                             'Vulnerable Ubuntu kernel (< 5.11-based / pre-April 2021 patch)'],
        'enumeration': [   'uname -r',
                           'cat /etc/os-release',
                           'sysctl kernel.unprivileged_userns_clone',
                           'cat /proc/sys/kernel/unprivileged_userns_clone 2>/dev/null'],
        'detection_indicators': [   'Ubuntu distribution with kernel below the April 2021 fix',
                                    'kernel.unprivileged_userns_clone = 1',
                                    'linux-exploit-suggester flags CVE-2021-3493',
                                    'cap_setuid'],
        'tools': ['linux-exploit-suggester', 'linpeas', 'searchsploit', 'uname'],
        'cve': ['CVE-2021-3493'],
        'mitigation': [   'Apply Ubuntu kernel update (USN-4917, April 2021)',
                          'Set kernel.unprivileged_userns_clone=0 to disable unprivileged user '
                          'namespaces'],
        'poc_references': [   'https://github.com/briskets/CVE-2021-3493',
                              'https://www.exploit-db.com/exploits/49933'],
        'research_references': [   'https://ubuntu.com/security/CVE-2021-3493',
                                   'https://nvd.nist.gov/vuln/detail/CVE-2021-3493']},
    {   'id': 'linux-path-hijacking-relative-command',
        'name': 'PATH hijacking of root-run scripts and SUID wrappers',
        'platform': 'linux',
        'category': 'path-hijack',
        'severity': 'high',
        'summary': 'When a privileged process (SUID binary, root cron/service, or a script run via '
                   'sudo) invokes another program by a bare/relative name, an attacker who '
                   'controls an earlier entry in the effective PATH — or a writable PATH directory '
                   "— can supply a malicious binary that runs with the caller's privileges.",
        'technique': 'The shell and system()/execlp/execvp resolve unqualified command names '
                     "against PATH left-to-right. If a privileged script calls e.g. 'service', "
                     "'cat', 'ps', or a custom helper without an absolute path, and the process's "
                     'PATH contains a directory the attacker can write (or the attacker can set '
                     'PATH before invoking a SUID wrapper that does not sanitize it), the '
                     "attacker's same-named binary is executed first. A literal '.' or an empty "
                     'element in PATH (which resolves to the current directory) is a classic '
                     'instance. strings on a SUID binary often reveals the relative command names '
                     'it calls.',
        'prerequisites': [   'A privileged program invoking a command by relative name',
                             'A writable directory earlier in the effective PATH, or the ability '
                             'to influence PATH for the privileged process'],
        'enumeration': [   'echo $PATH',
                           "strings <suid-binary> | grep -iE '^(/|)([a-z0-9_-]+)$'   # spot "
                           'relative command names',
                           'ltrace/strace the SUID binary if permitted to observe execvp/system '
                           'calls',
                           'for d in $(echo $PATH | tr \':\' \' \'); do [ -w "$d" ] && echo '
                           '"writable: $d"; done'],
        'detection_indicators': [   "'.' or an empty element ('::', leading/trailing ':') in PATH",
                                    'A world/group-writable directory present in PATH (e.g. /tmp, '
                                    '/usr/local/bin loosely permissioned)',
                                    'SUID binary strings referencing bare command names (e.g. '
                                    '\'system("ps")\')',
                                    'Root cron/service scripts calling commands without absolute '
                                    'paths'],
        'tools': ['strings', 'ltrace', 'strace', 'linpeas', 'pspy'],
        'cve': [],
        'mitigation': [   'Always call external commands by absolute path in privileged '
                          'scripts/binaries',
                          'Set a sanitized PATH (and use sudo secure_path) for privileged '
                          'execution',
                          "Remove '.' and writable directories from system PATH"],
        'poc_references': [   'https://book.hacktricks.wiki/en/linux-hardening/privilege-escalation/index.html#writable-path-abuses',
                              'https://gtfobins.github.io/'],
        'research_references': [   'https://book.hacktricks.wiki/en/linux-hardening/privilege-escalation/index.html#path',
                                   'https://www.cyberciti.biz/faq/unix-linux-bash-append-prepend-path-variable/']},
    {   'id': 'linux-polkit-pkexec-misconfig',
        'name': 'polkit / pkexec policy misconfiguration',
        'platform': 'linux',
        'category': 'service-misconfig',
        'severity': 'high',
        'summary': 'polkit (PolicyKit) mediates privileged actions; permissive local rules or '
                   'action policies (allowing a user/group to run privileged operations, or pkexec '
                   'actions, without authentication) let a low-privileged user execute commands as '
                   'root through pkexec or D-Bus-backed services.',
        'technique': 'polkit authorization is defined by .policy action files '
                     '(/usr/share/polkit-1/actions) and JavaScript .rules files '
                     '(/etc/polkit-1/rules.d, /usr/share/polkit-1/rules.d). A rule that returns '
                     'polkit.Result.YES for a broad action, or an action whose '
                     "allow_active/allow_any defaults to 'yes', permits an unprivileged user to "
                     'invoke that action (e.g. via pkexec, or a D-Bus method such as '
                     'org.freedesktop.systemd1 / packagekit / NetworkManager) and run code as root '
                     'without a password. Administrators sometimes add over-broad rules for '
                     'convenience. (Distinct, exploitation-grade polkit/pkexec bugs — PwnKit '
                     'CVE-2021-4034 and the polkit auth-bypass CVE-2021-3560 — are widely '
                     'referenced but are code vulnerabilities rather than pure misconfiguration.)',
        'prerequisites': [   'A polkit rule or action policy that authorizes a privileged '
                             "operation for the attacker's user/group without auth",
                             'A client path to invoke it (pkexec or a privileged D-Bus service)'],
        'enumeration': [   'pkexec --version; pkaction 2>/dev/null | head',
                           'ls -la /etc/polkit-1/rules.d/ /usr/share/polkit-1/rules.d/ '
                           '/usr/share/polkit-1/actions/ 2>/dev/null',
                           'grep -R '
                           "'ResultActive\\|ResultAny\\|Result.YES\\|allow_active\\|allow_any' "
                           '/etc/polkit-1 /usr/share/polkit-1 2>/dev/null',
                           'busctl list 2>/dev/null | grep -i '
                           "'systemd1\\|PackageKit\\|NetworkManager'"],
        'detection_indicators': [   "polkit .rules files returning 'polkit.Result.YES' for broad "
                                    'actions or admin groups',
                                    "action .policy files with '<allow_active>yes</allow_active>' "
                                    "or 'allow_any' set to yes for sensitive actions",
                                    'World-writable files under /etc/polkit-1/rules.d',
                                    'pkexec present and SUID (base for related CVEs)'],
        'tools': ['pkexec', 'pkaction', 'busctl', 'gdbus', 'linpeas'],
        'cve': ['CVE-2021-4034', 'CVE-2021-3560'],
        'mitigation': [   'Review custom polkit rules; avoid blanket Result.YES and permissive '
                          'allow_active/allow_any',
                          'Keep polkit/pkexec patched (>= 0.120 for PwnKit)',
                          'Restrict permissions on polkit rules/action directories'],
        'poc_references': [   'https://www.qualys.com/2022/01/25/cve-2021-4034/pwnkit.txt',
                              'https://github.blog/security/vulnerability-research/privilege-escalation-polkit-root-on-linux-with-bug/'],
        'research_references': [   'https://www.freedesktop.org/software/polkit/docs/latest/polkit.8.html',
                                   'https://book.hacktricks.wiki/en/linux-hardening/privilege-escalation/d-bus-enumeration-and-command-injection-privilege-escalation.html']},
    {   'id': 'linux-polkit-race-cve-2021-3560',
        'name': 'polkit authentication bypass (race condition)',
        'platform': 'linux',
        'category': 'service-misconfig',
        'severity': 'high',
        'summary': "A race condition in polkit's polkit_system_bus_name_get_creds_sync() lets an "
                   'unprivileged user bypass authentication and invoke privileged D-Bus methods '
                   '(e.g. via accountsservice to create an admin user), gaining root on systems '
                   'with polkit 0.113-0.118.',
        'technique': "Polkit authorizes a D-Bus request by asking dbus-daemon for the sender's "
                     'UID. If the requesting process is killed at the right moment after polkit '
                     "receives the message but before it resolves the sender's credentials, "
                     'dbus-daemon returns an error that polkit mishandles by substituting UID 0. '
                     'Polkit then evaluates the request as if it came from root and allows it. '
                     'Chaining this with accountsservice/CreateUser and SetPassword methods lets '
                     'an attacker create a new administrator account. Discovered by Kevin '
                     'Backhouse (GitHub Security Lab).',
        'prerequisites': [   'Local unprivileged shell',
                             'Vulnerable polkit 0.113 through 0.118 (or backports)',
                             'accountsservice/other privileged D-Bus service present'],
        'enumeration': [   'pkaction --version 2>/dev/null',
                           'dpkg -l policykit-1 2>/dev/null || rpm -q polkit 2>/dev/null',
                           'busctl list | grep -i accounts'],
        'detection_indicators': [   'polkit version 0.113-0.118',
                                    'linpeas / linux-exploit-suggester flags CVE-2021-3560',
                                    'accountsservice reachable over D-Bus'],
        'tools': ['linpeas', 'linux-exploit-suggester', 'searchsploit'],
        'cve': ['CVE-2021-3560'],
        'mitigation': [   'Update polkit to 0.119 or distro backport',
                          'Apply vendor advisories from June 2021'],
        'poc_references': [   'https://github.com/Almorabea/Polkit-exploit',
                              'https://github.com/secnigma/CVE-2021-3560-Polkit-Privilege-Esclation'],
        'research_references': [   'https://seclists.org/oss-sec/2021/q2/180',
                                   'https://nvd.nist.gov/vuln/detail/CVE-2021-3560']},
    {   'id': 'linux-ptrace-traceme-cve-2019-13272',
        'name': 'ptrace PTRACE_TRACEME credential mishandling',
        'platform': 'linux',
        'category': 'kernel-exploit',
        'severity': 'high',
        'summary': 'ptrace_link() records the wrong credentials when establishing a ptrace '
                   'relationship, letting a local user trace a privileged helper (classically '
                   'pkexec) after a privilege drop and gain root on kernels before 5.1.17.',
        'technique': 'When a process calls PTRACE_TRACEME, ptrace_link() stores a reference to the '
                     "tracer's credentials but incorrectly marks the relationship as privileged "
                     'based on stale credential state. By arranging a parent that drops privileges '
                     'and then execve()s a SUID helper such as pkexec, an attacker gets the kernel '
                     'to treat the ptrace relationship as privileged, allowing the unprivileged '
                     'tracer to influence the privileged process and execute code as root. Jann '
                     'Horn discovered and reported the flaw.',
        'prerequisites': [   'Local unprivileged shell',
                             'A suitable SUID helper (e.g. pkexec) reachable',
                             'Vulnerable kernel before 5.1.17'],
        'enumeration': [   'uname -r',
                           'ls -la $(which pkexec) 2>/dev/null',
                           'cat /proc/sys/kernel/yama/ptrace_scope'],
        'detection_indicators': [   'Kernel version 4.10 through < 5.1.17',
                                    'SUID pkexec available',
                                    'linux-exploit-suggester flags CVE-2019-13272'],
        'tools': ['linux-exploit-suggester', 'linpeas', 'searchsploit', 'uname'],
        'cve': ['CVE-2019-13272'],
        'mitigation': [   'Update to kernel 5.1.17 or distro backport',
                          'Seccomp policies that block ptrace (default in Docker/Podman) mitigate; '
                          'SELinux deny_ptrace can help'],
        'poc_references': [   'https://github.com/jas502n/CVE-2019-13272',
                              'https://www.exploit-db.com/exploits/47163'],
        'research_references': [   'https://access.redhat.com/articles/4292201',
                                   'https://nvd.nist.gov/vuln/detail/CVE-2019-13272']},
    {   'id': 'linux-sequoia-cve-2021-33909',
        'name': 'Sequoia (seq_file size_t conversion OOB write)',
        'platform': 'linux',
        'category': 'kernel-exploit',
        'severity': 'high',
        'summary': "An out-of-bounds write in the kernel's seq_file/filesystem layer, reachable by "
                   'creating a deeply nested directory path, gives local root on default '
                   'installations of Ubuntu, Debian, and Fedora on kernels since 2014.',
        'technique': 'When the kernel converts a long file path to a string in the seq_file '
                     'interface (via the filesystem layer), a size_t length value is improperly '
                     'cast to a signed int in a size comparison. By creating, mounting, and '
                     'deleting a directory structure whose path length exceeds 1 GB and then '
                     'operating on it, an unprivileged user drives the flawed length check to '
                     'write out of bounds on the kernel heap. Qualys chained this into full '
                     'arbitrary write and root. It affects essentially all Linux kernels from 3.16 '
                     '(2014) up to the July 2021 fix and works on stock installs.',
        'prerequisites': [   'Local unprivileged shell (unprivileged user namespace helps on some '
                             'distros)',
                             'Vulnerable kernel 3.16 through pre-July-2021 fix'],
        'enumeration': [   'uname -r',
                           'cat /etc/os-release',
                           'sysctl kernel.unprivileged_userns_clone'],
        'detection_indicators': [   'Kernel between 3.16 and the July 2021 fix',
                                    'Default Ubuntu/Debian/Fedora kernel without the patch',
                                    'linux-exploit-suggester flags CVE-2021-33909'],
        'tools': ['linux-exploit-suggester', 'linpeas', 'searchsploit', 'uname'],
        'cve': ['CVE-2021-33909'],
        'mitigation': [   'Apply the July 20, 2021 kernel updates from your distro',
                          'Set /proc/sys/kernel/unprivileged_userns_clone=0 and '
                          'user.max_user_namespaces=0 as a temporary mitigation on some distros'],
        'poc_references': [   'https://www.qualys.com/2021/07/20/cve-2021-33909/sequoia-local-privilege-escalation-linux.txt',
                              'https://www.exploit-db.com/exploits/50134'],
        'research_references': [   'https://blog.qualys.com/vulnerabilities-threat-research/2021/07/20/sequoia-a-local-privilege-escalation-vulnerability-in-linuxs-filesystem-layer-cve-2021-33909',
                                   'https://nvd.nist.gov/vuln/detail/CVE-2021-33909']},
    {   'id': 'linux-snapd-dirtysock-cve-2019-7304',
        'name': 'snapd dirty_sock (UNIX socket UID parsing)',
        'platform': 'linux',
        'category': 'service-misconfig',
        'severity': 'high',
        'summary': "snapd's local REST API over a UNIX socket incorrectly parses the client's peer "
                   'credentials, letting any local user access restricted API functions to create '
                   'a root user or sideload a malicious snap, gaining root on default Ubuntu and '
                   'other distros.',
        'technique': 'snapd restricts privileged API endpoints by checking the UID of the '
                     'connecting socket peer. A string-parsing loop over the socket peer address '
                     'lets a client inject characters that overwrite the parsed UID variable, so '
                     "the attacker's connection is treated as UID 0. With root-equivalent API "
                     'access, the exploit either calls the user-creation API to add a sudo-capable '
                     'account or sideloads a snap whose install hooks run as root. Affects snapd '
                     '2.28 through 2.37, which ships by default on Ubuntu.',
        'prerequisites': [   'Local unprivileged shell with access to the snapd socket',
                             'Vulnerable snapd 2.28 through 2.37'],
        'enumeration': ['snap version', 'ls -la /run/snapd.socket', 'dpkg -l snapd 2>/dev/null'],
        'detection_indicators': [   'snapd version 2.28-2.37',
                                    '/run/snapd.socket present',
                                    'linpeas / linux-exploit-suggester flags CVE-2019-7304'],
        'tools': ['linpeas', 'linux-exploit-suggester', 'searchsploit'],
        'cve': ['CVE-2019-7304'],
        'mitigation': [   'Update snapd to 2.37.1 or later',
                          'Apply Ubuntu security update USN-3887-1'],
        'poc_references': [   'https://github.com/initstring/dirty_sock',
                              'https://www.exploit-db.com/exploits/46362'],
        'research_references': [   'https://threatprotect.qualys.com/2019/02/15/snapd-dirty-sock-privilege-escalation-vulnerability/',
                                   'https://nvd.nist.gov/vuln/detail/CVE-2019-7304']},
    {   'id': 'linux-ssh-key-and-agent-abuse',
        'name': 'SSH key and ssh-agent abuse (writable authorized_keys, exposed private keys, '
                'agent hijack)',
        'platform': 'linux',
        'category': 'credential-harvesting',
        'severity': 'high',
        'summary': 'Writable authorized_keys files for privileged accounts, readable/unprotected '
                   'private keys, and hijackable ssh-agent sockets let an attacker authenticate as '
                   'root or another privileged user.',
        'technique': "Three vectors: (1) if root's (or another user's) ~/.ssh/authorized_keys — or "
                     'the ~/.ssh directory — is writable, the attacker appends their own public '
                     'key and logs in as that user; (2) private keys stored world-readable, backed '
                     'up insecurely, or reused across accounts can be harvested and used directly; '
                     '(3) if a privileged process leaves an ssh-agent socket accessible '
                     '(SSH_AUTH_SOCK owned by root but reachable, or a shared /tmp/ssh-* socket), '
                     'an attacker who can access the socket uses the loaded keys to authenticate '
                     'elsewhere without possessing the key material. Agent forwarding '
                     '(ForwardAgent yes) into an attacker-controlled host is a related risk.',
        'prerequisites': [   "Write access to a privileged user's authorized_keys/.ssh, OR access "
                             'to a usable private key, OR access to a live ssh-agent socket with '
                             'loaded identities'],
        'enumeration': [   'ls -la /root/.ssh/ /home/*/.ssh/ 2>/dev/null',
                           "find / -name 'authorized_keys' -writable 2>/dev/null",
                           "find / -name 'id_rsa' -o -name 'id_ed25519' -o -name '*.pem' "
                           '2>/dev/null | xargs -r ls -la 2>/dev/null',
                           'env | grep SSH_AUTH_SOCK; ls -la /tmp/ssh-* 2>/dev/null; ss -xlp '
                           '2>/dev/null | grep -i agent'],
        'detection_indicators': [   'authorized_keys or ~/.ssh writable by group/other',
                                    'Private keys with permissions readable by others (not 600) or '
                                    'stored in shared/backup locations',
                                    'ssh-agent sockets under /tmp/ssh-* accessible beyond the '
                                    'owner',
                                    'SSH_AUTH_SOCK pointing at a socket reachable by other users; '
                                    "'ForwardAgent yes' in ssh_config"],
        'tools': ['ssh', 'ssh-add', 'find', 'linpeas', 'linenum'],
        'cve': [],
        'mitigation': [   'authorized_keys and ~/.ssh must be owned by and writable only by the '
                          'account (700/600)',
                          'Protect private keys (600), rotate exposed keys, avoid key reuse',
                          'Avoid agent forwarding to untrusted hosts; restrict agent socket '
                          'permissions'],
        'poc_references': [   'https://book.hacktricks.wiki/en/linux-hardening/privilege-escalation/ssh-forward-agent-exploitation.html',
                              'https://www.clockwork.com/insights/ssh-agent-hijacking/'],
        'research_references': [   'https://man.openbsd.org/ssh-agent',
                                   'https://book.hacktricks.wiki/en/linux-hardening/privilege-escalation/index.html#ssh']},
    {   'id': 'linux-sudo-ld-preload-env-keep',
        'name': 'sudo LD_PRELOAD / LD_LIBRARY_PATH via env_keep / SETENV',
        'platform': 'linux',
        'category': 'sudo',
        'severity': 'high',
        'summary': 'When sudoers preserves LD_PRELOAD or LD_LIBRARY_PATH across the privilege '
                   'boundary (Defaults env_keep or a SETENV tag), a user can force the dynamic '
                   'loader to load an attacker-controlled shared object into a root process, '
                   'executing arbitrary code as root.',
        'technique': 'The dynamic linker honors LD_PRELOAD (a library loaded before all others) '
                     'and LD_LIBRARY_PATH (extra library search path). sudo normally strips these '
                     "'unsafe' variables. If sudoers contains 'Defaults env_keep += LD_PRELOAD' / "
                     "'LD_LIBRARY_PATH', or a command is tagged SETENV, the variables survive into "
                     'the elevated process. A user builds a shared object exporting a constructor '
                     'and preloads it while invoking any sudo-permitted command, running their '
                     'constructor as root. LD_LIBRARY_PATH variants override a legitimate library '
                     'the target binary depends on.',
        'prerequisites': [   'At least one sudo-runnable command (even a harmless one)',
                             'sudoers preserves LD_PRELOAD/LD_LIBRARY_PATH via env_keep, or the '
                             'command carries a SETENV tag'],
        'enumeration': [   "sudo -l   # inspect the 'env_keep' and per-command tags",
                           "grep -E 'env_keep|env_reset|setenv|SETENV' /etc/sudoers "
                           '/etc/sudoers.d/* 2>/dev/null'],
        'detection_indicators': [   "'env_keep+=LD_PRELOAD' or 'env_keep+=LD_LIBRARY_PATH' in sudo "
                                    '-l / sudoers',
                                    "'SETENV:' tag on a permitted command",
                                    "Absence of 'env_reset' or presence of 'Defaults !env_reset'",
                                    'NOPASSWD',
                                    'LD_PRELOAD'],
        'tools': ['sudo -l', 'linpeas', 'linenum'],
        'cve': [],
        'mitigation': [   "Keep 'Defaults env_reset' and do not add LD_PRELOAD/LD_LIBRARY_PATH to "
                          'env_keep',
                          'Avoid the SETENV tag on sudo rules',
                          'Prefer secure_path and a minimal preserved environment'],
        'poc_references': [   'https://touhidshaikh.com/blog/2018/04/sudo-ld_preload-linux-privilege-escalation/',
                              'https://www.hackingarticles.in/linux-privilege-escalation-using-ld_preload/'],
        'research_references': [   'https://book.hacktricks.wiki/en/linux-hardening/privilege-escalation/index.html#ld_preload-and-ld_library_path',
                                   'https://man7.org/linux/man-pages/man8/ld.so.8.html']},
    {   'id': 'linux-sudo-runas-negation-crossuser',
        'name': 'sudo runas negation and cross-user escalation',
        'platform': 'linux',
        'category': 'sudo',
        'severity': 'high',
        'summary': "Runas specifications that use negation ('!root', 'ALL, !root') or that permit "
                   'running commands as a non-root but powerful user can be abused: the negation '
                   'semantics were bypassable, and a permitted intermediate user may itself hold '
                   'privileges leading to root.',
        'technique': 'sudoers Runas_Spec controls which target identities a command may assume. A '
                     "rule intended to permit 'any user except root' (e.g. '(ALL, !root)') was "
                     'bypassable by requesting an invalid user ID that sudo resolved to root '
                     "(CVE-2019-14287, via 'sudo -u#-1'). Even without that bug, permitting a user "
                     'to run commands as a non-root account is dangerous when that account is a '
                     'member of a privileged group (docker, lxd, disk), owns cron jobs/scripts '
                     'that run as root, or can read secrets — a chained pivot to root. Related '
                     'sudo feature-abuse: pwfeedback stack overflow (CVE-2019-18634) and the Baron '
                     'Samedit heap overflow (CVE-2021-3156) affect old sudo versions.',
        'prerequisites': [   'sudoers Runas_Spec with negation, or permission to run as an '
                             'intermediate privileged account',
                             "For CVE-2019-14287: sudo < 1.8.28 with a '!root' style rule"],
        'enumeration': [   "sudo -l   # examine the '(runas)' field, especially negations and "
                           'non-root targets',
                           'sudo -V | head -1   # version check for CVE-2019-14287 / CVE-2021-3156 '
                           '/ CVE-2019-18634',
                           'id <target-user>; groups <target-user>   # assess power of a permitted '
                           'runas account'],
        'detection_indicators': [   "'(ALL, !root)' or any '!' negation in the runas field of sudo "
                                    '-l',
                                    'sudo version < 1.8.28 (CVE-2019-14287)',
                                    'runas target user that belongs to docker/lxd/disk/adm groups '
                                    'or owns root-run scripts',
                                    'NOPASSWD'],
        'tools': ['sudo -l', 'linpeas', 'linenum'],
        'cve': ['CVE-2019-14287', 'CVE-2019-18634', 'CVE-2021-3156'],
        'mitigation': [   'Never rely on runas negation; explicitly list allowed target users',
                          'Keep sudo patched (>= 1.8.28 for CVE-2019-14287; >= 1.9.5p2 for '
                          'CVE-2021-3156)',
                          "Treat 'run as non-root X' grants as equivalent to X's full privileges"],
        'poc_references': [   'https://www.exploit-db.com/exploits/47502',
                              'https://www.qualys.com/2021/01/26/cve-2021-3156/baron-samedit-heap-based-overflow-sudo.txt'],
        'research_references': [   'https://www.sudo.ws/security/advisories/minus_1_uid/',
                                   'https://book.hacktricks.wiki/en/linux-hardening/privilege-escalation/index.html#sudo']},
    {   'id': 'linux-sudoedit-cve-2023-22809',
        'name': "Sudoedit arbitrary file edit (EDITOR '--' bypass)",
        'platform': 'linux',
        'category': 'sudo',
        'severity': 'high',
        'summary': "A flaw in sudoedit's handling of user-controlled editor environment variables "
                   'lets a user granted sudoedit rights on specific files edit arbitrary files '
                   '(including /etc/sudoers or /etc/passwd) as root.',
        'technique': 'sudoedit derives the editor command from SUDO_EDITOR/VISUAL/EDITOR. The '
                     "parsing that builds the argument list treats an embedded '--' as an editor "
                     'argument rather than the end-of-options marker sudoedit uses to separate the '
                     "editor from the file list. By setting EDITOR='vim -- /path/to/target', an "
                     'attacker smuggles an extra file path past the sudoers policy check, so the '
                     'privileged edit is applied to a file the policy never authorized. This turns '
                     "a narrow 'edit file X' grant into arbitrary root file modification.",
        'prerequisites': [   'A sudoers rule granting the user sudoedit / sudo -e on at least one '
                             'file',
                             'Vulnerable sudo 1.8.0 through 1.9.12p1'],
        'enumeration': ['sudo --version', 'sudo -l (look for sudoedit / (root) sudoedit entries)'],
        'detection_indicators': [   'sudo version 1.8.0 through 1.9.12p1',
                                    '`sudo -l` shows a sudoedit rule for the current user',
                                    'linux-exploit-suggester / linpeas flags CVE-2023-22809',
                                    'NOPASSWD'],
        'tools': ['linpeas', 'sudo', 'gtfobins', 'searchsploit'],
        'cve': ['CVE-2023-22809'],
        'mitigation': [   'Upgrade sudo to 1.9.12p2 or backport',
                          'Workaround: add `Defaults!sudoedit env_delete+="SUDO_EDITOR VISUAL '
                          'EDITOR"` to sudoers'],
        'poc_references': [   'https://github.com/n3m1dch/CVE-2023-22809',
                              'https://www.exploit-db.com/exploits/51217'],
        'research_references': [   'https://www.synacktiv.com/sites/default/files/2023-01/sudo-CVE-2023-22809.pdf',
                                   'https://nvd.nist.gov/vuln/detail/CVE-2023-22809',
                                   'https://www.sudo.ws/security/advisories/sudoedit_any/']},
    {   'id': 'linux-sudoedit-wildcard-symlink',
        'name': 'sudoedit / sudo path-wildcard and symlink abuse',
        'platform': 'linux',
        'category': 'sudo',
        'severity': 'high',
        'summary': 'sudoers rules that use wildcards in file paths for sudoedit, or that let a '
                   'user edit a file in a directory they control, can be leveraged to edit '
                   'arbitrary root-owned files (or inject an editor) and escalate to root.',
        'technique': "A sudoers entry like 'sudoedit /home/*/report' or 'user ALL=(root) sudoedit "
                     "/path/*' lets the wildcard match attacker-controlled paths. When the "
                     'permitted directory component is writable or a symlink can be planted, the '
                     'user redirects the privileged edit to a sensitive file (e.g. /etc/sudoers, '
                     '/etc/passwd, an authorized_keys file, or a root cron file). Historically, '
                     'sudoedit followed symlinks in the final path component when wildcards were '
                     'present (CVE-2015-5602), and sudoedit honored extra file arguments smuggled '
                     'through the user-controlled EDITOR/SUDO_EDITOR variable (CVE-2023-22809), '
                     'each allowing edit of files outside the intended set.',
        'prerequisites': [   'sudoers grants sudoedit/editing with a wildcard path or a writable '
                             'directory component',
                             'Ability to create symlinks or files in the matched directory (or set '
                             'EDITOR for CVE-2023-22809)'],
        'enumeration': [   'sudo -l   # look for sudoedit entries or editor commands with * in the '
                           'path',
                           'sudoedit --version 2>/dev/null; sudo -V | head -1   # version for '
                           'CVE-2023-22809 (< 1.9.12p2)',
                           "grep -R 'sudoedit\\|\\*' /etc/sudoers /etc/sudoers.d/ 2>/dev/null"],
        'detection_indicators': [   "'sudoedit' rules containing '*' or a directory the user can "
                                    'write to',
                                    'sudo version below 1.9.12p2 (CVE-2023-22809)',
                                    'sudo version 1.8.x with wildcard sudoedit rules '
                                    '(CVE-2015-5602)',
                                    'NOPASSWD'],
        'tools': ['sudo -l', 'linpeas'],
        'cve': ['CVE-2015-5602', 'CVE-2023-22809'],
        'mitigation': [   'Avoid wildcards in sudoedit/editor path specs; enumerate exact files',
                          'Upgrade sudo to >= 1.9.12p2',
                          'Ensure parent directories of editable files are root-owned and '
                          'non-writable'],
        'poc_references': [   'https://www.exploit-db.com/exploits/37710',
                              'https://www.synacktiv.com/en/publications/cve-2023-22809-sudoedit-bypass-in-sudo-versions-before-1912p2.html'],
        'research_references': [   'https://www.sudo.ws/security/advisories/sudoedit_escape/',
                                   'https://book.hacktricks.wiki/en/linux-hardening/privilege-escalation/index.html#sudo']},
    {   'id': 'linux-systemd-timer-writable-unit',
        'name': 'systemd timer / triggered-unit abuse',
        'platform': 'linux',
        'category': 'cron-timers',
        'severity': 'high',
        'summary': 'A systemd .timer that triggers a .service whose unit file (or the ExecStart '
                   'target) is writable by a non-root user allows code execution as root when the '
                   'timer fires.',
        'technique': 'systemd timers replace cron on modern systems. A .timer unit activates a '
                     'matching .service. If either the .service unit file, the .timer file, or the '
                     'executable/script referenced by ExecStart is writable by the attacker, they '
                     'can point execution at their own payload (or edit the script) and wait for '
                     "the timer to fire as root (or the unit's User=). Relative ExecStart paths "
                     'combined with a controllable service environment can also be hijacked. Unit '
                     'files placed in a writable drop-in directory (/etc/systemd/system/<unit>.d/) '
                     'are equally abusable.',
        'prerequisites': [   'An active systemd timer triggering a root service',
                             'Write access to the .timer/.service unit, a drop-in directory, or '
                             'the ExecStart target'],
        'enumeration': [   'systemctl list-timers --all',
                           'systemctl cat <timer>.timer <service>.service 2>/dev/null',
                           'ls -la /etc/systemd/system/ /lib/systemd/system/ /run/systemd/system/ '
                           '2>/dev/null',
                           'find /etc/systemd/ /lib/systemd/ /run/systemd/ -writable 2>/dev/null',
                           "for u in $(systemctl list-timers --all --no-legend | awk '{print "
                           '$NF}\'); do systemctl cat "$u" 2>/dev/null; done'],
        'detection_indicators': [   'Unit files (.service/.timer) writable by group/other in find '
                                    '-writable output',
                                    'ExecStart= pointing at a script/binary in a user-writable '
                                    'path',
                                    'Writable systemd drop-in directories (*.service.d)',
                                    'Relative (non-absolute) ExecStart command'],
        'tools': ['systemctl', 'linpeas', 'pspy', 'linux-smart-enumeration'],
        'cve': [],
        'mitigation': [   'Ensure all unit files and their ExecStart targets are root-owned and '
                          'non-writable',
                          'Use absolute ExecStart paths',
                          'Restrict write access to /etc/systemd and drop-in directories'],
        'poc_references': [   'https://book.hacktricks.wiki/en/linux-hardening/privilege-escalation/index.html#timers',
                              'https://juggernaut-sec.com/systemd-timers-lpe/'],
        'research_references': [   'https://www.freedesktop.org/software/systemd/man/systemd.timer.html',
                                   'https://book.hacktricks.wiki/en/linux-hardening/privilege-escalation/index.html#systemd-path-relative-paths']},
    {   'id': 'linux-wildcard-argument-injection',
        'name': 'Wildcard / argument injection (tar, rsync, chown, chmod, zip, 7z)',
        'platform': 'linux',
        'category': 'wildcard-injection',
        'severity': 'high',
        'summary': 'When a privileged script or cron/service job runs a command with an unquoted '
                   "shell glob (e.g. '*') in a directory a user can write, filenames crafted to "
                   'look like command-line options are expanded into arguments, enabling command '
                   'execution or file-permission changes as root.',
        'technique': "The shell expands '*' into the alphabetical list of filenames, which are "
                     'then passed as arguments. If an attacker can create files in the globbed '
                     'directory, they create files whose names are option strings. Classic cases: '
                     "GNU tar's '--checkpoint=1' plus '--checkpoint-action=exec=<cmd>' (or "
                     "'--use-compress-program') turn a 'tar ... *' backup into arbitrary command "
                     "execution; rsync's '-e' / '--rsh' does the same; chown/chmod's "
                     "'--reference=<file>' makes the job copy ownership/permissions from an "
                     'attacker-chosen file. The privileged job need only run the command with a '
                     "bare '*' in a writable directory. This is a benign misconfiguration of "
                     'otherwise-legitimate maintenance scripts.',
        'prerequisites': [   'A privileged job running tar/rsync/chown/chmod/zip with an unquoted '
                             'glob',
                             'Write access to the directory whose contents are globbed'],
        'enumeration': [   "cat /etc/crontab /etc/cron.d/* 2>/dev/null   # look for '*' in "
                           'tar/rsync/chown/chmod lines',
                           './pspy64   # observe the exact argv of scheduled privileged commands',
                           "grep -R -- 'tar\\|rsync\\|chown\\|chmod\\|zip' /etc/cron* /etc/systemd "
                           "2>/dev/null | grep '\\*'",
                           'ls -la <the-globbed-directory>   # confirm you can create files there'],
        'detection_indicators': [   "A root cron/service command containing an unquoted '*' (e.g. "
                                    "'tar czf backup.tgz *', 'chown -R app *')",
                                    'The globbed working directory is writable by non-root users',
                                    "Use of tar/rsync without '--' or absolute file lists"],
        'tools': ['pspy', 'linpeas', 'linenum'],
        'cve': [],
        'mitigation': [   'Avoid bare globs in privileged scripts; use absolute file lists or '
                          "'find -print0 | xargs -0'",
                          "Separate options from operands with '--' and anchor paths (e.g. './*')",
                          'Run backups over directories not writable by untrusted users'],
        'poc_references': [   'https://www.exploit-db.com/papers/33930',
                              'http://blog.defensecode.com/2014/06/back-to-future-unix-wildcards-gone-wild.html'],
        'research_references': [   'https://book.hacktricks.wiki/en/linux-hardening/privilege-escalation/wildcards-spare-tricks.html',
                                   'https://www.helpnetsecurity.com/2014/06/27/exploiting-wildcards-on-linux/']},
    {   'id': 'linux-writable-init-motd-pam-profile',
        'name': 'Writable init/rc scripts, MOTD (pam_motd) scripts, and profile/PAM hooks',
        'platform': 'linux',
        'category': 'writable-file',
        'severity': 'high',
        'summary': 'Boot/login-time scripts that run as root — SysV init scripts, /etc/rc.local, '
                   'dynamic MOTD scripts in /etc/update-motd.d, and /etc/profile.d hooks — are '
                   'code-execution primitives if writable by a low-privileged user; the MOTD '
                   'scripts in particular run as root on every SSH/console login via pam_motd.',
        'technique': 'Several files are executed automatically by root or by the login stack. '
                     '/etc/rc.local and /etc/init.d/* run at boot as root; if writable, an '
                     "attacker's code runs at the next reboot. On Debian/Ubuntu, the pam_motd "
                     'module executes every script in /etc/update-motd.d/ as root at each '
                     'interactive login — a writable script there yields root on the next '
                     'SSH/console login (the attacker triggers it simply by logging in). '
                     '/etc/profile, /etc/profile.d/*.sh, and /etc/bash.bashrc run for shells and, '
                     'if writable, execute in the context of whoever logs in (including root '
                     'sessions). Writable PAM configuration or module paths similarly permit '
                     'hijacking authentication flows.',
        'prerequisites': [   'Write access to an init script, /etc/rc.local, an /etc/update-motd.d '
                             'script, or a profile/PAM hook that root will execute',
                             'A trigger: a reboot, an interactive login (for MOTD/profile), or a '
                             'root shell session'],
        'enumeration': [   'ls -la /etc/update-motd.d/ /etc/rc.local /etc/init.d/ 2>/dev/null',
                           'ls -la /etc/profile /etc/profile.d/ /etc/bash.bashrc 2>/dev/null',
                           'find /etc/update-motd.d /etc/init.d /etc/rc*.d /etc/profile.d '
                           '-writable 2>/dev/null',
                           "ls -la /etc/pam.d/ 2>/dev/null; grep -R 'pam_motd\\|pam_exec' "
                           '/etc/pam.d/ 2>/dev/null'],
        'detection_indicators': [   'Files under /etc/update-motd.d/ writable by group/other '
                                    '(executed as root by pam_motd on login)',
                                    '/etc/rc.local, /etc/init.d/* or /etc/rc*.d links writable by '
                                    'non-root',
                                    '/etc/profile, /etc/profile.d/*.sh or /etc/bash.bashrc '
                                    'writable by non-root',
                                    'pam_exec lines in /etc/pam.d referencing writable scripts'],
        'tools': ['find', 'ls', 'linpeas', 'linux-smart-enumeration', 'pspy'],
        'cve': [],
        'mitigation': [   'All boot, MOTD, profile, and PAM scripts must be root-owned and '
                          'non-writable by others',
                          'Audit /etc/update-motd.d permissions (executed as root at every login)',
                          'File-integrity monitoring on init, rc.local, profile.d, and pam.d'],
        'poc_references': [   'https://vk9-sec.com/write-to-etc-update-motd-privilege-escalation/',
                              'https://book.hacktricks.wiki/en/linux-hardening/privilege-escalation/index.html#init-init-d-systemd-and-rc-d'],
        'research_references': [   'https://man7.org/linux/man-pages/man8/pam_motd.8.html',
                                   'https://book.hacktricks.wiki/en/linux-hardening/privilege-escalation/index.html']},
    {   'id': 'linux-writable-systemd-service-unit',
        'name': 'Writable systemd service unit / relative ExecStart hijack',
        'platform': 'linux',
        'category': 'service-misconfig',
        'severity': 'high',
        'summary': 'A systemd service unit file that is writable by a low-privileged user, or that '
                   'references a writable executable or a relative path, lets that user run '
                   'arbitrary code as root at the next start/restart or reload.',
        'technique': "systemd runs service ExecStart/ExecStartPre commands as root (or the unit's "
                     'User=). If the unit file itself is writable, an attacker rewrites ExecStart '
                     "to their payload, runs 'systemctl daemon-reload', and triggers a "
                     'start/restart (directly if permitted, or by waiting for a '
                     'reboot/dependency). Even without editing the unit, a writable ExecStart '
                     'target binary/script, a writable drop-in override directory, or a relative '
                     'ExecStart resolved against a controllable PATH yields the same result. Being '
                     "permitted to 'systemctl restart <svc>' via sudo compounds this.",
        'prerequisites': [   'Write access to a service unit, its drop-in directory, or the '
                             'ExecStart executable',
                             'A path to trigger (re)start: sudo systemctl, socket/dependency '
                             'activation, or reboot'],
        'enumeration': [   'find /etc/systemd/system /lib/systemd/system /run/systemd/system '
                           '-writable -type f 2>/dev/null',
                           'systemctl list-unit-files --type=service',
                           'systemctl cat <service>.service',
                           'ls -la $(systemctl cat <service>.service 2>/dev/null | grep -oP '
                           "'ExecStart=\\K\\S+')"],
        'detection_indicators': [   'Service unit files writable by group/other',
                                    'ExecStart/ExecStartPre pointing at a user-writable file',
                                    'Writable *.service.d drop-in directories',
                                    'Non-absolute ExecStart command'],
        'tools': ['systemctl', 'linpeas', 'linux-smart-enumeration', 'pspy'],
        'cve': [],
        'mitigation': [   'Unit files and their targets must be root-owned, mode 644/755, '
                          'non-writable by others',
                          'Use absolute paths in ExecStart',
                          'Restrict sudo systemctl grants and write access to systemd directories'],
        'poc_references': [   'https://book.hacktricks.wiki/en/linux-hardening/privilege-escalation/index.html#writable-systemd-path-binaries',
                              'https://juggernaut-sec.com/systemd-lpe/'],
        'research_references': [   'https://www.freedesktop.org/software/systemd/man/systemd.service.html',
                                   'https://book.hacktricks.wiki/en/linux-hardening/privilege-escalation/index.html#services']},
    {   'id': 'macos-dylib-hijacking-dyld-insert',
        'name': 'macOS dylib hijacking / DYLD_INSERT_LIBRARIES injection',
        'platform': 'macos',
        'category': 'dylib-hijack',
        'severity': 'high',
        'summary': 'A privileged or entitled Mach-O process that searches a writable path for a '
                   'missing/weak-linked dylib, or that does not enforce hardened runtime/library '
                   'validation, can be made to load an attacker library — running code in its '
                   '(higher-privilege or entitled) context.',
        'technique': 'Two related primitives. (1) Dylib hijacking (Patrick Wardle): a binary with '
                     'an LC_LOAD_WEAK_DYLIB for a library that is absent, or with an @rpath search '
                     'order where an earlier rpath entry is attacker-writable, will load a planted '
                     'dylib at that path. Placing a malicious library there causes the target to '
                     "load and execute it on launch, inheriting the target's "
                     'privileges/entitlements. (2) DYLD_INSERT_LIBRARIES: the dynamic loader '
                     'force-loads libraries named in this environment variable — for any process '
                     'the attacker can spawn with a controlled environment that is not protected '
                     'by hardened runtime (which strips DYLD_* vars) or library validation. '
                     'Hijacking an entitled or root/SUID process this way yields privilege '
                     'escalation, TCC-grant inheritance, or persistence. dylibhijack/DylibHijack '
                     'tooling finds vulnerable @rpath binaries automatically.',
        'prerequisites': [   'a target Mach-O that weak-links or @rpath-searches a writable '
                             'location, OR',
                             'a launchable process lacking hardened runtime / library validation '
                             'to use DYLD_INSERT_LIBRARIES',
                             'write access to the relevant search path'],
        'enumeration': [   'otool -l /path/to/binary | grep -A3 LC_RPATH',
                           'otool -L /path/to/binary',
                           'codesign -dv --verbose=4 /path/to/App.app',
                           'codesign -d --entitlements - /path/to/binary',
                           'DYLD_PRINT_LIBRARIES=1 /path/to/binary'],
        'detection_indicators': [   'DYLD_INSERT_LIBRARIES',
                                    'LC_LOAD_WEAK_DYLIB',
                                    '@rpath',
                                    'LC_RPATH',
                                    'library validation',
                                    'com.apple.security.cs.disable-library-validation'],
        'tools': [   'dylibhijackscanner',
                     'insert_dylib',
                     'otool',
                     'codesign',
                     'objective-see-utilities'],
        'cve': [],
        'mitigation': [   'Ship apps with hardened runtime enabled (strips DYLD_* and enforces '
                          'library validation)',
                          'Avoid weak/@rpath dylib references pointing at user-writable locations',
                          'Enforce code-signing and notarization; set restricted segment where '
                          'appropriate',
                          'Monitor for unexpected dylib loads in privileged processes'],
        'poc_references': [   'https://www.virusbulletin.com/virusbulletin/2015/03/dylib-hijacking-os-x',
                              'https://github.com/objective-see/DHS'],
        'research_references': [   'https://book.hacktricks.xyz/macos-hardening/macos-security-and-privilege-escalation/macos-dyld-hijacking-and-dyld_insert_libraries',
                                   'https://theevilbit.github.io/posts/dyld_insert_libraries_dylib_injection_in_macos_osx_deep_dive/']},
    {   'id': 'macos-suid-authorizationdb-packagekit-root',
        'name': 'macOS SUID / AuthorizationDB / PackageKit local root',
        'platform': 'macos',
        'category': 'privilege-escalation',
        'severity': 'high',
        'summary': 'Local root on macOS via abusable SUID/setuid binaries, sudo misconfig, '
                   'tampering with the Authorization database rules, or logic bugs in privileged '
                   'installer components (PackageKit / system_installd, shared-file-list) that run '
                   'attacker-influenced code as root and can bypass SIP.',
        'technique': 'Several classic local-root avenues. (1) SUID/sudo: GTFOBins-style abuse of '
                     'setuid binaries or sudo rules, same as Linux, applies to macOS-specific SUID '
                     'binaries. (2) Authorization database: /var/db/auth.db (backed by '
                     '/System/Library/Security/authorization.plist) maps rights like '
                     'system.privilege.admin to rules; a process able to edit auth rules (or an '
                     'XPC helper with weak client validation) can lower the requirement for a '
                     'privileged operation and then invoke it. (3) PackageKit / system_installd: '
                     'the system_installd daemon runs Apple-signed packages as root with the '
                     'com.apple.rootless.install.heritable entitlement (CS_INSTALLER), so a logic '
                     'flaw letting an attacker influence a post-install script or a path it '
                     'touches yields root and SIP bypass — Apple issued a long chain of patches '
                     '(CVE-2022-26688, CVE-2023-23497, CVE-2024-23275, CVE-2024-44178, and '
                     'related). (4) Gatekeeper/quarantine bypasses such as CVE-2021-30657 let '
                     'unsigned code run as the user without prompts, a common first stage. Csaba '
                     "Fitzl's research documents shared-file-list and installer-based root "
                     'escalations in depth.',
        'prerequisites': [   'local code execution as a normal user',
                             'an abusable SUID/sudo rule, writable auth rule / weak XPC helper, or '
                             'an unpatched PackageKit/installd logic bug'],
        'enumeration': [   'find / -perm -4000 -type f 2>/dev/null',
                           'sudo -l',
                           'security authorizationdb read system.privilege.admin',
                           'ls -la /var/db/auth.db',
                           'csrutil status',
                           'codesign -d --entitlements - '
                           '/System/Library/PrivateFrameworks/PackageKit.framework'],
        'detection_indicators': [   '-rwsr-xr-x',
                                    'system.privilege.admin',
                                    'authorizationdb',
                                    'com.apple.rootless.install.heritable',
                                    'system_installd',
                                    'CS_INSTALLER'],
        'tools': ['gtfobins', 'swiftbelt', 'knockout', 'codesign', 'objective-see-utilities'],
        'cve': ['CVE-2021-30657', 'CVE-2022-26688', 'CVE-2024-23275'],
        'mitigation': [   'Keep macOS patched (installer/PackageKit and Gatekeeper fixes ship '
                          'regularly)',
                          'Minimize SUID binaries and permissive sudoers; protect /var/db/auth.db '
                          '(SIP)',
                          'Validate XPC clients (audit token) in privileged helpers',
                          'Enable SIP and Gatekeeper; require notarization'],
        'poc_references': [   'https://khronokernel.com/macos/2024/06/03/CVE-2024-27822.html',
                              'https://jhftss.github.io/Endless-Exploits/',
                              'https://cedowens.medium.com/macos-gatekeeper-bypass-2021-edition-5256a2955508'],
        'research_references': [   'https://book.hacktricks.xyz/macos-hardening/macos-security-and-privilege-escalation',
                                   'https://theevilbit.github.io/posts/']},
    {   'id': 'macos-tcc-privacy-bypass',
        'name': 'macOS TCC privacy database bypass',
        'platform': 'macos',
        'category': 'tcc-bypass',
        'severity': 'high',
        'summary': 'Transparency, Consent and Control (TCC) gates access to protected data (files, '
                   'camera, mic, automation, full disk). Attackers bypass it by riding a '
                   'Full-Disk-Access-granted app, injecting into entitled/injectable processes '
                   '(e.g. non-hardened Electron apps), or directly manipulating the TCC.db when '
                   'protection is weak.',
        'technique': 'TCC stores per-app grants in SQLite (~/Library/Application '
                     'Support/com.apple.TCC/TCC.db for the user, /Library/... for the system). '
                     'Bypasses: (1) piggyback on an app already granted Full Disk Access (e.g. '
                     'Terminal, a backup or EDR agent) to read protected paths its permission '
                     'covers; (2) inject code into a process that holds a privacy entitlement '
                     '(com.apple.private.tcc.allow) or is not hardened-runtime/library-validation '
                     'protected — many Electron and third-party apps allow DYLD injection or '
                     "plugin loading, inheriting the host's TCC grants; (3) directly read/modify "
                     'TCC.db if the attacker already has FDA or the DB is not SIP-protected, '
                     'adding a fake ALLOW row; (4) abuse specific Apple bugs such as PowerDir '
                     '(CVE-2021-30970, changing the target of the user TCC dir), CVE-2020-9934 '
                     "(env-var path confusion in tccd), and XCSSET's CVE-2021-30713. The result is "
                     'access to Documents, Photos, Messages, camera/mic, or full disk without a '
                     'consent prompt.',
        'prerequisites': [   'local code execution as a user, or an injectable/entitled app to '
                             'hijack',
                             'for direct TCC.db edits: existing Full Disk Access or an unpatched '
                             'SIP/tccd bug'],
        'enumeration': [   "sqlite3 ~/Library/Application\\ Support/com.apple.TCC/TCC.db 'select "
                           "service,client,auth_value from access'",
                           'tccutil reset All',
                           'codesign -d --entitlements - /path/to/App.app',
                           'csrutil status',
                           'ls -la /Library/Application\\ Support/com.apple.TCC/'],
        'detection_indicators': [   'com.apple.TCC',
                                    'TCC.db',
                                    'kTCCService',
                                    'com.apple.private.tcc.allow',
                                    'SystemPolicyAllFiles',
                                    'hardened runtime'],
        'tools': ['tccutil', 'objective-see-utilities', 'codesign', 'swiftbelt'],
        'cve': ['CVE-2021-30970', 'CVE-2020-9934', 'CVE-2021-30713'],
        'mitigation': [   'Keep macOS patched; enable SIP (protects the system TCC.db)',
                          'Enable hardened runtime + library validation on distributed apps; avoid '
                          'injectable Electron builds',
                          'Limit which apps receive Full Disk Access; audit TCC grants',
                          'Use MDM PPPC profiles to control automation/privacy entitlements'],
        'poc_references': [   'https://www.microsoft.com/en-us/security/blog/2022/01/10/new-macos-vulnerability-powerdir-could-lead-to-unauthorized-user-data-access/',
                              'https://theevilbit.github.io/posts/tcc_a_deep_dive/'],
        'research_references': [   'https://book.hacktricks.xyz/macos-hardening/macos-security-and-privilege-escalation/macos-security-protections/macos-tcc',
                                   'https://objective-see.org/blog.html']},
    {   'id': 'windows-alwaysinstallelevated',
        'name': 'AlwaysInstallElevated MSI',
        'platform': 'windows',
        'category': 'installer-misconfig',
        'severity': 'critical',
        'summary': 'When both the HKLM and HKCU AlwaysInstallElevated policy values equal 1, any '
                   'user can install an MSI package whose actions run with NT AUTHORITY\\SYSTEM '
                   'privileges.',
        'technique': 'AlwaysInstallElevated instructs Windows Installer to run package '
                     'installations with elevated (SYSTEM) rights even for non-administrators. If '
                     'the policy is set to 1 in both the machine and user hives, a low-privileged '
                     'user launches a crafted MSI (msiexec /i /quiet) whose install action '
                     'executes an arbitrary command as SYSTEM. Both keys must be enabled; either '
                     'one alone is not exploitable.',
        'prerequisites': ['AlwaysInstallElevated = 1 in BOTH HKLM and HKCU'],
        'enumeration': [   'reg query HKLM\\SOFTWARE\\Policies\\Microsoft\\Windows\\Installer /v '
                           'AlwaysInstallElevated',
                           'reg query HKCU\\SOFTWARE\\Policies\\Microsoft\\Windows\\Installer /v '
                           'AlwaysInstallElevated',
                           'PowerUp: Get-RegistryAlwaysInstallElevated'],
        'detection_indicators': [   'HKLM\\SOFTWARE\\Policies\\Microsoft\\Windows\\Installer\\AlwaysInstallElevated '
                                    '= 0x1',
                                    'HKCU\\SOFTWARE\\Policies\\Microsoft\\Windows\\Installer\\AlwaysInstallElevated '
                                    '= 0x1',
                                    'msiexec installing packages from user-writable paths and '
                                    'spawning SYSTEM child processes',
                                    'AlwaysInstallElevated'],
        'tools': ['powerup', 'msfvenom', 'winpeas', 'privesccheck', 'reg.exe'],
        'cve': [],
        'mitigation': [   'disable the policy (set to 0 or remove) in both hives via GPO',
                          'never deploy AlwaysInstallElevated in production',
                          'restrict who can run msiexec'],
        'poc_references': [   'https://book.hacktricks.xyz/windows-hardening/windows-local-privilege-escalation#alwaysinstallelevated',
                              'https://www.rapid7.com/db/modules/exploit/windows/local/always_install_elevated/'],
        'research_references': [   'https://attack.mitre.org/techniques/T1548/002/',
                                   'https://learn.microsoft.com/en-us/windows/win32/msi/alwaysinstallelevated']},
    {   'id': 'windows-efspotato-sharpefspotato',
        'name': 'EfsPotato / SharpEfsPotato (MS-EFSR coercion)',
        'platform': 'windows',
        'category': 'token-impersonation',
        'severity': 'critical',
        'summary': 'EfsPotato and the C# SharpEfsPotato abuse the Encrypting File System Remote '
                   'protocol (MS-EFSR / EfsRpc) over local RPC named pipes to coerce SYSTEM '
                   'authentication, then impersonate the SYSTEM token via SeImpersonatePrivilege.',
        'technique': 'The MS-EFSR EfsRpc functions (e.g. EfsRpcOpenFileRaw / EfsRpcEncryptFileSrv) '
                     'accept a UNC/path argument that triggers the caller (running as SYSTEM '
                     'inside lsass/efs) to authenticate to a controlled endpoint. Invoked over a '
                     'local named pipe (lsarpc, efsrpc, samr, lsass, netlogon), this local '
                     'coercion yields a SYSTEM token which SeImpersonatePrivilege lets the '
                     'attacker impersonate to launch a SYSTEM process. Related to the PetitPotam '
                     'coercion family but used locally for privilege escalation.',
        'prerequisites': [   'SeImpersonatePrivilege enabled',
                             'EFSRPC endpoint reachable via a local named pipe (default on many '
                             'builds)'],
        'enumeration': ['whoami /priv', 'systeminfo'],
        'detection_indicators': [   'SeImpersonatePrivilege Enabled',
                                    'EfsRpc named-pipe activity (\\pipe\\lsarpc, \\pipe\\efsrpc) '
                                    'from a service worker',
                                    'EfsPotato.exe / SharpEfsPotato on disk',
                                    'SYSTEM process spawned by MSSQL/IIS worker',
                                    'SeImpersonatePrivilege'],
        'tools': ['efspotato', 'sharpefspotato', 'sweetpotato'],
        'cve': [],
        'mitigation': [   'Apply MS-EFSR / NTLM relay hardening (EPA, SMB signing) and '
                          'PetitPotam-related patches',
                          'Restrict impersonation privileges',
                          'Monitor EfsRpc named-pipe usage from non-standard processes'],
        'poc_references': [   'https://github.com/zcgonvh/EfsPotato',
                              'https://github.com/bugch3ck/SharpEfsPotato'],
        'research_references': [   'https://hacktricks.wiki/en/windows-hardening/windows-local-privilege-escalation/roguepotato-and-printspoofer.html',
                                   'https://attack.mitre.org/techniques/T1134/']},
    {   'id': 'windows-godpotato',
        'name': 'GodPotato (RPCSS/DCOM impersonation, broad OS coverage)',
        'platform': 'windows',
        'category': 'token-impersonation',
        'severity': 'critical',
        'summary': 'GodPotato exploits flaws in the RPCSS/DCOM implementation to obtain and '
                   'impersonate a SYSTEM token from any SeImpersonate-capable context. It has very '
                   'broad coverage (Windows 8 through 11, Server 2012 through 2022) and does not '
                   'depend on the Print Spooler.',
        'technique': 'GodPotato abuses the DCOM/RPC (RPCSS) activation path so a SYSTEM object '
                     "authenticates to a local endpoint under the attacker's control; the returned "
                     'SYSTEM token is impersonated via SeImpersonatePrivilege and used to run an '
                     'arbitrary command as SYSTEM. It generalizes the potato technique across a '
                     'wide range of builds without the version-specific CLSID hunting JuicyPotato '
                     'required, using .NET.',
        'prerequisites': [   'SeImpersonatePrivilege enabled',
                             '.NET runtime present',
                             'Windows 8/Server 2012 through Windows 11/Server 2022'],
        'enumeration': ['whoami /priv', 'systeminfo'],
        'detection_indicators': [   'SeImpersonatePrivilege Enabled on almost any modern build',
                                    'GodPotato.exe / GodPotato-Net*.exe on disk',
                                    'rpcss/DCOM activation from a worker account preceding a '
                                    'SYSTEM child',
                                    'unmanaged->managed .NET process from a service account '
                                    'spawning cmd/powershell as SYSTEM',
                                    'SeImpersonatePrivilege'],
        'tools': ['godpotato', 'deadpotato', 'rustpotato'],
        'cve': [],
        'mitigation': [   'Remove impersonation privileges from application/service accounts where '
                          'feasible',
                          'Keep systems patched',
                          'EDR detections for potato binaries and SYSTEM spawn from service '
                          'accounts'],
        'poc_references': [   'https://github.com/BeichenDream/GodPotato',
                              'https://github.com/lypd0/DeadPotato',
                              'https://github.com/safedv/RustPotato'],
        'research_references': [   'https://hacktricks.wiki/en/windows-hardening/windows-local-privilege-escalation/roguepotato-and-printspoofer.html',
                                   'https://attack.mitre.org/techniques/T1134/001/']},
    {   'id': 'windows-juicypotato',
        'name': 'JuicyPotato (DCOM/BITS OXID abuse)',
        'platform': 'windows',
        'category': 'token-impersonation',
        'severity': 'critical',
        'summary': 'JuicyPotato weaponizes the RottenPotato local NTLM reflection technique '
                   'against DCOM/BITS by letting the attacker choose the CLSID and listening port, '
                   'coercing a SYSTEM DCOM object to authenticate to a local malicious OXID '
                   'resolver and impersonating the resulting SYSTEM token.',
        'technique': 'A DCOM server activation (e.g. BITS or other CLSIDs running as SYSTEM) is '
                     'triggered and pointed at an attacker-controlled OXID resolver on 127.0.0.1. '
                     'The activation performs local NTLM authentication which is reflected/relayed '
                     'to a local RPC endpoint, and the SYSTEM token produced is captured via '
                     'SeImpersonatePrivilege and used to launch a SYSTEM process. JuicyPotato '
                     'exposes CLSID and port selection so different SYSTEM COM servers can be '
                     'tried per Windows version.',
        'prerequisites': [   'SeImpersonatePrivilege or SeAssignPrimaryTokenPrivilege enabled',
                             'Windows <= 10 1803 / Server 2016 (Microsoft hardened DCOM local '
                             'activation on 1809/Server 2019, breaking the original OXID trick)',
                             'A working SYSTEM CLSID for the target OS/build'],
        'enumeration': [   'whoami /priv',
                           'systeminfo (identify OS build to pick a compatible CLSID)'],
        'detection_indicators': [   'SeImpersonatePrivilege Enabled + OS build 1803/Server2016 or '
                                    'older',
                                    'DCOM/BITS activation from a service-account process',
                                    'Loopback RPC/DCOM traffic to 127.0.0.1:135 shortly before a '
                                    'SYSTEM process spawns',
                                    'Sysmon process-create where a service account parent spawns '
                                    'cmd.exe/powershell.exe as SYSTEM',
                                    'SeImpersonatePrivilege'],
        'tools': ['juicypotato', 'juicypotatong'],
        'cve': [],
        'mitigation': [   'Patch to 1809/Server 2019+ where the classic OXID activation is blocked '
                          '(note JuicyPotatoNG revives it via a different CLSID/trick)',
                          'Restrict DCOM activation permissions',
                          'Minimize impersonation privileges on service accounts'],
        'poc_references': [   'https://github.com/ohpe/juicy-potato',
                              'https://github.com/antonioCoco/JuicyPotatoNG'],
        'research_references': [   'https://ohpe.it/juicy-potato/',
                                   'https://hacktricks.wiki/en/windows-hardening/windows-local-privilege-escalation/juicypotato.html',
                                   'https://attack.mitre.org/techniques/T1134/002/']},
    {   'id': 'windows-lsass-dumping',
        'name': 'LSASS memory dumping (credential extraction)',
        'platform': 'windows',
        'category': 'credential-harvesting',
        'severity': 'critical',
        'summary': 'Dumping the memory of the Local Security Authority Subsystem Service '
                   '(lsass.exe) exposes plaintext passwords, NTLM hashes, Kerberos tickets/keys, '
                   'and DPAPI master keys for logged-on users, enabling lateral movement and '
                   'further escalation.',
        'technique': 'With administrative or SeDebug access to lsass.exe, a memory image is '
                     "captured (e.g. Task Manager 'Create dump file', procdump -ma, rundll32 "
                     'comsvcs.dll,MiniDump, or living-off-the-land WerFault paths) and parsed '
                     'offline with mimikatz/pypykatz to recover credential material cached by SSPs '
                     '(wdigest, kerberos, tspkg, livessp). In-memory tools like nanodump produce '
                     'evasive dumps. LSA Protection (PPL) and Credential Guard raise the bar '
                     'significantly.',
        'prerequisites': [   'Local admin or SeDebugPrivilege',
                             'LSASS not protected by RunAsPPL/Credential Guard (or a PPL-bypass '
                             'driver)'],
        'enumeration': [   'whoami /priv (SeDebugPrivilege)',
                           'Get-Process lsass',
                           'reg query HKLM\\SYSTEM\\CurrentControlSet\\Control\\Lsa /v RunAsPPL'],
        'detection_indicators': [   'Handle to lsass.exe with PROCESS_VM_READ (Sysmon Event ID 10, '
                                    'target lsass.exe)',
                                    'comsvcs.dll MiniDump / procdump -ma lsass command lines',
                                    'lsass*.dmp files written to disk',
                                    'Unusual process (not a known EDR/AV) reading lsass memory'],
        'tools': ['mimikatz', 'pypykatz', 'procdump', 'nanodump', 'comsvcs.dll (lolbin)'],
        'cve': [],
        'mitigation': [   'Enable LSA Protection (RunAsPPL) and Credential Guard',
                          'Disable WDigest credential caching (UseLogonCredential=0)',
                          'Restrict debug privilege; deploy EDR with lsass-handle telemetry '
                          '(Sysmon EID 10)'],
        'poc_references': [   'https://github.com/gentilkiwi/mimikatz',
                              'https://github.com/skelsec/pypykatz',
                              'https://github.com/fortra/nanodump'],
        'research_references': [   'https://attack.mitre.org/techniques/T1003/001/',
                                   'https://learn.microsoft.com/en-us/windows-server/security/credentials-protection-and-management/configuring-additional-lsa-protection']},
    {   'id': 'windows-printnightmare-cve-2021-34527',
        'name': 'PrintNightmare (CVE-2021-34527 / CVE-2021-1675)',
        'platform': 'windows',
        'category': 'service-misconfig',
        'severity': 'critical',
        'summary': "A flaw in the Windows Print Spooler's RpcAddPrinterDriver/point-and-print "
                   'handling lets an authenticated user load an attacker-supplied driver DLL that '
                   'the SYSTEM spooler executes, giving local privilege escalation (and remote '
                   'code execution) as SYSTEM.',
        'technique': "The spooler's driver-installation RPC path fails to properly "
                     'validate/authorize driver packages, so a low-privileged (or remote '
                     'authenticated) user can add a printer driver pointing at a malicious DLL. '
                     'The Print Spooler service, running as SYSTEM, loads and executes the DLL, '
                     'yielding SYSTEM code execution. Public PoCs implement the '
                     'RpcAddPrinterDriverEx call; mimikatz integrated the technique. CVE-2021-1675 '
                     'was the initially-patched LPE and CVE-2021-34527 the follow-on RCE variant.',
        'prerequisites': [   'Print Spooler service running and reachable (local for LPE; '
                             'MS-RPRN/MS-PAR over SMB for remote)',
                             'Any authenticated account; Point-and-Print settings often required '
                             'for the low-priv path'],
        'enumeration': [   'sc query spooler / Get-Service Spooler',
                           'reg query "HKLM\\SOFTWARE\\Policies\\Microsoft\\Windows '
                           'NT\\Printers\\PointAndPrint"',
                           'rpcdump.py <host> | findstr MS-RPRN'],
        'detection_indicators': [   'New DLL written under '
                                    'C:\\Windows\\System32\\spool\\drivers\\x64\\3\\ then loaded '
                                    'by spoolsv.exe',
                                    'spoolsv.exe spawning cmd/powershell or loading an unusual DLL '
                                    '(Sysmon EID 7/1)',
                                    "Event 808/Microsoft-Windows-PrintService admin log 'failed to "
                                    "load' driver entries",
                                    'RpcAddPrinterDriverEx over MS-RPRN from an unexpected host'],
        'tools': [   'cube0x0 cve-2021-1675 (c#/impacket)',
                     'nemo-wq printnightmare poc',
                     'mimikatz misc::printnightmare',
                     'impacket'],
        'cve': ['CVE-2021-34527', 'CVE-2021-1675'],
        'mitigation': [   'Apply the Microsoft patches and set '
                          'RestrictDriverInstallationToAdministrators=1',
                          'Disable the Print Spooler service where not required (esp. on '
                          'DCs/servers)',
                          'Restrict Point-and-Print and monitor spooler driver directory writes'],
        'poc_references': [   'https://github.com/cube0x0/CVE-2021-1675',
                              'https://github.com/nemo-wq/PrintNightmare-CVE-2021-34527'],
        'research_references': [   'https://msrc.microsoft.com/update-guide/vulnerability/CVE-2021-34527',
                                   'https://www.rapid7.com/blog/post/ra-cve-2021-34527-printnightmare-analysis/']},
    {   'id': 'windows-printspoofer',
        'name': 'PrintSpoofer (Print Spooler named-pipe coercion)',
        'platform': 'windows',
        'category': 'token-impersonation',
        'severity': 'critical',
        'summary': "PrintSpoofer abuses the Print Spooler service's "
                   'RpcRemoteFindFirstPrinterChangeNotificationEx to force the SYSTEM spooler to '
                   'connect to an attacker-controlled named pipe, capturing and impersonating its '
                   'SYSTEM token. It is fully local (no network redirector) and works on Windows '
                   '10 / Server 2019.',
        'technique': 'The tool creates a named pipe and calls into the spooler RPC interface '
                     '(spoolss) requesting a change notification whose callback path points at the '
                     'controlled pipe. The Print Spooler, running as SYSTEM, connects to the pipe; '
                     'the tool calls ImpersonateNamedPipeClient under SeImpersonatePrivilege to '
                     'assume the SYSTEM context, then launches a SYSTEM process. Because it uses '
                     'the local spooler rather than DCOM/OXID it needs no external resolver.',
        'prerequisites': [   'SeImpersonatePrivilege or SeAssignPrimaryTokenPrivilege enabled',
                             'Print Spooler service (spoolsv) running'],
        'enumeration': ['whoami /priv', 'sc query spooler', 'Get-Service Spooler'],
        'detection_indicators': [   'SeImpersonatePrivilege Enabled and Spooler running',
                                    'Named pipe creation \\pipe\\spoolss followed by SYSTEM '
                                    'process spawn',
                                    'spoolsv.exe connecting to an unusual local named pipe',
                                    'Sysmon Event ID 17/18 (pipe created/connected) tied to a '
                                    'service worker process',
                                    'SeImpersonatePrivilege'],
        'tools': ['printspoofer', 'sweetpotato'],
        'cve': [],
        'mitigation': [   'Disable Print Spooler on servers that do not print',
                          'Restrict impersonation privileges on service accounts',
                          'Monitor \\pipe\\spoolss connections by non-spooler contexts'],
        'poc_references': ['https://github.com/itm4n/PrintSpoofer'],
        'research_references': [   'https://itm4n.github.io/printspoofer-abusing-impersonate-privileges/',
                                   'https://hacktricks.wiki/en/windows-hardening/windows-local-privilege-escalation/roguepotato-and-printspoofer.html']},
    {   'id': 'windows-roguepotato',
        'name': 'RoguePotato (remote OXID resolver revival)',
        'platform': 'windows',
        'category': 'token-impersonation',
        'severity': 'critical',
        'summary': 'RoguePotato revives the potato technique on Windows 10 1809 / Server 2019+ '
                   '(where JuicyPotato was patched) by redirecting the DCOM OXID resolution to a '
                   'remote/redirected resolver on TCP 135, restoring the local NTLM reflection '
                   'path to SYSTEM.',
        'technique': 'After Microsoft blocked the local (127.0.0.1) OXID resolver trick, '
                     'RoguePotato uses a fake OXID resolver reachable on port 135 (typically via a '
                     'socket redirector so the resolver runs remotely or is port-forwarded back to '
                     'the host). The coerced SYSTEM DCOM activation resolves the OXID against the '
                     'rogue resolver, which steers the authentication to a local named pipe the '
                     'tool controls; the SYSTEM token is impersonated via SeImpersonatePrivilege '
                     'to spawn a SYSTEM process.',
        'prerequisites': [   'SeImpersonatePrivilege enabled',
                             'Ability to reach/redirect TCP 135 (a redirector on a second host or '
                             'a local socket redirect)',
                             'Windows 10 1809 / Server 2019 and later'],
        'enumeration': ['whoami /priv', 'systeminfo'],
        'detection_indicators': [   'SeImpersonatePrivilege Enabled on a modern build '
                                    '(1809/Server2019+)',
                                    'Outbound/loopback RPC to an unusual OXID resolver on 135',
                                    'socat/redirector process or unexpected listener on 135',
                                    'Service account spawning SYSTEM shell',
                                    'SeImpersonatePrivilege'],
        'tools': ['roguepotato'],
        'cve': [],
        'mitigation': [   'Block/monitor unexpected outbound TCP 135',
                          'Restrict impersonation privileges',
                          'EDR alerting on OXID resolver redirection patterns'],
        'poc_references': ['https://github.com/antonioCoco/RoguePotato'],
        'research_references': [   'https://decoder.cloud/2020/05/11/no-more-juicypotato-old-story-welcome-roguepotato/',
                                   'https://hacktricks.wiki/en/windows-hardening/windows-local-privilege-escalation/roguepotato-and-printspoofer.html']},
    {   'id': 'windows-seimpersonate-potato',
        'name': 'Service-Account Token Impersonation (Potato family)',
        'platform': 'windows',
        'category': 'token-impersonation',
        'severity': 'critical',
        'summary': 'A service context holding SeImpersonatePrivilege (default for IIS, MSSQL, and '
                   'the *SERVICE accounts) can coerce a SYSTEM token via named-pipe/RPC tricks and '
                   'impersonate it to become SYSTEM — the standard last hop from a service '
                   'foothold gained through the service misconfigs above.',
        'technique': 'SeImpersonatePrivilege permits creating a process in another security '
                     'context once its token is obtained. The Potato family (JuicyPotato, '
                     'RoguePotato, PrintSpoofer, SharpEfsPotato, GodPotato) coerces a SYSTEM '
                     'component (DCOM/OXID resolver, Print Spooler, EFSRPC) into authenticating to '
                     'an attacker-controlled RPC or named-pipe endpoint, captures/impersonates the '
                     'SYSTEM token, and spawns a SYSTEM process. Tool choice depends on the '
                     'Windows build.',
        'prerequisites': [   'current context holds SeImpersonatePrivilege (or '
                             'SeAssignPrimaryTokenPrivilege)'],
        'enumeration': ['whoami /priv', 'whoami /groups', 'whoami /all'],
        'detection_indicators': [   'whoami /priv shows SeImpersonatePrivilege or '
                                    'SeAssignPrimaryTokenPrivilege Enabled in a non-admin service '
                                    'context',
                                    'unexpected local named-pipe creation followed by SYSTEM token '
                                    'impersonation',
                                    'spoolsv.exe / rpcss connecting to a local rogue RPC endpoint',
                                    'SeImpersonatePrivilege'],
        'tools': [   'printspoofer',
                     'roguepotato',
                     'juicypotato',
                     'sharpefspotato',
                     'godpotato',
                     'whoami'],
        'cve': [],
        'mitigation': [   'remove SeImpersonatePrivilege where not required',
                          'patch and restrict Spooler/RPC coercion vectors',
                          'isolate service accounts; use virtual/managed service accounts with '
                          'least privilege'],
        'poc_references': [   'https://itm4n.github.io/printspoofer-abusing-impersonate-privileges/',
                              'https://github.com/itm4n/PrintSpoofer'],
        'research_references': [   'https://attack.mitre.org/techniques/T1134/001/',
                                   'https://hacktricks.wiki/en/windows-hardening/windows-local-privilege-escalation/roguepotato-and-printspoofer.html']},
    {   'id': 'windows-sweetpotato',
        'name': 'SweetPotato (combined potato toolkit)',
        'platform': 'windows',
        'category': 'token-impersonation',
        'severity': 'critical',
        'summary': 'SweetPotato by CCob is a consolidated collection of service-account-to-SYSTEM '
                   'potato techniques (Rotten/Juicy-style DCOM, PrintSpoofer spooler coercion, and '
                   'EfsRpc) packaged for in-memory use with C2 frameworks such as Cobalt Strike '
                   'via execute-assembly.',
        'technique': 'SweetPotato bundles multiple SYSTEM-token capture primitives behind one .NET '
                     'assembly and lets the operator select the exploit method appropriate to the '
                     'target build (e.g. the PrintSpoofer/spoolss path or the EfsRpc path). All '
                     'rely on SeImpersonatePrivilege to impersonate the coerced SYSTEM token and '
                     'then execute a chosen command as SYSTEM. Its value is packaging and C2 '
                     'integration rather than a new primitive.',
        'prerequisites': [   'SeImpersonatePrivilege enabled',
                             'A working sub-technique for the target OS build'],
        'enumeration': ['whoami /priv', 'systeminfo'],
        'detection_indicators': [   'SeImpersonatePrivilege Enabled',
                                    'In-memory .NET assembly load (execute-assembly) from a '
                                    'service worker',
                                    'spoolss/efsrpc named-pipe coercion patterns',
                                    'SYSTEM child of a beacon/worker process',
                                    'SeImpersonatePrivilege'],
        'tools': ['sweetpotato'],
        'cve': [],
        'mitigation': [   'Same as underlying techniques: patch, remove impersonation privileges, '
                          'disable spooler',
                          'AMSI/EDR .NET assembly-load telemetry'],
        'poc_references': ['https://github.com/CCob/SweetPotato'],
        'research_references': [   'https://hacktricks.wiki/en/windows-hardening/windows-local-privilege-escalation/roguepotato-and-printspoofer.html',
                                   'https://attack.mitre.org/techniques/T1134/']},
    {   'id': 'windows-token-impersonation-seimpersonate-namedpipe',
        'name': 'SeImpersonatePrivilege / SeAssignPrimaryTokenPrivilege token impersonation '
                '(named-pipe potato mechanism)',
        'platform': 'windows',
        'category': 'token-impersonation',
        'severity': 'critical',
        'summary': 'Service accounts (IIS AppPool, MSSQL, NETWORK SERVICE, LOCAL SERVICE) hold '
                   'SeImpersonatePrivilege/SeAssignPrimaryTokenPrivilege, which allow a process to '
                   'impersonate the security context of any token it receives. Coercing a SYSTEM '
                   'process to authenticate to a controlled named pipe or RPC endpoint yields a '
                   'SYSTEM token, giving full local escalation.',
        'technique': 'Windows lets a thread holding SeImpersonatePrivilege call '
                     'ImpersonateNamedPipeClient (or duplicate a token and CreateProcessWithToken) '
                     'to run in the security context of a client that connects to it. The '
                     "universal 'potato' pattern is: stand up a listener (named pipe such as "
                     '\\\\.\\pipe\\spoolss or an RPC/DCOM/OXID endpoint), then trick a '
                     'highly-privileged SYSTEM service into connecting/authenticating to it (NTLM '
                     "local reflection, RPC callback, or spooler/EFSRPC coercion). The service's "
                     'SYSTEM token is captured and impersonated, then used to spawn a new SYSTEM '
                     'process. SeAssignPrimaryTokenPrivilege enables the CreateProcessAsUser '
                     'primary-token variant when SeImpersonate alone is insufficient. This is a '
                     'design-level abuse of impersonation, not a single CVE.',
        'prerequisites': [   'Foothold as a Windows service account or any user whose token has '
                             'SeImpersonatePrivilege or SeAssignPrimaryTokenPrivilege enabled',
                             'Ability to run a binary/assembly on the host'],
        'enumeration': ['whoami /priv', 'whoami /all', 'whoami /groups'],
        'detection_indicators': [   '"SeImpersonatePrivilege" State=Enabled in whoami /priv output',
                                    '"SeAssignPrimaryTokenPrivilege" Enabled',
                                    'Running as NT AUTHORITY\\NETWORK SERVICE / LOCAL SERVICE / '
                                    'IIS APPPOOL\\ / a *$ or svc_ service account',
                                    'Security event 4673 (privileged service called) and 4624 '
                                    'logon type 9 (NewCredentials) followed by a SYSTEM child '
                                    'process from a service account parent',
                                    'Anomalous named-pipe creation (\\pipe\\spoolss, '
                                    '\\pipe\\lsarpc) by a web/db worker process',
                                    'SeImpersonatePrivilege'],
        'tools': [   'juicypotato',
                     'roguepotato',
                     'printspoofer',
                     'godpotato',
                     'efspotato',
                     'sweetpotato',
                     'juicypotatong',
                     'rottenpotatong',
                     'privesccheck',
                     'winpeas',
                     'seatbelt'],
        'cve': [],
        'mitigation': [   'Do not grant service accounts more privilege than required; prefer '
                          'virtual/gMSA accounts scoped tightly',
                          'Keep hosts patched (RPC/OXID and spooler mitigations narrow the '
                          'coercion primitives)',
                          'Disable Print Spooler where not needed',
                          'Monitor event 4673/4674 and unusual SYSTEM child processes spawned by '
                          'worker accounts'],
        'poc_references': [   'https://github.com/ohpe/juicy-potato',
                              'https://github.com/antonioCoco/RoguePotato',
                              'https://github.com/itm4n/PrintSpoofer',
                              'https://github.com/foxglovesec/RottenPotato'],
        'research_references': [   'https://attack.mitre.org/techniques/T1134/',
                                   'https://hacktricks.wiki/en/windows-hardening/windows-local-privilege-escalation/privilege-escalation-abusing-tokens.html',
                                   'https://foxglovesecurity.com/2016/09/26/rotten-potato-privilege-escalation-from-service-accounts-to-system/',
                                   'https://powerofcommunity.net/assets/v0/poc2023/AntonioCocomazzi.pdf']},
    {   'id': 'windows-weak-service-permissions-binpath',
        'name': 'Weak Service Object Permissions (SERVICE_CHANGE_CONFIG / binPath)',
        'platform': 'windows',
        'category': 'service-misconfig',
        'severity': 'critical',
        'summary': 'A service whose SCM security descriptor grants SERVICE_CHANGE_CONFIG (or '
                   'SERVICE_ALL_ACCESS) to a non-admin principal lets that user rewrite binPath to '
                   'any command, then start/restart the service to run it as the service identity.',
        'technique': 'Each service has a DACL controlling rights such as SERVICE_CHANGE_CONFIG, '
                     'SERVICE_START and SERVICE_STOP. If a low-privileged group (Authenticated '
                     'Users, Everyone, BUILTIN\\Users, INTERACTIVE) holds SERVICE_CHANGE_CONFIG, '
                     'the binary path can be reconfigured to an arbitrary executable/command; '
                     'combined with start/stop rights (or a reboot) the command executes in the '
                     "service's security context, typically LocalSystem.",
        'prerequisites': [   'SERVICE_CHANGE_CONFIG on the target service',
                             'SERVICE_START/SERVICE_STOP rights or a reboot to trigger'],
        'enumeration': [   'accesschk.exe -accepteula -uwcqv "Authenticated Users" *',
                           'accesschk.exe -accepteula -uwcqv %USERNAME% *',
                           'sc.exe sdshow <service>',
                           'PowerUp: Get-ModifiableService | Invoke-AllChecks'],
        'detection_indicators': [   'accesschk shows SERVICE_ALL_ACCESS or SERVICE_CHANGE_CONFIG '
                                    'for NT AUTHORITY\\Authenticated Users / Everyone / '
                                    'BUILTIN\\Users',
                                    'sc sdshow SDDL granting CC/DC/RP/WP/DT/LO to AU/BU/IU/WD ACE '
                                    'SIDs',
                                    'non-admin holding both change-config and start rights on a '
                                    'SYSTEM service'],
        'tools': ['accesschk', 'powerup', 'sharpup', 'privesccheck', 'sc.exe', 'winpeas'],
        'cve': [],
        'mitigation': [   'remove change-config/write rights from non-admin principals',
                          'audit and reset service SDDLs to defaults',
                          'run services under least-privilege accounts'],
        'poc_references': [   'https://book.hacktricks.xyz/windows-hardening/windows-local-privilege-escalation#permissions',
                              'https://medium.com/r3d-buck3t/privilege-escalation-with-insecure-windows-service-permissions-5d97312db107'],
        'research_references': [   'https://attack.mitre.org/techniques/T1543/003/',
                                   'https://learn.microsoft.com/en-us/sysinternals/downloads/accesschk']},
    {   'id': 'windows-weak-service-registry-acl-imagepath',
        'name': 'Weak Registry ACLs on Service Keys (ImagePath)',
        'platform': 'windows',
        'category': 'writable-registry',
        'severity': 'critical',
        'summary': "A weak DACL on a service's registry key lets a non-admin rewrite ImagePath (or "
                   'the failure-recovery command / Parameters) directly, running an arbitrary '
                   'command as the service account without needing SCM change-config rights.',
        'technique': 'The SCM launches a service from the ImagePath value under '
                     'HKLM\\SYSTEM\\CurrentControlSet\\Services\\<svc>. If the registry key grants '
                     'a low-privileged principal KEY_SET_VALUE / KEY_WRITE, the user edits '
                     'ImagePath (or FailureCommand, or a Parameters value used by the service) to '
                     'an attacker-controlled command. On start, restart, reboot, or a triggered '
                     'failure action the SCM executes it in the service identity, commonly '
                     'LocalSystem.',
        'prerequisites': [   'registry write on the service key',
                             'ability to trigger service start/restart/failure'],
        'enumeration': [   'accesschk.exe -accepteula -kvuqsw '
                           '"HKLM\\System\\CurrentControlSet\\Services"',
                           'accesschk.exe -accepteula -kvuqsw '
                           '"HKLM\\System\\CurrentControlSet\\Services\\<svc>"',
                           'Get-Acl "HKLM:\\SYSTEM\\CurrentControlSet\\Services\\<svc>" | '
                           'Format-List',
                           'reg query "HKLM\\SYSTEM\\CurrentControlSet\\Services\\<svc>" /v '
                           'ImagePath'],
        'detection_indicators': [   'accesschk -k shows KEY_ALL_ACCESS / KEY_SET_VALUE / KEY_WRITE '
                                    'for Users/Authenticated Users/Everyone/INTERACTIVE on a '
                                    'Services subkey',
                                    'Get-Acl on a Services key showing SetValue for a non-admin '
                                    'SID',
                                    'modified ImagePath pointing to a non-standard/user path'],
        'tools': ['accesschk', 'privesccheck', 'powerup', 'reg.exe', 'winpeas'],
        'cve': [],
        'mitigation': [   'restore default registry DACLs on Services keys',
                          'deny write to non-admins on HKLM Services hive',
                          'audit registry ACLs with accesschk regularly'],
        'poc_references': [   'https://book.hacktricks.xyz/windows-hardening/windows-local-privilege-escalation#registry-modify-services',
                              'https://github.com/itm4n/PrivescCheck'],
        'research_references': [   'https://attack.mitre.org/techniques/T1574/011/',
                                   'https://learn.microsoft.com/en-us/sysinternals/downloads/accesschk']},
    {   'id': 'network-llmnr-nbtns-mdns-poisoning-responder',
        'name': 'LLMNR / NBT-NS / mDNS poisoning & NTLM capture (Responder)',
        'platform': 'windows',
        'category': 'network-poisoning',
        'severity': 'high',
        'summary': 'Windows falls back to broadcast/multicast name resolution (LLMNR, NBT-NS, '
                   'mDNS) when DNS fails; an attacker on the LAN answers those queries, coercing '
                   'victims to authenticate to them and capturing NetNTLM hashes to crack or '
                   'relay.',
        'technique': 'When a host cannot resolve a name via DNS (typos, missing WPAD, stale '
                     'shares), Windows broadcasts LLMNR (UDP 5355), NBT-NS (UDP 137) and mDNS (UDP '
                     "5353) requests. A poisoner such as Responder replies 'that name is me', so "
                     'the victim connects and performs NTLM authentication (often for '
                     'SMB/HTTP/WPAD). The attacker captures the NTLMv1/v2 challenge-response, '
                     'which is either cracked offline (hashcat) to recover the plaintext, or — if '
                     'SMB signing is not enforced — relayed live (ntlmrelayx) to another host to '
                     'authenticate as the victim. WPAD auto-discovery and automatic share access '
                     'make coercion frequent and reliable, and this is one of the most common '
                     'initial internal-network privilege footholds.',
        'prerequisites': [   'attacker on the same broadcast/L2 segment as victims',
                             'LLMNR/NBT-NS/mDNS enabled (default) and name-resolution failures '
                             'occurring',
                             'for relay: SMB signing not required on the target'],
        'enumeration': [   "Get-ItemProperty 'HKLM:\\Software\\Policies\\Microsoft\\Windows "
                           "NT\\DNSClient' -Name EnableMulticast",
                           'reg query '
                           'HKLM\\SYSTEM\\CurrentControlSet\\Services\\NetBT\\Parameters\\Interfaces',
                           'nmap --script broadcast-dns-service-discovery',
                           'Responder.py -I eth0 -A  (analyze-only, passive)'],
        'detection_indicators': ['LLMNR', 'NBT-NS', 'mDNS', 'EnableMulticast', 'WPAD', 'NetNTLMv2'],
        'tools': ['responder', 'inveigh', 'ntlmrelayx', 'hashcat', 'pcredz'],
        'cve': [],
        'mitigation': [   'Disable LLMNR (GPO: Turn off multicast name resolution) and NBT-NS on '
                          'all interfaces',
                          'Disable mDNS where not needed; deploy a proper WPAD DNS record (or '
                          'disable WPAD)',
                          'Enforce SMB signing (and LDAP signing/channel binding) to defeat relay',
                          'Network segmentation and 802.1x; monitor for poisoning responders'],
        'poc_references': [   'https://github.com/lgandx/Responder',
                              'https://www.thehacker.recipes/ad/movement/mitm-and-coerced-authentications/llmnr-nbtns-mdns'],
        'research_references': [   'https://book.hacktricks.xyz/windows-hardening/active-directory-methodology/spoofing-llmnr-nbt-ns-mdns-dns-and-wpad-and-relay-attacks',
                                   'https://en.hackndo.com/ntlm-relay/']},
    {   'id': 'windows-byovd-vulnerable-driver',
        'name': 'Bring-Your-Own-Vulnerable-Driver (BYOVD)',
        'platform': 'windows',
        'category': 'byovd',
        'severity': 'high',
        'summary': 'An admin-level attacker loads a legitimately signed but vulnerable kernel '
                   'driver (catalogued at loldrivers.io) and abuses its IOCTLs for arbitrary '
                   'kernel read/write — disabling EDR, clearing protections, or achieving '
                   'SYSTEM/kernel code execution without a kernel 0-day.',
        'technique': 'Many WHQL/vendor-signed drivers expose dangerous IOCTLs (physical-memory '
                     'mapping, arbitrary MSR/CR writes, process-handle stripping). BYOVD drops '
                     'such a driver — e.g. Dell dbutil_2_3.sys (CVE-2021-21551), MSI Afterburner '
                     'RTCore64.sys (CVE-2019-16098), Gigabyte gdrv.sys (CVE-2018-19320), or '
                     'gaming/anti-cheat drivers — installs it as a kernel service (loading a '
                     'driver requires local admin/SeLoadDriverPrivilege, but Secure Boot/DSE still '
                     'trusts its valid signature), then sends crafted IOCTLs to gain kernel '
                     'read/write. That primitive is used to null out EDR callback routines and '
                     "remove Protected-Process-Light on security processes ('EDR killers' like "
                     'some ransomware crews use), map an unsigned payload into the kernel '
                     '(kdmapper-style manual mapping bypassing DSE), or read/write EPROCESS to '
                     'elevate. The technique is a signature/trust abuse rather than a '
                     'code-execution vuln, which is why it survives even on patched, Secure-Boot '
                     'systems until the driver is blocklisted.',
        'prerequisites': [   'local administrator (ability to create/start a kernel service and '
                             'load a driver)',
                             'a vulnerable signed driver not yet on the Microsoft '
                             'vulnerable-driver blocklist / HVCI blocklist'],
        'enumeration': [   'sc query type= driver',
                           'driverquery /v',
                           'Get-CimInstance Win32_SystemDriver',
                           'reg query HKLM\\SYSTEM\\CurrentControlSet\\Control\\CI\\Config',
                           'bcdedit /enum  (check test-signing / integrity)'],
        'detection_indicators': [   'RTCore64.sys',
                                    'dbutil_2_3.sys',
                                    'gdrv.sys',
                                    '\\Device\\PhysicalMemory',
                                    'SeLoadDriverPrivilege',
                                    'loldrivers'],
        'tools': ['loldrivers', 'kdmapper', 'byovdkit', 'backstab', 'spyboy'],
        'cve': ['CVE-2021-21551', 'CVE-2019-16098', 'CVE-2018-19320'],
        'mitigation': [   'Enable the Microsoft vulnerable driver blocklist and HVCI/Memory '
                          'Integrity',
                          'Enforce Secure Boot; use WDAC/App Control to allow only approved '
                          'drivers',
                          'Alert on new kernel service creation and known-abused driver hashes',
                          'Restrict local admin; monitor EDR tamper / callback removal'],
        'poc_references': [   'https://www.loldrivers.io/',
                              'https://www.rapid7.com/blog/post/2021/12/13/driver-based-attacks-past-and-present/',
                              'https://github.com/TheCruZ/kdmapper'],
        'research_references': [   'https://blog.talosintelligence.com/exploring-vulnerable-windows-drivers/',
                                   'https://learn.microsoft.com/en-us/windows/security/application-security/application-control/windows-defender-application-control/design/microsoft-recommended-driver-block-rules']},
    {   'id': 'windows-credential-manager-vault',
        'name': 'Windows Credential Manager / Vault harvesting',
        'platform': 'windows',
        'category': 'credential-harvesting',
        'severity': 'high',
        'summary': 'Windows Credential Manager (the Vault) stores saved domain, web, RDP, and '
                   "generic credentials (DPAPI-protected) that an attacker in the user's context "
                   "can enumerate and decrypt, and 'runas /savecred' entries can be reused "
                   'directly to run commands as another user.',
        'technique': 'Saved credentials live in the Web and Windows Vaults under '
                     '%LOCALAPPDATA%\\Microsoft\\{Vault,Credentials} and are DPAPI-protected to '
                     "the user. In the user's session they are enumerated (cmdkey /list, vaultcmd) "
                     "and decrypted with the user's DPAPI keys (mimikatz vault::cred, SharpDPAPI, "
                     'LaZagne). Where a credential was stored with runas /savecred, an attacker '
                     'can invoke runas /savecred to execute as that (often privileged) account '
                     'without knowing the password.',
        'prerequisites': [   'Execution in the context of the user who saved the credentials (for '
                             "DPAPI decryption), or that user's DPAPI keys"],
        'enumeration': [   'cmdkey /list',
                           'vaultcmd /list',
                           'vaultcmd /listcreds:"Windows Credentials" /all'],
        'detection_indicators': [   'cmdkey /list revealing saved DOMAIN/TERMSRV credentials',
                                    'runas /savecred usage',
                                    'access to %LOCALAPPDATA%\\Microsoft\\Credentials and \\Vault '
                                    'blobs',
                                    'vault::cred / SharpDPAPI / LaZagne execution'],
        'tools': ['cmdkey', 'vaultcmd', 'mimikatz vault::cred', 'sharpdpapi', 'lazagne'],
        'cve': [],
        'mitigation': [   'Discourage saving credentials/runas savecred for privileged accounts',
                          'Enable Credential Guard; use least-privilege service accounts',
                          'Audit Credential Manager reads and runas /savecred launches'],
        'poc_references': [   'https://github.com/AlessandroZ/LaZagne',
                              'https://github.com/GhostPack/SharpDPAPI'],
        'research_references': [   'https://attack.mitre.org/techniques/T1555/004/',
                                   'https://hacktricks.wiki/en/windows-hardening/windows-local-privilege-escalation/index.html']},
    {   'id': 'windows-dll-search-order-hijacking',
        'name': 'DLL Search Order Hijacking',
        'platform': 'windows',
        'category': 'dll-hijack',
        'severity': 'high',
        'summary': 'A privileged application loads a DLL by bare name and resolves it from an '
                   'earlier, attacker-writable directory in the Windows DLL search order, running '
                   'attacker code in the target process context.',
        'technique': 'LoadLibrary without a full path walks a defined search order (application '
                     'directory, System32, System, Windows dir, current directory, PATH). If a '
                     'privileged process loads a non-KnownDLL from a location the attacker can '
                     'write (its own writable install folder, or the current working directory), '
                     "planting a same-named DLL there executes attacker code with that process's "
                     'privileges. SafeDllSearchMode and the KnownDLLs list reduce but do not '
                     'eliminate the surface.',
        'prerequisites': [   'a privileged process that loads a non-fully-qualified, non-KnownDLL',
                             'write access to an earlier directory in the search order'],
        'enumeration': [   'Process Monitor filter: Result is NAME NOT FOUND AND Path ends with '
                           '.dll',
                           'accesschk.exe -accepteula -quv "<application install directory>"',
                           'PowerUp: Find-ProcessDLLHijack ; Find-PathDLLHijack',
                           'cross-reference hijacklibs.net for known-vulnerable DLL names'],
        'detection_indicators': [   'Process Monitor: DLL CreateFile with NAME NOT FOUND across '
                                    'earlier search paths before a successful load in a writable '
                                    'dir',
                                    'unsigned DLL sitting next to a signed, privileged EXE',
                                    'DLL loaded from a user-writable application folder or CWD'],
        'tools': ['procmon', 'spartacus', 'robber', 'powerup', 'hijacklibs', 'winpeas'],
        'cve': [],
        'mitigation': [   'load DLLs with a fully-qualified path',
                          'call SetDefaultDllDirectories(LOAD_LIBRARY_SEARCH_SYSTEM32)',
                          'set SafeDllSearchMode=1, remove CWD from search, lock install-dir '
                          'DACLs, deploy WDAC/AppLocker'],
        'poc_references': [   'https://book.hacktricks.xyz/windows-hardening/windows-local-privilege-escalation/dll-hijacking',
                              'https://hijacklibs.net/'],
        'research_references': [   'https://attack.mitre.org/techniques/T1574/001/',
                                   'https://learn.microsoft.com/en-us/windows/win32/dlls/dynamic-link-library-search-order']},
    {   'id': 'windows-dpapi-secrets',
        'name': 'DPAPI secret & masterkey extraction',
        'platform': 'windows',
        'category': 'credential-harvesting',
        'severity': 'high',
        'summary': 'The Data Protection API protects browser passwords, saved '
                   'RDP/credential-manager secrets, Wi-Fi keys, and app secrets using per-user '
                   'master keys; recovering the master keys (via the user password/hash, LSASS, or '
                   "the domain DPAPI backup key) decrypts all of a user's DPAPI blobs.",
        'technique': 'DPAPI-protected blobs are decrypted with a user master key stored under '
                     "%APPDATA%\\Microsoft\\Protect\\<SID>\\, itself encrypted from the user's "
                     'password/NTLM hash. Attackers decrypt master keys using the plaintext/hash '
                     '(offline), by extracting keys from a running LSASS (mimikatz '
                     'sekurlsa::dpapi), or—domain-wide—with the DPAPI domain backup key exported '
                     "from a DC, which decrypts every user's master keys. SharpDPAPI/mimikatz then "
                     'decrypt Credential Manager blobs, Chrome/Edge logins, RDP passwords, and '
                     'vault entries.',
        'prerequisites': [   "Access to the target user's DPAPI blobs and one of: the user's "
                             'password/NTLM hash, LSASS access, or the domain DPAPI backup key '
                             '(Domain Admin on a DC)'],
        'enumeration': [   'dir /a %APPDATA%\\Microsoft\\Protect',
                           'dir /a %LOCALAPPDATA%\\Microsoft\\Credentials',
                           'cmdkey /list'],
        'detection_indicators': [   'Access to %APPDATA%\\Microsoft\\Protect\\<SID> masterkey '
                                    'files by another user/context',
                                    'SharpDPAPI/mimikatz dpapi module usage',
                                    'LSADUMP::backupkeys or DC backup-key export (Directory '
                                    'Service access to the domain backup key)',
                                    'Reads of Credentials/Vault blob files'],
        'tools': [   'sharpdpapi (ghostpack)',
                     'mimikatz dpapi::/sekurlsa::dpapi',
                     'donpapi',
                     'impacket dpapi.py'],
        'cve': [],
        'mitigation': [   'Protect the domain DPAPI backup key (Tier-0 DC hardening)',
                          'Enable Credential Guard and strong user passwords',
                          'Monitor access to Protect/Credentials/Vault directories and DC '
                          'backup-key retrieval'],
        'poc_references': [   'https://github.com/GhostPack/SharpDPAPI',
                              'https://github.com/gentilkiwi/mimikatz'],
        'research_references': [   'https://attack.mitre.org/techniques/T1555/',
                                   'https://www.harmj0y.net/blog/redteaming/operational-guidance-for-offensive-user-dpapi-abuse/']},
    {   'id': 'windows-gpp-cpassword',
        'name': 'Group Policy Preferences cpassword',
        'platform': 'windows',
        'category': 'credential-harvesting',
        'severity': 'high',
        'summary': 'Group Policy Preferences that set local account passwords store an '
                   'AES-encrypted cpassword in domain-readable SYSVOL XML; Microsoft published the '
                   'AES key, so any domain user can read and decrypt these (often local-admin) '
                   'credentials.',
        'technique': 'GPP for local users, services, scheduled tasks, data sources and drive maps '
                     'writes a cpassword attribute into XML (Groups.xml, Services.xml, '
                     'ScheduledTasks.xml, DataSources.xml, Drives.xml) under '
                     '\\\\<domain>\\SYSVOL\\...\\Policies. The 32-byte AES key was documented on '
                     'MSDN, so the value decrypts trivially, exposing reusable local-admin '
                     'credentials for lateral movement and local privilege escalation. MS14-025 '
                     '(CVE-2014-1812) blocks creating new GPP passwords but does not delete '
                     'existing files.',
        'prerequisites': [   'any authenticated domain user (SYSVOL read access)',
                             'existing GPP XML containing a cpassword value'],
        'enumeration': [   'findstr /S /I cpassword '
                           '\\\\<domain>\\SYSVOL\\<domain>\\Policies\\*.xml',
                           'Get-GPPPassword   (PowerSploit)',
                           'dir /s \\\\<domain>\\SYSVOL\\*.xml  then inspect for cpassword',
                           'nxc smb <dc> -u <user> -p <pass> -M gpp_password   (NetExec)'],
        'detection_indicators': [   'cpassword="..." attribute inside any XML under '
                                    'SYSVOL\\...\\Preferences',
                                    'read access to Groups.xml / Services.xml / ScheduledTasks.xml '
                                    'on a Domain Controller',
                                    'SMB reads of \\\\*\\SYSVOL\\*\\Preferences\\*.xml'],
        'tools': [   'powersploit-get-gpppassword',
                     'metasploit-smb_enum_gpp',
                     'gpp-decrypt',
                     'netexec',
                     'impacket-get-gpppassword.py'],
        'cve': ['CVE-2014-1812'],
        'mitigation': [   'apply MS14-025',
                          'delete existing GPP XML files containing cpassword',
                          'use LAPS/Windows LAPS to manage local admin passwords'],
        'poc_references': [   'https://dirteam.com/sander/2014/05/23/security-thoughts-passwords-in-group-policy-preferences-cve-2014-1812/',
                              'https://www.microsoft.com/en-us/msrc/blog/2014/05/ms14-025-an-update-for-group-policy-preferences'],
        'research_references': [   'https://attack.mitre.org/techniques/T1552/006/',
                                   'https://adsecurity.org/?p=2288']},
    {   'id': 'windows-hivenightmare-serioussam-cve-2021-36934',
        'name': 'HiveNightmare / SeriousSAM (CVE-2021-36934)',
        'platform': 'windows',
        'category': 'kernel-exploit',
        'severity': 'high',
        'summary': 'Overly permissive ACLs on the SAM, SYSTEM, and SECURITY registry hives on '
                   'affected Windows 10/11 builds let any non-admin user read them from a Volume '
                   'Shadow Copy, extracting local account hashes and LSA secrets to escalate to '
                   'admin/SYSTEM.',
        'technique': 'On vulnerable builds the config hive files (\\Windows\\System32\\config\\SAM '
                     'etc.) grant BUILTIN\\Users read access. While the live files are locked, a '
                     'pre-existing VSS shadow copy '
                     '(\\\\?\\GLOBALROOT\\Device\\HarddiskVolumeShadowCopyN\\Windows\\System32\\config\\SAM) '
                     'is readable by unprivileged users, so the hives are copied and parsed '
                     'offline (impacket-secretsdump) to recover the local admin hash for '
                     'pass-the-hash or offline cracking. Requires at least one existing System '
                     'Restore/shadow copy.',
        'prerequisites': [   'Affected Windows 10 (1809+)/11 build before the fix',
                             'At least one Volume Shadow Copy exists (e.g. from a system restore '
                             'point / update)',
                             'Any interactive user account'],
        'enumeration': [   'icacls %windir%\\System32\\config\\SAM (BUILTIN\\Users:(I)(RX) '
                           'indicates vulnerable)',
                           'vssadmin list shadows'],
        'detection_indicators': [   'icacls shows BUILTIN\\Users read on SAM/SYSTEM/SECURITY',
                                    'Non-admin process reading '
                                    '\\\\?\\GLOBALROOT\\Device\\HarddiskVolumeShadowCopy*\\Windows\\System32\\config\\SAM',
                                    'HiveNightmare.exe/hivenightmare on disk; SAM/SECURITY/SYSTEM '
                                    'copies in a user-writable dir'],
        'tools': [   'hivenightmare (gossithedog)',
                     'hivenightmare (firefart)',
                     'impacket-secretsdump'],
        'cve': ['CVE-2021-36934'],
        'mitigation': [   'Apply the Microsoft patch and run the mitigation: restrict ACLs on '
                          '%windir%\\System32\\config\\* and delete existing shadow copies (VSS)',
                          'Rotate local admin passwords after exposure',
                          'Monitor unprivileged access to shadow-copy hive paths'],
        'poc_references': [   'https://github.com/GossiTheDog/HiveNightmare',
                              'https://github.com/firefart/hivenightmare'],
        'research_references': [   'https://msrc.microsoft.com/update-guide/vulnerability/CVE-2021-36934',
                                   'https://www.exploit-db.com/docs/50245']},
    {   'id': 'windows-kerberos-ticket-theft-ptt',
        'name': 'Kerberos ticket theft & pass-the-ticket',
        'platform': 'windows',
        'category': 'kerberos',
        'severity': 'high',
        'summary': 'Kerberos TGTs and service tickets held in LSASS or on disk can be extracted '
                   'and reinjected (pass-the-ticket) to impersonate users without their password; '
                   'harvesting a privileged TGT enables lateral movement and domain escalation.',
        'technique': 'With admin/SeDebug access, cached Kerberos tickets are extracted from LSASS '
                     '(mimikatz sekurlsa::tickets /export, Rubeus dump) or requested (Rubeus '
                     'tgtdeleg/asktgt). A stolen TGT/TGS is then injected into a logon session '
                     '(kerberos::ptt / Rubeus ptt) to authenticate as the victim. Related abuses '
                     'include capturing a computer/service account TGT for delegation attacks and '
                     'reusing tickets across hosts. Ticket harvesting complements '
                     'Kerberoasting/AS-REP roasting for offline cracking of service passwords.',
        'prerequisites': [   "Local admin/SeDebug to read other sessions' tickets, or possession "
                             'of an exported ticket (.kirbi/.ccache)'],
        'enumeration': [   'klist',
                           'klist sessions',
                           'whoami /priv (SeDebugPrivilege for cross-session extraction)'],
        'detection_indicators': [   'sekurlsa::tickets / Rubeus dump/ptt execution',
                                    'TGS/TGT requests with anomalous encryption types (RC4) or '
                                    'from unusual hosts (Event 4768/4769)',
                                    '.kirbi/.ccache files on disk',
                                    'Logon session with an injected ticket not matching the '
                                    "account's normal auth"],
        'tools': [   'rubeus (ghostpack)',
                     'mimikatz kerberos::/sekurlsa::tickets',
                     'impacket (ticketer, gettgt)'],
        'cve': [],
        'mitigation': [   'Enable Credential Guard to protect tickets in LSASS',
                          'Enforce AES, disable RC4; use strong service-account passwords and gMSA',
                          'Monitor 4768/4769 for RC4/anomalous ticket requests; limit local admin'],
        'poc_references': [   'https://github.com/GhostPack/Rubeus',
                              'https://github.com/gentilkiwi/mimikatz'],
        'research_references': [   'https://attack.mitre.org/techniques/T1558/',
                                   'https://attack.mitre.org/techniques/T1550/003/']},
    {   'id': 'windows-phantom-dll-hijacking',
        'name': 'Phantom (Missing) DLL Hijacking',
        'platform': 'windows',
        'category': 'dll-hijack',
        'severity': 'high',
        'summary': 'Some Windows binaries attempt to load DLLs that do not exist on the system; '
                   'planting a same-named DLL in a searched writable location grants code '
                   'execution when the (often auto-elevated or SYSTEM) host process runs.',
        'technique': 'Phantom DLLs are referenced-but-absent modules (optional plugins, debug '
                     'helpers, removed components). Because the file is missing, the loader '
                     'continues down the search path; if any searched directory is writable, an '
                     'attacker-supplied DLL of that name is loaded. It re-triggers each time the '
                     'host process starts, providing both privilege escalation and persistence. '
                     'Coined by Hexacorn; classic examples historically include wlbsctrl.dll, '
                     'WptsExtensions.dll and TSMSISrv.dll.',
        'prerequisites': [   'a host process referencing a nonexistent DLL',
                             'write access to a searched directory'],
        'enumeration': [   'Process Monitor filter: Result is NAME NOT FOUND AND Path ends with '
                           '.dll, correlated to elevated processes',
                           'cross-reference the hijacklibs.net phantom-DLL catalog',
                           'accesschk.exe -accepteula -uwdq "<candidate search directory>"'],
        'detection_indicators': [   'Process Monitor NAME NOT FOUND for a DLL that never resolves '
                                    'in any search path',
                                    'a new DLL appearing in System32 or an app dir matching a '
                                    'known phantom name',
                                    'high-integrity/auto-elevated process probing for a '
                                    'nonexistent DLL'],
        'tools': ['procmon', 'hijacklibs', 'spartacus', 'powerup', 'winpeas'],
        'cve': [],
        'mitigation': [   'place a legitimate signed stub or repair the reference',
                          'restrict DACLs on search directories',
                          'monitor DLL creation in System32 and application folders',
                          'WDAC/AppLocker DLL rules'],
        'poc_references': [   'https://www.hexacorn.com/blog/2013/12/08/beyond-good-ol-run-key-part-5/',
                              'https://hijacklibs.net/'],
        'research_references': [   'https://attack.mitre.org/techniques/T1574/001/',
                                   'https://learn.microsoft.com/en-us/windows/win32/dlls/dynamic-link-library-search-order']},
    {   'id': 'windows-sam-system-hive-dump',
        'name': 'SAM/SYSTEM/SECURITY hive dumping (local account hashes & LSA secrets)',
        'platform': 'windows',
        'category': 'credential-harvesting',
        'severity': 'high',
        'summary': 'Copying the SAM, SYSTEM, and SECURITY registry hives lets an attacker extract '
                   'local account NTLM hashes (SAM+SYSTEM bootkey), LSA secrets, and cached domain '
                   'credentials offline for cracking, pass-the-hash, and lateral movement.',
        'technique': 'The SAM hive stores local password hashes encrypted with the bootkey held in '
                     'SYSTEM; SECURITY holds LSA secrets and cached domain logon verifiers. With '
                     'admin (or SeBackup/shadow-copy access) the hives are exported (reg save '
                     'HKLM\\SAM / HKLM\\SYSTEM / HKLM\\SECURITY, or copied from a VSS snapshot) '
                     'and parsed offline with impacket-secretsdump or mimikatz lsadump to yield '
                     'NTLM hashes, machine account secrets, service-account passwords stored as '
                     'LSA secrets, and DCC2 cached hashes.',
        'prerequisites': [   'Local admin, or SeBackupPrivilege/shadow-copy read access to the '
                             'hive files'],
        'enumeration': [   'reg save HKLM\\SAM %TEMP%\\sam.save',
                           'reg save HKLM\\SYSTEM %TEMP%\\system.save',
                           'vssadmin list shadows'],
        'detection_indicators': [   'reg save/reg export of HKLM\\SAM, HKLM\\SYSTEM, '
                                    'HKLM\\SECURITY',
                                    'Access to \\Windows\\System32\\config\\SAM via a shadow copy '
                                    'path',
                                    'secretsdump.py / lsadump usage',
                                    'Event 4688 for reg.exe saving sensitive hives'],
        'tools': ['reg.exe', 'impacket-secretsdump', 'mimikatz lsadump::sam', 'creddump7'],
        'cve': [],
        'mitigation': [   'Restrict local admin and Backup Operators',
                          'Use unique local admin passwords (LAPS/Windows LAPS)',
                          'Audit reg save of SAM/SYSTEM/SECURITY and shadow-copy creation'],
        'poc_references': [   'https://github.com/fortra/impacket',
                              'https://github.com/gentilkiwi/mimikatz'],
        'research_references': [   'https://attack.mitre.org/techniques/T1003/002/',
                                   'https://attack.mitre.org/techniques/T1003/004/']},
    {   'id': 'windows-sebackup-serestore',
        'name': 'SeBackupPrivilege / SeRestorePrivilege abuse',
        'platform': 'windows',
        'category': 'privileges',
        'severity': 'high',
        'summary': 'SeBackupPrivilege bypasses file ACLs for read (backup semantics) and '
                   'SeRestorePrivilege bypasses them for write, letting a non-admin read protected '
                   "files (SAM/SYSTEM hives, other users' data) or overwrite protected "
                   'files/registry to escalate.',
        'technique': 'SeBackupPrivilege opens files with FILE_FLAG_BACKUP_SEMANTICS, ignoring the '
                     'DACL, so an attacker can copy the SAM and SYSTEM registry hives (e.g. via a '
                     'shadow copy created with diskshadow, or robocopy /b) and extract local '
                     'hashes offline. SeRestorePrivilege conversely allows writing to '
                     'normally-protected locations, enabling overwrite of a service binary, a '
                     'privileged DLL, or registry values (e.g. an IFEO debugger or service '
                     'ImagePath) to gain SYSTEM. These map to the legitimate Backup/Restore '
                     'Operators rights being over-assigned.',
        'prerequisites': [   'Token with SeBackupPrivilege (read) and/or SeRestorePrivilege '
                             '(write) enabled, e.g. Backup Operators membership'],
        'enumeration': [   'whoami /priv',
                           'whoami /groups (look for Backup Operators)',
                           'reg save HKLM\\SAM sam.hive (succeeds with SeBackup)'],
        'detection_indicators': [   '"SeBackupPrivilege"/"SeRestorePrivilege" Enabled in whoami '
                                    '/priv',
                                    'Membership in BUILTIN\\Backup Operators',
                                    'diskshadow.exe / vssadmin shadow-copy creation by non-backup '
                                    'software',
                                    'reg save/robocopy /b of SAM,SYSTEM,SECURITY hives',
                                    'Event 4674/4985 around backup-semantics file access'],
        'tools': [   'sebackupprivilege (giuliano108) powershell cmdlets',
                     'diskshadow',
                     'robocopy',
                     'impacket-secretsdump'],
        'cve': [],
        'mitigation': [   'Restrict Backup Operators membership; avoid granting these rights to '
                          'service/user accounts',
                          'Monitor shadow-copy creation and SAM/SYSTEM hive access',
                          'Use least-privilege backup solutions with auditing'],
        'poc_references': [   'https://github.com/giuliano108/SeBackupPrivilege',
                              'https://github.com/fortra/impacket'],
        'research_references': [   'https://ppn.snovvcrash.rocks/pentest/infrastructure/ad/privileges-abuse/sebackup-serestore',
                                   'https://www.ired.team/offensive-security-experiments/active-directory-kerberos-abuse/privileged-accounts-and-token-privileges']},
    {   'id': 'windows-sedebugprivilege',
        'name': 'SeDebugPrivilege abuse (LSASS access & process injection)',
        'platform': 'windows',
        'category': 'privileges',
        'severity': 'high',
        'summary': 'SeDebugPrivilege lets a token open any process (including '
                   'SYSTEM/protected-adjacent processes) with full access, enabling LSASS memory '
                   'dumping for credential theft and code injection/token theft into SYSTEM '
                   'processes.',
        'technique': 'With SeDebugPrivilege, OpenProcess against arbitrary PIDs succeeds, allowing '
                     "a debugger-class actor to read/write another process's memory. Offensively "
                     'this is used to (a) call MiniDumpWriteDump on lsass.exe and harvest '
                     'credentials offline, or (b) inject into or duplicate the token of an '
                     'existing SYSTEM process and spawn a SYSTEM child. It does not bypass full '
                     'PPL protection on LSASS by itself, but grants the access needed for classic '
                     'dumping and token-manipulation primitives.',
        'prerequisites': [   'Token with SeDebugPrivilege enabled (typically already '
                             'Administrator; sometimes granted to service/backup accounts)'],
        'enumeration': ['whoami /priv', 'tasklist /v', 'Get-Process lsass'],
        'detection_indicators': [   '"SeDebugPrivilege" State=Enabled in whoami /priv',
                                    'Process opening lsass.exe with PROCESS_VM_READ/QUERY (Sysmon '
                                    'Event ID 10 targeting lsass.exe)',
                                    'Security Event 4703 (token privilege adjusted) enabling '
                                    'SeDebugPrivilege',
                                    'MiniDump/comsvcs usage against lsass'],
        'tools': ['mimikatz', 'procdump', 'nanodump', 'seatbelt', 'privesccheck'],
        'cve': [],
        'mitigation': [   'Enable LSA Protection (RunAsPPL) and Credential Guard',
                          "Restrict the 'Debug programs' user right to Administrators only",
                          'Alert on non-EDR handles to lsass.exe (Sysmon EID 10)'],
        'poc_references': [   'https://github.com/gentilkiwi/mimikatz',
                              'https://github.com/fortra/nanodump'],
        'research_references': [   'https://attack.mitre.org/techniques/T1003/001/',
                                   'https://learn.microsoft.com/en-us/windows/security/threat-protection/security-policy-settings/debug-programs',
                                   'https://www.ired.team/offensive-security-experiments/active-directory-kerberos-abuse/privileged-accounts-and-token-privileges']},
    {   'id': 'windows-seloaddriver',
        'name': 'SeLoadDriverPrivilege abuse (vulnerable/kernel driver load)',
        'platform': 'windows',
        'category': 'privileges',
        'severity': 'high',
        'summary': 'SeLoadDriverPrivilege lets a token load kernel drivers via NtLoadDriver from '
                   'an HKCU-referenced registry path, enabling a BYOVD '
                   '(bring-your-own-vulnerable-driver) chain such as loading Capcom.sys and '
                   'executing attacker code in kernel mode for SYSTEM/kernel escalation.',
        'technique': 'The privilege allows calling NtLoadDriver. The attacker creates a '
                     'driver-service registry key under HKEY_CURRENT_USER (writable without admin) '
                     'pointing ImagePath at a chosen driver, enables the privilege, and loads it. '
                     'Loading a known-vulnerable but validly-signed driver (e.g. Capcom.sys, which '
                     'exposes an IOCTL to run arbitrary code in kernel context) then lets a '
                     'second-stage exploit execute kernel code to elevate. EoPLoadDriver automates '
                     'the privilege enable + registry key + NtLoadDriver steps.',
        'prerequisites': [   'Token with SeLoadDriverPrivilege enabled',
                             'A vulnerable signed driver available on disk (or loadable) plus a '
                             'second-stage exploit for it',
                             'Ability to write the HKCU driver-service registry key'],
        'enumeration': [   'whoami /priv',
                           'reg query HKCU (to confirm write access for the driver key)'],
        'detection_indicators': [   '"SeLoadDriverPrivilege" Enabled in whoami /priv',
                                    'NtLoadDriver / new driver-service key under HKU\\<SID> '
                                    'ImagePath',
                                    'Capcom.sys or other known-vulnerable driver on disk',
                                    'Event 4697/7045 or Sysmon EID 6 (driver load) of an '
                                    'unsigned-by-vendor or blocklisted driver',
                                    'EoPLoadDriver.exe / ExploitCapcom.exe artifacts'],
        'tools': ['eoploaddriver (tarlogicsecurity)', 'capcom.sys', 'dsefix'],
        'cve': [],
        'mitigation': [   "Restrict 'Load and unload device drivers' right to Administrators",
                          'Enable Microsoft vulnerable-driver blocklist and HVCI/Memory Integrity',
                          'Monitor new kernel driver loads (Sysmon EID 6) against a known-good '
                          'allowlist'],
        'poc_references': ['https://github.com/TarlogicSecurity/EoPLoadDriver'],
        'research_references': [   'https://www.tarlogic.com/blog/seloaddriverprivilege-privilege-escalation/',
                                   'https://learn.microsoft.com/en-us/windows-hardware/drivers/dashboard/microsoft-recommended-driver-block-rules']},
    {   'id': 'windows-semanagevolume',
        'name': 'SeManageVolumePrivilege abuse',
        'platform': 'windows',
        'category': 'privileges',
        'severity': 'high',
        'summary': 'SeManageVolumePrivilege (Perform volume maintenance tasks) can be abused via '
                   'FSCTL_SD_GLOBAL_CHANGE to alter the global security descriptor on the volume, '
                   'effectively granting broad write access to C:\\ that enables planting a DLL a '
                   'SYSTEM service will load.',
        'technique': 'The privilege permits low-level volume operations. A public technique issues '
                     'FSCTL_SD_GLOBAL_CHANGE to rewrite SIDs in security descriptors across the '
                     'volume, granting standard users write access to normally-protected '
                     'directories. With write access to C:\\Windows\\System32 (or a spooler/wbem '
                     'drivers path), the attacker drops a malicious DLL that a SYSTEM process '
                     'loads (e.g. via a Print Spooler PrintConfig.dll load), yielding SYSTEM.',
        'prerequisites': [   'Token with SeManageVolumePrivilege enabled',
                             'A SYSTEM process that will load a DLL from a now-writable path'],
        'enumeration': ['whoami /priv', 'icacls C:\\Windows\\System32'],
        'detection_indicators': [   '"SeManageVolumePrivilege" Enabled in whoami /priv',
                                    'SeManageVolumeExploit.exe on disk',
                                    'FSCTL_SD_GLOBAL_CHANGE volume operations by a non-admin',
                                    'New DLL written to System32/spool/wbem by a standard user, '
                                    'followed by SYSTEM DLL load (Sysmon EID 7)'],
        'tools': ['semanagevolumeexploit (csenox)'],
        'cve': [],
        'mitigation': [   "Restrict 'Perform volume maintenance tasks' to Administrators",
                          'File integrity monitoring on System32 and driver directories',
                          'Application allow-listing to block untrusted DLL loads'],
        'poc_references': ['https://github.com/CsEnox/SeManageVolumeExploit'],
        'research_references': [   'https://hackfa.st/Offensive-Security/Windows-Environment/Privilege-Escalation/Token-Impersonation/SeManageVolumePrivilege/',
                                   'https://github.com/gtworek/Priv2Admin']},
    {   'id': 'windows-service-dll-hijacking',
        'name': 'Service DLL Hijacking (ServiceDll / missing dependency)',
        'platform': 'windows',
        'category': 'dll-hijack',
        'severity': 'high',
        'summary': 'Shared-process (svchost) services load logic from a ServiceDll registry value '
                   'or resolve dependent/absent DLLs via search order; a writable ServiceDll path '
                   'or writable search directory yields code execution in the SYSTEM service.',
        'technique': 'Many services run inside svchost.exe and load their DLL from '
                     'HKLM\\SYSTEM\\CurrentControlSet\\Services\\<svc>\\Parameters\\ServiceDll. If '
                     'that DLL file or its directory is user-writable, or the service loads a '
                     'dependent DLL that is missing and resolvable in a writable directory '
                     '(search-order / phantom), replacing or planting the DLL runs attacker code '
                     'in the service (typically SYSTEM) context at start.',
        'prerequisites': [   'writable ServiceDll or a writable search directory for a missing '
                             'dependency',
                             'service restart or reboot'],
        'enumeration': [   'reg query '
                           '"HKLM\\SYSTEM\\CurrentControlSet\\Services\\<svc>\\Parameters" /v '
                           'ServiceDll',
                           'Process Monitor filter: Result is NAME NOT FOUND AND Path ends with '
                           '.dll',
                           'accesschk.exe -accepteula -quv "<ServiceDll path>"'],
        'detection_indicators': [   'Process Monitor CreateFile on a *.dll returning NAME NOT '
                                    'FOUND / PATH NOT FOUND from a writable directory for '
                                    'svchost/service',
                                    'writable ACL on the ServiceDll file or its folder',
                                    'ServiceDll path pointing outside System32'],
        'tools': ['procmon', 'accesschk', 'winpeas', 'powerup', 'privesccheck'],
        'cve': [],
        'mitigation': [   'restrict DLL and directory DACLs to admins/SYSTEM',
                          'keep service DLLs in System32 / KnownDLLs',
                          'use fully-qualified DLL loads and SafeDllSearchMode'],
        'poc_references': [   'https://book.hacktricks.xyz/windows-hardening/windows-local-privilege-escalation/dll-hijacking',
                              'https://hijacklibs.net/'],
        'research_references': [   'https://attack.mitre.org/techniques/T1574/001/',
                                   'https://learn.microsoft.com/en-us/windows/win32/dlls/dynamic-link-library-search-order']},
    {   'id': 'windows-setakeownership',
        'name': 'SeTakeOwnershipPrivilege abuse',
        'platform': 'windows',
        'category': 'privileges',
        'severity': 'high',
        'summary': 'SeTakeOwnershipPrivilege lets a token take ownership of any securable object '
                   'without WRITE_OWNER being granted, after which the new owner can rewrite the '
                   'DACL to grant full control over a privileged file, registry key, or service '
                   'and escalate to SYSTEM.',
        'technique': 'The privilege allows setting oneself as the owner of an object (file, '
                     'registry key, service) regardless of its DACL. Once owner, the attacker '
                     'edits the DACL to grant themselves full control, then modifies a '
                     'SYSTEM-executed resource: replace or hijack a DLL/binary loaded by a SYSTEM '
                     "service, alter a service's configuration, or edit a privileged registry key. "
                     'Native takeown.exe and icacls can perform the ownership/ACL changes.',
        'prerequisites': [   'Token with SeTakeOwnershipPrivilege enabled',
                             'A SYSTEM-executed file/registry target that can be triggered after '
                             'modification'],
        'enumeration': ['whoami /priv', 'icacls C:\\Path\\To\\service.exe', 'sc qc <service>'],
        'detection_indicators': [   '"SeTakeOwnershipPrivilege" Enabled in whoami /priv',
                                    'takeown.exe / SetSecurityInfo ownership changes on '
                                    'system32/service binaries',
                                    'Event 4670 (permissions on an object were changed) on '
                                    'privileged files/keys',
                                    'New owner set on a service binary or DLL by a non-admin SID'],
        'tools': ['takeown.exe', 'icacls', 'powerup', 'accesschk'],
        'cve': [],
        'mitigation': [   "Restrict the 'Take ownership of files or other objects' user right to "
                          'Administrators',
                          'File integrity monitoring / audit object-access on system binaries and '
                          'services',
                          'Alert on ownership changes to protected paths'],
        'poc_references': [   'https://github.com/PowerShellMafia/PowerSploit',
                              'https://github.com/gtworek/Priv2Admin'],
        'research_references': [   'https://github.com/gtworek/Priv2Admin',
                                   'https://learn.microsoft.com/en-us/windows/security/threat-protection/security-policy-settings/take-ownership-of-files-or-other-objects']},
    {   'id': 'windows-uac-bypass-eventvwr',
        'name': 'UAC Bypass via eventvwr.exe',
        'platform': 'windows',
        'category': 'uac-bypass',
        'severity': 'high',
        'summary': 'eventvwr.exe auto-elevates and opens its .msc via the HKCU '
                   'mscfile\\shell\\open\\command handler; hijacking that per-user key runs an '
                   'arbitrary command at high integrity without a UAC prompt.',
        'technique': 'eventvwr.exe (auto-elevate) launches eventvwr.msc using the mscfile file '
                     'association, resolved from '
                     'HKCU\\Software\\Classes\\mscfile\\shell\\open\\command before HKLM. A '
                     'medium-integrity administrator sets that key to an arbitrary command; '
                     'running eventvwr.exe then executes it at high integrity. The technique is '
                     'fileless (registry only). Discovered by Matt Nelson (enigma0x3) and Matt '
                     'Graeber.',
        'prerequisites': ['member of local Administrators in Admin Approval Mode'],
        'enumeration': [   'reg query "HKCU\\Software\\Classes\\mscfile\\shell\\open\\command"  '
                           '(absence is normal)',
                           'monitor that key for writes'],
        'detection_indicators': [   'creation/modification of '
                                    'HKCU\\Software\\Classes\\mscfile\\shell\\open\\command',
                                    'eventvwr.exe spawning non-mmc.exe children',
                                    "Sigma/Splunk 'eventvwr UAC bypass' registry rules firing"],
        'tools': ['uacme', 'metasploit-bypassuac_eventvwr', 'reg.exe'],
        'cve': [],
        'mitigation': [   'set UAC to Always Notify',
                          'remove admin rights from daily accounts',
                          'alert on mscfile\\shell\\open\\command writes'],
        'poc_references': [   'https://enigma0x3.net/2016/08/15/fileless-uac-bypass-using-eventvwr-exe-and-registry-hijacking/',
                              'https://pentestlab.blog/2017/05/02/uac-bypass-event-viewer/'],
        'research_references': [   'https://attack.mitre.org/techniques/T1548/002/',
                                   'https://lolbas-project.github.io/lolbas/Binaries/Eventvwr/']},
    {   'id': 'windows-uac-bypass-fodhelper',
        'name': 'UAC Bypass via fodhelper.exe',
        'platform': 'windows',
        'category': 'uac-bypass',
        'severity': 'high',
        'summary': 'fodhelper.exe auto-elevates and reads a per-user ms-settings shell command key '
                   'that is absent by default; creating it under HKCU runs an attacker command at '
                   'high integrity with no UAC prompt.',
        'technique': 'On Windows 10+, fodhelper.exe is a Microsoft-signed auto-elevating binary '
                     'that queries HKCU\\Software\\Classes\\ms-settings\\Shell\\Open\\command '
                     '(honoring a DelegateExecute value). A medium-integrity administrator creates '
                     'that key, sets its default command, and runs fodhelper.exe; the command '
                     'executes at high integrity. This bypasses UAC for an '
                     'admin-in-Admin-Approval-Mode (medium to high integrity) — it is not a '
                     'cross-user escalation. computerdefaults.exe behaves similarly.',
        'prerequisites': [   'member of local Administrators running in Admin Approval Mode '
                             '(default UAC)'],
        'enumeration': [   'reg query '
                           '"HKCU\\Software\\Classes\\ms-settings\\Shell\\Open\\command"  (absence '
                           'is normal)',
                           'reg query '
                           'HKLM\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Policies\\System '
                           '/v ConsentPromptBehaviorAdmin  (check UAC level)',
                           'monitor the ms-settings command key for creation'],
        'detection_indicators': [   'creation of '
                                    'HKCU\\Software\\Classes\\ms-settings\\Shell\\Open\\command, '
                                    'especially a DelegateExecute value',
                                    'fodhelper.exe spawning cmd.exe/powershell.exe or other '
                                    'children',
                                    'Sysmon RegSetValue on ms-settings\\shell\\open\\command'],
        'tools': ['uacme', 'metasploit-bypassuac_fodhelper', 'reg.exe'],
        'cve': [],
        'mitigation': [   'set UAC to Always Notify',
                          'remove administrator rights from daily-use accounts',
                          'alert on ms-settings\\shell\\open\\command creation'],
        'poc_references': [   'https://winscripting.blog/2017/05/12/first-entry-welcome-and-uac-bypass/',
                              'https://pentestlab.blog/2017/06/07/uac-bypass-fodhelper/'],
        'research_references': [   'https://attack.mitre.org/techniques/T1548/002/',
                                   'https://github.com/hfiref0x/UACME']},
    {   'id': 'windows-uac-bypass-sdclt',
        'name': 'UAC Bypass via sdclt.exe',
        'platform': 'windows',
        'category': 'uac-bypass',
        'severity': 'high',
        'summary': 'The auto-elevating sdclt.exe (Backup and Restore) can be abused through HKCU '
                   'App Paths or its IsolatedCommand key so a per-user registry entry executes an '
                   'arbitrary command at high integrity without prompting.',
        'technique': 'On Windows 10, sdclt.exe auto-elevates. Two documented, fileless registry '
                     'hijacks exist: (a) the App Paths / control.exe route via '
                     'HKCU\\Software\\Classes\\Folder\\shell\\open\\command, and (b) the '
                     'IsolatedCommand route via '
                     'HKCU\\Software\\Classes\\exefile\\shell\\runas\\command\\IsolatedCommand. '
                     'Setting the per-user key and launching sdclt.exe (e.g. with /KickOffElev) '
                     'runs the command at high integrity. Both discovered by enigma0x3.',
        'prerequisites': ['member of local Administrators in Admin Approval Mode'],
        'enumeration': [   'reg query "HKCU\\Software\\Classes\\Folder\\shell\\open\\command"',
                           'reg query "HKCU\\Software\\Classes\\exefile\\shell\\runas\\command"',
                           'monitor those keys for creation'],
        'detection_indicators': [   'writes to '
                                    'HKCU\\Software\\Classes\\Folder\\shell\\open\\command',
                                    'writes to '
                                    'HKCU\\Software\\Classes\\exefile\\shell\\runas\\command\\IsolatedCommand',
                                    'sdclt.exe spawning cmd.exe/powershell.exe'],
        'tools': ['uacme', 'metasploit', 'reg.exe'],
        'cve': [],
        'mitigation': [   'set UAC to Always Notify',
                          'remove admin rights from daily accounts',
                          'alert on the sdclt-related HKCU key writes'],
        'poc_references': [   'https://enigma0x3.net/2017/03/17/fileless-uac-bypass-using-sdclt-exe/',
                              'https://enigma0x3.net/2017/03/14/bypassing-uac-using-app-paths/'],
        'research_references': [   'https://attack.mitre.org/techniques/T1548/002/',
                                   'https://pentestlab.blog/2017/06/09/uac-bypass-sdclt/']},
    {   'id': 'windows-uac-bypass-silentcleanup',
        'name': 'UAC Bypass via SilentCleanup / DiskCleanup Scheduled Task',
        'platform': 'windows',
        'category': 'uac-bypass',
        'severity': 'high',
        'summary': 'The built-in SilentCleanup scheduled task runs cleanmgr.exe with highest '
                   'privileges and is startable by unprivileged users; because its action expands '
                   'the user-controllable %windir% variable, redirecting windir in '
                   'HKCU\\Environment runs an attacker binary elevated.',
        'technique': '\\Microsoft\\Windows\\DiskCleanup\\SilentCleanup is configured '
                     'RunLevel=Highest but its principal lets Users start it. Its action path uses '
                     '%windir%\\system32\\cleanmgr.exe, and environment variables resolve from the '
                     'invoking user; windir can be overridden via HKCU\\Environment. Setting '
                     'windir to an attacker launcher and starting the task executes it '
                     'auto-elevated with no prompt. Unlike binary/DLL hijacks this abuses '
                     'environment-variable expansion inside an auto-elevated task, a class '
                     "documented by James Forshaw (Tyranid's Lair).",
        'prerequisites': [   'member of local Administrators in Admin Approval Mode (SilentCleanup '
                             'auto-elevates for admins)'],
        'enumeration': [   'schtasks /query /tn "\\Microsoft\\Windows\\DiskCleanup\\SilentCleanup" '
                           '/fo LIST /v',
                           'reg query "HKCU\\Environment" /v windir   (absence is normal)',
                           'Get-ScheduledTask -TaskName SilentCleanup | Select -ExpandProperty '
                           'Principal'],
        'detection_indicators': [   "HKCU\\Environment 'windir' set to a non-default value",
                                    'SilentCleanup task started by a non-SYSTEM user',
                                    'cleanmgr.exe or its child spawned from an unusual path'],
        'tools': ['schtasks', 'uacme', 'metasploit-bypassuac_silentcleanup', 'reg.exe'],
        'cve': [],
        'mitigation': [   'reconfigure the task to not use environment variables',
                          'set UAC to Always Notify',
                          'alert on HKCU\\Environment windir being set',
                          'remove admin rights from daily accounts'],
        'poc_references': [   'https://www.tiraniddo.dev/2017/05/exploiting-environment-variables-in.html',
                              'https://www.rapid7.com/db/modules/exploit/windows/local/bypassuac_silentcleanup/'],
        'research_references': [   'https://attack.mitre.org/techniques/T1548/002/',
                                   'https://github.com/hfiref0x/UACME']},
    {   'id': 'windows-unattend-sysprep-gpp-cpassword',
        'name': 'Credentials in unattend.xml / sysprep / Group Policy Preferences',
        'platform': 'windows',
        'category': 'credential-harvesting',
        'severity': 'high',
        'summary': 'Automated-deployment and GPO artifacts frequently embed local administrator or '
                   'service passwords: unattend.xml/sysprep.inf/autounattend.xml store base64 '
                   'admin passwords, and Group Policy Preferences XML on SYSVOL contains '
                   'AES-encrypted cpassword whose key Microsoft publicly disclosed (MS14-025).',
        'technique': 'Unattended-install answer files leave AdministratorPassword (base64-encoded) '
                     'in Panther/sysprep locations readable to users. Group Policy Preferences '
                     '(Groups.xml, Services.xml, ScheduledTasks.xml, Drives.xml, DataSources.xml) '
                     "on \\\\domain\\SYSVOL store a 'cpassword' encrypted with a static AES key "
                     'Microsoft published, so any authenticated domain user can decrypt embedded '
                     'local-admin/service passwords. Both are simple file reads plus a known '
                     'decryption.',
        'prerequisites': [   'Read access to the answer file locally, or authenticated domain '
                             'access to SYSVOL for GPP'],
        'enumeration': [   'dir /s /b C:\\unattend.xml C:\\Windows\\Panther\\Unattend.xml '
                           'C:\\Windows\\System32\\sysprep\\unattend.xml',
                           'findstr /si password *.xml *.ini *.txt',
                           'findstr /S cpassword \\\\<domain>\\SYSVOL\\<domain>\\Policies\\*.xml'],
        'detection_indicators': [   'Presence of unattend.xml/autounattend.xml/sysprep.inf with a '
                                    '<Password> value',
                                    'cpassword= attribute in SYSVOL GPP XML',
                                    'Get-GPPPassword / gpp-decrypt execution',
                                    'Enumeration of SYSVOL Policies for *.xml'],
        'tools': ['powerup get-gpppassword', 'gpp-decrypt', 'metasploit smb_enum_gpp', 'winpeas'],
        'cve': ['CVE-2014-1812'],
        'mitigation': [   'Delete answer files (or scrub passwords) after imaging; do not store '
                          'secrets in unattend.xml',
                          'Apply MS14-025 and remove existing GPP cpassword XML from SYSVOL',
                          'Use LAPS/Windows LAPS for local admin passwords'],
        'poc_references': [   'https://github.com/PowerShellMafia/PowerSploit',
                              'https://github.com/peass-ng/PEASS-ng'],
        'research_references': [   'https://attack.mitre.org/techniques/T1552/006/',
                                   'https://support.microsoft.com/en-us/topic/ms14-025-vulnerability-in-group-policy-preferences-could-allow-elevation-of-privilege-8b0d6c4e-8e4a-1e6a-3c8a-6a1a8b0f2c9c']},
    {   'id': 'windows-unquoted-service-path',
        'name': 'Unquoted Service Path',
        'platform': 'windows',
        'category': 'service-misconfig',
        'severity': 'high',
        'summary': 'A service whose ImagePath is unquoted and contains spaces lets a '
                   'low-privileged user drop a binary at an intermediate path token that the SCM '
                   'launches as the service account (often SYSTEM).',
        'technique': 'The Service Control Manager parses an unquoted ImagePath left-to-right, '
                     'splitting on spaces. For C:\\Program Files\\Some App\\svc.exe it attempts '
                     'C:\\Program.exe, then C:\\Program Files\\Some.exe, before the real target. '
                     'If any intermediate directory in that chain is user-writable, planting a '
                     "same-named executable there causes it to run at the service's privilege "
                     'level on next start/restart or reboot.',
        'prerequisites': [   'write access to an intermediate directory in the unquoted path',
                             'ability to restart the service or reboot'],
        'enumeration': [   'wmic service get name,displayname,pathname,startmode | findstr /i /v '
                           '"\\"" | findstr /i /v "C:\\\\Windows\\\\"',
                           'Get-CimInstance Win32_Service | ? { $_.PathName -notmatch \'^\\"\' '
                           "-and $_.PathName -match ' ' -and $_.PathName -notmatch 'C:\\\\Windows' "
                           '} | Select Name,PathName,StartName,StartMode',
                           'sc.exe qc <service>',
                           'PowerUp: Get-UnquotedService  (or Invoke-AllChecks)',
                           'accesschk.exe -accepteula -uwdq "<intermediate directory>"  (test '
                           'write access)'],
        'detection_indicators': [   'BINARY_PATH_NAME / ImagePath value not wrapped in quotes AND '
                                    'containing a space',
                                    'service binary path resolving into a user-writable directory '
                                    '(e.g. under C:\\ or a writable Program Files subfolder)',
                                    'StartMode Auto with a non-System32 unquoted path',
                                    'unquoted'],
        'tools': ['winpeas', 'powerup', 'privesccheck', 'sharpup', 'sc.exe', 'wmic', 'accesschk'],
        'cve': [],
        'mitigation': [   'quote every ImagePath containing spaces',
                          'restrict write DACLs on Program Files subdirectories and C:\\ root',
                          'install services into protected, non-writable locations'],
        'poc_references': [   'https://book.hacktricks.xyz/windows-hardening/windows-local-privilege-escalation#unquoted-service-paths',
                              'https://github.com/PowerShellMafia/PowerSploit/blob/master/Privesc/PowerUp.ps1'],
        'research_references': [   'https://attack.mitre.org/techniques/T1574/009/',
                                   'https://learn.microsoft.com/en-us/sysinternals/downloads/accesschk']},
    {   'id': 'windows-weak-scheduled-task-permissions',
        'name': 'Weak Scheduled Task Permissions',
        'platform': 'windows',
        'category': 'cron-timers',
        'severity': 'high',
        'summary': 'A scheduled task that runs as SYSTEM or an admin but references a '
                   'user-writable program, script, or working directory (or whose task definition '
                   "file is writable) lets a low-privileged user gain execution at the task's "
                   'privilege on next trigger.',
        'technique': 'Task Scheduler tasks define an action (program + arguments) and a principal '
                     '(RunLevel/user). If the action target, a script it calls, or a folder in the '
                     'resolution chain is writable, or the task XML under '
                     'C:\\Windows\\System32\\Tasks is writable, the attacker overwrites the '
                     'payload path. When the trigger fires (schedule, logon, event) the task '
                     "executes the attacker's code at the configured privilege level.",
        'prerequisites': [   'write access to the task target/script/working dir or the task XML',
                             'the task triggers while running as a higher-privileged principal'],
        'enumeration': [   'schtasks /query /fo LIST /v',
                           'Get-ScheduledTask | % { $_.TaskName; $_.Actions.Execute }',
                           'accesschk.exe -accepteula -quv "C:\\path\\to\\task-target.exe"',
                           'accesschk.exe -accepteula -dqv "C:\\Windows\\System32\\Tasks"',
                           'PowerUp: Get-ModifiableScheduledTaskFile'],
        'detection_indicators': [   'task Principal RunLevel=HighestAvailable or SYSTEM with an '
                                    'action path in a user-writable directory',
                                    'writable ACL on C:\\Windows\\System32\\Tasks\\<task> or on '
                                    'the referenced binary/script',
                                    'task authored by a non-admin account'],
        'tools': ['schtasks', 'accesschk', 'icacls', 'powerup', 'winpeas', 'privesccheck'],
        'cve': [],
        'mitigation': [   'run tasks from protected, admin-only paths',
                          'restrict DACLs on task files, target binaries and called scripts',
                          'use least-privilege task principals'],
        'poc_references': [   'https://book.hacktricks.xyz/windows-hardening/windows-local-privilege-escalation#scheduled-tasks',
                              'https://github.com/PowerShellMafia/PowerSploit/blob/master/Privesc/PowerUp.ps1'],
        'research_references': [   'https://attack.mitre.org/techniques/T1053/005/',
                                   'https://learn.microsoft.com/en-us/sysinternals/downloads/accesschk']},
    {   'id': 'windows-weak-service-binary-file-permissions',
        'name': 'Weak Service Executable File Permissions',
        'platform': 'windows',
        'category': 'writable-file',
        'severity': 'high',
        'summary': 'When the on-disk executable a service runs (or its containing folder) is '
                   'writable by a low-privileged user, the user replaces the binary and it '
                   'executes as the service account at next start.',
        'technique': "Independent of SCM object rights, the NTFS DACL on the service's EXE (or a "
                     'parent folder that permits create/rename/delete) can allow a non-admin to '
                     'overwrite or swap the binary. On the next service start or reboot the SCM '
                     "launches the trojanized file at the service's privilege (commonly SYSTEM). "
                     'Folder write can enable a delete-and-recreate replacement even when the file '
                     'itself is locked.',
        'prerequisites': [   'write access to the service binary or its containing folder',
                             'ability to restart the service or reboot'],
        'enumeration': [   'accesschk.exe -accepteula -quv "C:\\Path\\service.exe"',
                           'icacls "C:\\Path\\service.exe"',
                           'Get-Acl "C:\\Path\\service.exe" | Format-List',
                           'PowerUp: Get-ModifiableServiceFile'],
        'detection_indicators': [   'icacls/accesschk shows (F)/(M)/(W) or '
                                    'WRITE_DAC/FILE_WRITE_DATA for Users/Authenticated '
                                    'Users/Everyone on a service binary or its folder',
                                    'service executable located outside %WinDir% in a '
                                    'user-writable path',
                                    'service binary with non-inherited weak ACE'],
        'tools': ['accesschk', 'icacls', 'powerup', 'winpeas', 'privesccheck'],
        'cve': [],
        'mitigation': [   'restrict binary and folder DACLs to Administrators/SYSTEM',
                          'store service binaries in protected system locations',
                          'enable file integrity monitoring on service EXEs'],
        'poc_references': [   'https://book.hacktricks.xyz/windows-hardening/windows-local-privilege-escalation#services-binaries-weak-permissions',
                              'https://github.com/PowerShellMafia/PowerSploit/blob/master/Privesc/PowerUp.ps1'],
        'research_references': [   'https://attack.mitre.org/techniques/T1574/010/',
                                   'https://learn.microsoft.com/en-us/sysinternals/downloads/accesschk']},
    {   'id': 'windows-win32k-gdi-kernel-lpe',
        'name': 'Windows win32k / GDI kernel LPE to SYSTEM',
        'platform': 'windows',
        'category': 'kernel-exploit',
        'severity': 'high',
        'summary': 'Memory-corruption bugs in the win32k.sys / GDI kernel-mode subsystem (e.g. '
                   'CVE-2021-1732, CVE-2022-21882) give a low-privileged local process arbitrary '
                   'kernel read/write, which is used to steal the SYSTEM token and run code as '
                   'SYSTEM. HackSys Extreme Vulnerable Driver (HEVD) is the standard training '
                   'target.',
        'technique': 'The win32k window-manager runs in kernel mode and historically exposes a '
                     'large attack surface. CVE-2021-1732 and its patch-bypass CVE-2022-21882 '
                     'abuse xxxClientAllocWindowClassExtraBytes / NtUserConsoleControl: by '
                     "desynchronizing the kernel and user-mode views of a window's cbWndExtra "
                     'size, the exploit corrupts an adjacent window object to build an arbitrary '
                     'write, then constructs a fake spmenu and uses GetMenuBarInfo for an '
                     'arbitrary read. With read/write it walks EPROCESS structures to copy the '
                     'SYSTEM process token into the exploiting process (token stealing), yielding '
                     'SYSTEM. The same primitives are practiced against HEVD (stack overflow, UAF, '
                     'type confusion, arbitrary write) in a controlled driver. These are '
                     'memory-corruption LPEs distinct from file-disclosure bugs like '
                     'HiveNightmare/SeriousSAM.',
        'prerequisites': [   'local low-privileged code execution (interactive or service context)',
                             'an unpatched vulnerable win32k/GDI build (or HEVD installed for lab '
                             'use)'],
        'enumeration': [   'systeminfo',
                           'wmic qfe list',
                           'Get-HotFix',
                           'whoami /priv',
                           '[System.Environment]::OSVersion.Version',
                           'wes.py --update  (Windows Exploit Suggester - Next Generation)'],
        'detection_indicators': [   'win32k',
                                    'win32kfull.sys',
                                    'NtUserConsoleControl',
                                    'cbwndextra',
                                    'tagWND',
                                    'KB5009543'],
        'tools': ['windows-exploit-suggester-ng', 'watson', 'winpeas', 'hevd', 'metasploit'],
        'cve': ['CVE-2021-1732', 'CVE-2022-21882'],
        'mitigation': [   'Apply monthly cumulative updates promptly (win32k fixes)',
                          'Enable win32k syscall filtering / Win32k lockdown for suitable '
                          'processes',
                          'Use HVCI / VBS and exploit-guard mitigations; run least-privilege',
                          'Restrict local logon and monitor for token-manipulation behavior'],
        'poc_references': [   'https://unit42.paloaltonetworks.com/win32k-analysis-part-2/',
                              'https://github.com/KaLendsi/CVE-2021-1732-Exploit',
                              'https://github.com/L4ys/CVE-2022-21882'],
        'research_references': [   'https://github.com/hacksysteam/HackSysExtremeVulnerableDriver',
                                   'https://connormcgarr.github.io/']},
    {   'id': 'windows-writable-path-directory',
        'name': 'Writable %PATH% Directory Hijacking',
        'platform': 'windows',
        'category': 'path-hijack',
        'severity': 'high',
        'summary': 'A directory writable by low-privileged users that appears in the machine '
                   '%PATH% lets an attacker plant an EXE or DLL that hijacks unqualified '
                   'command/DLL resolution for privileged processes, services and admin sessions.',
        'technique': 'When a service, scheduled task or administrator invokes a program or loads a '
                     'DLL by bare name, Windows searches PATH directories in order. A '
                     'user-writable directory listed in the machine PATH (especially an early '
                     'entry) lets the attacker plant a same-named binary that shadows a system '
                     "tool or dependency; it then runs with the caller's privileges. This is path "
                     'interception via the PATH environment variable.',
        'prerequisites': [   'a user-writable directory present in the machine PATH',
                             'a privileged caller invoking an unqualified program or DLL name'],
        'enumeration': [   'reg query "HKLM\\SYSTEM\\CurrentControlSet\\Control\\Session '
                           'Manager\\Environment" /v Path',
                           "$env:Path -split ';' | % { icacls $_ } 2>$null",
                           'accesschk.exe -accepteula -uwdq <each PATH directory>',
                           "PowerUp: Get-ModifiablePath -Path ($env:Path -split ';')"],
        'detection_indicators': [   'a machine PATH entry whose DACL grants write to '
                                    'Users/Authenticated Users/Everyone',
                                    'a non-default, user-writable directory prepended to the '
                                    'system PATH',
                                    'an EXE in a PATH directory shadowing a System32 tool name'],
        'tools': ['accesschk', 'icacls', 'powerup', 'winpeas', 'privesccheck'],
        'cve': [],
        'mitigation': [   'remove user-writable directories from the machine PATH',
                          'restrict DACLs on all PATH directories to admins',
                          'avoid placing the current directory in PATH'],
        'poc_references': [   'https://book.hacktricks.xyz/windows-hardening/windows-local-privilege-escalation#dll-hijacking',
                              'https://github.com/PowerShellMafia/PowerSploit/blob/master/Privesc/PowerUp.ps1'],
        'research_references': [   'https://attack.mitre.org/techniques/T1574/007/',
                                   'https://learn.microsoft.com/en-us/sysinternals/downloads/accesschk']},
    {   'id': 'windows-wsus-http-abuse',
        'name': 'WSUS over-HTTP abuse (WSUSpendu / PyWSUS)',
        'platform': 'windows',
        'category': 'service-misconfig',
        'severity': 'high',
        'summary': 'When domain clients pull Windows updates from a WSUS server over cleartext '
                   'HTTP, a man-in-the-middle (or a compromised WSUS server) can inject a '
                   'signed-but-legitimate Microsoft binary plus attacker arguments as a fake '
                   "'update', which the SYSTEM-level update agent installs — yielding local SYSTEM "
                   'code execution.',
        'technique': 'WSUS clients are configured via '
                     'HKLM\\SOFTWARE\\Policies\\Microsoft\\Windows\\WindowsUpdate '
                     '(WUServer/WUStatusServer, UseWUServer). If WUServer is an http:// URL, '
                     'update metadata and approvals travel unencrypted. WSUS only requires that '
                     'the deployed binary be Microsoft-signed — not that it be an actual update — '
                     'so tools like PyWSUS (MITM the HTTP channel and serve a crafted approval) or '
                     'WSUSpendu (inject an update directly on a compromised WSUS server) deliver a '
                     'legitimately-signed LOLBIN such as PsExec with attacker-controlled '
                     'command-line arguments. The Windows Update agent, running as SYSTEM, '
                     'executes it, giving local privilege escalation (and lateral movement to '
                     'every client of that WSUS). CVE-2020-1013 covered a related WSUS/proxy LPE.',
        'prerequisites': [   'target uses WSUS over HTTP (no TLS pinning), AND',
                             'a MITM position on the client-WSUS path (e.g. via ARP/DNS/NBNS '
                             'spoofing), OR admin on the WSUS server'],
        'enumeration': [   'reg query HKLM\\SOFTWARE\\Policies\\Microsoft\\Windows\\WindowsUpdate',
                           'reg query '
                           'HKLM\\SOFTWARE\\Policies\\Microsoft\\Windows\\WindowsUpdate\\AU',
                           'Get-ItemProperty '
                           'HKLM:\\SOFTWARE\\Policies\\Microsoft\\Windows\\WindowsUpdate',
                           'gpresult /h report.html'],
        'detection_indicators': ['WUServer', 'UseWUServer', 'http://', 'WindowsUpdate\\AU', 'WSUS'],
        'tools': ['pywsus', 'wsuspendu', 'responder', 'mitm6'],
        'cve': ['CVE-2020-1013'],
        'mitigation': [   'Configure WSUS to use HTTPS (TLS) for the WUServer URL',
                          'Segment and harden WSUS servers; restrict who can approve updates',
                          'Prevent local MITM (802.1x, disable LLMNR/NBT-NS, dynamic ARP '
                          'inspection)',
                          'Consider signed-metadata/ESU controls and monitor for rogue approvals'],
        'poc_references': [   'https://github.com/GoSecure/pywsus',
                              'https://github.com/AlsidOfficial/WSUSpendu',
                              'https://www.gosecure.net/blog/2020/09/03/wsus-attacks-part-1-introducing-pywsus/'],
        'research_references': [   'https://www.gosecure.net/blog/2020/10/29/wsus-attacks-part-2-cve-2020-1013-a-windows-10-local-privilege-escalation-1-day/',
                                   'https://book.hacktricks.xyz/windows-hardening/windows-local-privilege-escalation#wsus']},
    {   'id': 'windows-autoruns-startup-runkeys',
        'name': 'Autoruns / Startup Folder & Run Keys',
        'platform': 'windows',
        'category': 'autoruns',
        'severity': 'medium',
        'summary': 'Writable HKLM Run/RunOnce keys, the all-users Startup folder, or Winlogon '
                   'Userinit/Shell values let a low-privileged user plant a payload that executes '
                   'in the context of the next (often administrative) user to log on.',
        'technique': 'Programs referenced by '
                     'HKLM\\Software\\Microsoft\\Windows\\CurrentVersion\\Run[Once], the common '
                     'Startup folder (C:\\ProgramData\\Microsoft\\Windows\\Start '
                     'Menu\\Programs\\StartUp), and Winlogon Userinit/Shell run automatically at '
                     'logon. If those keys, folders, or the binaries they reference are writable '
                     'by a non-admin, the attacker adds or overwrites an entry; it executes when '
                     'an administrator logs on, escalating to that user. It doubles as '
                     'persistence.',
        'prerequisites': [   'write access to an autorun location and/or the binary it references',
                             'a higher-privileged user subsequently logs on'],
        'enumeration': [   'reg query HKLM\\Software\\Microsoft\\Windows\\CurrentVersion\\Run',
                           'reg query HKLM\\Software\\Microsoft\\Windows\\CurrentVersion\\RunOnce',
                           'reg query "HKLM\\SOFTWARE\\Microsoft\\Windows '
                           'NT\\CurrentVersion\\Winlogon" /v Userinit',
                           'autorunsc.exe -accepteula -a * -c',
                           'accesschk.exe -accepteula -kvuqsw '
                           'HKLM\\Software\\Microsoft\\Windows\\CurrentVersion\\Run'],
        'detection_indicators': [   'writable DACL on an HKLM Run/RunOnce key or on a binary it '
                                    'references',
                                    'unexpected value under Run/RunOnce or a modified Winlogon '
                                    'Shell/Userinit',
                                    'user-writable ProgramData Startup folder',
                                    'autorunsc flags unsigned/user-writable autostart entries'],
        'tools': ['autoruns', 'autorunsc', 'reg.exe', 'powerup', 'accesschk', 'winpeas'],
        'cve': [],
        'mitigation': [   'restrict DACLs on autorun keys, folders and referenced binaries',
                          'monitor with Sysinternals Autoruns',
                          'deploy application allow-listing (WDAC/AppLocker)'],
        'poc_references': [   'https://book.hacktricks.xyz/windows-hardening/windows-local-privilege-escalation#run-at-startup',
                              'https://www.hexacorn.com/blog/2013/12/08/beyond-good-ol-run-key-part-5/'],
        'research_references': [   'https://attack.mitre.org/techniques/T1547/001/',
                                   'https://learn.microsoft.com/en-us/sysinternals/downloads/autoruns']},
    {   'id': 'windows-cached-domain-credentials-dcc2',
        'name': 'Cached domain credentials (MSCache/DCC2) extraction',
        'platform': 'windows',
        'category': 'credential-harvesting',
        'severity': 'medium',
        'summary': 'Windows caches domain logon verifiers (MS-Cache v2 / DCC2) so users can log on '
                   'when a domain controller is unreachable; these can be dumped from the SECURITY '
                   'hive and cracked offline to recover domain account passwords.',
        'technique': 'Cached domain logon information is stored under HKLM\\SECURITY\\Cache as a '
                     'salted PBKDF2/HMAC-derived verifier (DCC2, aka mscash2). It cannot be used '
                     'directly in pass-the-hash, but is recovered from the SECURITY+SYSTEM hives '
                     '(secretsdump, mimikatz lsadump::cache) and subjected to offline password '
                     'cracking (hashcat mode 2100). Number of cached accounts is governed by the '
                     'CachedLogonsCount policy.',
        'prerequisites': ['Local admin or SeBackup access to SECURITY and SYSTEM hives'],
        'enumeration': [   'reg query "HKLM\\SOFTWARE\\Microsoft\\Windows '
                           'NT\\CurrentVersion\\Winlogon" /v CachedLogonsCount',
                           'reg save HKLM\\SECURITY / HKLM\\SYSTEM'],
        'detection_indicators': [   'Access/export of HKLM\\SECURITY hive',
                                    'lsadump::cache or secretsdump usage',
                                    'hashcat -m 2100 ($DCC2$) artifacts'],
        'tools': ['impacket-secretsdump', 'mimikatz lsadump::cache', 'hashcat'],
        'cve': [],
        'mitigation': [   'Lower CachedLogonsCount (e.g. to 0-1) on servers where offline logon is '
                          'unnecessary',
                          'Enforce strong/long passwords to resist offline cracking',
                          'Restrict local admin; monitor SECURITY hive access'],
        'poc_references': [   'https://github.com/fortra/impacket',
                              'https://github.com/gentilkiwi/mimikatz'],
        'research_references': [   'https://attack.mitre.org/techniques/T1003/005/',
                                   'https://hashcat.net/wiki/doku.php?id=example_hashes']},
    {   'id': 'windows-com-hijacking',
        'name': 'COM Hijacking (HKCU CLSID)',
        'platform': 'windows',
        'category': 'com-hijack',
        'severity': 'medium',
        'summary': 'Because HKCU is searched before HKLM for COM class registrations, populating a '
                   'per-user CLSID InprocServer32/LocalServer32 that shadows or fills an abandoned '
                   'system CLSID causes a privileged or auto-elevated process to load attacker '
                   'code.',
        'technique': 'COM resolves a CLSID by checking HKCU\\Software\\Classes\\CLSID first, then '
                     'HKLM. A non-admin can register an HKCU entry for a CLSID that a '
                     'higher-privileged, auto-elevated, or scheduled process instantiates, '
                     'pointing InprocServer32 at a malicious DLL — or abuse an orphaned CLSID '
                     "whose server is missing. The code then runs in the consuming process's "
                     'context, frequently combined with UAC bypass and persistence.',
        'prerequisites': [   'a privileged/auto-elevated process instantiates a CLSID hijackable '
                             'via HKCU'],
        'enumeration': [   'Process Monitor filter: Operation=RegOpenKey AND Path contains '
                           '\\CLSID\\ AND Result=NAME NOT FOUND',
                           'reg query "HKCU\\Software\\Classes\\CLSID" /s   (inspect '
                           'InprocServer32 values)',
                           'OleViewDotNet to enumerate registered/hijackable CLSIDs'],
        'detection_indicators': [   'Process Monitor: privileged process RegOpenKey on '
                                    'HKCU\\Software\\Classes\\CLSID\\{...}\\InprocServer32 with '
                                    'NAME NOT FOUND then HKLM fallback',
                                    'new HKCU CLSID InprocServer32 entries referencing '
                                    'user-writable DLLs',
                                    'references to abandoned/orphaned CLSIDs'],
        'tools': ['procmon', 'oleviewdotnet', 'accomplice', 'sharpup', 'winpeas'],
        'cve': [],
        'mitigation': [   'monitor HKCU CLSID InprocServer32 writes',
                          'prefer HKLM registration and full DLL paths',
                          'remove orphaned CLSID references',
                          'deploy WDAC/AppLocker DLL rules'],
        'poc_references': [   'https://github.com/tyranid/oleviewdotnet',
                              'https://book.hacktricks.xyz/windows-hardening/windows-local-privilege-escalation#com-hijacking'],
        'research_references': [   'https://attack.mitre.org/techniques/T1546/015/',
                                   'https://learn.microsoft.com/en-us/windows/win32/com/com-registration']},
    {   'id': 'windows-ifeo-debugger-hijack',
        'name': 'Image File Execution Options (IFEO) Debugger Hijack',
        'platform': 'windows',
        'category': 'writable-registry',
        'severity': 'medium',
        'summary': "A Debugger value under an executable's IFEO key makes Windows launch that "
                   'debugger instead of the target; write access to IFEO lets an attacker run code '
                   'when a higher-privileged context launches the target EXE (classic sethc.exe / '
                   'utilman.exe SYSTEM shell at the logon screen).',
        'technique': 'HKLM\\SOFTWARE\\Microsoft\\Windows NT\\CurrentVersion\\Image File Execution '
                     'Options\\<exe>\\Debugger is honored by the loader, which runs the named '
                     'program with the original as an argument; the related '
                     'SilentProcessExit\\MonitorProcess achieves a similar effect. Targeting an '
                     'EXE that a higher-privileged process launches (or the accessibility binaries '
                     'sethc.exe/utilman.exe reachable pre-authentication) yields code execution in '
                     'that elevated/SYSTEM context. Writing IFEO normally needs admin/offline '
                     'access, so this is chiefly a persistence and elevation-holding primitive.',
        'prerequisites': [   'write access to the IFEO key (typically admin/offline)',
                             'the target EXE is later launched by a higher-privileged context'],
        'enumeration': [   'reg query "HKLM\\SOFTWARE\\Microsoft\\Windows '
                           'NT\\CurrentVersion\\Image File Execution Options" /s /v Debugger',
                           'autorunsc.exe -accepteula -t',
                           "Get-ChildItem 'HKLM:\\SOFTWARE\\Microsoft\\Windows "
                           "NT\\CurrentVersion\\Image File Execution Options' | Get-ItemProperty | "
                           '? { $_.Debugger }'],
        'detection_indicators': [   'a Debugger value present under an IFEO subkey for a common '
                                    'EXE (cmd, sethc, utilman, magnify)',
                                    'SilentProcessExit MonitorProcess entries',
                                    "Autoruns 'Image Hijacks' tab populated"],
        'tools': ['reg.exe', 'autoruns', 'autorunsc', 'gflags', 'get-acl'],
        'cve': [],
        'mitigation': [   'restrict the IFEO key DACL to Administrators',
                          'monitor creation of Debugger / MonitorProcess values',
                          'set an SLA on unexpected IFEO entries; use Autoruns to review'],
        'poc_references': [   'https://book.hacktricks.xyz/windows-hardening/windows-local-privilege-escalation#image-file-execution-options',
                              'https://learn.microsoft.com/en-us/windows-hardware/drivers/debugger/how-to-launch-a-debugger-automatically'],
        'research_references': [   'https://attack.mitre.org/techniques/T1546/012/',
                                   'https://learn.microsoft.com/en-us/sysinternals/downloads/autoruns']},
    {   'id': 'windows-registry-app-wifi-stored-creds',
        'name': 'Stored credentials in registry, files & apps (autologon, PuTTY, Wi-Fi, VNC)',
        'platform': 'windows',
        'category': 'credential-harvesting',
        'severity': 'medium',
        'summary': 'Passwords are commonly left in cleartext or trivially-recoverable form in the '
                   'registry (Winlogon AutoAdminLogon DefaultPassword), application configs '
                   '(PuTTY, WinSCP, VNC, OpenVPN), and Wi-Fi profiles, providing easy credential '
                   'wins for lateral movement or escalation.',
        'technique': 'Automatic-logon configuration stores DefaultPassword under '
                     'HKLM\\...\\Winlogon in cleartext. Third-party apps store credentials weakly: '
                     'PuTTY proxy passwords and stored sessions, WinSCP saved sessions '
                     '(obfuscated, reversible), VNC password (fixed-key DES), OpenVPN, and '
                     'SNMP/PuTTY registry entries. Wi-Fi PSKs are recoverable with netsh wlan show '
                     'profile key=clear. Tools like LaZagne and winPEAS automate scraping all of '
                     'these locations.',
        'prerequisites': [   'Read access to the relevant registry keys/files (often standard-user '
                             'readable)'],
        'enumeration': [   'reg query "HKLM\\SOFTWARE\\Microsoft\\Windows '
                           'NT\\CurrentVersion\\Winlogon" /v DefaultPassword',
                           'reg query "HKCU\\Software\\SimonTatham\\PuTTY\\Sessions" /s',
                           'netsh wlan show profile',
                           'netsh wlan show profile name="SSID" key=clear',
                           'findstr /si password *.xml *.ini *.config *.txt'],
        'detection_indicators': [   'AutoAdminLogon=1 with a DefaultPassword value present',
                                    'netsh wlan show profile key=clear execution',
                                    'LaZagne/winPEAS scraping app-credential registry/files',
                                    'cleartext password strings in config files under user/app '
                                    'directories'],
        'tools': ['lazagne', 'winpeas', 'seatbelt', 'netsh'],
        'cve': [],
        'mitigation': [   'Never use AutoAdminLogon with a stored DefaultPassword (use '
                          'gMSA/scheduled logon alternatives)',
                          'Avoid saving credentials in app configs; use credential managers/key '
                          'vaults',
                          'Restrict who can read Wi-Fi profiles; audit config files for secrets'],
        'poc_references': [   'https://github.com/AlessandroZ/LaZagne',
                              'https://github.com/peass-ng/PEASS-ng'],
        'research_references': [   'https://attack.mitre.org/techniques/T1552/002/',
                                   'https://attack.mitre.org/techniques/T1552/001/']}]

PRIVESC_TOOLS: list[dict] = [   {   'id': 'bloodhound-sharphound',
        'name': 'BloodHound / SharpHound',
        'platform': 'active-directory',
        'category': 'ad',
        'summary': 'Attack-path-mapping platform for Active Directory (and Azure AD/Entra). The '
                   'SharpHound collector enumerates users, groups, sessions, ACLs, GPOs, '
                   'delegation, and cert services; BloodHound ingests this into a graph and '
                   'computes shortest paths from any owned principal to high-value targets (e.g. '
                   'Domain Admins), surfacing privesc chains invisible to manual review.',
        'usage_note': 'Used by both red and blue teams; defenders run it to find and cut attack '
                      'paths (dangerous ACLs, delegation, nested admin). Collection detection: '
                      'heavy LDAP/SAMR enumeration and session queries in a short window. Repo is '
                      'now under the SpecterOps org (BloodHound Community Edition); the legacy '
                      'BloodHoundAD repo is archived.',
        'language': 'C# (SharpHound collector); TypeScript/Go + Neo4j (BloodHound)',
        'url': 'https://github.com/SpecterOps/BloodHound'},
    {   'id': 'bloodyad',
        'name': 'bloodyAD',
        'platform': 'active-directory',
        'category': 'ad',
        'summary': 'Fast Active Directory privilege-escalation framework (Python) that abuses AD '
                   'objects and ACLs directly from Linux — add computer accounts, set RBCD, edit '
                   'DACLs (genericAll/owner), change passwords, toggle UAC flags and manage shadow '
                   'credentials — over LDAP(S). Enacts the abuse paths that BloodHound identifies '
                   'without a Windows host.',
        'usage_note': 'e.g. `bloodyAD --host <dc> -d <domain> -u user -p pass add computer`, `set '
                      'owner`, `add genericAll`, `add rbcd`; supports Kerberos and pass-the-hash '
                      'authentication.',
        'language': 'python',
        'url': 'https://github.com/CravateRouge/bloodyAD'},
    {   'id': 'certify',
        'name': 'Certify',
        'platform': 'active-directory',
        'category': 'ad',
        'summary': 'C# tool (GhostPack) to enumerate and abuse Active Directory Certificate '
                   'Services (AD CS). Finds vulnerable certificate templates and exploits the '
                   'ESC1–ESC8 misconfigurations to request certificates that impersonate '
                   'high-privilege users (e.g. Domain Admin) for PKINIT authentication — the '
                   'Windows counterpart to Certipy.',
        'usage_note': '`Certify.exe find /vulnerable` enumerates weak templates; abuse requests a '
                      'certificate as a privileged principal (e.g. `request /template:<vuln> '
                      '/altname:administrator`), then Rubeus performs PKINIT to obtain a TGT/NT '
                      'hash.',
        'language': 'csharp',
        'url': 'https://github.com/GhostPack/Certify'},
    {   'id': 'certipy',
        'name': 'Certipy (and Certify)',
        'platform': 'active-directory',
        'category': 'ad',
        'summary': 'AD Certificate Services (AD CS) enumeration and abuse toolkit. Identifies and '
                   'exploits vulnerable certificate templates and CA misconfigurations (the '
                   'ESC1-ESC17 attack classes), enabling low-privileged users to obtain '
                   'certificates that authenticate as high-privileged principals, a direct path '
                   'from user to Domain Admin. Certipy is the Python/cross-platform tool by ly4k; '
                   'Certify (github.com/GhostPack/Certify) is the original C#/Windows equivalent.',
        'usage_note': "Authorized use: Certipy's `find` command enumerates templates and flags "
                      'vulnerable ESC conditions for remediation reporting. Detection/hardening: '
                      'audit certificate enrollment (events 4886/4887), remove '
                      'ENROLLEE_SUPPLIES_SUBJECT + client-auth EKU on low-privilege templates, '
                      'enforce manager approval, and enable NTLM relay protections (ESC8/ESC11).',
        'language': 'Python (Certipy); C# (Certify)',
        'url': 'https://github.com/ly4k/Certipy'},
    {   'id': 'coercer',
        'name': 'Coercer',
        'platform': 'active-directory',
        'category': 'ad',
        'summary': 'Automated authentication-coercion tool (p0dalirius) that sweeps many known '
                   'vulnerable RPC methods across multiple interfaces (MS-EFSR, MS-RPRN, MS-FSRVP, '
                   'MS-DFSNM, etc.) to force a remote Windows host to authenticate to an attacker. '
                   'Generalizes PetitPotam/PrinterBug into a single fuzzing-and-trigger tool, '
                   'feeding NTLM relay chains toward domain compromise.',
        'usage_note': 'Authorized coercion/relay-exposure testing. Hardening mirrors PetitPotam: '
                      'patch, EPA on AD CS, SMB/LDAP signing, disable NTLM. Detection: a single '
                      'host receiving inbound authentications triggered across many RPC named '
                      'pipes in a short window.',
        'language': 'Python',
        'url': 'https://github.com/p0dalirius/Coercer'},
    {   'id': 'krbrelayup',
        'name': 'KrbRelayUp',
        'platform': 'active-directory',
        'category': 'ad',
        'summary': 'Universal no-fix local privilege escalation (user-to-SYSTEM) for domain-joined '
                   'Windows hosts where LDAP signing/channel binding is not enforced (the '
                   'default). Wraps a Kerberos relay (KrbRelay) with RBCD, Shadow Credentials, or '
                   "AD CS methods to relay the machine's own authentication and gain SYSTEM on the "
                   'local box.',
        'usage_note': 'Authorized use to demonstrate default-configuration risk. Hardening: '
                      'enforce LDAP signing and LDAP channel binding on DCs, enable EPA. '
                      'Detection: local machine account performing RBCD/msDS-KeyCredentialLink '
                      'writes about itself, and Kerberos relay artifacts. Related: '
                      'github.com/cube0x0/KrbRelay.',
        'language': 'C#',
        'url': 'https://github.com/Dec0ne/KrbRelayUp'},
    {   'id': 'mitm6',
        'name': 'mitm6',
        'platform': 'active-directory',
        'category': 'ad',
        'summary': "IPv6/DHCPv6 DNS-takeover primitive (dirkjanm) that abuses Windows' default "
                   "preference for IPv6 to become the network's DNS server via rogue DHCPv6 "
                   'replies, then supplies spoofed name resolution that funnels victim '
                   'authentication into ntlmrelayx for NTLM/LDAP(S) relay attacks against Active '
                   'Directory.',
        'usage_note': 'Run `mitm6 -d <domain>` alongside `ntlmrelayx.py -6 -t ldaps://<dc> '
                      '--delegate-access` to relay coerced auth into RBCD or computer-account '
                      'creation. Very noisy — authorized engagements only.',
        'language': 'python',
        'url': 'https://github.com/dirkjanm/mitm6'},
    {   'id': 'petitpotam',
        'name': 'PetitPotam',
        'platform': 'active-directory',
        'category': 'ad',
        'summary': 'Coercion PoC (CVE-2021-36942) abusing MS-EFSRPC EfsRpcOpenFileRaw and related '
                   'methods to force a Windows host, notably a Domain Controller, to authenticate '
                   'to an attacker-controlled machine. Chained with ntlmrelayx to AD CS (ESC8), it '
                   'enables domain compromise without any credentials.',
        'usage_note': 'Authorized use to validate relay/coercion exposure. Hardening: patch, '
                      'enable Extended Protection for Authentication (EPA) on AD CS web '
                      'enrollment, require SMB/LDAP signing, disable NTLM where possible. '
                      'Detection: unexpected DC-initiated authentication to non-infrastructure '
                      'hosts; EFSRPC over the lsarpc/efsrpc named pipes.',
        'language': 'Python / C#',
        'url': 'https://github.com/topotam/PetitPotam'},
    {   'id': 'purpleknight',
        'name': 'Purple Knight (Semperis)',
        'platform': 'active-directory',
        'category': 'ad',
        'summary': 'Free Semperis assessment tool that scans Active Directory (and Entra ID / '
                   'Okta) for security indicators of exposure and compromise, including '
                   'privilege-escalation paths and misconfigurations, and scores overall posture '
                   'with remediation guidance.',
        'usage_note': 'Run against a domain (defensive/assessment oriented) to surface risky '
                      'delegations, weak ACLs, dangerous group memberships, and escalation paths '
                      'with an overall security score. Detection: authenticated LDAP/AD reads and '
                      'directory-wide enumeration, typically run by defenders.',
        'language': 'Windows tool (binary)',
        'url': 'https://www.purple-knight.com/'},
    {   'id': 'rubeus',
        'name': 'Rubeus',
        'platform': 'active-directory',
        'category': 'ad',
        'summary': 'C# toolset (GhostPack) for raw Kerberos interaction and abuse: ticket '
                   'requesting/renewal, Kerberoasting, AS-REP roasting, pass-the-ticket, '
                   'overpass-the-hash, S4U (constrained-delegation) abuse, and '
                   'unconstrained-delegation ticket harvesting. Core tool for escalating within AD '
                   'by abusing Kerberos delegation and roastable accounts.',
        'usage_note': 'Authorized AD assessment use. Detection: monitor RC4/downgrade TGS requests '
                      '(event 4769 with encryption 0x17), abnormal volumes of service-ticket '
                      'requests (Kerberoasting), and S4U2self/S4U2proxy patterns. Harden with '
                      'strong SPN-account passwords/gMSA and removing unnecessary delegation.',
        'language': 'C#',
        'url': 'https://github.com/GhostPack/Rubeus'},
    {   'id': 'whisker',
        'name': 'Whisker',
        'platform': 'active-directory',
        'category': 'ad',
        'summary': 'C# shadow-credentials attack tool (Elad Shamir) that writes a key to a target '
                   "user or computer's msDS-KeyCredentialLink attribute when you hold write "
                   'privileges over the object, enabling PKINIT/Kerberos authentication as that '
                   'account without changing its password — a stealthy takeover primitive in Key '
                   'Trust / AD CS environments.',
        'usage_note': '`Whisker.exe add /target:<account>` adds the key credential and emits a '
                      'Rubeus command to obtain a TGT and NT hash via PKINIT. Requires '
                      'GenericWrite/GenericAll over the target and a PKINIT-capable environment.',
        'language': 'csharp',
        'url': 'https://github.com/eladshamir/Whisker'},
    {   'id': 'pacu',
        'name': 'Pacu',
        'platform': 'cloud',
        'category': 'container-cloud',
        'summary': 'Modular AWS exploitation framework (Rhino Security Labs) for offensive testing '
                   'of Amazon Web Services environments. Includes IAM privilege-escalation '
                   "enumeration and abuse modules that map a principal's effective permissions and "
                   'identify/exploit misconfigurations (iam:PassRole, policy version rollback, '
                   'CreatePolicyVersion, Lambda/EC2 role abuse) to elevate from a low-privileged '
                   'identity.',
        'usage_note': 'Import keys into a session, enumerate with `iam__enum_permissions`, then '
                      'assess escalation vectors with `iam__privesc_scan`; run report-only/offline '
                      'first and only exercise abuse modules against authorized accounts.',
        'language': 'python',
        'url': 'https://github.com/RhinoSecurityLabs/pacu'},
    {   'id': 'prowler',
        'name': 'Prowler',
        'platform': 'cloud',
        'category': 'container-cloud',
        'summary': 'Open-source multi-cloud security tool for AWS, Azure, GCP and Kubernetes that '
                   'runs hundreds of read-only checks against CIS benchmarks and provider best '
                   'practices, flagging misconfigurations, weak/over-permissive IAM and '
                   'privilege-escalation exposure. Complements ScoutSuite with a '
                   'checks-and-compliance orientation.',
        'usage_note': 'Run an assessment, e.g. `prowler aws` or `prowler azure`, and filter to '
                      'IAM/privilege-escalation checks; outputs CSV/JSON/HTML/OCSF for triage and '
                      'remediation.',
        'language': 'python',
        'url': 'https://github.com/prowler-cloud/prowler'},
    {   'id': 'scoutsuite',
        'name': 'Scout Suite',
        'platform': 'cloud',
        'category': 'container-cloud',
        'summary': 'Multi-cloud security-auditing tool (NCC Group) for AWS, Azure, GCP, Oracle '
                   'Cloud and Alibaba. Reads provider APIs read-only and produces an HTML report '
                   'highlighting misconfigurations, over-permissive IAM roles/policies and '
                   'privilege-escalation paths — used defensively to find the same weaknesses an '
                   'attacker would abuse to elevate.',
        'usage_note': 'Run read-only against an account, e.g. `scout aws` / `scout gcp` / `scout '
                      "azure`, then review the report's IAM, exposure and privilege sections. "
                      'Requires only read/audit credentials.',
        'language': 'python',
        'url': 'https://github.com/nccgroup/ScoutSuite'},
    {   'id': 'amicontained',
        'name': 'amicontained',
        'platform': 'container',
        'category': 'container-cloud',
        'summary': 'Container introspection tool (genuinetools) that reports, from inside a '
                   'container, the runtime in use, effective Linux capabilities, seccomp/AppArmor '
                   'status, namespace configuration and blocked/allowed syscalls. Used to gauge '
                   'how confined a container is and where a breakout or privilege escalation is '
                   'feasible.',
        'usage_note': 'Run inside the container: `amicontained` prints capabilities and seccomp '
                      'mode; excess capabilities (e.g. CAP_SYS_ADMIN) or a disabled seccomp '
                      'profile flag likely escape paths.',
        'language': 'go',
        'url': 'https://github.com/genuinetools/amicontained'},
    {   'id': 'cdk',
        'name': 'CDK (Container DupKit)',
        'platform': 'container',
        'category': 'container-cloud',
        'summary': 'Zero-dependency container penetration toolkit (Go) combining '
                   'information-gathering, exploitation and lateral-movement modules to evaluate '
                   'and escape Docker, Kubernetes and containerd — covering capability abuse, '
                   'mount/host-namespace escapes and cloud-metadata/service-account token theft to '
                   'move from container to host or cluster.',
        'usage_note': 'Drop the static binary in a container and run `cdk evaluate` for '
                      'enumeration, then targeted `cdk run <exploit>` modules on authorized '
                      "targets. Already referenced by the KB's docker-socket technique.",
        'language': 'go',
        'url': 'https://github.com/cdk-team/CDK'},
    {   'id': 'deepce',
        'name': 'DEEPCE',
        'platform': 'container',
        'category': 'container-cloud',
        'summary': 'Dependency-free shell script (Docker Enumeration, Escalation of Privileges and '
                   "Container Escapes) that enumerates a container's mounts, capabilities, "
                   'sockets, environment and credentials and can automate common Docker breakouts '
                   '(mounted docker.sock, privileged mode, sensitive host mounts) to escalate to '
                   'the host.',
        'usage_note': 'Run enumeration-only first (`./deepce.sh`); it flags exposed docker.sock, '
                      '--privileged and host mounts, with optional exploit helpers to be used only '
                      'in authorized tests.',
        'language': 'shell',
        'url': 'https://github.com/stealthcopter/deepce'},
    {   'id': 'kube-hunter',
        'name': 'kube-hunter',
        'platform': 'container',
        'category': 'container-cloud',
        'summary': 'Kubernetes attack-surface discovery tool (Aqua Security) that scans clusters '
                   'remotely, on the network, or from inside a pod for exposed components — '
                   'open/anonymous kubelet (10250/10255), unauthenticated API server, dashboard, '
                   'etcd — and reports weaknesses that can lead to RCE and privilege escalation. '
                   'Now archived but a widely cited reference.',
        'usage_note': 'Passive discovery: `kube-hunter --remote <ip>` or `--pod`; `--active` '
                      'attempts exploitation and must only be used with authorization. Maps well '
                      "to the KB's exposed-kubelet privesc technique.",
        'language': 'python',
        'url': 'https://github.com/aquasecurity/kube-hunter'},
    {   'id': 'kubeletctl',
        'name': 'kubeletctl',
        'platform': 'container',
        'category': 'container-cloud',
        'summary': 'CLI client for the kubelet API (CyberArk) that enumerates and interacts with '
                   'an exposed/anonymous-auth kubelet on port 10250 — listing pods and running '
                   'commands inside running containers. Turns an unauthenticated kubelet into RCE '
                   'and a privilege-escalation foothold by executing in pods and harvesting their '
                   'service-account tokens.',
        'usage_note': 'Enumerate the surface with `kubeletctl pods` / `scan` against the node, '
                      'then (authorized only) `kubeletctl exec` into a container; commonly chained '
                      'to steal SA tokens and pivot to the API server.',
        'language': 'go',
        'url': 'https://github.com/cyberark/kubeletctl'},
    {   'id': 'peirates',
        'name': 'Peirates',
        'platform': 'container',
        'category': 'container-cloud',
        'summary': 'Kubernetes penetration-testing and privilege-escalation toolkit (InGuardians) '
                   'that automates service-account token abuse, secret harvesting, pod-to-node '
                   'escape (privileged/hostPath pod creation) and cloud-metadata credential theft '
                   'from a compromised pod, chaining a foothold up to node or cluster-admin '
                   'control.',
        'usage_note': 'Run inside a pod; the interactive menu enumerates mounted SA tokens and '
                      'secrets and offers escalation actions such as launching a host-mounting '
                      'pod. Authorized clusters only.',
        'language': 'go',
        'url': 'https://github.com/inguardians/peirates'},
    {   'id': 'hashcat',
        'name': 'hashcat',
        'platform': 'cross-platform',
        'category': 'credential',
        'summary': 'GPU-accelerated password-recovery tool supporting hundreds of hash modes '
                   'central to privilege escalation: Kerberoast TGS-REP (-m 13100), AS-REP roast '
                   '(18200), NTLM (1000), NetNTLMv2 (5600), domain cached credentials DCC2/mscash2 '
                   '(2100) and Linux shadow (1800/500). Turns captured hashes into plaintext for '
                   'credential reuse and elevation.',
        'usage_note': 'e.g. `hashcat -m 13100 hashes.txt wordlist.txt -r rules/best64.rule`; takes '
                      'over where a capture tool (kerbrute, impacket, pypykatz, responder) leaves '
                      "off. Fills the KB's missing cracker slot alongside kerbrute.",
        'language': 'c',
        'url': 'https://github.com/hashcat/hashcat'},
    {   'id': 'john',
        'name': 'John the Ripper (jumbo)',
        'platform': 'cross-platform',
        'category': 'credential',
        'summary': 'CPU-focused password cracker (Openwall jumbo edition) with an extensive format '
                   'list and a family of *2john helper tools (unshadow, kirbi2john, etc.). Cracks '
                   'Kerberoast/AS-REP, NTLM, DCC2 and Unix shadow hashes and is often the easiest '
                   'way to extract and normalize hashes into a crackable form.',
        'usage_note': 'Convert then crack, e.g. `unshadow passwd shadow > hashes && john hashes`, '
                      'or `john --format=krb5tgs kerb.txt --wordlist=rockyou.txt`. Complements '
                      'hashcat when no GPU is available.',
        'language': 'c',
        'url': 'https://github.com/openwall/john'},
    {   'id': 'lazagne',
        'name': 'LaZagne',
        'platform': 'cross-platform',
        'category': 'credential',
        'summary': 'Broad local credential-recovery tool that harvests stored secrets from a wide '
                   'range of software — browsers, mail clients, Wi-Fi profiles, databases, '
                   'sysadmin tools (WinSCP, PuTTY, FileZilla), chats, git/svn and OS '
                   'keyrings/DPAPI — on Windows and Linux. Discovered passwords are frequently '
                   'reusable for privilege escalation and lateral movement.',
        'usage_note': 'Run as the current user to dump everything: `lazagne.exe all` (Windows) or '
                      '`python lazagne.py all` (Linux); scope to a single provider with e.g. '
                      '`browsers`. Recovered creds are then cracked or replayed.',
        'language': 'python',
        'url': 'https://github.com/AlessandroZ/LaZagne'},
    {   'id': 'pypykatz',
        'name': 'pypykatz',
        'platform': 'cross-platform',
        'category': 'credential',
        'summary': 'Pure-Python reimplementation of Mimikatz for OFFLINE credential extraction: '
                   'parses LSASS memory dumps, SAM/SYSTEM/SECURITY registry hives and DPAPI '
                   'blobs/masterkeys to recover plaintext passwords, NT hashes and Kerberos '
                   'tickets without running native code on the target. Central to privilege '
                   'escalation because recovered SYSTEM/admin secrets are reused for lateral '
                   'movement and elevation.',
        'usage_note': 'Acquire an LSASS dump with a benign method (Task Manager, procdump, or '
                      'comsvcs.dll MiniDump) then parse on the analyst host: `pypykatz lsa '
                      'minidump lssas.dmp`; extract local hashes offline with `pypykatz registry '
                      '--sam sam SYSTEM`.',
        'language': 'python',
        'url': 'https://github.com/skelsec/pypykatz'},
    {   'id': 'responder',
        'name': 'Responder',
        'platform': 'cross-platform',
        'category': 'credential',
        'summary': 'LLMNR/NBT-NS/mDNS poisoner and rogue authentication server. Answers broadcast '
                   'name-resolution queries to coerce victims into authenticating, capturing '
                   'NetNTLMv1/v2 hashes for offline cracking or relaying. A primary '
                   'initial-foothold and privesc-enabling tool on Windows networks (often paired '
                   'with ntlmrelayx).',
        'usage_note': 'Authorized internal assessment use. Defensive: disable LLMNR/NBT-NS/mDNS '
                      'via GPO, enforce SMB signing to block relay, deploy honeytokens. Detection: '
                      'a host answering LLMNR/NBT-NS for many names, or unexpected NetNTLM '
                      'authentications to a non-server workstation.',
        'language': 'Python',
        'url': 'https://github.com/lgandx/Responder'},
    {   'id': 'donpapi',
        'name': 'DonPAPI',
        'platform': 'windows',
        'category': 'credential',
        'summary': 'Remote, mass-scale DPAPI credential-harvesting tool (login-securité) that '
                   'collects and decrypts DPAPI-protected secrets — Windows credentials, browser '
                   'passwords/cookies, Wi-Fi keys, vaults and masterkeys — across many hosts via '
                   'impacket, without dropping binaries. The remote complement to SharpDPAPI for '
                   'post-compromise credential sweeps.',
        'usage_note': '`donpapi collect -t <targets> -u user -p pass` (or `-H <hash>`) gathers and '
                      'decrypts remotely; ideal after initial access to find reusable creds for '
                      'privilege escalation across a fleet.',
        'language': 'python',
        'url': 'https://github.com/login-securite/DonPAPI'},
    {   'id': 'mimikatz',
        'name': 'mimikatz',
        'platform': 'windows',
        'category': 'credential',
        'summary': 'The seminal Windows credential-extraction and Kerberos-abuse toolkit by '
                   'Benjamin Delpy. Dumps plaintext passwords, NTLM hashes, and Kerberos tickets '
                   'from LSASS memory, and implements pass-the-hash, pass-the-ticket, '
                   'overpass-the-hash, Golden/Silver ticket forging, DCSync, and token/privilege '
                   'manipulation, several of which escalate from local admin to domain-wide '
                   'control.',
        'usage_note': 'In authorized red-team labs, requires SeDebugPrivilege/admin to read LSASS. '
                      'Detection is well understood: enable Credential Guard / LSA protection '
                      '(RunAsPPL), monitor LSASS handle opens with suspicious access masks (Sysmon '
                      'EID 10), and alert on DCSync-style replication from non-DC hosts (event '
                      '4662). Widely flagged by AV/EDR by signature.',
        'language': 'C',
        'url': 'https://github.com/gentilkiwi/mimikatz'},
    {   'id': 'sharpdpapi',
        'name': 'SharpDPAPI',
        'platform': 'windows',
        'category': 'credential',
        'summary': 'C# port of Mimikatz DPAPI functionality (GhostPack) that decrypts Windows Data '
                   'Protection API-protected secrets — saved credentials, Credential '
                   'Manager/vaults, RDP, browser cookies/passwords and masterkeys — locally, or '
                   'across a domain using the DPAPI backup/domain key. Yields reusable creds for '
                   'lateral movement and elevation.',
        'usage_note': 'e.g. `SharpDPAPI.exe masterkeys`, `credentials`, `vaults`, `cookies`; with '
                      "a DPAPI domain backup key it decrypts any user's masterkeys offline. Pairs "
                      'with SharpChrome for browser secrets.',
        'language': 'csharp',
        'url': 'https://github.com/GhostPack/SharpDPAPI'},
    {   'id': 'snaffler',
        'name': 'Snaffler',
        'platform': 'windows',
        'category': 'credential',
        'summary': 'Credential/secret discovery tool that crawls accessible network shares across '
                   'an Active Directory environment, hunting for files likely to contain secrets '
                   '(private keys, config files, scripts, password stores) using tunable match '
                   'rules.',
        'usage_note': 'Run as a domain user to enumerate computers, discover readable shares, and '
                      'grep files for high-value patterns; harvested credentials frequently enable '
                      'privilege escalation and lateral movement. Detection: mass SMB share '
                      'enumeration and file reads from a single host, LDAP computer enumeration.',
        'language': 'C#',
        'url': 'https://github.com/SnaffCon/Snaffler'},
    {   'id': 'kerbrute',
        'name': 'kerbrute',
        'platform': 'active-directory',
        'category': 'enumeration',
        'summary': 'Fast Kerberos pre-authentication tool (ropnop) for username enumeration and '
                   'password spraying against AD. Uses AS-REQ responses to validate usernames '
                   'without logging failed logons the way SMB does, and to spray candidate '
                   'passwords, the enumeration/initial-access step that precedes escalation.',
        'usage_note': 'Authorized use only; respect account lockout thresholds when spraying. '
                      'Detection: bursts of Kerberos AS-REQ pre-auth failures (event 4771, failure '
                      'code 0x18) and username probing (0x6 principal-unknown) from a single '
                      "source. kerbrute's failures may bypass some SMB-focused monitoring, so tune "
                      'Kerberos-specific detections.',
        'language': 'Go',
        'url': 'https://github.com/ropnop/kerbrute'},
    {   'id': 'powerview',
        'name': 'PowerView',
        'platform': 'active-directory',
        'category': 'enumeration',
        'summary': "PowerShell AD reconnaissance toolkit (part of PowerSploit's Recon module). "
                   'Enumerates domain users, groups, ACLs, trusts, GPOs, local admin access, '
                   'sessions, and delegation without native RSAT tools, the manual counterpart to '
                   'SharpHound for discovering privesc-relevant misconfigurations.',
        'usage_note': 'Authorized enumeration and blue-team ACL auditing (e.g. '
                      '`Find-InterestingDomainAcl`, `Get-DomainUser -SPN`). Detection: anomalous '
                      'LDAP query patterns from non-admin workstations; script-block logging '
                      '(event 4104) captures PowerView function names. Note PowerSploit is '
                      'archived/unmaintained; many operators use the community `dev` fork or '
                      'ports.',
        'language': 'PowerShell',
        'url': 'https://github.com/PowerShellMafia/PowerSploit'},
    {   'id': 'beroot',
        'name': 'BeRoot',
        'platform': 'cross-platform',
        'category': 'enumeration',
        'summary': 'Multi-platform privesc path detector (Windows, Linux, macOS) that checks '
                   'common misconfigurations which could allow local escalation, reporting '
                   'potential paths rather than exploiting them.',
        'usage_note': 'Run the per-OS build to enumerate items such as writable service '
                      'binaries/paths, weak permissions, sudo rules, and scheduled jobs. Useful '
                      'for consistent cross-platform triage. Detection: OS-specific '
                      'service/sudo/cron enumeration.',
        'language': 'Python / C#',
        'url': 'https://github.com/AlessandroZ/BeRoot'},
    {   'id': 'enum4linux-ng',
        'name': 'enum4linux-ng',
        'platform': 'linux',
        'category': 'enumeration',
        'summary': 'Modern rewrite of enum4linux for enumerating information from Windows/Samba '
                   'SMB services (users, groups, shares, password policy, OS/domain info) from a '
                   'Linux attacker host, with structured JSON/YAML output.',
        'usage_note': 'Point at a target SMB/AD host to gather domain, user, group, share, and '
                      'policy data that supports lateral movement and privilege-escalation '
                      'planning. Detection (target side): SMB/RPC null/authenticated session '
                      'enumeration, LSARPC/SAMR queries.',
        'language': 'Python',
        'url': 'https://github.com/cddmp/enum4linux-ng'},
    {   'id': 'linenum',
        'name': 'LinEnum',
        'platform': 'linux',
        'category': 'enumeration',
        'summary': 'Classic, widely-referenced Linux local enumeration script that collects '
                   'system, user, and configuration data relevant to privilege escalation. Largely '
                   'superseded by LinPEAS/LSE but still common in training material.',
        'usage_note': 'Supports thorough mode (-t), keyword search, and report export. Gathers '
                      'SUID/SGID, cron entries, world-writable files/dirs, sudo rights, and '
                      'environment details. Detection: bulk find/ls -la sweeps and config reads.',
        'language': 'Bash',
        'url': 'https://github.com/rebootuser/LinEnum'},
    {   'id': 'linpeas',
        'name': 'LinPEAS (PEASS-ng)',
        'platform': 'linux',
        'category': 'enumeration',
        'summary': 'Comprehensive Linux/Unix privilege-escalation enumeration script that '
                   'automatically searches for known local privesc vectors and highlights the most '
                   'promising ones with a color-coded (red/yellow) likelihood scheme. The de facto '
                   'standard first-run enumerator on Linux hosts.',
        'usage_note': 'Run after initial low-priv access to surface SUID/SGID binaries, writable '
                      'cron jobs, sudo misconfigurations, Linux capabilities, exposed credentials, '
                      'kernel version, network/container hints. Findings ranked by exploit '
                      'probability so operators triage red/yellow entries first. Detection: mass '
                      'filesystem walks, find for SUID, reads of /etc/crontab, /etc/passwd, '
                      '~/.ssh, and process/env dumps.',
        'language': 'Bash (also precompiled binary)',
        'url': 'https://github.com/peass-ng/PEASS-ng/tree/master/linPEAS'},
    {   'id': 'linuxprivchecker',
        'name': 'linuxprivchecker',
        'platform': 'linux',
        'category': 'enumeration',
        'summary': 'Python enumeration script that inventories the host and attempts to correlate '
                   'discovered software/kernel versions with candidate local privilege-escalation '
                   'exploits.',
        'usage_note': 'Runs local checks (kernel, SUID, writable configs, cron, world-writable) '
                      'and prints candidate exploits. Handy on hosts where Python is present but '
                      'network egress is limited. Detection: Python process performing broad '
                      'filesystem and version enumeration.',
        'language': 'Python',
        'url': 'https://github.com/sleventyeleven/linuxprivchecker'},
    {   'id': 'lse',
        'name': 'linux-smart-enumeration (LSE)',
        'platform': 'linux',
        'category': 'enumeration',
        'summary': 'Linux enumeration script optimized for signal-to-noise, with selectable '
                   'verbosity levels (0-2) that progressively reveal more detail. Designed to '
                   'point out concrete privesc paths rather than dumping raw data like older '
                   'scripts.',
        'usage_note': 'Run with increasing -l levels; at level 0 it shows only high-probability '
                      'findings, useful when LinPEAS output is overwhelming. Uses colored test '
                      'results (found / probably vulnerable). Detection: same signature class as '
                      'LinPEAS (SUID/cron/sudo enumeration).',
        'language': 'Bash',
        'url': 'https://github.com/diego-treitos/linux-smart-enumeration'},
    {   'id': 'pspy',
        'name': 'pspy',
        'platform': 'linux',
        'category': 'enumeration',
        'summary': 'Unprivileged process-snooping tool that watches process creation and '
                   'filesystem events without root by combining procfs polling with inotify. '
                   'Reveals cron jobs and scheduled/automated commands run by other users '
                   '(including root).',
        'usage_note': 'Run as a low-priv user to observe root-run cron/timer commands and their '
                      'arguments in real time, exposing exploitable scheduled tasks and secrets '
                      'passed on command lines. Detection: sustained high-rate /proc scanning and '
                      'inotify watches from a non-root process.',
        'language': 'Go',
        'url': 'https://github.com/DominicBreuker/pspy'},
    {   'id': 'swiftbelt',
        'name': 'SwiftBelt',
        'platform': 'macos',
        'category': 'enumeration',
        'summary': "macOS host situational-awareness and enumeration tool (inspired by harmj0y's "
                   'Seatbelt) that gathers privilege-escalation-relevant context — running '
                   'processes, installed security products, browser history, SSH/AWS config, TCC '
                   'database and installed apps — using native Swift APIs to avoid noisy shell '
                   'commands. First macOS entry for the KB.',
        'usage_note': 'Run the compiled binary as the current user to inventory the host and '
                      'identify escalation surface and defensive tooling; a JXA scripting variant '
                      '(SwiftBelt-JXA) exists at github.com/cedowens/SwiftBelt-JXA.',
        'language': 'swift',
        'url': 'https://github.com/cedowens/SwiftBelt'},
    {   'id': 'accesschk',
        'name': 'AccessChk (Sysinternals)',
        'platform': 'windows',
        'category': 'enumeration',
        'summary': 'Official Microsoft Sysinternals utility that reports the effective permissions '
                   'users and groups have on files, directories, registry keys, services, '
                   'processes, and other securable objects.',
        'usage_note': 'Classic privesc use is validating weak-ACL findings, e.g. checking for '
                      'services/binaries/registry keys writable by low-priv principals '
                      '(accesschk.exe -uwcqv Users *). Being Microsoft-signed, it is a common '
                      'living-off-the-land enumeration tool. Detection: accesschk.exe execution '
                      'and bulk object-permission queries.',
        'language': 'C/C++ (signed Windows binary)',
        'url': 'https://learn.microsoft.com/en-us/sysinternals/downloads/accesschk'},
    {   'id': 'jaws',
        'name': 'JAWS (Just Another Windows (Enum) Script)',
        'platform': 'windows',
        'category': 'enumeration',
        'summary': 'Dependency-light PowerShell enumeration script for Windows privilege '
                   'escalation, written to run on default PowerShell v2+ found on stripped-down or '
                   'legacy hosts.',
        'usage_note': 'Handy on minimal hosts (common in OSCP/lab scenarios) to collect network '
                      'config, services, scheduled tasks, installed software, and file/permission '
                      'data to console or CSV. Detection: PowerShell enumeration of '
                      'services/tasks/ACLs.',
        'language': 'PowerShell',
        'url': 'https://github.com/411Hall/JAWS'},
    {   'id': 'powerup',
        'name': 'PowerUp',
        'platform': 'windows',
        'category': 'enumeration',
        'summary': 'PowerShell privilege-escalation checker (the Privesc module of PowerSploit) '
                   'that enumerates common Windows misconfigurations and flags abusable '
                   'service/registry/path weaknesses, with optional abuse helper functions.',
        'usage_note': 'Invoke-AllChecks reports unquoted service paths, modifiable '
                      'services/binaries, AlwaysInstallElevated, DLL-hijack opportunities, and '
                      'unattended-install credential files. Detection: PowerShell script-block '
                      'logging, AMSI hits, WMI/service ACL enumeration.',
        'language': 'PowerShell',
        'url': 'https://github.com/PowerShellMafia/PowerSploit/tree/master/Privesc'},
    {   'id': 'privesccheck',
        'name': 'PrivescCheck',
        'platform': 'windows',
        'category': 'enumeration',
        'summary': 'Actively maintained PowerShell script that enumerates a wide range of Windows '
                   'configuration weaknesses for privilege escalation, producing severity-ranked, '
                   'readable, and export-friendly output.',
        'usage_note': 'Invoke-PrivescCheck (optionally -Extended/-Audit) inspects services, '
                      'scheduled tasks, registry/file ACLs, credentials, UAC, hijackable DLLs, and '
                      'more; built to minimize noise and work in constrained shells. Detection: '
                      'script-block logging, broad config/registry reads.',
        'language': 'PowerShell',
        'url': 'https://github.com/itm4n/PrivescCheck'},
    {   'id': 'seatbelt',
        'name': 'Seatbelt',
        'platform': 'windows',
        'category': 'enumeration',
        'summary': 'GhostPack C# host-survey tool that runs a broad set of grouped safety checks '
                   'enumerating security-relevant configuration and defensive posture on Windows '
                   'for situational awareness and privesc triage.',
        'usage_note': 'Run grouped checks (e.g., -group=system, -group=user, or -group=all) to '
                      'gather UAC/LSA settings, token privileges, credential artifacts, AV/EDR '
                      'presence, scheduled tasks, PowerShell history, and more. Detection: '
                      'registry/WMI enumeration bursts, credential-store and event-log reads by a '
                      '.NET assembly.',
        'language': 'C#',
        'url': 'https://github.com/GhostPack/Seatbelt'},
    {   'id': 'sharpup',
        'name': 'SharpUp',
        'platform': 'windows',
        'category': 'enumeration',
        'summary': "GhostPack C# port of PowerUp's core checks for identifying common Windows "
                   'privilege-escalation misconfigurations without invoking PowerShell.',
        'usage_note': 'SharpUp.exe audit enumerates unquoted service paths, modifiable '
                      'services/binaries/paths, AlwaysInstallElevated, and cached/unattended '
                      'credentials. Preferred where PowerShell/AMSI is constrained. Detection: '
                      '.NET assembly performing service and ACL enumeration.',
        'language': 'C#',
        'url': 'https://github.com/GhostPack/SharpUp'},
    {   'id': 'winpeas',
        'name': 'WinPEAS (PEASS-ng)',
        'platform': 'windows',
        'category': 'enumeration',
        'summary': 'Windows counterpart of LinPEAS; enumerates local privilege-escalation vectors '
                   'on Windows and highlights likely-exploitable misconfigurations. Part of the '
                   'actively maintained peass-ng project.',
        'usage_note': 'Executed post-access to check unquoted service paths, weak '
                      'service/registry/file ACLs, AlwaysInstallElevated, stored/cached '
                      'credentials, token privileges, scheduled tasks, AutoRuns, and missing '
                      'patches. Detection: sc.exe/registry queries, WMI/CIM calls, '
                      'credential-store reads, and heavy local-config enumeration by a single '
                      'process.',
        'language': 'C# / .bat / PowerShell variants',
        'url': 'https://github.com/peass-ng/PEASS-ng/tree/master/winPEAS'},
    {   'id': 'dirtypipe-pwnkit',
        'name': 'DirtyPipe / PwnKit public PoCs',
        'platform': 'linux',
        'category': 'exploitation',
        'summary': 'Two widely-referenced Linux local privilege-escalation vulnerabilities with '
                   "public PoCs. PwnKit (CVE-2021-4034) is a memory-corruption flaw in Polkit's "
                   'pkexec SUID binary giving instant root on most distros; DirtyPipe '
                   '(CVE-2022-0847) is a Linux kernel page-cache flaw (5.8+) letting an '
                   'unprivileged user overwrite read-only files (e.g. /etc/passwd) to gain root. '
                   'Both are staple kernel/SUID exploit checks after a Linux foothold.',
        'usage_note': 'Authorized/patch-validation use. Reference PoCs: PwnKit '
                      'github.com/berdav/CVE-2021-4034 and DirtyPipe advisory dirtypipe.cm4all.com '
                      '(PoC by Max Kellermann). Remediation: patch polkit and kernel. Detection: '
                      'pkexec invocations with malformed argv/GCONV_PATH env, and unexpected '
                      'writes to read-only system files.',
        'language': 'C',
        'url': 'https://github.com/berdav/CVE-2021-4034'},
    {   'id': 'sudo-suid-abuse',
        'name': 'sudo / SUID / capabilities abuse (GTFOBins-style local privesc technique)',
        'platform': 'linux',
        'category': 'exploitation',
        'summary': 'Core Linux local-privesc technique class rather than a single tool: abusing '
                   'overly permissive sudoers rules, SUID-root binaries, and Linux file '
                   'capabilities (cap_setuid, cap_dac_read_search) to execute code as root. Also '
                   'covers writable cron jobs, PATH hijacking, LD_PRELOAD via env_keep, and '
                   'wildcard/tar injection. GTFOBins is the lookup index mapping each binary to '
                   'its abuse primitive.',
        'usage_note': 'Benign enumeration commands: `sudo -l` (allowed commands), `find / -perm '
                      '-4000 -type f 2>/dev/null` (SUID), `getcap -r / 2>/dev/null` '
                      '(capabilities), `cat /etc/crontab` and cron dirs. Remediate by tightening '
                      'sudoers (avoid NOPASSWD on shell-escapable binaries), stripping unnecessary '
                      'SUID bits, and dropping unneeded capabilities.',
        'language': 'N/A (technique / shell)',
        'url': 'https://gtfobins.github.io/#+sudo'},
    {   'id': 'potato-family',
        'name': 'Potato family (PrintSpoofer / JuicyPotato / RoguePotato / GodPotato)',
        'platform': 'windows',
        'category': 'exploitation',
        'summary': 'Family of local privilege-escalation PoCs that convert Windows '
                   'SeImpersonatePrivilege / SeAssignPrimaryTokenPrivilege (commonly held by '
                   'service accounts like IIS/MSSQL) into a SYSTEM token by abusing NTLM/DCOM/RPC '
                   'authentication relay to local RPC. GodPotato (BeichenDream) works on modern '
                   'Windows 8-11 / Server 2012-2022; PrintSpoofer (itm4n) abuses the print spooler '
                   'named pipe; RoguePotato (antonioCoco) and the original JuicyPotato (ohpe) '
                   'cover earlier OS versions and DCOM/OXID resolution.',
        'usage_note': 'Authorized use to demonstrate service-account-to-SYSTEM escalation. Related '
                      'repos: PrintSpoofer github.com/itm4n/PrintSpoofer, RoguePotato '
                      'github.com/antonioCoco/RoguePotato, JuicyPotato '
                      'github.com/ohpe/juicy-potato. Hardening: remove SeImpersonate from unneeded '
                      'service identities, patch, restrict RPC/DCOM. Detection: a service account '
                      'spawning a SYSTEM process via a local named-pipe/RPC relay pattern.',
        'language': 'C++ / C#',
        'url': 'https://github.com/BeichenDream/GodPotato'},
    {   'id': 'powerupsql',
        'name': 'PowerUpSQL',
        'platform': 'windows',
        'category': 'exploitation',
        'summary': 'PowerShell toolkit (NetSPI) for discovering and attacking Microsoft SQL '
                   'Server. Enumerates instances across a domain and escalates via login '
                   'impersonation (EXECUTE AS), xp_cmdshell OS command execution and linked-server '
                   'crawl chains to reach sysadmin or host-level code execution — a common '
                   'Windows/AD privilege-escalation pivot.',
        'usage_note': 'Discover with `Get-SQLInstanceDomain`, audit with `Invoke-SQLAudit`, check '
                      'elevation with `Invoke-SQLEscalatePriv` and traverse trust chains with '
                      '`Get-SQLServerLinkCrawl`; exercise xp_cmdshell only on authorized targets.',
        'language': 'powershell',
        'url': 'https://github.com/NetSPI/PowerUpSQL'},
    {   'id': 'msf-local-exploit-suggester',
        'name': 'Metasploit local_exploit_suggester',
        'platform': 'cross-platform',
        'category': 'kernel-suggester',
        'summary': 'Metasploit post module that, given an existing session, checks the compromised '
                   "host against Metasploit's catalog of local exploit modules and reports which "
                   "are likely applicable to the target's OS/patch level.",
        'usage_note': 'use post/multi/recon/local_exploit_suggester and set SESSION against an '
                      'existing Meterpreter/shell session to list candidate local privesc modules. '
                      'Suggests only; it does not run the exploits. Detection: session-side '
                      "enumeration commands issued by the module's checks.",
        'language': 'Ruby',
        'url': 'https://github.com/rapid7/metasploit-framework/blob/master/modules/post/multi/recon/local_exploit_suggester.rb'},
    {   'id': 'linux-exploit-suggester',
        'name': 'linux-exploit-suggester (LES)',
        'platform': 'linux',
        'category': 'kernel-suggester',
        'summary': 'Kernel/userspace exploit suggester that compares the host kernel version and '
                   'exposed packages against a curated database of known local privesc '
                   'CVEs/exploits, and also flags relevant hardening (grsecurity, kptr_restrict, '
                   'etc.) that affects exploitability.',
        'usage_note': 'Run on-target for a ranked list of candidate kernel exploits with exposure '
                      'indicators, or feed a kernel string with --kernel. Suggests, does not '
                      'exploit. Detection: reads of /proc/version, package manager queries, uname '
                      'invocation.',
        'language': 'Bash',
        'url': 'https://github.com/mzet-/linux-exploit-suggester'},
    {   'id': 'linux-exploit-suggester-2',
        'name': 'linux-exploit-suggester-2 (LES2)',
        'platform': 'linux',
        'category': 'kernel-suggester',
        'summary': 'Alternative/rewrite of LES that maps the running kernel version to a smaller, '
                   'higher-signal set of well-known kernel privesc exploits (e.g., Dirty COW-class '
                   'and classic CVEs).',
        'usage_note': 'Auto-detects kernel or accepts -k <version>; outputs applicable classic '
                      'exploits with reference links. Detection: uname/kernel-version reads with '
                      'minimal filesystem footprint.',
        'language': 'Perl',
        'url': 'https://github.com/jondonas/linux-exploit-suggester-2'},
    {   'id': 'sherlock',
        'name': 'Sherlock',
        'platform': 'windows',
        'category': 'kernel-suggester',
        'summary': 'Legacy PowerShell script that quickly checks a Windows host against a curated '
                   'set of common privilege-escalation vulnerabilities. Archived and superseded by '
                   'Watson but still referenced in training.',
        'usage_note': 'Find-AllVulns reports whether the host is likely vulnerable to specific '
                      'well-known privesc CVEs (e.g., MS16-class). Detection: PowerShell '
                      'script-block logging and version/patch enumeration.',
        'language': 'PowerShell',
        'url': 'https://github.com/rasta-mouse/Sherlock'},
    {   'id': 'watson',
        'name': 'Watson',
        'platform': 'windows',
        'category': 'kernel-suggester',
        'summary': '.NET tool that enumerates missing KB patches on a Windows host and identifies '
                   'known privilege-escalation vulnerabilities addressable by those patches '
                   '(successor to Sherlock).',
        'usage_note': 'Run on-target to list missing patches mapped to specific privesc CVEs. '
                      'Version-specific: builds target particular Windows/.NET versions, so match '
                      "the target's runtime. Detection: WMI QuickFixEngineering/patch enumeration "
                      'by a .NET assembly.',
        'language': 'C#',
        'url': 'https://github.com/rasta-mouse/Watson'},
    {   'id': 'wesng',
        'name': 'Windows-Exploit-Suggester-NG (WES-NG)',
        'platform': 'windows',
        'category': 'kernel-suggester',
        'summary': 'Offline Windows missing-patch exploit suggester that parses systeminfo output '
                   'and cross-references it against a locally-updatable Microsoft '
                   'security-bulletin database to list missing patches that have public exploits.',
        'usage_note': 'Collect systeminfo from the target, then run WES-NG on the analyst box '
                      '(after wes.py --update); it outputs missing KBs mapped to CVEs and exploit '
                      'availability. Runs entirely offline on the analyst side, so no on-host '
                      'signature. Detection (host side): a single systeminfo execution.',
        'language': 'Python',
        'url': 'https://github.com/bitsadmin/wesng'},
    {   'id': 'chisel-ligolo',
        'name': 'chisel / ligolo-ng (pivoting & tunneling)',
        'platform': 'cross-platform',
        'category': 'post-exploitation',
        'summary': 'Network pivoting/tunneling tools used to reach internal segments from a '
                   'compromised host and thereby escalate reach across a network. Ligolo-ng '
                   '(nicocha30) creates a userland TUN interface for transparent routing without '
                   'SOCKS/proxychains; Chisel (jpillora/chisel) is a fast TCP/UDP tunnel over HTTP '
                   'with SSH-encrypted transport for port-forwarding and SOCKS.',
        'usage_note': 'Authorized pivoting during engagements. Chisel repo: '
                      'github.com/jpillora/chisel. Detection: long-lived encrypted outbound '
                      'tunnels (HTTP-upgraded WebSocket for Chisel), new TUN interfaces on hosts, '
                      'and internal traffic sourced from an unexpected internal box. Egress-filter '
                      'and inspect for tunneling to reduce lateral movement.',
        'language': 'Go',
        'url': 'https://github.com/nicocha30/ligolo-ng'},
    {   'id': 'impacket',
        'name': 'Impacket (secretsdump, psexec, ntlmrelayx, GetUserSPNs)',
        'platform': 'cross-platform',
        'category': 'post-exploitation',
        'summary': 'Foundational Python library and example-script collection for low-level '
                   'network protocols (SMB, MSRPC, Kerberos, LDAP). Key privesc/lateral scripts: '
                   'secretsdump.py (remote SAM/LSA/NTDS.dit extraction incl. DCSync), '
                   'psexec.py/wmiexec.py/smbexec.py (remote code execution as SYSTEM), '
                   'ntlmrelayx.py (NTLM relay to LDAP/AD CS/SMB), and GetUserSPNs.py '
                   '(Kerberoasting).',
        'usage_note': 'Authorized use across the AD kill chain. Detection: DCSync via non-DC '
                      'replication (4662), service-based RCE from psexec (7045 service install, '
                      'named-pipe artifacts), and relay chains (coercion + LDAP/AD CS auth). Now '
                      'maintained by Fortra at github.com/fortra/impacket (the historical '
                      'SecureAuthCorp repo redirects).',
        'language': 'Python',
        'url': 'https://github.com/fortra/impacket'},
    {   'id': 'netexec',
        'name': 'NetExec (successor to CrackMapExec)',
        'platform': 'cross-platform',
        'category': 'post-exploitation',
        'summary': 'Network execution / swiss-army tool for assessing and exploiting AD and '
                   'network services (SMB, WinRM, LDAP, MSSQL, RDP, SSH, WMI, FTP). Automates '
                   'credential spraying, hash/ticket authentication, share and session '
                   'enumeration, remote command execution, LSA/SAM dumping, and a large module '
                   'ecosystem, used to move laterally and escalate across a domain at scale.',
        'usage_note': 'Authorized use only. NetExec (nxc) is the actively maintained successor to '
                      'CrackMapExec (github.com/byt3bl33d3r/CrackMapExec, retired). Detection: '
                      'burst SMB/WinRM authentications across many hosts (spraying), remote '
                      'service/named-pipe RCE, and remote registry secrets dumps. Enforce lockout '
                      'policies, SMB signing, and LSA protection.',
        'language': 'Python',
        'url': 'https://github.com/Pennyw0rth/NetExec'},
    {   'id': 'pwncat',
        'name': 'pwncat',
        'platform': 'linux',
        'category': 'post-exploitation',
        'summary': 'Post-exploitation reverse/bind-shell handler and framework (Caleb Stewart). '
                   'Upgrades a raw shell to a managed session and provides modules for host '
                   'enumeration, persistence, and Linux privilege-escalation checks (SUID, sudo, '
                   'capabilities, writable paths), automating the recon-to-escalation workflow '
                   'after initial access.',
        'usage_note': 'Authorized lab/CTF and assessment use. Distinct from the older '
                      'cytopia/pwncat netcat clone. Detection: outbound reverse-shell connections '
                      'and enumeration bursts (mass reads of /etc, SUID scans). Provides a '
                      'structured, auditable way to run privesc enumeration during engagements.',
        'language': 'Python',
        'url': 'https://github.com/calebstewart/pwncat'},
    {   'id': 'evil-winrm',
        'name': 'Evil-WinRM',
        'platform': 'windows',
        'category': 'post-exploitation',
        'summary': 'Feature-rich WinRM (Windows Remote Management) shell client for authenticated '
                   'remote access to Windows hosts using passwords, NTLM hashes (pass-the-hash), '
                   'or Kerberos tickets. Adds in-memory PowerShell script/loader execution, file '
                   'upload/download, and AMSI-bypass helpers, the standard interactive shell once '
                   'valid credentials or a hash are obtained.',
        'usage_note': 'Authorized use with obtained credentials in scope. Detection: WinRM logons '
                      '(event 4624 type 3 to WS-Management), PowerShell remoting session creation, '
                      'and in-memory script loads via script-block logging (4104). Restrict WinRM '
                      'to admins, use JEA, and monitor ports 5985/5986.',
        'language': 'Ruby',
        'url': 'https://github.com/Hackplayers/evil-winrm'},
    {   'id': 'powersploit',
        'name': 'PowerSploit',
        'platform': 'windows',
        'category': 'post-exploitation',
        'summary': 'Archived but highly influential PowerShell post-exploitation framework whose '
                   'modules (Privesc/PowerUp, Recon/PowerView, CodeExecution, Exfiltration, '
                   'Persistence) are widely reused for enumeration and privilege escalation.',
        'usage_note': 'Import modules to run enumeration: PowerUp for local privesc checks, '
                      'PowerView for AD/domain recon. Foundational codebase forked into many '
                      'modern C#/PowerShell tools. Detection: script-block logging, AMSI, and '
                      'LDAP/WMI recon patterns.',
        'language': 'PowerShell',
        'url': 'https://github.com/PowerShellMafia/PowerSploit'},
    {   'id': 'wadcoms',
        'name': 'WADComs',
        'platform': 'active-directory',
        'category': 'reference-db',
        'summary': 'Interactive cheat-sheet matrix of offensive-security commands for '
                   'Windows/Active Directory environments. Cross-references common tooling '
                   '(Impacket, NetExec, Rubeus, Certipy, etc.) against attack scenarios and the '
                   'credential material held (password, hash, ticket), producing ready command '
                   'syntax for enumeration and AD attack paths.',
        'usage_note': 'Reference use during authorized AD assessments and blue-team training: '
                      'understand which tool/command an attacker would run at a given foothold '
                      'stage so you can build matching detections. Purely a lookup index; ships no '
                      'exploit binaries.',
        'language': 'N/A (curated dataset / Jekyll site)',
        'url': 'https://wadcoms.github.io/'},
    {   'id': 'hacktricks',
        'name': 'HackTricks',
        'platform': 'cross-platform',
        'category': 'reference-db',
        'summary': 'Large community-maintained knowledge base of pentesting and '
                   'privilege-escalation methodology across Linux, Windows, Active Directory, '
                   'cloud, and containers. Contains dedicated Linux and Windows local-privesc '
                   'checklists enumerating misconfiguration classes (sudo, SUID, cron, '
                   'capabilities, kernel exploits, service/registry perms, token privileges) with '
                   'links to relevant PoCs.',
        'usage_note': 'Primary methodology reference and checklist source. The project migrated to '
                      'the book.hacktricks.wiki domain (source at '
                      'github.com/HackTricks-wiki/hacktricks); older book.hacktricks.xyz links '
                      'redirect. Use the Linux/Windows Local Privilege Escalation pages as '
                      'structured hardening checklists.',
        'language': 'N/A (knowledge base / GitBook)',
        'url': 'https://book.hacktricks.wiki/'},
    {   'id': 'payloadsallthethings',
        'name': 'PayloadsAllTheThings',
        'platform': 'cross-platform',
        'category': 'reference-db',
        'summary': 'Comprehensive repository of payloads, bypasses, and methodology notes for web '
                   'and infrastructure security testing, including dedicated Linux and Windows '
                   'privilege-escalation sections that document enumeration steps, common '
                   'misconfigurations, and references to public exploits.',
        'usage_note': 'Use the Methodology and Resources / privilege-escalation directories as an '
                      'offline reference and checklist. Each technique links to source research; '
                      'treat as a study/hardening index rather than a turnkey toolkit.',
        'language': 'N/A (curated repository)',
        'url': 'https://github.com/swisskyrepo/PayloadsAllTheThings'},
    {   'id': 'gtfobins',
        'name': 'GTFOBins',
        'platform': 'linux',
        'category': 'reference-db',
        'summary': 'Curated database of Unix binaries that can be abused to bypass local security '
                   'restrictions. Maps standard utilities (tar, find, vim, awk, less, etc.) to the '
                   'functions they can be coerced into: SUID exploitation, sudo abuse, '
                   'capabilities, shell escapes, file read/write, and reverse shells. The '
                   'canonical reference for turning a misconfigured sudoers entry or a SUID root '
                   'binary into a privesc.',
        'usage_note': 'Defensive/enumeration use: after listing `sudo -l` allowances or SUID '
                      'binaries (`find / -perm -4000 -type f 2>/dev/null`), cross-reference each '
                      'binary against GTFOBins to see whether it is a known privesc vector, then '
                      'remediate the sudoers rule or remove the SUID bit. Detection: monitor for '
                      'shell spawns parented by unexpected utilities (e.g. `find` or `vim` '
                      'spawning `/bin/sh`).',
        'language': 'N/A (curated dataset / Jekyll site)',
        'url': 'https://gtfobins.github.io/'},
    {   'id': 'lolbas',
        'name': 'LOLBAS (Living Off The Land Binaries, Scripts and Libraries)',
        'platform': 'windows',
        'category': 'reference-db',
        'summary': 'Windows counterpart to GTFOBins. Catalogs signed, Microsoft-shipped binaries, '
                   'scripts and libraries (certutil, rundll32, regsvr32, mshta, msbuild, '
                   'bitsadmin, etc.) abusable for execution, download, UAC bypass, credential '
                   'theft, and defense evasion while appearing legitimate. Each entry lists the '
                   'abuse function, sample command, MITRE ATT&CK mapping, and detection notes.',
        'usage_note': 'Defensive use: build allow/deny and detection rules from LOLBAS entries; '
                      'hunt for signed-binary abuse (e.g. `certutil -urlcache` downloads, '
                      '`rundll32` with unusual exports). Provides the ATT&CK technique IDs needed '
                      'to tune EDR/SIEM detections.',
        'language': 'N/A (curated dataset / Jekyll site)',
        'url': 'https://lolbas-project.github.io/'},
    {   'id': 'loldrivers',
        'name': 'LOLDrivers (Living Off The Land Drivers)',
        'platform': 'windows',
        'category': 'reference-db',
        'summary': 'Consolidated database of known vulnerable and malicious Windows drivers used '
                   'in BYOVD (Bring Your Own Vulnerable Driver) attacks. Provides hashes, '
                   'signatures, and Sigma/YARA detection artifacts for drivers attackers load to '
                   'gain kernel-level code execution, disable EDR, or escalate from admin to '
                   'SYSTEM/kernel.',
        'usage_note': 'Defensive use: feed the hash and signature lists into Windows Defender '
                      'Application Control (WDAC) / Microsoft vulnerable-driver blocklist and EDR '
                      'to block BYOVD. Detection: alert on service creation loading a driver whose '
                      'hash matches a LOLDrivers entry.',
        'language': 'N/A (curated dataset / community project)',
        'url': 'https://www.loldrivers.io/'}]
