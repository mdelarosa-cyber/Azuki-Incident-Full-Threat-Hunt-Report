# 📘 Azuki Incident – Full Threat Hunt Report

Threat Hunting Report – GitHub Portfolio Version

## SUMMARY OF FINDINGS

---

Initial access occurred via a successful RemoteInteractive login from 88.97.178.12, compromising user kenji.sato on host azuki-sl.

Discovery actions included ARP cache enumeration, indicating situational awareness and network mapping.

Multiple defense evasion techniques identified, including hidden folders, Windows Defender exclusions, and event log clearing.

Persistence mechanisms established via malicious scheduled tasks and unauthorized administrator account creation.

Credential access achieved using the Mimikatz module sekurlsa::logonpasswords.

Command-and-Control (C2) communications established using both 78.141.196.6 (HTTPS) and discord.com (cloud exfiltration channel).

Lateral movement attempts made toward internal host 10.1.0.188 using cmdkey and mstsc.exe.

WHO, WHAT, WHEN, WHERE, WHY, HOW
WHO
Attacker

Source IP: 88.97.178.12

C2 Infrastructure: 78.141.196.6 (HTTPS), discord.com (exfiltration)

Compromised

Account: kenji.sato

Host: azuki-sl

WHAT (Attack Narrative)

RemoteInteractive logon from a public IP compromised host azuki-sl.

Attacker performed network discovery using arp -a.

A hidden staging folder C:\ProgramData\WindowsCache was created with attrib +h +s.

Windows Defender was modified to ignore file extensions (.exe, .ps1, .bat) and folder paths in Temp.

Malicious binaries downloaded via certutil.exe from http://78.141.196.6:8080/svchost.exe
.

Persistence scheduled task Windows Update Check created pointing to malicious svchost.exe.

Fake svchost.exe beaconed outbound to 78.141.196.6:443.

Credential access achieved using Mimikatz → sekurlsa::logonpasswords.

Archive export-data.zip created for staging.

Exfiltration performed through discord.com over HTTPS.

Event logs cleared using wevtutil cl Security.

Unauthorized admin account support added to Administrators group.

Lateral movement attempted to 10.1.0.188 using cmdkey and mstsc.exe.

WHEN – Timeline (UTC)

(Times condensed for GitHub readability; full timeline available in docx)

Time (UTC)	Event
11:55:03	RemoteInteractive logon from 88.97.178.12
18:49:27	Windows Defender exclusions added
19:04:01	ARP cache enumeration (arp -a)
19:07:46	Malicious scheduled task created
19:08:26	Mimikatz module sekurlsa::logonpasswords executed
Various	C2 communication to 78.141.196.6 + discord.com
Later	Logs cleared (wevtutil.exe cl security)
Later	Account "support" added to Administrators
WHERE
Compromised Host: azuki-sl
Infrastructure Identified

Attacker IP: 88.97.178.12

C2 Server: 78.141.196.6

Exfil Service: discord.com

Malware Locations

C:\ProgramData\WindowsCache\svchost.exe

C:\ProgramData\WindowsCache\export-data.zip

C:\Users\...\Temp\wupdate.ps1

WHY
Root Cause

Weak remote access controls allowed successful RemoteInteractive login using compromised credentials.

Attacker Objective

Harvest credentials

Establish persistent access

Exfiltrate staged data

Laterally expand toward 10.1.0.188

HOW – Attack Chain Overview

Initial Access → Remote login via compromised credentials

Discovery → Host/network enumeration via ARP

Defense Evasion → Hidden folder, Defender exclusions, log clearing

Execution → PowerShell script wupdate.ps1

Persistence → Scheduled task + admin account “support”

Credential Access → Mimikatz dump from LSASS

C2 → HTTPS beaconing + Discord-based exfil

Lateral Movement → Use of mstsc.exe targeting 10.1.0.188

IMPACT ASSESSMENT
Actual Impact

Full compromise of local credentials

Potential compromise of adjacent systems

Exfiltration of staged archive (export-data.zip)

Loss of event log telemetry due to security log clearing

Risk Level: CRITICAL
RECOMMENDATIONS
IMMEDIATE

Disable compromised accounts (kenji.sato, support)

Isolate azuki-sl from network

Block outbound traffic to 78.141.196.6 and discord.com

SHORT-TERM (1–7 days)

Reset all passwords

Review RDP access policies

Restore event logging configurations

LONG-TERM

Implement MFA for all remote access

Enforce Defender tamper protection

Deploy EDR with behavioral protections and script blocking

Conduct enterprise-wide credential hygiene assessment

APPENDIX
A. Indicators of Compromise (IOCs)
Category	Indicator	Description
Attacker IP	88.97.178.12	Initial access source
C2 Server	78.141.196.6:443	HTTPS beaconing
Exfil Channel	discord.com	Encrypted data exfil
Malware File	C:\ProgramData\WindowsCache\svchost.exe	Fake Windows binary
Archive	export-data.zip	Staged exfiltration data
Persistence Account	support	Unauthorized admin
B. MITRE ATT&CK Mapping
Tactic	Technique	ID	Evidence
Initial Access	Valid Accounts	T1078	RemoteInteractive login
Discovery	Network Discovery	T1046	ARP enumeration
Defense Evasion	Hide Artifacts	T1564	Hidden WindowsCache folder
Defense Evasion	Modify AV Config	T1562.001	Defender exclusions
Persistence	Scheduled Task	T1053.005	“Windows Update Check”
Persistence	Create Local Account	T1136.001	User “support” added
Credential Access	OS Credential Dumping	T1003.001	sekurlsa::logonpasswords
Command & Control	Web Protocols	T1071.001	HTTPS to 78.141.196.6
Exfiltration	Exfiltration Over Web	T1041	discord.com
Impact	Indicator Removal	T1070.001	wevtutil.exe clearing logs
C. KQL Queries Used
