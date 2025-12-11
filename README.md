# 📘 Threat Hunt Report: Azuki Incident

Date: 12/10/2025

### Platforms and Tools Used:

- Microsoft Defender for Endpoint (Advanced Hunting), Microsoft 365 Defender Portal, Kusto Query Language (KQL), MITRE ATT&CK Framework, Windows Event Telemetry (Process, Registry, Network, File, Logon), Microsoft Word / GitHub Markdown reporting

### Detected Attacker Tooling (LOLBins):

- certutil.exe, wevtutil.exe, arp.exe, attrib.exe, schtasks.exe, mstsc.exe, cmdkey.exe, net.exe

### Cloud/SaaS Channels Identified:

- discord.com (exfiltration/C2), External malicious server at 78.141.196.6

## Scenario Overview - Azuki Import/Export Incident

Azuki Import/Export Trading Co. (梓貿易株式会社) is a small shipping logistics company (23 employees) operating between Japan and Southeast Asia. The security investigation was initiated after a competitor undercut Azuki’s 6-year shipping contract by exactly 3%, and sensitive supplier contracts and pricing data were later observed on underground forums. This strongly suggested a targeted compromise with data theft motivated by competitive and financial gain.

The investigation focused on a single compromised endpoint, AZUKI-SL, an IT admin workstation, using Microsoft Defender for Endpoint (MDE) telemetry as the primary evidence source. The hunt aimed to answer core incident response questions:

Initial access method – How did the attacker first get in?

Compromised accounts – Which identities were abused?

Data stolen – What information was accessed or staged?

Exfiltration method – How did the data leave the environment?

Persistence – Did the attacker maintain ongoing access?

This scenario was designed as a full end-to-end professional threat hunt, emphasizing methodology over simple “flag hunting.” The workflow followed a structured process: reviewing the investigation guide, iterating through each attack stage (initial access, discovery, defense evasion, persistence, credential access, C2, lateral movement, and exfiltration), and documenting findings, queries, IOCs, and the final timeline in a formal investigation report—mirroring real SOC investigation practices.


## SUMMARY OF FINDINGS

Initial access occurred via a successful RemoteInteractive login from 88.97.178.12, compromising user kenji.sato on host azuki-sl.

Discovery actions included ARP cache enumeration, indicating situational awareness and network mapping.

Multiple defense evasion techniques identified, including hidden folders, Windows Defender exclusions, and event log clearing.

Persistence mechanisms established via malicious scheduled tasks and unauthorized administrator account creation.

Credential access achieved using the Mimikatz module sekurlsa::logonpasswords.

Command-and-Control (C2) communications established using both 78.141.196.6 (HTTPS) and discord.com (cloud exfiltration channel).

Lateral movement attempts made toward internal host 10.1.0.188 using cmdkey and mstsc.exe.

## WHO, WHAT, WHEN, WHERE, WHY, HOW

### WHO
### Attacker

- Source IP: 88.97.178.12

- C2 Infrastructure: 78.141.196.6 (HTTPS), discord.com (exfiltration)

### Compromised

- Account: kenji.sato

- Host: azuki-sl

## WHAT (Attack Narrative)

1. RemoteInteractive logon from a public IP compromised host azuki-sl.

2. Attacker performed network discovery using arp -a.

3. A hidden staging folder C:\ProgramData\WindowsCache was created with attrib +h +s.

4. Windows Defender was modified to ignore file extensions (.exe, .ps1, .bat) and folder paths in Temp.

5. Malicious binaries downloaded via certutil.exe from http://78.141.196.6:8080/svchost.exe

6. Persistence scheduled task Windows Update Check created pointing to malicious svchost.exe.

7. Fake svchost.exe beaconed outbound to 78.141.196.6:443.

8. Credential access achieved using Mimikatz → sekurlsa::logonpasswords.

9. Archive export-data.zip created for staging.

10. Exfiltration performed through discord.com over HTTPS.

11. Event logs cleared using wevtutil cl Security.

12. Unauthorized admin account support added to Administrators group.

13. Lateral movement attempted to 10.1.0.188 using cmdkey and mstsc.exe.

## WHEN – Timeline (UTC)

(Times condensed for GitHub readability; full timeline available in docx)

| Time (UTC) | Event                                               |
| ---------- | --------------------------------------------------- |
| 2025-11-19T11:55:03.2854924Z | RemoteInteractive logon from 88.97.178.12           |
| 2025-11-19T18:49:27.6830204Z | Windows Defender exclusions added                   |
| 2025-11-19T19:04:01.773778Z  | ARP cache enumeration (`arp -a`)                    |
| 2025-11-19T19:07:46.9796512Z | Malicious scheduled task created                    |
| 2025-11-19T19:08:26.2804285Z | Mimikatz module `sekurlsa::logonpasswords` executed |
| 2025-11-19T19:09:21.4234133Z | C2 communication to 78.141.196.6 + discord.com      |
| 2025-11-19T19:11:39.0934399Z | Logs cleared (`wevtutil.exe cl security`)           |
| 2025-11-19T19:09:53.0528848Z | Account "support" added to Administrators           |

## WHERE
### Compromised Host: azuki-sl

### Infrastructure Identified
- Attacker IP: 88.97.178.12

- C2 Server: 78.141.196.6

- Exfil Service: discord.com

### Malware Locations
C:\ProgramData\WindowsCache\svchost.exe

C:\ProgramData\WindowsCache\export-data.zip

C:\Users\...\Temp\wupdate.ps1

## WHY
### Root Cause

Weak remote access controls allowed successful RemoteInteractive login using compromised credentials.

### Attacker Objective

- Harvest credentials

- Establish persistent access

- Exfiltrate staged data

- Laterally expand toward 10.1.0.188

## HOW – Attack Chain Overview

1. Initial Access → Remote login via compromised credentials
   - Identified a successful remote logon from external IP address 88.97.178.12 on 2025-11-19 at 11:55:03 UTC. This activity is assessed as the likely point of initial access.
   <img width="650" height="118" alt="Initial Access Query" src="https://github.com/user-attachments/assets/dc3a7a55-4491-4a6a-a238-2cad6179d094" />
   <img width="1153" height="433" alt="Initial Access IP, AccountName" src="https://github.com/user-attachments/assets/877a6c76-aa4a-4de1-8dd9-51a56e303315" />


3. Discovery → Host/network enumeration via ARP

4. Defense Evasion → Hidden folder, Defender exclusions, log clearing

5. Execution → PowerShell script wupdate.ps1

6. Persistence → Scheduled task + admin account “support”

7. Credential Access → Mimikatz dump from LSASS

8. C2 → HTTPS beaconing + Discord-based exfil

9. Lateral Movement → Use of mstsc.exe targeting 10.1.0.188

## IMPACT ASSESSMENT
### Actual Impact

- Full compromise of local credentials

- Potential compromise of adjacent systems

- Exfiltration of staged archive (export-data.zip)

- Loss of event log telemetry due to security log clearing

## Risk Level: CRITICAL

## RECOMMENDATIONS
### IMMEDIATE

- Disable compromised accounts (kenji.sato, support)

- Isolate azuki-sl from network

- Block outbound traffic to 78.141.196.6 and discord.com

### SHORT-TERM (1–7 days)

- Reset all passwords

- Review RDP access policies

- Restore event logging configurations

### LONG-TERM

- Implement MFA for all remote access

- Enforce Defender tamper protection

- Deploy EDR with behavioral protections and script blocking

- Conduct enterprise-wide credential hygiene assessment

## APPENDIX

### A. Indicators of Compromise (IOCs)

| Category            | Indicator                               | Description              |
| ------------------- | --------------------------------------- | ------------------------ |
| Attacker IP         | 88.97.178.12                            | Initial access source    |
| C2 Server           | 78.141.196.6:443                        | HTTPS beaconing          |
| Exfil Channel       | discord.com                             | Encrypted data exfil     |
| Malware File        | C:\ProgramData\WindowsCache\svchost.exe | Fake Windows binary      |
| Archive             | export-data.zip                         | Staged exfiltration data |
| Persistence Account | support                                 | Unauthorized admin       |

### B. MITRE ATT&CK Mapping

| Tactic            | Technique             | ID        | Evidence                   |
| ----------------- | --------------------- | --------- | -------------------------- |
| Initial Access    | Valid Accounts        | T1078     | RemoteInteractive login    |
| Discovery         | Network Discovery     | T1046     | ARP enumeration            |
| Defense Evasion   | Hide Artifacts        | T1564     | Hidden WindowsCache folder |
| Defense Evasion   | Modify AV Config      | T1562.001 | Defender exclusions        |
| Persistence       | Scheduled Task        | T1053.005 | “Windows Update Check”     |
| Persistence       | Create Local Account  | T1136.001 | User “support” added       |
| Credential Access | OS Credential Dumping | T1003.001 | sekurlsa::logonpasswords   |
| Command & Control | Web Protocols         | T1071.001 | HTTPS to 78.141.196.6      |
| Exfiltration      | Exfiltration Over Web | T1041     | discord.com                |
| Impact            | Indicator Removal     | T1070.001 | wevtutil.exe clearing logs |

C. KQL Queries Used
