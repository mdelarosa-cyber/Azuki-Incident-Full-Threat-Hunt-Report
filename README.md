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
   <img width="1153" height="433" alt="Initial Access IP, AccountName" src="https://github.com/user-attachments/assets/e53376e1-f341-4f1e-9320-33f9bbabd9b6" />

3. Discovery → Host/network enumeration via ARP
   - Leveraging prior host and account context, I queried for ARP activity to validate potential network discovery. Logs show the attacker executed ARP commands to enumerate the host’s ARP cache.
   <img width="531" height="109" alt="Discovery_KQL" src="https://github.com/user-attachments/assets/1c66686b-dcae-4953-9600-9b1b454cc14d" />
   <img width="883" height="259" alt="ARP EXE" src="https://github.com/user-attachments/assets/a0fbfc59-9f2c-495c-bfef-0eee0ed3ec7b" />

5. Defense Evasion → Hidden folder, Defender exclusions, log clearing
   - Analysis of DeviceProcessEvents revealed the execution of:
attrib.exe +h +s C:\ProgramData\WindowsCache.
Threat actors commonly use attrib.exe to hide directories used for data staging or persistence, indicating potential preparation for exfiltration.
   <img width="1192" height="107" alt="Defense_Evasion" src="https://github.com/user-attachments/assets/1480c6b8-32f7-4041-b1d7-25a89c4e4c48" />
   <img width="974" height="364" alt="attrib_exe" src="https://github.com/user-attachments/assets/7e416080-a07f-42bf-aea5-8d3449ea4b6c" />
   - Queried DeviceRegistryEvents for Defender file-extension exclusions and identified three malicious exclusions—.bat, .ps1, .exe—using the following KQL query.
   <img width="619" height="108" alt="Defense_Evasion2" src="https://github.com/user-attachments/assets/37bf3dfb-b49b-4dca-9c92-775163dbf5ec" />
   <img width="1188" height="133" alt="Defense 2 evasion" src="https://github.com/user-attachments/assets/f7f196da-2d14-4dd4-adf1-2efe56ec5119" />
   - I reviewed Windows Defender exclusion settings to identify any temporary folder paths potentially created by the attacker. The search revealed an exclusion for
C:\Users\KENJI~1.SAT\AppData\Local\Temp, created on 2025-11-19T18:49:27.6830204Z on azuki-sl. The following KQL query was used to identify this modification.
   <img width="643" height="138" alt="Defense_Evasion3" src="https://github.com/user-attachments/assets/27b9e283-0c83-419e-a9f0-6a686b29f479" />
   <img width="939" height="174" alt="Defense3Evasion" src="https://github.com/user-attachments/assets/6ddd06e2-c06a-40ef-8838-1d4e368afeb2" />
   - 
7. Execution → PowerShell script wupdate.ps1
   - I reviewed built-in Windows tools with network capabilities that could have been leveraged during the attack. The analysis showed that certutil.exe was used to download a file from http://78.141.196.6:8080/svchost.exe and save it into the hidden directory C:\ProgramData\WindowsCache\svchost.exe.
   <img width="661" height="127" alt="Defenseevasion4" src="https://github.com/user-attachments/assets/a1285069-43c3-4793-9fd2-feb1823b13a3" />
   <img width="1511" height="135" alt="Defense4evasion" src="https://github.com/user-attachments/assets/64a0d5d8-4453-4374-9057-37e01541abb3" />


9. Persistence → Scheduled task + admin account “support”

10. Credential Access → Mimikatz dump from LSASS

11. C2 → HTTPS beaconing + Discord-based exfil

12. Lateral Movement → Use of mstsc.exe targeting 10.1.0.188

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
