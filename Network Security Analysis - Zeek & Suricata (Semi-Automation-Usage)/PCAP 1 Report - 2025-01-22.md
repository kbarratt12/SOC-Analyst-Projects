# Network Forensics Case Studies: Real-World Analysis
Author: Malachi Barratt

Date: October 2025

Data Source: malware-traffic-analysis.net

## Overview
This section documents two real-world malware analysis scenarios from malware-traffic-analysis.net, demonstrating how the automated forensics pipeline translates raw network traffic into actionable threat intelligence. Each case study traces the investigative journey from initial triage through final IOC correlation, highlighting the efficiency and depth gained through automation.

## Case Study 1: "Download from Fake Software Site" (2025-01-22)
### Victim Profile & Initial Indicators
The analysis focused on network traffic from compromised host 10.1.17.215 (MAC: 00:d0:b7:26:4a:74), belonging to user shutchenson in the BLUEMOONTUESDAY.COM domain. The host was registered as DESKTOP-L8C5GSJ on the corporate network. This victim profile: a typical end-user machine: is the most common entry point for organizational compromise and the exact target attackers prioritize.
### Stage 1: Quick Triage - Initial Assessment
Running quick-report.sh against the PCAP immediately surfaced the attack surface. The script flagged several red flags within seconds:
A small cluster of destination IPs dominated the connection volume, indicating potential command-and-control (C2) beaconing or data exfiltration. DNS queries revealed multiple suspicious high-entropy domains, a hallmark of algorithmically-generated domain names (DGA) or obfuscated C2 infrastructure. Suricata's signature-based detection triggered alerts on multiple connections, though the sheer volume required filtering to identify the most relevant threats.
#### Suricata Alerts - Key Findings:

- Priority 1 - ET MALWARE Fake Microsoft Teams VBS Payload Inbound (from 5.252.153.241)

- Priority 1 - ET MALWARE Fake Microsoft Teams CnC Payload Request (GET)

- PS1 Powershell File Request, Generic Powershell DownloadString Command, and Generic Powershell DownloadFile Command alerts

These alerts indicated the attacker was leveraging PowerShell for command execution: a hallmark of modern malware delivery chains.
Suspicious Domains:

appointedtimeagriculture.com - a high-entropy, semantically random domain typical of bulletproof hosting or malware C2
authenticatoor.org - the fake software distribution site where the user initially downloaded malware (a typo-squatted domain mimicking legitimate authenticator services, a common social engineering technique)

Why this matters: Manual inspection of raw packet captures would require hours to identify these patterns. Quick-report compressed the analysis to minutes, immediately focusing investigative effort on the most suspicious activity rather than wading through benign traffic.

### Stage 2: Deep Forensic Analysis - Pattern Recognition
With suspicious IPs and domains flagged, detailed-report.sh dug deeper into connection metadata to understand how the attack unfolded:
Unusual long-lived connections on non-standard ports revealed persistent communication channels, inconsistent with normal user browsing behavior. Multiple failed authentication attempts on internal services suggested lateral movement or credential harvesting attempts. File transfer logs identified the download and execution of multiple executable files with suspicious characteristics (packed binaries, obfuscated names). TLS/SSL certificate anomalies (self-signed certificates, mismatched common names) indicated either compromised infrastructure or intentionally deceptive encryption setup.
#### Long-Lived Connections - C2 Beaconing Pattern:
- 2592.042750 sec (43 minutes) - 10.1.17.215 <> 5.252.153.241:80 (http)
- 2441.875806 sec (40+ minutes) - 10.1.17.215 <> 20.10.31.115:443 (ssl)
- 1527.610671 sec (25+ minutes) - 10.1.17.215 <> 45.125.66.252:443 (ssl)
- 616.706301 sec (10 min) - 10.1.17.215 <> 10.1.17.2:445 (SMB/Kerberos/DCE-RPC)
- 601.195884 sec - 10.1.17.215 <> 10.1.17.2:53 (dns)
  
These multi-minute connections are anomalous for normal browsing and indicate persistent C2 communication. The 43-minute conversation with 5.252.153.241 over HTTP (not HTTPS) suggests an intentionally obfuscated control channel designed to blend with legitimate traffic.

#### PowerShell Payload Delivery Sequence:

- GET /api/file/get-file/264872 - 417 bytes text/plain (reconnaissance payload)
- GET /api/file/get-file/29842.ps1 - 1,512 bytes text/plain (PowerShell script)
- GET /api/file/get-file/TeamViewer - 4,380,968 bytes application/x-dosexec (4.3 MB executable)
- GET /api/file/get-file/Teamviewer_Resource_fr - 668,968 bytes application/x-dosexec
- GET /api/file/get-file/TV - 12,920 bytes application/x-dosexec
- GET /api/file/get-file/pas.ps1 - 1,553 bytes text/plain (persistence script)

The staging is deliberate: initial reconnaissance, followed by PowerShell deployment, then multi-staged executable downloads with obfuscated names ("TV", "Teamviewer_Resource_fr") to evade detection.

Why this matters: These patterns tell a story. Each piece of evidence: long connections, auth failures, executables: builds a coherent picture of intrusion tactics. Without automation correlating these disparate log sources, an analyst would need to manually grep through dozens of log files, missing connections between events.

### Stage 3: Targeted IP Investigation - Focused Enrichment
#### Running ip-look.sh 10.1.17.215 revealed:
- Identity Confirmation (Kerberos Logs):
- shutchenson/BLUEMOONTUESDAY -> krbtgt/BLUEMOONTUESDAY (FAILED)
- shutchenson/BLUEMOONTUESDAY.COM -> krbtgt/BLUEMOONTUESDAY.COM (SUCCESS)
- shutchenson/BLUEMOONTUESDAY.COM -> host/desktop-l8c5gsj.bluemoontuesday.com (SUCCESS)
- shutchenson/BLUEMOONTUESDAY.COM -> LDAP/WIN-GSH54QLW48D.bluemoontuesday.com (SUCCESS)

These successful Kerberos authentications confirmed the compromised user's credentials were still valid: a critical indicator that the attacker gained local code execution and could pivot using legitimate domain credentials.

#### Malware Payload Downloads - Complete Inventory:

- 264872 - Initial dropper/loader (417 bytes)
- 29842.ps1 - PowerShell reconnaissance script (1,512 bytes)
- TeamViewer - Fake TeamViewer bundle (4.3 MB executable)
- Teamviewer_Resource_fr - Supplementary DLL/component (668 KB)
- TV - Lightweight stub executable (12 KB)
- pas.ps1 - Persistence/privilege escalation script (1,553 bytes)

Why this matters: IP-look provided a complete victim timeline and asset inventory in one command. An analyst manually correlating DHCP, Kerberos, HTTP, and SMB logs would spend 1+ hour reconstructing this profile. The script output is immediately actionable for incident response: they now know which user, which host, which files were downloaded, and the complete timeline.

### Stage 4: IOC Correlation - Threat Attribution
ioc-cor.sh synthesized findings across Zeek and Suricata to produce a definitive IOC list:

#### Extracted IOC Summary:

- 5 Candidate C2 Infrastructure IPs (5.252.153.241, 45.125.66.32, 45.125.66.252, 20.10.31.115, 185.188.32.26) - Of these, 3 confirmed as primary C2: 5.252.153.241, 45.125.66.32, 45.125.66.252. The other two (20.10.31.115, 185.188.32.26) were flagged by correlation but represent secondary infrastructure or edge cases, demonstrating how the pipeline surfaces multiple suspicious IPs and allows analysts to prioritize confirmed threats.
- 2 Malicious Domains (authenticatoor.org [fake software site], appointedtimeagriculture.com [secondary infrastructure])
- 6 Malware Payloads (multiple executables and PS1 scripts)
- 3 Spoofed User Agents

#### Suricata-Zeek Correlation Confirmation:
The script cross-referenced each alert with actual connection data:
Alert: "ET MALWARE Fake Microsoft Teams CnC Payload Request (GET)"
-> Zeek Connection: 10.1.17.215 <> 5.252.153.241:80 (duration: 2592 sec)
-> Verdict: CONFIRMED MALICIOUS

This correlation eliminated false positives and confirmed that detected traffic was genuinely part of an active attack, not misconfigured legitimate services.
Why this matters: Correlation provided the final, definitive IOC list ready for immediate action: blocking at firewall, submission to threat intelligence platforms, and malware sandbox analysis. The analyst now has 100% confidence in the threat indicators because they're backed by correlated evidence across multiple detection engines.

### Findings Summary (Case Study 1)
- Attack Vector: Social engineering / fake software distribution (faked Microsoft Teams download)
- Attack Type: Multi-stage malware delivery with persistent C2 beaconing
#### Compromise Timeline:

- Initial payload delivery: HTTP GET to 5.252.153.241 over 43-minute window
- PowerShell execution: Immediate upon payload receipt
- Multi-stage deployment: Executables staged and executed within minutes
- Persistence attempt: ps.ps1 script for sustained access

#### Affected Assets:

- 1 user workstation (10.1.17.215 / DESKTOP-L8C5GSJ)
- 1 user account compromised (shutchenson@BLUEMOONTUESDAY.COM)
Potential secondary C2 channels to 20.10.31.115 and 45.125.66.252

Attack Sophistication: Moderate-to-High

Proper staging and obfuscation (fake TeamViewer branding)
- Spamhaus-listed infrastructure (deliberate operational security failure or compromised provider)
- Multi-stage execution (reconnaissance -> PowerShell -> multi-part executable delivery)
- Credential harvesting attempt (fake Google Authenticator domain)

## Automation Impact: Case Study 1
#### Manual Analysis Estimate (Industry Standard):

- Quick triage of raw PCAP: 1-2 hours
- Identifying C2 servers and correlation: 2-3 hours
- Extracting payloads and computing hashes: 1 hour
- Domain/IP reputation research: 45 minutes
- Final IOC list compilation: 30 minutes
Total: 5.5-7 hours

Pipeline Analysis Time: 12 minutes (all 4 scripts executed sequentially)
