# Network Security Analysis Lab: Automated Forensics Pipeline

## Quick Overview
Developed a **Zeek/Suricata-based automated network forensics pipeline** which reduced malware investigation time using **4 custom Bash automation scripts** and log correlation techniques.

---

## What I Built

### Core Infrastructure
- **Cloud Environment**: DigitalOcean Ubuntu 22.04 droplet (2 vCPU, 4GB RAM)  
- **Security Tools**: Zeek network monitor + Suricata IDS/IPS  
- **Automation**: 4 custom Bash scripts for automated log analysis  

---

## Automated Incident Response Scripts

### 1. Quick Report Script
*5-minute triage for initial assessment:*
- Top connection destinations  
- Protocol distribution  
- Suricata alert summary  
- Suspicious domain detection  

### 2. Detailed Investigation Script
*Deep-dive pattern analysis:*
- Long-duration connections (C2 beaconing)  
- Non-standard ports (evasion detection)  
- Failed authentication attempts (brute force)  
- TLS/SSL certificate anomalies  

### 3. IOC Correlation Script
*Threat intelligence extraction:*
- Cross-references Suricata alerts with Zeek logs  
- Extracts malicious IPs, domains, and file hashes  
- Identifies DGA (Domain Generation Algorithm) activity  

### 4. IP Investigation Tool
*Interactive forensics:*
- User inputs suspected IP address  
- Auto-generates comprehensive report with:  
  - MAC address, hostname, user account  
  - All network connections  
  - File transfers and DNS queries  
  - Kerberos authentication activity  

---

## Results

### Exercise
- **Date**: 2025-01-22  
- **Scenario**: Employee downloaded malicious file after searching for Google Authenticator  
- **Source**: malware-traffic-analysis.net  

### Compromised System Identified
- **IP Address**: 10.1.17.215 ✓  
- **MAC Address**: 00:d0:b7:26:4a:74 ✓  
- **Hostname**: DESKTOP-L8C5GSJ ✓  
- **User Account**: shutchenson ✓  
- **Domain**: bluemoontuesday.com  

### Attack Infrastructure
- Fake software site (Typosquatting): `authenticatoor.org` ✓  
- Phishing page: `google-authenticator.burleson-appliance.net`  
- C2 servers: `5.252.153.241`, `45.125.66.32`, `45.125.66.252` ✓  

**Validation**: All findings matched official answer key, demonstrating effective automated analysis.  

---

## Technical Skills Demonstrated

### Linux & Cloud
- Cloud infrastructure deployment  
- DNS troubleshooting (`systemd-resolved` configuration)  
- Package management (third-party repositories, GPG verification)  
- Firewall configuration (inbound/outbound rules)  

### Bash Scripting
- Here-documents for report generation  
- Process substitution and piping  
- Conditional logic and file testing  
- While loops for data correlation  
- Variable manipulation and user input  

### Security Analysis
- PCAP analysis with Zeek and Suricata  
- Log parsing (`zeek-cut`, `grep`, `awk`, `sed`)  
- JSON parsing with `jq`  
- IOC extraction and correlation  
- Command & Control detection  
- Timeline reconstruction  

### Network Security Concepts
- C2 beaconing identification  
- DGA domain detection  
- Phishing infrastructure analysis  
- File hash analysis  
- Authentication log investigation  

---

## Problems Solved

**Challenge 1: Cloud Capacity Issues**  
- Problem: Oracle Cloud ARM instances unavailable.  
- Solution: Pivoted to DigitalOcean; planned backup infrastructure.  

**Challenge 2: DNS Resolution Failures**  
- Problem: Package installs failing with DNS errors.  
- Solution: Fixed `systemd-resolved` misconfiguration, added public DNS servers.  
- *Key Learning*: Layer 3 troubleshooting is fundamental.  

**Challenge 3: Empty Script Output**  
- Problem: IP lookup tool returned no results.  
- Solution: Found typo (`10.1.7.215` vs `10.1.17.215`) via log verification.  
- *Key Learning*: Input validation is critical in tools.  

**Challenge 4: Tool Installation**  
- Problem: Zeek not in default Ubuntu repositories.  
- Solution: Added official Zeek repository with GPG verification.  
- *Key Learning*: Enterprise tools often require third-party repos.  

---

## Key Takeaways

### Technical Growth
- Transformed raw packet captures into actionable intelligence.  
- Created reusable automation for investigations.  
- Integrated multiple data sources for comprehensive analysis.  

### Problem-Solving Approach
- Systematic troubleshooting (Layer 3 → Application).  
- Backup planning for infrastructure constraints.  
- Iterative testing and debugging of automation.  

### Real-World Applicability
- Techniques aligned with SOC operations and IR workflows.  
- Scripts adaptable across malware families.  
- Foundation for SIEM/SOAR integration.  

---

## Sample Commands & Code

### Zeek Log Analysis

```bash
# Connection summary (sort by duration)
cat conn.log | zeek-cut id.orig_h id.resp_h id.resp_p duration | sort -k4 -rn

# DNS queries
cat dns.log | zeek-cut query | sort -u

# HTTP traffic
cat http.log | zeek-cut host uri user_agent
