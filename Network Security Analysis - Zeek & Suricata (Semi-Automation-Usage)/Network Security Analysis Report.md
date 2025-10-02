# Automated Network Forensics Pipeline  
**Author:** Malachi Barratt  
**Date:** October 2025  

---

## Executive Summary  
This project demonstrates the design and deployment of an **automated network forensics pipeline** to accelerate malware investigation and incident response. By integrating **Zeek** for network visibility, **Suricata** for intrusion detection, and custom **Bash automation scripts**, the pipeline reduced analysis overhead and enabled rapid correlation of suspicious activity. The environment was deployed in a **cloud-based Ubuntu 22.04 server** on DigitalOcean.  

The pipeline is capable of:  
- Capturing and parsing live or replayed packet data.  
- Automatically extracting indicators of compromise (IOCs).  
- Correlating logs between Zeek and Suricata to provide context-rich alerts.  
- Reducing manual analyst effort by consolidating evidence into structured reports.  

This report outlines the architecture, scripts, workflow, and impact of the project, highlighting the integration of automation in modern network forensics.

---

## Introduction  
Network forensics is a critical component of modern cybersecurity operations, enabling analysts to reconstruct malicious activity and validate security incidents. Traditional workflows often rely heavily on manual inspection of logs, which can be **time-consuming** and **error-prone**, especially when analyzing high-volume traffic.  

The goal of this project was to address these challenges by creating a **semi-automated pipeline** capable of capturing, parsing, and correlating network traffic efficiently. By combining open-source tools with custom scripts, the pipeline not only accelerates investigation but also improves the **accuracy and repeatability** of forensic analysis.  

The key objectives were:  
1. Capture raw network data for analysis.  
2. Parse traffic through multiple engines (Zeek and Suricata).  
3. Automate extraction of indicators of compromise.  
4. Correlate and summarize findings for actionable intelligence.

---

## Infrastructure Overview  
The pipeline was deployed in a **cloud-based environment** to allow scalable processing of large traffic captures. DigitalOcean’s Ubuntu 22.04 droplet (2 vCPU, 4GB RAM, 80GB SSD) provided sufficient resources for running Zeek and Suricata simultaneously without performance bottlenecks.  

The choice of DigitalOcean followed a temporary setback: Oracle Cloud ARM instances were unavailable due to capacity limits. This real-world obstacle reinforced the importance of **having backup cloud options** for uninterrupted project deployment.  

Early configuration challenges included DNS resolution failures that blocked package installations. Systemd-resolved was initially configured only to localhost (127.0.0.53), preventing external name resolution. This was fixed by explicitly setting reliable public DNS servers (8.8.8.8, 1.1.1.1, 67.207.67.2) and adjusting firewall rules to allow outbound DNS traffic.  

**Core tools included:**  
- **Zeek**: Detailed, metadata-rich network logs across protocols like HTTP, DNS, and SSL; installed via the official repository with GPG verification.  
- **Suricata**: Real-time intrusion detection using signature-based rules from the OISF PPA; requires regular signature updates.  
- **Bash scripting**: Automates log parsing, report generation, and IOC correlation, reducing manual effort.  

This combination supports rapid triage, detailed forensic analysis, and IOC enrichment workflows.

---

## Pipeline Architecture  
The pipeline is structured to process traffic efficiently, with minimal analyst intervention. The workflow consists of the following stages:  

1. **Traffic Ingestion**  
   Raw packets are captured live with `tcpdump` or replayed from stored PCAPs. Traffic is organized in a dedicated `/pcap/` directory for batch processing.  

2. **Parallel Analysis**  
   Zeek parses traffic into protocol-specific logs, while Suricata operates concurrently to detect threats with a tuned ruleset.  

3. **Automated Extraction (Custom Scripts)**  
   - **quick-report.sh**: Fast triage of suspicious activity.  
   - **detailed-report.sh**: Comprehensive forensic reporting.  
   - **ip-look.sh**: In-depth investigation of individual IPs.  
   - **ioc-cor.sh**: Correlates alerts and logs to extract actionable IOCs.  

4. **Output & Reporting**  
   Reports consolidate alerts, network metadata, and IOCs. Analysts receive structured findings with timestamps, IPs, domains, and correlation points to streamline investigation.

This architecture ensures both **speed and depth of analysis**, giving analysts actionable insights without overwhelming manual work.

---

## Automation Scripts  

### 1. `quick-report.sh` — Rapid Triage Report  
Provides **immediate assessment** of captured traffic. Processes connection logs, DNS queries, Suricata alerts, and file transfers to generate a high-level overview.  

**Key outputs:**  
- Top 10 destination IPs  
- Top 5 network protocols  
- Top 10 Suricata alerts  
- Suspicious high-entropy domains  
- Recent file transfers with MIME type & filename  

---

### 2. `detailed-report.sh` — Comprehensive Forensic Report  
Generates a **multi-section forensic report** for in-depth analysis. Extracts unusual connection patterns, authentication failures, file activity, and TLS/SSL metadata.  

**Key outputs:**  
- Non-standard port and long-lived connections  
- Various authentication failures  
- Executables, scripts, and archive file transfers  
- TLS/SSL subject common names and unusual certificates  

---

### 3. `ip-look.sh` — Targeted IP Investigation  
Focuses on **specific IP addresses**, enabling analysts to pivot from known IOCs to related network activity. Collects DHCP, Kerberos, HTTP, DNS, and file transfer logs.  

**Key outputs:**  
- MAC address and DHCP associations  
- Kerberos authentication records  
- Top 10 connections from the IP  
- HTTP requests, including URIs and user agents  
- File transfers and DNS queries associated with the IP  

---

### 4. `ioc-cor.sh` — IOC Extraction & Correlation  
**Correlates Zeek and Suricata data**, identifying suspicious IPs, domains, unusual HTTP user agents, large uploads, and potentially malicious files.  

**Key outputs:**  
- Top 20 IPs by connection count  
- High-entropy domains  
- Unusual HTTP user agents  
- Large HTTP uploads  
- Suspicious file hashes (SHA1)  
- Correlated Suricata alerts with Zeek connection data  

---

## Workflow in Action  
Operational workflow:  

1. **Quick Triage** → Run `quick-report.sh` to highlight IPs, domains, and alerts.  
2. **Deep-Dive Analysis** → Run `detailed-report.sh` for a structured forensic breakdown.  
3. **IP Enrichment** → Run `ip-look.sh` for IOC-specific insights.  
4. **IOC Correlation** → Run `ioc-cor.sh` to merge Suricata alerts with Zeek metadata.  

This enables analysts to move seamlessly from high-level awareness to detailed, IOC-focused investigation.

---

## Benefits and Impact  
The automated pipeline provides:  
- **Time Efficiency**: Multi-step log parsing reduced to single-command execution.  
- **Consistency**: Automated correlation ensures standardized reporting.  
- **IOC Extraction**: Actionable IP/domain/file hash lists.  
- **Scalability**: Cloud-hosted environment can process multiple PCAPs in parallel.  

By combining automation with robust tooling, the pipeline reduces analyst workload while improving investigative accuracy.

---

## Challenges and Fixes  
Implementation challenges included:  

- **Noisy Suricata logs** → Filtered with `jq` in `ioc-cor.sh`.  
- **Distributed Zeek logs** → Consolidated using `zeek-cut` pipelines.  
- **High CPU spikes** → Mitigated by tuning Suricata threading and limiting concurrent captures.  
- **DNS and firewall issues** → Fixed systemd-resolved configuration and allowed the proper DNS IPs (67.207.67.2) through the firewall.  
- **Empty script outputs** → Corrected IP typos in input variables for accurate log correlation.  

These adjustments improved performance, reliability, and accuracy of the pipeline.

---

## Future Enhancements  
Planned improvements include:  
- Integrating **Elasticsearch + Kibana** for traffic and alert visualization.  
- Converting Bash scripts into a **modular Python framework** for maintainability.  
- Integration with **MISP** for automated threat intelligence sharing.  
- Incorporating **YARA and file carving** for extracting malware payloads.  

These enhancements aim to make the pipeline more scalable, maintainable, and intelligent.

---

## Conclusion  
This automated network forensics pipeline demonstrates how open-source tools and scripting can transform manual investigations into a **streamlined, semi-automated process**. Analysts can quickly triage, deeply investigate, and correlate network threats with high accuracy.  

**Skills demonstrated:**  
- Cloud-based infrastructure design  
- Forensic automation with Bash  
- Multi-tool log correlation  
- Threat detection and IOC reporting  

