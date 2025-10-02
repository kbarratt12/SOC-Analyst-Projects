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
The pipeline was deployed in a **cloud-based environment** to allow scalable processing of large traffic captures. Using DigitalOcean’s Ubuntu 22.04 servers ensured a lightweight, easily reproducible setup. The environment consisted of 2 vCPU cores, 4GB RAM, and an 80GB SSD, which provided sufficient resources for running Zeek and Suricata simultaneously without performance bottlenecks.  

**Core tools included:**  
- **Zeek**: Provides detailed, metadata-rich network logs across protocols like HTTP, DNS, and SSL.  
- **Suricata**: Performs real-time intrusion detection using signature-based rules, outputting structured JSON alerts.  
- **Bash scripting**: Automates log parsing, report generation, and IOC correlation, reducing the need for manual intervention.  

By combining these components, the infrastructure supports rapid triage, detailed forensic analysis, and IOC enrichment workflows.

---

## Pipeline Architecture  
The pipeline is structured to process traffic efficiently, with minimal analyst intervention. At a high level, the workflow consists of the following stages:  

1. **Traffic Ingestion**  
   Raw packets are captured live with `tcpdump` or replayed from stored PCAPs. All traffic is organized in a dedicated `/pcap/` directory for batch processing.  

2. **Parallel Analysis**  
   Zeek parses traffic to generate protocol-specific logs, allowing analysts to see detailed metadata for HTTP, DNS, SSL, and more. Suricata operates concurrently to detect threats using a tuned rule set.  

3. **Automated Extraction (Custom Scripts)**  
   - **quick-report.sh**: Provides fast triage of suspicious activity.  
   - **detailed-report.sh**: Generates comprehensive forensic reports.  
   - **ip-look.sh**: Investigates a single IP in depth.  
   - **ioc-cor.sh**: Correlates alerts and logs to extract IOCs.  

4. **Output & Reporting**  
   Reports consolidate alerts, network metadata, and IOCs. Analysts receive structured findings with timestamps, IPs, domains, and correlation points to streamline further investigation.

This architecture ensures both speed and depth of analysis, giving analysts actionable insights without overwhelming manual work.

---

## Automation Scripts  

### 1. `quick-report.sh` — Rapid Triage Report  
The `quick-report.sh` script is designed for **immediate assessment** of captured traffic. It provides analysts with a condensed view of potential threats, helping prioritize which incidents require deeper investigation. The script processes connection logs, DNS queries, Suricata alerts, and file transfer logs to generate a high-level overview.  

**Key outputs:**  
- Top 10 destination IPs.  
- Top 5 network protocols.  
- Top 10 Suricata alerts.  
- Suspicious domains with high entropy.  
- Recent file transfers with MIME type & filename.  

---

### 2. `detailed-report.sh` — Comprehensive Forensic Report  
`detailed-report.sh` generates a **multi-section forensic report** suitable for in-depth analysis. It extracts unusual connection patterns, authentication failures, file activity, and TLS/SSL metadata, allowing analysts to detect potential C2 communication or data exfiltration attempts. By structuring the findings, the script ensures that investigations are consistent and repeatable.  

**Key outputs:**  
- Non-standard port and long-lived connections.  
- SSH and HTTP authentication failures.  
- Executables, scripts, and archive file transfers.  
- TLS/SSL subject common names and unusual certificates.  

---

### 3. `ip-look.sh` — Targeted IP Investigation  
The `ip-look.sh` script focuses on **specific IP addresses**, enabling analysts to pivot from known IOCs to explore related network activity. Analysts are prompted for an IP, after which the script collates DHCP, Kerberos, HTTP, DNS, and file transfer logs, providing contextual insight into user and host behavior.  

**Key outputs:**  
- MAC address and DHCP associations.  
- Kerberos authentication records.  
- Top 10 connections from the IP.  
- HTTP requests, including URIs and user agents.  
- File transfers and DNS queries associated with the IP.  

---

### 4. `ioc-cor.sh` — IOC Extraction & Correlation  
The `ioc-cor.sh` script **bridges Zeek and Suricata** data, correlating alerts with network metadata. It identifies suspicious IPs, domains, unusual HTTP user agents, large uploads, and potentially malicious files, providing a single source of truth for threat indicators. By cross-referencing Suricata alerts with Zeek logs, analysts can validate IOCs and prioritize response.  

**Key outputs:**  
- Top 20 IPs by connection count.  
- High-entropy domains.  
- Unusual HTTP user agents.  
- Large HTTP uploads.  
- Suspicious file hashes (SHA1).  
- Correlated Suricata alerts with Zeek connection data.  

---

## Workflow in Action  
The operational workflow is designed for efficiency:  

1. **Quick Triage** → Run `quick-report.sh` to highlight IPs, domains, and alerts.  
2. **Deep-Dive Analysis** → Run `detailed-report.sh` for a structured forensic breakdown.  
3. **IP Enrichment** → Run `ip-look.sh` for IOC-specific insights.  
4. **IOC Correlation** → Run `ioc-cor.sh` to merge Suricata alerts with Zeek metadata.  

This workflow enables analysts to move seamlessly from high-level awareness to detailed, IOC-focused investigation.

---

## Benefits and Impact  
The automated pipeline offers several tangible benefits:  

- **Time Efficiency**: Multi-step log parsing reduced to single-command execution.  
- **Consistency**: Automated correlation ensures standardized reporting.  
- **IOC Extraction**: Generates actionable IP/domain/file hash lists.  
- **Scalability**: Cloud-hosted environment can process multiple PCAPs in parallel.  

By combining automation with robust tooling, the pipeline reduces analyst workload while improving investigative accuracy.

---

## Challenges and Fixes  
Several challenges were addressed during implementation:  

- **Noisy Suricata logs** → Filtered with `jq` in `ioc-cor.sh`.  
- **Distributed Zeek logs** → Consolidated using `zeek-cut` pipelines.  
- **High CPU spikes** → Mitigated by tuning Suricata threading and limiting concurrent captures.  

These solutions enhanced both performance and reliability of the pipeline.

---

## Future Enhancements  
Planned improvements include:  
- Adding **Elasticsearch + Kibana** for visualization of traffic and alerts.  
- Converting Bash scripts into a **modular Python framework** for maintainability.  
- Integrating with **MISP** for automated threat intelligence sharing.  
- Incorporating **YARA and file carving** for extracting malware payloads.  

These enhancements aim to make the pipeline more scalable, maintainable, and intelligent.

---

## Conclusion  
This automated network forensics pipeline demonstrates how open-source tools and scripting can transform manual investigations into a **streamlined, semi-automated process**. By leveraging Zeek and Suricata alongside custom automation, analysts can quickly triage, deeply investigate, and correlate network threats with high accuracy.  

**Skills demonstrated:**  
- Cloud-based infrastructure design.  
- Forensic automation with Bash.  
- Multi-tool log correlation.  
- Threat detection and IOC reporting.  
