# T-Pot Honeypot Implementation and Security Analysis Report

## Executive Summary

This report documents the successful implementation and security analysis of a T-Pot honeypot system, integrated with Wazuh SIEM, on a DigitalOcean virtual machine. The project established a secure, isolated environment for capturing and analyzing malicious attack traffic. This deployment improved visibility into attack campaigns by capturing over **6,000 unique attack events** while maintaining complete host isolation. A key outcome was the successful demonstration of a **proof-of-concept for automated threat intelligence workflows**, laying the groundwork for future security automation capabilities.

The project successfully achieved its core objectives, including the deployment of a fully functional honeypot, the establishment of a zero-trust network architecture, and the analysis of thousands of attack events. The implementation phase provided practical experience in resolving complex technical challenges, such as resource management and network configuration issues, while solidifying a practical understanding of containerized security environments.

---

## Project Phases and Execution

The T-Pot honeypot deployment and analysis project was executed through a systematic, phased approach to ensure a secure and effective outcome. This methodology helped manage complexity and provided a clear path from initial concept to a fully operational system.

### Phase 1: Planning and Preparation

**Goal:** Define project scope, select a platform, and design the security architecture.

**Activities:**

- Chose DigitalOcean as the cloud provider for its ease of use and affordability.  
- Selected T-Pot for its all-in-one, containerized, and secure design.  
- Designed a zero-trust network architecture to strictly segment the honeypot from the management plane.  
- Created an implementation plan detailing firewall rules and host hardening measures.  

### Phase 2: Implementation and Deployment

**Goal:** Deploy the T-Pot honeypot and integrate it with the Wazuh SIEM.

**Activities:**

- Provisioned a DigitalOcean VM and configured host OS hardening.  
- Installed the T-Pot platform, including over 20 containerized honeypot services.  
- Configured firewall rules to allow a wide range of inbound traffic while restricting management access to a non-standard SSH port and a specific management IP.  
- Integrated the T-Pot host with the Wazuh SIEM to ensure real-time log forwarding and monitoring.  

### Phase 3: Data Analysis and Validation

**Goal:** Analyze captured traffic and validate the effectiveness of the security design.

**Activities:**

- Used Kibana dashboards to analyze over 6,000 attack events, focusing on geolocation, temporal patterns, and credential patterns.  
- Developed a Python script to parse Elasticsearch JSON exports for in-depth data extraction.  
- Diagnosed and resolved unexpected network and resource issues to ensure system stability.  
- Confirmed the effectiveness of network segmentation and container isolation by verifying that no attacks successfully breached the host system.  

### Phase 4: Automation and Future Development

**Goal:** Establish a foundation for automated threat intelligence workflows.

**Activities:**

- Designed and partially implemented a proof-of-concept workflow using Shuffle SOAR to automate IOC extraction and threat enrichment with the VirusTotal API.  
- Documented lessons learned, including technical barriers like API access limitations, to guide future phases.  
- Outlined a strategic roadmap for future enhancements, including real-time API integration and advanced machine learning analytics.  

---

## Technical Architecture and Security Design

### Infrastructure Overview

- **Honeypot Host:** DigitalOcean VM located in Douglasville, GA (IP: 134.199.194.67)  
- **Honeypot Software:** T-Pot, a multi-honeypot platform with over 20 containerized services  
- **SIEM:** Wazuh manager, receiving logs from the T-Pot host for centralized analysis  

### Network Strategy

The network was designed with a **wide port exposure** (TCP/UDP ports 1–64000) to maximize the attack surface. This strategy is mitigated by T-Pot’s containerization, ensuring that attacks are contained within isolated Docker environments, never reaching the host OS.

### Network Segmentation

The network was segmented to enforce a zero-trust model, isolating the honeypot services from the management plane.

**Firewall Configuration:**

- **Inbound Rules:**
  - Ports 1–64000 open to the internet to expose honeypot services  
  - SSH port (64295) restricted to a single, trusted management IP  

- **Outbound Rules:**
  - Wazuh agent communication (ports 1514–1515) to the isolated Wazuh manager  
  - DNS (port 53/UDP) and HTTPS (port 443/TCP) for system updates and maintenance  

### Host OS Hardening

- **SSH Key Authentication:** Password-based login disabled; access restricted to a pre-authorized public key  
- **Automated Updates:** System configured to apply security updates automatically  

---

## Implementation Challenges and Problem-Solving

| Issue | Root Cause | Resolution |
|-------|-----------|------------|
| Elasticsearch Crash | Memory limitations and container orchestration dependencies, causing OOM kills | Optimized Docker resource allocation |
| Local DNS Hijacking | Internal Docker resolver redirected `ghcr.io` queries to 192.168.1.1 | Set 1.1.1.1 as DNS nameserver in `/etc/resolv.conf` |
| Container Update Failure | Outbound traffic blocked by firewall | Added explicit rules for outbound HTTPS (443/TCP) and DNS (53/UDP) |

This systematic troubleshooting approach was critical for maintaining operational status and security posture.

---

## Traffic Analysis and Findings

- **Traffic Pattern:** Majority inbound attack traffic; outbound traffic confirmed as legitimate maintenance. No evidence of compromise.  
- **Geolocation:** Attacks originated from multiple countries, enabling future correlation by type/protocol.  
- **Service-Specific Targeting:** SSH brute-force attempts on Cowrie; various exploits against web and IoT services.  
- **Credential Patterns:** Widespread use of common/default passwords (e.g., `root/password`, `admin/admin`), highlighting automated attack prevalence.  

---

## Automation Integration and Future Implementation

### Proof-of-Concept Automation

- **Data Ingestion:** Shuffle webhook endpoint receives JSON-formatted T-Pot logs  
- **IOC Extraction:** Python script parses JSON to extract IOCs (source IPs, JA3 hashes, malicious payloads)  
- **Threat Enrichment:** Extracted IOCs sent to VirusTotal for validation and scoring  
- **Automated Reporting:** Workflow generates summary reports for analysts or ticketing systems  

Full deployment limited by T-Pot security hardening preventing direct Kibana API access.

### Future Implementation Strategy

1. **Kibana Integration:** Access Kibana encryption keys (`docker exec -it tpot_kibana ./bin/kibana-encryption-keys generate`) for API connectivity  
2. **Real-Time Processing:** Direct API integration between Kibana and Shuffle for automated, real-time intelligence  
3. **Advanced Analytics:** Apply machine learning to identify complex patterns, predict attacks, and correlate across honeypot services  

---

## Key Learning Outcomes and Technical Growth

- **Conceptual Understanding:** From basic honeypot knowledge to containerized service simulation and defense-in-depth principles  
- **Problem-Solving:** Systematic troubleshooting across systemd, Docker, UFW, and DNS  
- **Infrastructure Management:** Multi-service Docker environment, network segmentation, large-scale log analysis  
- **Security Monitoring:** Log analysis, threat actor behavior insights, integration of multiple security tools  

---

## Conclusion

The T-Pot honeypot implementation successfully validated modern security platform capabilities and practical deployment challenges. Containerization effectively contained attacks, and the zero-trust network model ensured host isolation. Captured data provides rich intelligence for threat analysis, including credential patterns and geographic origins.

This deployment establishes a foundation for **ongoing threat intelligence**, **automated response capabilities**, and **organizational security improvements**. Lessons learned in systematic troubleshooting and automation proof-of-concept development provide invaluable guidance for future security initiatives.
