# Honeypot Attack Analysis: Dashboard Intelligence Report

## Executive Summary

The T-Pot honeypot system captured a total of **7,893 attacks** over the last 14 hours. The activity was highly concentrated, with the top 10 IP addresses accounting for **36% of all attacks**. Analysis shows attackers primarily use legitimate cloud infrastructure (Google Cloud, DigitalOcean, and Scaleway) and compromised home/business networks from a broad range of countries including **United States, Bolivia, Vietnam, Netherlands, Seychelles, and France**.  

The campaigns are characterized by coordinated bursts of activity focused on reconnaissance, credential brute-forcing, and exploitation attempts such as **CVE-2020-11899**, targeting common services like SSH and HTTP. These findings highlight a landscape dominated by automated, botnet-like operations that use professional tactics to evade detection.  

The data provides valuable insights for strengthening credential policies, implementing enhanced cloud-aware monitoring, and prioritizing patching of known vulnerabilities.

---

## 1. Overview

This report provides a detailed analysis of attack data captured by the T-Pot honeypot system, leveraging **Kibana dashboards** to transform raw logs into actionable security intelligence. The analysis focuses on:

- Key attack sources  
- Geographic distribution  
- Timing of attacks  
- Specific targeting methods  

The goal is to understand the current threat landscape and inform defensive strategies.

---

## 2. Attack Source & Geographic Analysis

### Top Attack Sources by IP

| IP Address       | Attacks | Provider | Notes |
|-----------------|--------|------------------|-------|
| 208.109.190.200 | 778    | UCLOUD INFORMATION TECHNOLOGY | reputation, malware reports, or abuse score (placeholder) |
| 200.105.196.189 | 583    | AXS Bolivia S.A. | reputation, malware reports, or abuse score (placeholder) |
| 181.115.190.30  | 396    | Google Cloud Platform | reputation, malware reports, or abuse score (placeholder) |
| 116.99.172.53   | 345    | GoDaddy.com, LLC | reputation, malware reports, or abuse score (placeholder) |
| 196.251.87.127  | 264    | EMPRESA NACIONAL DE TELECOMUNICACIONES S.A. | reputation, malware reports, or abuse score (placeholder) |

### Top Attacking ASNs / Organizations

| ASN / Organization                                      | Attack Count |
|---------------------------------------------------------|-------------|
| AXS Bolivia S.A.                                        | 749         |
| UCLOUD INFORMATION TECHNOLOGY HK LIMITED               | 477         |
| GoDaddy.com, LLC                                       | 404         |
| Google Cloud Platform                                   | 401         |
| EMPRESA NACIONAL DE TELECOMUNICACIONES SOCIEDAD ANONIMA | 396         |

### Geographic Attack Distribution

| Country       | Attack Count |
|---------------|-------------|
| United States | 2,734       |
| Bolivia       | 1,145       |
| Vietnam       | 588         |
| Netherlands   | 373         |
| Seychelles    | 346         |

---

## 3. Attack Timing & Service Targeting

### Campaign-Style Activity

Time-based histograms showed attacks occurring in **bursts**, indicating:

- **Planned Operations:** Attackers manage campaigns in time blocks.  
- **Operational Security:** Bursts make activity appear intermittent rather than systematic.

### Attack Distribution by Service

| Honeypot Service | Attacks | Notes |
|-----------------|--------|-------|
| Honeytrap       | 3,617  | Network reconnaissance and port scanning |
| Dionaea         | 1,304  | Malware distribution attempts |
| Cowrie          | 1,274  | SSH credential brute-forcing |
| Sentrypeer      | 815    | Specialized VoIP/telecommunications targeting |
| Tanner          | 71     | Miscellaneous honeypot activity |

### Top IDS Alerts

| ID       | Description                                       | Count |
|----------|-------------------------------------------------|-------|
| 2228000  | SURICATA SSH invalid banner                      | 551   |
| 2210061  | SURICATA STREAM spurious retransmission         | 108   |
| 2001978  | ET INFO SSH session in progress on Expected Port | 88    |
| 2001984  | ET INFO SSH session in progress on Unusual Port | 77    |
| 2260002  | SURICATA Applayer Detect protocol only one direction | 76 |

---

## 4. Credential & Technical Analysis

### Common Usernames

| Username | Count |
|---------|-------|
| root    | 91    |
| admin   | 21    |
| monitor | 16    |
| solv    | 4     |
| test    | 4     |

### Common Passwords

| Password | Count |
|---------|-------|
| P@ssw0rd | 17   |
| admin    | 9    |
| 123456   | 6    |
| 1234     | 5    |
| password | 5    |

### Protocol & Port Targeting

Most attacks were conducted over **TCP**, focusing on:

- **SSH (22):** Most frequent, Cowrie attacks  
- **HTTP (80) & HTTPS (443):** Web reconnaissance  
- **SMB (445):** Windows-based attacks  
- **Additional notable ports:** 5060, 3378, 3379, 27017, 2222, 8989

---

## 5. Operating System Distribution (P0f)

| OS                     | Count |
|-----------------------|-------|
| Linux 2.2.x-3.x        | 5,791 |
| Windows NT kernel 5.x  | 2,979 |
| Linux 2.2.x-3.x barebone | 1,181 |
| Linux 2.2.x-3.x no timestamps | 175 |
| Linux 3.11+            | 78    |
| Windows NT kernel      | 69    |
| Windows 7 or 8         | 33    |
| Mac OS X               | 18    |
| Linux 2.4.x            | 11    |
| Linux 3.1-3.10         | 10    |

**Notes:** Linux dominates due to widespread use in servers and IoT devices. Windows targets older NT kernels, while macOS appears minimally, likely via automated scanning.

---

## 6. Attacker Reputation

| Reputation Type | Count |
|----------------|-------|
| Known attacker  | 3,627 |
| Mass scanner    | 330   |
| Bot / crawler   | 1     |

---

## 7. Threat Actor Profile & Sophistication

Observed patterns indicate **automated, botnet-driven campaigns**:

- **Infrastructure Management:** Multiple cloud providers across regions show professional planning.  
- **Operational Coordination:** Burst-style attacks targeting multiple services.  
- **Motivation:** Exploit default credentials, expand botnets, or install malware.  

---

## 8. Security Implications & Defensive Insights

### Technical Defenses (SOC-Level)

- **High-Risk IP Blocking:** Review top attacking IPs regularly and block or rate-limit traffic from them. Consider integrating **IP reputation services**.  
- **Credential Auditing & MFA:** Enforce strong, unique passwords. Use multi-factor authentication for all public-facing services.  
- **Patch Management:** Prioritize patching known vulnerabilities such as **CVE-2020-11899**. Maintain a vulnerability tracking program.  
- **Behavioral Monitoring:** Track unusual activity like bursts of SSH login attempts, port scans, or repeated exploitation attempts. Use alerts for rapid response.  
- **Cloud-Aware Monitoring:** Monitor traffic from cloud providers closely. Threat feeds can enrich detection.  
- **Logging & SIEM Integration:** Forward honeypot logs to a centralized SIEM for correlation and faster incident response.

### Strategic Defenses (CISO-Level)

- **Threat Intelligence Integration:** Use ASN and geographic clustering to feed internal threat intelligence. Update detection rules based on observed patterns.  
- **Geographic Access Policies:** Restrict access from high-risk regions if it aligns with business needs.  
- **Network Segmentation:** Keep honeypots isolated from production networks to prevent lateral movement.  
- **Security Awareness & Policy:** Train teams to recognize automated attacks and phishing attempts linked to observed attacker infrastructure.  
- **Continuous Improvement:** Perform periodic red-team exercises or penetration tests to validate defenses against patterns observed in honeypot activity.

---

## 9. Conclusion

The honeypot deployment captured diverse attack activity, revealing professional, coordinated campaigns using legitimate cloud infrastructure and systematic methodologies.  

This intelligence aids in improving defensive posture, enforcing credential hygiene, implementing behavioral monitoring, and prioritizing patching for vulnerabilities such as **CVE-2020-11899**. Modern cyber attacks are increasingly professional and coordinated, requiring sophisticated defensive strategies.
