# Incident Report – Traffic Analysis Exercise  
**Date:** 2025-01-22  
**Analyst:** Malachi Barratt  
**SOC:** Internal  

---

## 1. Victim Details

| Question | Answer | Source / Methodology |
|----------|--------|--------------------|
| IP address of infected client | 10.1.17.215 | Zeek `dhcp.log`, `conn.log` |
| MAC address of infected client | 00:d0:b7:26:4a:74 | Zeek `dhcp.log` |
| Host name of infected client | DESKTOP-L8C5GSJ | Kerberos / `host` field in logs |
| Windows user account | shutchenson | Kerberos logs `client` field |

---

## 2. Malware Delivery / Fake Software Page

| Question | Answer | Source / Methodology |
|----------|--------|--------------------|
| Likely domain name for fake Google Authenticator page | authenticatoor.org | SSL log `certificate CN` and HTTP request correlation |
| File downloads observed | PowerShell scripts (`29842.ps1`, `pas.ps1`), Executables (`TeamViewer`, `Teamviewer_Resource_fr`, `TV`) | HTTP GET requests in Zeek `http.log` |

**Example HTTP Downloads (from 10.1.17.215 to 5.252.153.241)**

| Timestamp | URL | File Type | Size |
|-----------|-----|----------|------|
| 1737575158.675869 | /api/file/get-file/29842.ps1 | text/plain (PowerShell) | 1.5 KB |
| 1737575221.528276 | /api/file/get-file/TeamViewer | application/x-dosexec | 4.38 MB |
| 1737575224.988901 | /api/file/get-file/Teamviewer_Resource_fr | application/x-dosexec | 668 KB |
| 1737575225.357954 | /api/file/get-file/TV | application/x-dosexec | 12.9 KB |
| 1737575225.514713 | /api/file/get-file/pas.ps1 | text/plain (PowerShell) | 1.5 KB |

> These scripts and executables indicate the host was likely instructed to run remote commands and potentially enable remote control.

---

## 3. C2 (Command & Control) Infrastructure

| Question | Answer | Source / Methodology |
|----------|--------|--------------------|
| IP addresses used for C2 servers | 5.252.153.241 | Long-duration HTTP connections, Suricata alerts |
| | 45.125.66.32 | SSL connections >10 minutes |
| | 45.125.66.252 | SSL connections and Suricata correlation |

**Notable Traffic Patterns**

- `10.1.17.215` → `5.252.153.241` HTTP GET requests for PowerShell scripts and executables.  
- Long-lived SSL connections to `45.125.66.32` and `45.125.66.252` indicate persistent beaconing.  

---

## 4. Post-Infection Observations

- **Powershell Execution:** The downloaded `.ps1` files were likely executed by the victim, as indicated by Suricata alerts:  
  - `ET INFO PS1 Powershell File Request`  
  - `ET HUNTING Generic Powershell DownloadFile/DownloadString Command`  
- **Potential Remote Access:** Multiple TeamViewer executables downloaded, suggesting remote management access may have been established.  
- **DNS & TLS Activity:**  
  - High-entropy domains (`appointedtimeagriculture.com`) queried.  
  - Unusual SSL certificate CN: `google-authenticator.burleson-appliance.net`.  
- **Kerberos Failures:** Multiple failed authentication attempts, possibly malware attempting credential use.  
- **Data Exfiltration Potential:** Long-duration connections and large HTTP downloads suggest C2 could move data out.  

---

## 5. Methodology

1. Collected Zeek logs: `dhcp.log`, `conn.log`, `http.log`, `ssl.log`, `krb.log`, `dns.log`.  
2. Ran 4 custom Bash scripts to:  
   - Correlate IPs and C2 activity.  
   - Extract downloaded files with MIME type.  
   - Detect long-lived connections.  
   - Identify suspicious TLS certificate CNs.  
3. Ran Suricata on the PCAP to detect:  
   - Powershell downloads.  
   - Fake Microsoft Teams payload activity.  
   - TeamViewer C2 requests.  
4. Verified findings with exercise reference answers and GitHub IOC list.  

---

## 6. Conclusion & Recommendations

- Host `10.1.17.215` (DESKTOP-L8C5GSJ / shutchenson) is confirmed infected.  
- Infection vector: Fake Google Authenticator page (`authenticatoor.org`) → PowerShell & executables.  
- C2 traffic confirmed with `5.252.153.241`, `45.125.66.32`, `45.125.66.252`.  
- Recommended actions:  
  - Isolate the host immediately.  
  - Analyze downloaded files for malware behavior and hashes.  
  - Reset compromised credentials.  
  - Monitor network for similar C2 patterns and high-entropy DNS requests.  
