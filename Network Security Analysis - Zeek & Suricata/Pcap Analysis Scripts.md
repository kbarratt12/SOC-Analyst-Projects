detailed-report.sh
```bash
root@thehive:~/malware-analysis# cat detailed-report.sh
#!/bin/bash

# --- Configuration ---
LOG_DIR="./"
REPORT_FILE="detailed-investigation-report.txt"

# --- Main Report Generation ---
cat > "$REPORT_FILE" << EOF
=== DETAILED INVESTIGATION REPORT ===

Date: $(date)
Log Directory: $LOG_DIR

===================================
## 1. Unusual Connection Patterns
===================================

### Connections on Non-Standard Ports (e.g., non-80, 443, 21, 22, 23, 25, 110, 143, 3389)
# Focus on less common ports that may be used for C2 (Command and Control) traffic.
$(cat ${LOG_DIR}conn.log | zeek-cut id.orig_h id.resp_h id.resp_p proto | awk '
  $4 !~ /^(80|443|21|22|23|25|110|143|3389)$/ { print }' | head -20)

### Long-Lived Connections (Possible Data Exfiltration or Persistent C2)
# Connections with a duration greater than 600 seconds (10 minutes).
$(cat ${LOG_DIR}conn.log | zeek-cut id.orig_h id.resp_h duration proto service | awk '$3 > 600 { print }' | sort -k3 -rn | head -10)

===================================
## 2. Authentication Failures (Brute Force/Credential Spraying)
===================================

### Failed SSH Logins (Top 10 Source IPs)
$(cat ${LOG_DIR}ssh.log 2>/dev/null | grep -E 'FAILURE' | zeek-cut id.orig_h | sort | uniq -c | sort -rn | head -10)

### Failed HTTP Authentication (Top 10 Source IPs)
$(cat ${LOG_DIR}http.log 2>/dev/null | grep -E '401|403' | zeek-cut id.orig_h | sort | uniq -c | sort -rn | head -10)

===================================
## 3. Detailed File Activity
===================================

### Potentially Malicious File Types (Executables, Scripts, Archives)
# Focusing on .exe, .dll, .js, .vbs, .bat, .zip, .rar, .7z transfers.
$(cat ${LOG_DIR}files.log 2>/dev/null | zeek-cut tx_hosts rx_hosts filename mime_type | grep -E '\.(exe|dll|js|vbs|bat|zip|rar|7z)$|application/(x-msdownload|x-executable|zip|x-rar-compressed)' | head -20)

===================================
## 4. TLS/SSL Traffic Analysis
===================================

### Unique TLS Subject Common Names (Unusual Certificates)
# Useful for finding connections to unknown C2 servers.
$(cat ${LOG_DIR}ssl.log 2>/dev/null | zeek-cut id.resp_h server_name | sort | uniq | head -20)

### Outbound TLS Connections to High-Risk Countries (Requires GeoIP enrichment)
# (Note: This is a placeholder; requires a GeoIP lookup script/tool)
# (e.g., cat ssl.log | zeek-cut id.resp_h | geoip_lookup | grep "CN|RU|IR|KP")
EOF

# Display the report
cat "$REPORT_FILE"

# --- Execution Steps ---
# 1. Save: nano detailed-report.sh, paste content, Ctrl+X, Y, Enter.
# 2. Make Executable: chmod +x detailed-report.sh
# 3. Run: ./detailed-report.sh
```
quick-report.sh
```bash
root@thehive:~/malware-analysis# cat quick-report.sh
#!/bin/bash

# --- Configuration ---
LOG_DIR="./" # Assuming logs are in the current directory
REPORT_FILE="quick-analysis-report.txt"

# --- Main Report Generation ---
cat > "$REPORT_FILE" << EOF
=== Quick PCAP Analysis Report ===

Date: $(date)
Log Directory: $LOG_DIR

---------------------------------
## Top 10 Destination IPs (High-Volume Targets)
---------------------------------
$(cat ${LOG_DIR}conn.log | zeek-cut id.resp_h | sort | uniq -c | sort -rn | head -10)

---------------------------------
## Top 5 Protocol Count (Overall Traffic Profile)
---------------------------------
$(cat ${LOG_DIR}conn.log | zeek-cut proto | sort | uniq -c | sort -rn | head -5)

---------------------------------
## Suricata Alerts (Top 10 Most Frequent)
---------------------------------
$(cat suricata-output/fast.log 2>/dev/null | cut -d ' ' -f 4- | sort | uniq -c | sort -rn | head -10)

---------------------------------
## Suspicious Domains (Long, High-Entropy Names)
---------------------------------
$(cat ${LOG_DIR}dns.log | zeek-cut query | grep -E '[a-z0-9]{25,}' | sort | uniq)

---------------------------------
## Files Transferred (MIME Type & Filename)
---------------------------------
$(cat ${LOG_DIR}files.log 2>/dev/null | zeek-cut mime_type filename | head -10)
EOF

# Display the report
cat "$REPORT_FILE"

# --- Execution Steps ---
# 1. Save: nano quick-report.sh, paste content, Ctrl+X, Y, Enter.
# 2. Make Executable: chmod +x quick-report.sh
# 3. Run: ./quick-report.sh
```
ip-look.sh
```bash
root@thehive:~/malware-analysis# cat ip-look.sh
#!/bin/bash

# --- Configuration ---
LOG_DIR="./"
REPORT_FILE="ip-investigation-report.txt"

# --- Prompt for IP Input ---
echo "======================================================="
read -p "Enter the primary suspected IP address (e.g., 10.1.17.215): " SUSPECT_IP
echo "======================================================="

if [ -z "$SUSPECT_IP" ]; then
    echo "No IP address entered. Exiting."
    exit 1
fi

# --- Core Lookup Function ---
perform_lookup() {
    local ip="$1"

    cat > "$REPORT_FILE" << EOF
=== TARGETED IP INVESTIGATION REPORT: $ip ===

Date: $(date)

==================================================
## 1. IDENTITY & USER (Questions 1-3)
==================================================

### MAC Address of Client ($ip)
# Found in dhcp.log - Links IP to hardware address.
$(cat ${LOG_DIR}dhcp.log 2>/dev/null | zeek-cut client_addr mac | grep "$ip" | sort -u)

### Hostname & User Account from Kerberos
# Kerberos is used for domain authentication - client=user, service=hostname.
# Fields: ts, id.orig_h, client, service, success
$(cat ${LOG_DIR}kerberos.log 2>/dev/null | zeek-cut ts id.orig_h client service success | grep "$ip" | grep -v '\$' | head -5)
# NOTE: The client field with a trailing '$' indicates the machine account/hostname.

==================================================
## 2. CONNECTION SUMMARY (High-Level Activity)
==================================================

### Top 10 Connections from $ip
$(cat ${LOG_DIR}conn.log 2>/dev/null | zeek-cut id.orig_h id.resp_h id.resp_p proto | grep "$ip" | zeek-cut id.resp_h | sort | uniq -c | sort -rn | head -10)

### HTTP Activity (Web Requests)
# Shows requests, user agents, methods, and status codes.
$(cat ${LOG_DIR}http.log 2>/dev/null | zeek-cut ts id.orig_h host uri user_agent method status_code | grep "$ip" | head -10)

==================================================
## 3. GLOBAL THREAT INDICATORS (Questions 4-5)
==================================================

### Suspected Command and Control (C2) IPs
# Looking for external IPs with long-lived connections (> 600s/10 minutes).
$(cat ${LOG_DIR}conn.log 2>/dev/null | zeek-cut duration id.orig_h id.resp_h id.resp_p service | awk '$1 > 600 && $3 != "10.1.17.2" { print $1 " - " $3 " (" $5 ")" }' | sort -rn)

### Likely Fake Google Authenticator Domain
# Extracted from ssl.log via certificate common name.
$(cat ${LOG_DIR}ssl.log 2>/dev/null | zeek-cut server_name | grep 'google-authenticator' | sort -u)

==================================================
## 4. FILES & DNS
==================================================

### File Transfers (tx_hosts/rx_hosts)
# Shows files sent/received by $ip.
$(cat ${LOG_DIR}files.log 2>/dev/null | zeek-cut tx_hosts rx_hosts mime_type filename sha1 | grep "$ip" | head -5)

### DNS Lookups
# Shows domains queried by, or resolved to, $ip.
$(cat ${LOG_DIR}dns.log 2>/dev/null | zeek-cut ts id.orig_h query answers | grep "$ip" | head -5)

EOF

# Display the final report
echo "Investigation complete. Reading report..."
echo "------------------------------------------------------"
cat "$REPORT_FILE"
echo "------------------------------------------------------"
}

# --- Execute Lookup ---
perform_lookup "$SUSPECT_IP"
```
ioc-cor.sh

```bash
root@thehive:~/malware-analysis# cat ioc-cor.sh
#!/bin/bash

# --- Configuration ---
LOG_DIR="./"
SURICATA_DIR="./suricata-output"
REPORT_FILE="ioc-correlation-report.txt"

# --- Pre-requisite Check ---
if ! command -v jq &> /dev/null
then
    echo "JQ is required for this script but is not installed. Please install JQ."
    exit 1
fi

# --- Main Report Generation ---
cat > "$REPORT_FILE" << EOF
=== IOC & CORRELATION REPORT ===

Date: $(date)

===================================
## 1. Top 20 Suspicious Connections
===================================

### Top 20 IPs with Most Connections (Potential Scanning/High-Volume C2)
$(cat ${LOG_DIR}conn.log | zeek-cut id.resp_h | sort | uniq -c | sort -rn | head -20)

### Top 10 Long-Duration Connections (Possible Persistent C2 Beaconing)
$(cat ${LOG_DIR}conn.log | zeek-cut duration id.orig_h id.resp_h id.resp_p service | sort -rn | head -10)

===================================
## 2. Suspicious Domains & Hosts
===================================

### Domains with High Entropy (Possible DGA Activity - length 20+)
$(cat ${LOG_DIR}dns.log | zeek-cut query | grep -E '[a-z]{20,}' | sort -u)

### Unusual User Agents (Non-Browser Traffic)
$(cat ${LOG_DIR}http.log | zeek-cut user_agent | grep -iE 'python|curl|wget|powershell|java' | sort -u)

===================================
## 3. Data Exfiltration/Lateral Movement Artifacts
===================================

### Large Uploads (Possible Data Exfil - Top 10 by request body size)
# request_body_len > 0 and sort by largest
$(cat ${LOG_DIR}http.log | zeek-cut method request_body_len response_body_len id.orig_h host uri | awk '$2 > 0 { print }' | sort -k2 -rn | head -10)

### Potentially Malicious File Hashes (IOCs)
# Focus on files detected as executables or scripts
$(cat ${LOG_DIR}files.log | zeek-cut mime_type filename sha1 | grep -iE 'exe|dll|bat|ps1|script')

EOF

# --- Step 4: Suricata Correlation (Live Scripting) ---
echo "===================================" >> "$REPORT_FILE"
echo "## 4. Suricata Correlation Check" >> "$REPORT_FILE"
echo "===================================" >> "$REPORT_FILE"

# 4a. Get malicious IPs from Suricata alerts and save to a temporary file
echo "-> Extracting unique malicious destination IPs from Suricata alerts..."
cat ${SURICATA_DIR}/eve.json 2>/dev/null | jq -r 'select(.event_type=="alert") | .dest_ip' | sort -u > malicious-ips.tmp

# 4b. Check those IPs against Zeek conn.log
if [ -s malicious-ips.tmp ]; then
    echo "-> Cross-referencing malicious IPs with Zeek conn.log:" >> "$REPORT_FILE"
    while read ip; do
        echo "--- Connections to $ip ---" >> "$REPORT_FILE"
        # Find connection details for the alerted IPs
        cat ${LOG_DIR}conn.log | zeek-cut ts id.orig_h id.resp_h id.resp_p service duration | grep "$ip" >> "$REPORT_FILE"
    done < malicious-ips.tmp
else
    echo "No unique malicious IPs found in Suricata alerts." >> "$REPORT_FILE"
fi

# 4c. Clean up temporary file
rm malicious-ips.tmp 2>/dev/null

# Display the report
cat "$REPORT_FILE"

# --- Execution Steps ---
# 1. Save: nano ioc-correlation-report.sh
# 2. Make Executable: chmod +x ioc-correlation-report.sh
# 3. Run: ./ioc-correlation-report.sh
```
