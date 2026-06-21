# Ticket CS-02 — Firewall: SMB DDoS Attack
 
> **Role Demonstrated:** SOC L1 Alert Triage, Firewall Log Analysis, Splunk Investigation, MITRE ATT&CK Mapping  
> **Case Type:** Inbound SMB DDoS attempt blocked by firewall

---

## 1. Ticket Overview

| Field | Details |
|---|---|
| Ticket ID | CS-02 |
| Alert Name | Firewall: SMB DDoS Attack |
| Ticket Status | In Progress |
| Priority | High |
| Alert Severity | High |
| Department | Support |
| Source | Email |
| Created Date | 03/02/2025 19:45 |
| Assigned To | SOC Team |
| SLA Plan | High |
| Due Date | 06/17/2026 02:14 |
| Recommended SOC Decision | Monitor / No immediate escalation |
| Analyst Assessment | Suspicious inbound SMB DDoS activity blocked by firewall |

---

## 2. Alert Details

| Field | Value |
|---|---|
| Receive Time | 02/18/2025 15:40 |
| Source IP | 192.42.116.210 |
| Source Context | TOR Exit / Data Center / Web Hosting / Transit |
| Source Domain | cyberology.nl |
| Source Country | Netherlands |
| Destination IP | 10.0.14.29 |
| Destination Host | Windows Server 2019 |
| Destination Role | File Server |
| Source Port | 48008 |
| Destination Port | 445 |
| Destination Service | SMB |
| Protocol | UDP |
| Direction | Inbound |
| Firewall Action | Blocked |
| Threat Name | SMB DDoS Attack |
| Log Source | Firewall Logs / Splunk |

---

## 3. Investigation Evidence

### Splunk Query Used

```spl
index=main sourcetype="firewall_logs" dstPort=445 srcIP="192.42.116.210"
| where Threat_Name="SMB DDOS Attack"
| stats count by srcIP, dstIP, dstPort, Action, Protocol, Direction, Severity
| sort - count
```

### Splunk Result

| srcIP | dstIP | dstPort | Action | Protocol | Direction | Severity | Count |
|---|---|---:|---|---|---|---|---:|
| 192.42.116.210 | 10.0.14.29 | 445 | blocked | udp | Inbound | high | 245 |

---

## 4. Analyst Analysis

Inbound traffic was observed from external source IP `192.42.116.210` to internal destination host `10.0.14.29` on destination port `445/SMB`.

The firewall classified the activity as `SMB DDoS Attack` with **High** severity and blocked the traffic. Splunk review confirmed `245` blocked inbound events from the same external source IP to the same internal file server.

This activity is suspicious because SMB is a sensitive file-sharing service and should generally not be exposed directly to the internet unless explicitly approved. The source IP context is also suspicious because it is associated with TOR/data center infrastructure.

The firewall log recorded the protocol as `UDP`. This should be validated because SMB commonly uses `TCP/445`. The UDP value may indicate firewall signature behavior, parser normalization, malformed traffic, or non-standard traffic targeting port `445`.

No evidence of allowed SMB traffic, successful connection, internal compromise, or file server impact was identified from the available logs.

**Current Assessment:** Suspicious inbound SMB DDoS activity blocked by firewall.

---

## 5. MITRE ATT&CK Mapping

| Tactic | Technique ID | Technique Name | Confidence | Reason |
|---|---|---|---|---|
| Impact | [T1498](https://attack.mitre.org/techniques/T1498/) | Network Denial of Service | High | The alert indicates attempted denial-of-service activity against a network-facing service. |
| Impact | [T1498.001](https://attack.mitre.org/techniques/T1498/001/) | Direct Network Flood | Medium | Possible if the events represent direct high-volume inbound traffic toward SMB service on port 445. |
| Impact | [T1499](https://attack.mitre.org/techniques/T1499/) | Endpoint Denial of Service | Low / Not Confirmed | Only applicable if host-level evidence shows file server resource exhaustion or SMB service disruption. |
| Discovery | [T1046](https://attack.mitre.org/techniques/T1046/) | Network Service Discovery | Low / Not Confirmed | Only applicable if separate logs show scanning or service enumeration before the DDoS activity. |

### MITRE Mapping Decision

Primary mapping:

```text
TA0040 - Impact
T1498 - Network Denial of Service
```

Possible sub-technique:

```text
T1498.001 - Direct Network Flood
```

Do **not** confidently claim `T1499 - Endpoint Denial of Service` unless Windows logs, server metrics, or service monitoring confirm file server resource exhaustion or SMB service disruption.

Do **not** claim `T1046 - Network Service Discovery` unless additional evidence shows scanning or enumeration activity.

---

## 6. Actions Taken

- Reviewed firewall ticket details and alert metadata.
- Validated source IP, destination IP, source port, destination port, protocol, direction, severity, and firewall action.
- Confirmed that the destination service was SMB on port `445`.
- Confirmed that the firewall action was `blocked`.
- Ran Splunk query to check repeated activity from the same source IP.
- Confirmed `245` blocked inbound SMB DDoS events.
- Reviewed source IP context and identified TOR/data center association.
- Checked for evidence of allowed SMB traffic or successful connection.
- Documented findings and recommended monitoring.

---

## 7. Impact Assessment

| Category | Assessment |
|---|---|
| Confirmed Compromise | No evidence found |
| Confirmed Service Impact | No evidence found |
| Allowed SMB Traffic | No evidence found |
| Blocked SMB Traffic | Yes |
| Affected Asset | Windows Server 2019 File Server |
| Business Risk | Medium to High |
| Current Risk Status | Controlled by firewall block |

### Potential Impact If Successful

- SMB service degradation or denial of service
- Increased CPU, memory, or network utilization on the file server
- File-share unavailability for users
- Exposure of sensitive shared resources if SMB access is misconfigured
- Increased risk of SMB exploitation attempts if port 445 is reachable externally
- Business disruption if the server supports critical file-sharing operations

---

## 8. False Positive / Non-Impacting Possibility

This alert may be non-impacting because the firewall blocked the observed traffic before it could reach the internal file server.

Possible reasons:

- Automated internet background traffic targeting SMB port `445`
- Malformed or non-standard traffic to port `445`
- Firewall DDoS signature triggered due to repeated blocked attempts
- Traffic from TOR or hosting infrastructure generating unwanted scanning/noise
- No evidence of allowed SMB connection or server-side impact

False positive closure should only be considered after confirming:

- No related SMB traffic was allowed
- No Windows authentication failures or SMB session events were observed
- No file server performance issue occurred
- SMB exposure is not intentionally required from the internet

---

## 9. Escalation Decision

**Decision:** Monitor / No immediate escalation required.

**Reason:**  
The firewall blocked inbound traffic from `192.42.116.210` to `10.0.14.29` on destination port `445`. Splunk confirmed `245` blocked events. No evidence of allowed SMB traffic, successful connection, internal compromise, or file server impact was identified from the available logs.

### Escalate If

- The same activity continues or increases in volume.
- Multiple external source IPs target the same destination.
- Any related SMB traffic is allowed.
- The file server shows CPU, memory, network, or SMB service issues.
- Windows event logs show suspicious authentication failures or SMB access attempts.
- The destination server is confirmed as a critical business file server.
- Additional indicators of compromise are observed.

---

## 10. Final Analyst Note

SOC investigated ticket `CS-02` related to `Firewall: SMB DDoS Attack`.

Logs showed inbound traffic from external source IP `192.42.116.210` to internal destination IP `10.0.14.29` on destination port `445/SMB`. The destination host is a Windows Server 2019 file server. The firewall classified the activity as `SMB DDoS Attack` and blocked the traffic.

Splunk review confirmed `245` matching blocked events. No allowed SMB traffic, successful connection, internal host compromise, or service impact was identified from the available evidence.

**Final Assessment:** Suspicious inbound SMB DDoS activity blocked by firewall. Continue monitoring and escalate if repeated activity, allowed SMB traffic, multiple attacking sources, or file server impact is observed.

---

## ⚠️ Disclaimer

This repository is created for educational, portfolio, and career development purposes only.

All scenarios are sanitized and written in a safe format. No confidential company information, client data, or real production logs are included.

---

## 👤 Author

**Ananda Das**
Cybersecurity Student | SOC Analyst Learner | SIEM, Threat Detection & Incident Response Enthusiast

GitHub: [@nothingnhm](https://github.com/nothingnhm)

---

## ⭐ Repository Purpose

This project is part of my cybersecurity portfolio to demonstrate practical experience in ticket triage, IT troubleshooting, SOC alert analysis, and professional documentation.
