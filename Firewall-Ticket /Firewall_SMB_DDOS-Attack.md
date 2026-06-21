# Ticket Firewall: SMB DDoS Attack

> **Portfolio Type:** SOC L1 Alert Triage Case Study  
> **Format:** One ticket = one page  
> **Objective:** Demonstrate alert validation, SIEM investigation, MITRE ATT&CK mapping, impact assessment, and SOC decision-making.

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
| Analyst Decision | Suspicious but Blocked |
| Final Handling | Monitor / No immediate escalation |

---

## 2. Alert Details

| Field | Value |
|---|---|
| Receive Time | 02/18/2025 15:40 |
| Source IP | 192.42.116.210 |
| Source Context | TOR Exit / Data Center / Web Hosting / Netherlands |
| Source Domain | cyberology.nl |
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

Inbound traffic was observed from external IP `192.42.116.210` to internal host `10.0.14.29` on destination port `445/SMB`.

The firewall classified the activity as `SMB DDoS Attack` and blocked the traffic. Splunk review confirmed `245` matching blocked inbound events from the same source IP to the same internal file server.

This activity is suspicious because SMB should generally not be exposed directly to the internet unless there is a specific approved business requirement. The source is also associated with TOR/data center infrastructure, which increases suspicion.

No evidence of allowed SMB traffic, successful connection, internal compromise, or file server service impact was identified from the available logs.

**Assessment:** Suspicious inbound SMB DDoS activity blocked by firewall.

---

## 5. MITRE ATT&CK Mapping

| Tactic | Technique ID | Technique Name | Confidence | Reason |
|---|---|---|---|---|
| Impact | [T1498](https://attack.mitre.org/techniques/T1498/) | Network Denial of Service | High | The alert indicates attempted denial-of-service activity against a network service. |
| Impact | [T1498.001](https://attack.mitre.org/techniques/T1498/001/) | Direct Network Flood | Medium | Possible if the events represent direct high-volume inbound traffic toward SMB. |
| Impact | [T1499](https://attack.mitre.org/techniques/T1499/) | Endpoint Denial of Service | Low / Possible | Could apply if the SMB service or file server resources were exhausted, but no host impact was confirmed. |
| Discovery | [T1046](https://attack.mitre.org/techniques/T1046/) | Network Service Discovery | Low / Not Confirmed | Only applicable if logs show scanning or service enumeration before the DDoS activity. |

**MITRE Decision:**  
Primary mapping should be `T1498 - Network Denial of Service`.  
`T1498.001 - Direct Network Flood` can be listed as a possible sub-technique.  
Do not claim `T1499 - Endpoint Denial of Service` unless host-level evidence confirms SMB/file server exhaustion or service disruption.  
Do not claim `T1046 - Network Service Discovery` unless additional logs show scanning behavior.

---

## 6. Actions Taken

- Reviewed firewall ticket details and alert metadata.
- Validated source IP, destination IP, destination port, protocol, direction, severity, and firewall action.
- Confirmed that the destination service was SMB on port 445.
- Ran Splunk query to check repeated activity from the same source IP.
- Confirmed 245 blocked inbound SMB DDoS events.
- Checked whether the traffic was blocked or allowed.
- Reviewed source IP context and identified TOR/data center association.
- Documented findings and recommended continued monitoring.

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

**Potential impact if successful:** SMB service degradation, file server resource exhaustion, file-share unavailability, unauthorized SMB exposure risk, and possible disruption to business file access.

---

## 8. Escalation Decision

**Decision:** Monitor / No immediate escalation required.

**Reason:**  
The firewall blocked inbound traffic from `192.42.116.210` to `10.0.14.29` on destination port `445`. Splunk confirmed `245` blocked events. No allowed SMB traffic, successful connection, internal compromise, or file server impact was identified from the available logs.

**Escalate if:**

- The same activity continues or increases in volume.
- Multiple external source IPs target the same destination.
- Any related SMB traffic is allowed.
- The file server shows CPU, memory, network, or SMB service issues.
- Windows logs show suspicious authentication failures or SMB access attempts.
- The destination server is confirmed as a critical business file server.
- Additional indicators of compromise are observed.

---

## 9. Closure / Analyst Note

SOC investigated ticket `CS-02` related to a firewall alert for `SMB DDoS Attack`. Logs showed inbound traffic from external source IP `192.42.116.210` to internal destination `10.0.14.29` on destination port `445/SMB`.

Splunk confirmed `245` matching events. All observed events were blocked by the firewall. No evidence of successful traffic delivery, allowed SMB connection, internal host compromise, or service impact was identified.

**Final Assessment:** Suspicious inbound SMB DDoS activity blocked by firewall. Continue monitoring and escalate if repeated activity, allowed traffic, multiple source IPs, or file server impact is observed.

---

## 10. Portfolio Redaction Note

Before publishing this ticket publicly, redact requester names, email addresses, internal usernames, organization names, ticketing URLs, and any real customer-sensitive information from screenshots. Keep only technical evidence required to demonstrate SOC investigation skills.
