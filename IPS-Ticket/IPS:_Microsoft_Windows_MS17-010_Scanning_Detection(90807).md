# SOC Analyst Investigation Report

## Ticket Overview

| Field            | Details                                                   |
| ---------------- | --------------------------------------------------------- |
| Ticket ID        | CS-020                                                    |
| Alert Name       | IPS: Microsoft Windows MS17-010 Scanning Detection(90807) |
| Ticket Status    | Closed                                                    |
| Priority / SLA   | Low / Default SLA                                         |
| Created Date     | 4/25/25 3:52 PM                                           |
| Closed By        | Ananda Das                                                |
| Analyst Decision | **False Positive — Authorized Qualys Scanner Activity**   |

## Executive Summary

An IPS alert was triggered for **Microsoft Windows MS17-010 Scanning Detection(90807)** involving inbound SMB traffic from source IP **150.230.234.34** to internal destination **10.0.14.29 / WinHRFileServer1** on **445/SMB**.

The source IP was validated as an approved **Qualys External Scanning IP** used for authorized vulnerability assessment under **IN Platform 1**. Splunk review showed multiple SMB/Windows enumeration and vulnerability scanning signatures consistent with scanner behavior. No unauthorized access, successful exploitation, host compromise, or service impact was observed.

## Alert Details

| Field                | Value                                                |
| -------------------- | ---------------------------------------------------- |
| Receive Time         | 2/16/2025 08:55                                      |
| Source IP            | 150.230.234.34                                       |
| Destination IP       | 10.0.14.29                                           |
| Destination Port     | 445                                                  |
| Service              | SMB / Windows File Sharing                           |
| Direction            | Inbound                                              |
| Threat Name          | Microsoft Windows MS17-010 Scanning Detection(90807) |
| Severity             | High                                                 |
| Firewall Action      | Allowed                                              |
| IPS Action           | Allowed                                              |
| User                 | NA                                                   |
| IPS Device           | IPS_01                                               |
| Scanner Context      | Approved Qualys External Scanner                     |
| Qualys Platform      | IN Platform 1                                        |
| Approved Scanner IPs | Primary: 168.138.113.116 / Secondary: 150.230.234.34 |

## Affected Assets

| Asset Field          | Details             |
| -------------------- | ------------------- |
| Destination IP       | 10.0.14.29          |
| Hostname             | WinHRFileServer1    |
| Operating System     | Windows Server 2019 |
| Platform             | Windows             |
| Asset Role           | File Server         |
| Asset Type           | VM                  |
| Business Criticality | Not Provided        |

## Evidence Reviewed

| Evidence Source         | Observation                                                                                                                                        |
| ----------------------- | -------------------------------------------------------------------------------------------------------------------------------------------------- |
| IPS Alert               | MS17-010 scanning detection on SMB/445                                                                                                             |
| Firewall / IPS Logs     | Traffic shown as **allowed**                                                                                                                       |
| Source Validation       | **150.230.234.34** confirmed as approved Qualys scanner IP                                                                                         |
| Related Signatures      | NTLMSSP detection, registry read/write attempts, user enumeration, share enumeration, SMB brute-force, MS17-010 scanning, DCSync-related detection |
| Unauthorized Access     | Not Observed                                                                                                                                       |
| Successful Exploitation | Not Observed                                                                                                                                       |
| Host Compromise         | Not Observed                                                                                                                                       |
| Service Impact          | Not Provided                                                                                                                                       |

## SIEM / Splunk Analysis

```spl id="my8fq3"
index=main "150.230.234.34" "10.0.14.29"
| stats count by _time, sourcetype, Action, srcIP, dstIP, dstPort, Threat_Name, Severity
| sort - count
```

| Activity Summary      | Observation                                               |
| --------------------- | --------------------------------------------------------- |
| Source IP             | 150.230.234.34                                            |
| Destination           | 10.0.14.29:445                                            |
| Main Detection        | Microsoft Windows MS17-010 Scanning Detection(90807)      |
| Additional Detections | SMB/Windows enumeration and vulnerability scan signatures |
| Action                | Allowed                                                   |
| Assessment            | Matches approved Qualys vulnerability scanning behavior   |

**Analysis Note:** The observed signatures would be suspicious from an unknown source. In this case, the source IP is confirmed as an approved scanner, so the activity is treated as authorized vulnerability assessment.

## MITRE ATT&CK Mapping

| Tactic         | Technique                 | ID        | Reason                                                    |
| -------------- | ------------------------- | --------- | --------------------------------------------------------- |
| Reconnaissance | Active Scanning           | T1595     | Approved scanner performed SMB vulnerability probing      |
| Reconnaissance | Vulnerability Scanning    | T1595.002 | MS17-010 and Windows service checks were observed         |
| Discovery      | Network Service Discovery | T1046     | SMB/445 service enumeration activity was observed         |
| Discovery      | Account Discovery         | T1087     | User enumeration signatures were observed during scanning |

## Analyst Assessment

**Assessment:** **False Positive — Authorized Scanner Activity**

The alert is not malicious from an incident perspective because the source IP **150.230.234.34** is confirmed as an approved Qualys external scanner. The observed SMB/Windows signatures are consistent with authorized vulnerability scanning.

No evidence confirms unauthorized access, successful exploitation, credential compromise, malware execution, or service impact.

## Impact Analysis

| Area            | Assessment                            |
| --------------- | ------------------------------------- |
| Confidentiality | No unauthorized data access observed  |
| Integrity       | No unauthorized modification observed |
| Availability    | No service disruption reported        |
| Business Impact | No confirmed impact                   |
| Current Risk    | Low due to approved scanner context   |

## Recommended Actions

1. Close the ticket as **False Positive / Authorized Qualys Scanner Activity**.
2. Tag **150.230.234.34** as `Approved_Qualys_Scanner` in SIEM.
3. Confirm the scan was within approved scope and scanning window.
4. Tune alerts only for the approved scanner IP and approved scan scope.
5. Do **not** disable MS17-010, SMB brute-force, DCSync, registry enumeration, or Windows enumeration detections globally.
6. Investigate normally if similar detections appear from unknown or non-approved sources.

## Escalation Decision

**Decision:** **No SOC L2 escalation required.**

**Reason:** The source IP is validated as an approved Qualys scanner, and the observed activity matches expected vulnerability scanning behavior. No compromise, unauthorized access, or business impact was identified.

## Final Ticket Closure Comment

SOC investigated ticket **CS-0297 — IPS: Microsoft Windows MS17-010 Scanning Detection(90807)**. Inbound SMB traffic from **150.230.234.34** to **10.0.14.29 / WinHRFileServer1** on **445/SMB** was reviewed. The source IP was confirmed as an approved **Qualys External Scanning IP** for **IN Platform 1**. Splunk showed multiple SMB/Windows vulnerability scanning signatures consistent with authorized assessment activity. No unauthorized access, successful exploitation, host compromise, or service impact was observed. Ticket closed as **False Positive — Authorized Qualys Scanner Activity**.

## Skills Demonstrated

IPS alert triage, approved scanner validation, SMB vulnerability scan analysis, Splunk log review, false-positive handling, MITRE ATT&CK mapping, evidence-based assessment, alert tuning recommendation, and SOC ticket documentation.

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
