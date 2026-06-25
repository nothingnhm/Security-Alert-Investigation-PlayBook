# SOC Analyst Investigation Report

## Ticket Overview

| Field                 | Details                                                              |
| --------------------- | -------------------------------------------------------------------- |
| Ticket ID             | CS-06                                                                |
| Alert Name            | Firewall: Microsoft Active Directory DCSync Attempt Detection(54406) |
| Ticket Status         | Closed                                                               |
| Ticket Priority / SLA | Low / Medium                                                         |
| Created Date          | 3/2/25 7:45 PM                                                       |
| Closed By             | ananda das                                                           |
| Analyst Decision      | **False Positive — Authorized Qualys Scanner Activity**              |

## Executive Summary

A firewall alert was generated for **Microsoft Active Directory DCSync Attempt Detection(54406)** involving inbound TCP traffic from **150.230.234.34** to internal host **10.0.14.34** on destination port **445/SMB**.

Although the firewall signature severity was **High** and the traffic action was **allowed**, the source IP was confirmed as an organization-approved **Qualys External Scanning IP**. The destination host is identified as **WinHRFileServer6**, a **Windows Server 2019 File Server**, not a confirmed Domain Controller.

No evidence of unauthorized access, credential replication, compromise, or service impact was provided. The activity is assessed as authorized vulnerability scanning.

## Alert Details

| Field            | Value                                                                                   |
| ---------------- | --------------------------------------------------------------------------------------- |
| Receive Time     | 3/2/2025 08:55                                                                          |
| Source IP        | 150.230.234.34                                                                          |
| Source Port      | 36103                                                                                   |
| Destination IP   | 10.0.14.34                                                                              |
| Destination Port | 445                                                                                     |
| Service          | SMB                                                                                     |
| Protocol         | TCP                                                                                     |
| Direction        | Inbound                                                                                 |
| Threat Name      | Microsoft Active Directory DCSync Attempt Detection(54406)                              |
| Severity         | High                                                                                    |
| Firewall Action  | Allowed                                                                                 |
| Source Details   | Oracle Corporation; Data Center/Web Hosting/Transit; AS31898; oracle.com; Mumbai, India |
| Business Context | Known Qualys External Scanning IP — IN Platform 1                                       |
| Qualys Mapping   | Primary: 168.138.113.116; Secondary: 150.230.234.34                                     |

## Affected Assets

| Asset Field              | Details                      |
| ------------------------ | ---------------------------- |
| Destination IP           | 10.0.14.34                   |
| Hostname                 | WinHRFileServer6             |
| Operating System         | Windows Server 2019          |
| Asset Role               | File Server                  |
| Business Criticality     | Not Provided                 |
| Domain Controller Status | Not Confirmed / Not Provided |

## Evidence Reviewed

| Evidence Source              | Observation                                                       |
| ---------------------------- | ----------------------------------------------------------------- |
| Ticket Screenshot            | Firewall alert for **DCSync Attempt Detection(54406)**            |
| Firewall Event               | Inbound TCP traffic from **150.230.234.34** to **10.0.14.34:445** |
| Firewall Action              | **Allowed**                                                       |
| Source IP Validation         | Confirmed as known **Qualys External Scanning IP**                |
| Destination Asset Context    | Windows Server 2019 File Server                                   |
| Splunk / SQL Evidence        | Not Required / Not Provided                                       |
| AD Replication Evidence      | Not Observed                                                      |
| Unauthorized Access Evidence | Not Observed                                                      |
| Service Impact               | Not Provided                                                      |

## SIEM / Splunk Analysis

No Splunk query was required for closure because the source IP **150.230.234.34** was validated as an approved company-used **Qualys External Scanning IP**.

```spl id="h6m4w8"
index=main sourcetype="firewall_logs" srcIP="150.230.234.34" dstIP="10.0.14.34" dstPort=445
| stats count by srcIP, dstIP, srcPort, dstPort, Threat_Name, Severity, action, Protocol, Direction
| sort - count
```

**Expected validation use:** confirm whether similar activity from the same scanner IP was logged and verify no non-scanner source triggered the same DCSync signature.

## MITRE ATT&CK Mapping

| Tactic            | Technique                     | ID        | Reason                                                                                   |
| ----------------- | ----------------------------- | --------- | ---------------------------------------------------------------------------------------- |
| Credential Access | OS Credential Dumping: DCSync | T1003.006 | Firewall signature indicated DCSync attempt; no successful replication evidence observed |
| Discovery         | Network Service Discovery     | T1046     | Authorized scanner probed SMB/445 as part of vulnerability scanning behavior             |

## Analyst Assessment

**Assessment:** **False Positive — Authorized Security Scanner Activity**

The alert signature is sensitive because DCSync activity may indicate attempted Active Directory credential replication. However, the source IP **150.230.234.34** is confirmed as an approved **Qualys External Scanning IP**, and the destination is documented as a **File Server**, not a confirmed Domain Controller.

The allowed action should be documented, but the available evidence supports authorized vulnerability scanning rather than malicious activity.

## Impact Analysis

| Area            | Assessment                                     |
| --------------- | ---------------------------------------------- |
| Confidentiality | No credential or data access observed          |
| Integrity       | No system modification observed                |
| Availability    | No service disruption provided                 |
| Business Impact | No confirmed impact                            |
| Current Risk    | Low, due to confirmed approved scanner context |

## Recommended Actions

1. Close the ticket as **False Positive / Authorized Qualys Scanner Activity**.
2. Ensure **150.230.234.34** remains documented in the approved scanner inventory.
3. Tune SIEM/firewall logic to tag approved scanner IPs and reduce repeated false positives.
4. Continue monitoring for DCSync alerts from unknown, internal, or non-approved sources.
5. Escalate if the same signature appears from an unapproved IP, a workstation, or against a confirmed Domain Controller.
6. Validate that allowed SMB access from scanner IPs is restricted only to approved Qualys scanning infrastructure.

## Escalation Decision

**Decision:** **No escalation required; ticket closed as False Positive.**

**Reason:** The source IP is confirmed as an authorized Qualys scanner. No evidence of unauthorized authentication, successful DCSync replication, credential access, host compromise, or service impact was observed from the provided data.

## Final Ticket Closure Comment

SOC investigated ticket **CS-06 — Microsoft Active Directory DCSync Attempt Detection(54406)**. The alert showed inbound TCP traffic from **150.230.234.34** to **10.0.14.34 / WinHRFileServer6** on port **445/SMB**. The source IP was validated as an approved **Qualys External Scanning IP** for **IN Platform 1**. No unauthorized access, credential replication, compromise, or service impact was observed. Ticket closed as **False Positive — Authorized Qualys Scanner Activity**.

## Skills Demonstrated

Firewall alert triage, authorized scanner validation, DCSync alert analysis, SMB traffic review, MITRE ATT&CK mapping, false-positive handling, business-context validation, escalation decision-making, and SOC ticket documentation.
