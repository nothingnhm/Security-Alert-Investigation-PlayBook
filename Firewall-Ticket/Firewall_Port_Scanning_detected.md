# SOC Analyst Investigation Report

## Ticket Overview

| Field            | Details                                            |
| ---------------- | -------------------------------------------------- |
| Ticket ID        | CS-07                                              |
| Alert Name       | Firewall: Port Scanning detected                   | 
| Ticket Status    | Closed                                             |
| Priority / SLA   | Normal / Medium                                    |
| Created Date     | 3/2/25 7:45 PM                                     |
| Closed By        | ananda das                                         |
| Close Date       | 6/23/26 12:22 AM                                   |
| Analyst Decision | **True Positive — Blocked Port Scanning Activity** |

## Executive Summary

A firewall alert was triggered for **Port Scanning detected** involving inbound TCP traffic from external source IP **146.190.48.172** to internal destination IP **10.0.2.22** on destination port **3540**.

The firewall detected the activity with **Medium** severity and blocked the traffic. Splunk review confirmed **647 blocked inbound TCP events** from the same source IP to the same destination. The source IP is associated with **DigitalOcean, LLC** and has a reported **100% abuse confidence**.

No allowed traffic, successful connection, host compromise, or service impact was observed from the provided evidence.

## Alert Details

| Field             | Value                                                                                                                 |
| ----------------- | --------------------------------------------------------------------------------------------------------------------- |
| Receive Time      | 2/18/2025 07:55                                                                                                       |
| Source IP         | 146.190.48.172                                                                                                        |
| Source Port       | 9233                                                                                                                  |
| Destination IP    | 10.0.2.22                                                                                                             |
| Destination Port  | 3540                                                                                                                  |
| Threat Name       | Port Scanning detected                                                                                                |
| Severity          | Medium                                                                                                                |
| Firewall Action   | Blocked                                                                                                               |
| Protocol          | TCP                                                                                                                   |
| Direction         | Inbound                                                                                                               |
| Source Reputation | 100% abuse confidence                                                                                                 |
| Source Details    | DigitalOcean, LLC; Data Center/Web Hosting/Transit; AS14061; digitalocean.com; Santa Clara, California, United States |

## Affected Assets

| Asset Field          | Details                                                                           |
| -------------------- | --------------------------------------------------------------------------------- |
| Destination IP       | 10.0.2.22                                                                         |
| Hostname             | WinITADFS01                                                                       |
| Operating System     | Windows Server 2022                                                               |
| Platform             | Windows                                                                           |
| Asset Role           | Active Directory / ADFS-related Server                                            |
| Business Criticality | Not Provided                                                                      |
| Exposure Concern     | Multiple source and destination ports were used against an AD/ADFS-related server |

## Evidence Reviewed

| Evidence Source          | Observation                                                       |
| ------------------------ | ----------------------------------------------------------------- |
| Ticket Screenshot        | Firewall alert for **Port Scanning detected**                     |
| Firewall Event           | Inbound TCP traffic from **146.190.48.172** to **10.0.2.22:3540** |
| Firewall Action          | **Blocked**                                                       |
| Splunk Result            | **647 blocked inbound TCP events**                                |
| Source Port Pattern      | Multiple source ports used                                        |
| Destination Port Pattern | Multiple destination ports scanned                                |
| Allowed Traffic          | Not Observed                                                      |
| Successful Connection    | Not Observed                                                      |
| Host Compromise Evidence | Not Observed                                                      |
| Service Impact           | Not Provided                                                      |

## SIEM / Splunk Analysis

```spl
index=main sourcetype="firewall_logs" srcIP="146.190.48.172"
| stats count by srcIP, dstIP, Action, Protocol, Direction
| sort - count
```

| srcIP          | dstIP     | Action  | Protocol | Direction | Count |
| -------------- | --------- | ------- | -------- | --------- | ----: |
| 146.190.48.172 | 10.0.2.22 | blocked | tcp      | Inbound   |   647 |

**Analysis Note:** Multiple source ports and multiple destination ports were observed, supporting the firewall classification of port scanning behavior. All reviewed events were blocked.

## MITRE ATT&CK Mapping

| Tactic         | Technique                 | ID    | Reason                                                               |
| -------------- | ------------------------- | ----- | -------------------------------------------------------------------- |
| Reconnaissance | Active Scanning           | T1595 | External source performed repeated inbound probing activity          |
| Discovery      | Network Service Discovery | T1046 | Multiple destination ports were scanned to identify exposed services |

## Analyst Assessment

**Assessment:** **True Positive — Blocked Reconnaissance Activity**

The alert is valid because firewall and Splunk evidence confirm repeated inbound scanning behavior from **146.190.48.172** toward **10.0.2.22**. The source IP has a high abuse reputation and originates from cloud-hosting infrastructure, increasing the suspicious nature of the activity.

This is assessed as a **blocked external reconnaissance attempt**, not a confirmed compromise.

## Impact Analysis

| Area            | Assessment                                                                    |
| --------------- | ----------------------------------------------------------------------------- |
| Confidentiality | No unauthorized access observed                                               |
| Integrity       | No modification activity observed                                             |
| Availability    | No service disruption reported                                                |
| Business Impact | No confirmed impact; elevated concern due to AD/ADFS-related server targeting |
| Current Risk    | Reduced because all reviewed traffic was blocked                              |

## Recommended Actions

1. Continue monitoring for repeated scanning attempts from **146.190.48.172**.
2. Check whether the same source IP targeted other internal hosts.
3. Review firewall logs for any **allowed** traffic from the same source IP.
4. Validate destination port **3540** against the approved internal service inventory.
5. Confirm whether any scanned ports on **10.0.2.22** are expected to be externally exposed.
6. Consider adding the source IP to a watchlist or blocklist if activity continues, following organizational policy.
7. Escalate if allowed traffic, increased volume, multiple internal targets, or endpoint indicators are observed.

## Escalation Decision

**Decision:** **No escalation required; ticket closed as True Positive — Blocked.**

**Reason:** The firewall blocked the observed inbound scanning activity, and Splunk confirmed **647 blocked events**. No allowed traffic, successful connection, compromise, or service impact was identified from the provided evidence.

## Final Ticket Closure Comment

SOC investigated ticket **CS-07— Firewall: Port Scanning detected**. Inbound TCP traffic from external source IP **146.190.48.172** to internal host **10.0.2.22 / WinITADFS01** was detected as port scanning activity. Splunk review confirmed **647 blocked inbound events**, with multiple source ports and multiple destination ports observed. The source IP has **100% abuse confidence** and is associated with DigitalOcean cloud-hosting infrastructure. No allowed traffic, successful connection, compromise, or service impact was observed. Ticket closed as **True Positive — Blocked**, with continued monitoring recommended.

## Skills Demonstrated

Firewall alert triage, Splunk log analysis, port scanning investigation, source reputation review, AD/ADFS asset risk assessment, MITRE ATT&CK mapping, impact assessment, escalation decision-making, and SOC ticket documentation.

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
