# SOC Analyst Investigation Report

## Ticket Overview

| Field            | Details                                      |
| ---------------- | -------------------------------------------- |
| Ticket ID        | CS-011                                       |
| Alert Name       | Firewall: Ping of Death                      |
| Ticket Status    | Closed                                       |
| Priority / SLA   | Normal / High                                |
| Created Date     | 3/2/25 7:45 PM                               |
| Closed By        | sushanth P                                   |
| Close Date       | 6/20/26 9:47 AM                              |
| Analyst Decision | **True Positive — Blocked ICMP DoS Attempt** |

## Executive Summary

A firewall alert was triggered for **Ping of Death** involving inbound ICMP traffic from external source IP **92.255.85.253** to internal destination **10.0.2.20 / WinITAD01**.

The firewall detected the activity with **High** severity and blocked the traffic. Splunk review confirmed **571 blocked inbound ICMP events** from the same source to the internal Active Directory server. The source IP has **100% abuse confidence** and is associated with data center/web-hosting infrastructure.

No allowed traffic, successful connection, host compromise, or service impact was observed from the provided evidence.

## Alert Details

| Field             | Value                                                                                                                  |
| ----------------- | ---------------------------------------------------------------------------------------------------------------------- |
| Receive Time      | 2/11/2025 13:49                                                                                                        |
| Source IP         | 92.255.85.253                                                                                                          |
| Source Port       | 3103                                                                                                                   |
| Destination IP    | 10.0.2.20                                                                                                              |
| Destination Port  | 1                                                                                                                      |
| Protocol          | ICMP                                                                                                                   |
| Direction         | Inbound                                                                                                                |
| Threat Name       | Ping of Death                                                                                                          |
| Severity          | High                                                                                                                   |
| Firewall Action   | Blocked                                                                                                                |
| Source Reputation | 100% abuse confidence                                                                                                  |
| Source Details    | Chang Way Technologies Co. Limited; Data Center/Web Hosting/Transit; changway.hk; Saint Petersburg, Russian Federation |

## Affected Assets

| Asset Field          | Details                                              |
| -------------------- | ---------------------------------------------------- |
| Destination IP       | 10.0.2.20                                            |
| Hostname             | WinITAD01                                            |
| Operating System     | Windows Server 2022                                  |
| Asset Role           | Active Directory / AD Server                         |
| Business Criticality | Not Provided                                         |
| Exposure Concern     | ICMP DoS-style traffic targeted a critical AD server |

## Evidence Reviewed

| Evidence Source          | Observation                                                  |
| ------------------------ | ------------------------------------------------------------ |
| Ticket Screenshot        | Firewall alert for **Ping of Death**                         |
| Firewall Event           | Inbound ICMP traffic from **92.255.85.253** to **10.0.2.20** |
| Firewall Action          | **Blocked**                                                  |
| Splunk Result            | **571 blocked inbound ICMP events**                          |
| Allowed Traffic          | Not Observed                                                 |
| Host Compromise Evidence | Not Observed                                                 |
| Service Impact           | Not Provided                                                 |
| Endpoint/EDR Evidence    | Not Provided                                                 |

## SIEM / Splunk Analysis

```spl id="z1mx82"
index=main sourcetype="firewall_logs" srcIP="92.255.85.253" dstIP="10.0.2.20"
| stats count by srcIP, dstIP, srcPort, dstPort, Threat_Name, Severity, Action, Protocol, Direction
| sort - count
```

| srcIP         | dstIP     | srcPort | dstPort | Threat_Name   | Severity | Action  | Protocol | Direction | Count |
| ------------- | --------- | ------: | ------: | ------------- | -------- | ------- | -------- | --------- | ----: |
| 92.255.85.253 | 10.0.2.20 |    3103 |       1 | Ping of Death | high     | blocked | icmp     | Inbound   |   571 |

**Analysis Note:** Since the protocol is **ICMP**, the logged source/destination port values should not be interpreted as normal TCP/UDP ports. They may represent firewall normalization or ICMP type/code mapping.

## MITRE ATT&CK Mapping

| Tactic | Technique                  | ID    | Reason                                                                 |
| ------ | -------------------------- | ----- | ---------------------------------------------------------------------- |
| Impact | Endpoint Denial of Service | T1499 | Ping of Death activity can target host availability                    |
| Impact | Network Denial of Service  | T1498 | Repeated inbound ICMP traffic was detected and blocked by the firewall |

## Analyst Assessment

**Assessment:** **True Positive — Blocked ICMP DoS Attempt**

The alert is valid because the firewall detected repeated inbound ICMP traffic matching a **Ping of Death** signature. The source IP has high abuse confidence, and the destination is an Active Directory server, making the target sensitive.

The activity was blocked. No successful delivery, compromise, or service disruption was confirmed.

## Impact Analysis

| Area            | Assessment                                                       |
| --------------- | ---------------------------------------------------------------- |
| Confidentiality | No unauthorized access observed                                  |
| Integrity       | No system modification observed                                  |
| Availability    | Potential DoS risk, but no confirmed service impact              |
| Business Impact | No confirmed impact; elevated concern due to AD server targeting |
| Current Risk    | Reduced because firewall blocked all reviewed traffic            |

## Recommended Actions

1. Continue monitoring for repeated ICMP activity from **92.255.85.253**.
2. Check whether the same source IP targeted other internal hosts.
3. Review firewall logs for any **allowed** ICMP traffic from this source.
4. Confirm whether inbound ICMP from the internet is required for **WinITAD01**.
5. Keep inbound ICMP blocked to critical AD infrastructure unless explicitly approved.
6. Consider adding the source IP to a watchlist or blocklist as per organizational policy.
7. Escalate if traffic becomes allowed, multiple AD servers are targeted, or AD service degradation is observed.

## Escalation Decision

**Decision:** **No escalation required; ticket closed as True Positive — Blocked.**

**Reason:** The firewall blocked the inbound ICMP Ping of Death activity, and Splunk confirmed **571 blocked events**. No allowed traffic, host compromise, or service impact was identified from the provided evidence.

## Final Ticket Closure Comment

SOC investigated ticket **CS-011 — Firewall: Ping of Death**. Inbound ICMP traffic from external source IP **92.255.85.253** to **10.0.2.20 / WinITAD01** was detected with High severity and blocked by the firewall. Splunk confirmed **571 blocked inbound ICMP events**. The source IP has **100% abuse confidence** and is associated with data center/web-hosting infrastructure. No allowed traffic, host compromise, or AD service impact was observed. Ticket closed as **True Positive — Blocked**, with continued monitoring recommended for recurrence or service impact.

## Skills Demonstrated

Firewall alert triage, ICMP DoS investigation, Splunk log validation, source reputation review, Active Directory asset risk assessment, MITRE ATT&CK mapping, impact analysis, escalation decision-making, and SOC ticket documentation.

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
