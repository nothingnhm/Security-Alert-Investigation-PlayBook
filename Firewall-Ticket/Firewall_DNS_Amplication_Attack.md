# SOC Analyst Investigation Report

## Ticket Overview

| Field            | Details                                                |
| ---------------- | ------------------------------------------------------ |
| Ticket ID        | CS-04                                                  |
| Alert Name       | Firewall: DNS Amplication Attack                       |
| Ticket Status    | Closed                                                 |
| Priority / SLA   | High / High                                            |
| Created Date     | 3/2/25 7:45 PM                                         |
| Closed By        | Ananda Das                                             |
| Analyst Decision | **True Positive — Blocked DNS Amplification Activity** |

## Executive Summary

A firewall alert was triggered for **DNS Amplication Attack** involving inbound traffic from external source IP **34.133.106.109** to internal destination IP **10.0.2.27** on destination port **53/DNS**.

The firewall classified the event as **High severity** and blocked the traffic. Splunk review confirmed **110 blocked events** against the primary destination and **771 total blocked events** from the same source across multiple internal hosts. No allowed DNS traffic, successful connection, compromise, or DNS service impact was observed from the provided evidence.

## Alert Details

| Field            | Value                                                                                 |
| ---------------- | ------------------------------------------------------------------------------------- |
| Receive Time     | 2/26/2025 18:20                                                                       |
| Source IP        | 34.133.106.109                                                                        |
| Source Port      | 8004                                                                                  |
| Destination IP   | 10.0.2.27                                                                             |
| Destination Port | 53                                                                                    |
| Service          | DNS                                                                                   |
| Protocol         | UDP                                                                                   |
| Direction        | Inbound                                                                               |
| Threat Name      | DNS Amplication Attack                                                                |
| Severity         | High                                                                                  |
| Firewall Action  | Blocked                                                                               |
| Source Details   | Google LLC / Google Cloud; googleusercontent.com; Council Bluffs, Iowa, United States |

## Affected Assets

| Asset Field            | Details                                                                           |
| ---------------------- | --------------------------------------------------------------------------------- |
| Primary Destination IP | 10.0.2.27                                                                         |
| Hostname               | WinITDNS02                                                                        |
| Operating System       | Windows Server 2022                                                               |
| Asset Role             | DNS Server                                                                        |
| Additional Targets     | 10.0.14.12, 10.0.15.14, 10.0.2.32, 10.0.15.16, 10.0.16.22, 10.0.11.10, 10.0.14.29 |

## Evidence Reviewed

| Evidence Source       | Observation                                                        |
| --------------------- | ------------------------------------------------------------------ |
| Ticket Screenshot     | Firewall alert for **DNS Amplication Attack**                      |
| Firewall Event        | Inbound UDP traffic from **34.133.106.109** to **10.0.2.27:53**    |
| Firewall Action       | **Blocked**                                                        |
| Primary Splunk Result | **110 blocked events** against **10.0.2.27**                       |
| Broader Splunk Result | **771 total blocked events** across multiple internal destinations |
| Allowed Traffic       | Not Observed                                                       |
| Host Compromise       | Not Observed                                                       |
| DNS Service Impact    | Not Provided                                                       |

## SIEM / Splunk Analysis

```spl id="q21crm"
index=main sourcetype="firewall_logs" dstPort=53 dstIP="10.0.2.27"
| where Threat_Name="DNS Amplication Attack"
| stats count by srcIP, dstIP, dstPort, Action, Protocol, Direction, Severity
| sort - count
```

| srcIP          | dstIP     | dstPort | Action  | Protocol | Direction | Severity | Count |
| -------------- | --------- | ------: | ------- | -------- | --------- | -------- | ----: |
| 34.133.106.109 | 10.0.2.27 |      53 | blocked | udp      | Inbound   | high     |   110 |

```spl id="7dmka6"
index=main sourcetype="firewall_logs" dstPort=53
| where Threat_Name="DNS Amplication Attack"
| stats count by srcIP, dstIP, dstPort, Action, Protocol, Direction, Severity
| sort - count
```

| Summary                                  | Result |
| ---------------------------------------- | -----: |
| Total blocked events from 34.133.106.109 |    771 |
| Number of internal destinations observed |      8 |
| Highest single destination count         |    200 |

**Analysis Note:** The primary event was logged as **UDP/53**, which aligns with DNS amplification-style activity. Some broader Splunk results were logged as TCP/53; this should be validated as firewall normalization, related probing, or separate DNS service targeting.

## MITRE ATT&CK Mapping

| Tactic | Technique                 | ID        | Reason                                                                          |
| ------ | ------------------------- | --------- | ------------------------------------------------------------------------------- |
| Impact | Network Denial of Service | T1498     | Firewall classified repeated DNS traffic as amplification-style attack activity |
| Impact | Reflection Amplification  | T1498.002 | DNS amplification behavior was observed against DNS service port 53             |

## Analyst Assessment

**Assessment:** **True Positive — Blocked DNS Amplification Activity**

The alert is valid because firewall and Splunk evidence confirm repeated inbound DNS-related traffic from **34.133.106.109** targeting internal DNS services. The activity was blocked by the firewall. No evidence confirms successful connection, service disruption, compromise, or business impact.

This is assessed as a **blocked external DNS amplification-style attack**, not a confirmed breach.

## Impact Analysis

| Area            | Assessment                                                     |
| --------------- | -------------------------------------------------------------- |
| Confidentiality | No unauthorized data access observed                           |
| Integrity       | No modification activity observed                              |
| Availability    | Potential DNS availability risk, but no confirmed outage       |
| Business Impact | No confirmed impact; elevated risk due to DNS server targeting |
| Current Risk    | Reduced because all reviewed traffic was blocked               |

## Recommended Actions

1. Continue monitoring for repeat DNS amplification alerts from **34.133.106.109**.
2. Confirm whether any traffic from this source to internal port **53** was allowed.
3. Validate whether internal DNS servers should receive inbound DNS traffic from external sources.
4. Review DNS server health metrics if available, including query volume, CPU, memory, and service availability.
5. Add the source IP to a watchlist or blocklist if repeated activity continues, following organizational policy.
6. Escalate if allowed traffic, increased volume, multiple external sources, or DNS service impact is observed.

## Escalation Decision

**Decision:** **No escalation required; ticket closed as True Positive — Blocked.**

**Reason:** Firewall blocked the observed DNS amplification-style activity. Splunk confirmed blocked events against the primary DNS server and additional internal destinations. No allowed traffic, compromise, or DNS service impact was observed from the provided evidence.

## Final Ticket Closure Comment

SOC investigated ticket **CS-04 — Firewall: DNS Amplication Attack**. Inbound DNS traffic from external source IP **34.133.106.109** to internal DNS server **10.0.2.27 / WinITDNS02** on port **53** was detected with High severity and blocked by the firewall. Splunk confirmed **110 blocked events** against the primary destination and **771 total blocked events** across multiple internal hosts. No allowed traffic, successful connection, compromise, or DNS service impact was observed. Ticket closed as **True Positive — Blocked**, with continued monitoring recommended for recurrence or allowed DNS traffic.

## Skills Demonstrated

Firewall alert triage, DNS attack analysis, Splunk investigation, DDoS/amplification validation, MITRE ATT&CK mapping, impact assessment, escalation decision-making, and SOC ticket documentation.

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
