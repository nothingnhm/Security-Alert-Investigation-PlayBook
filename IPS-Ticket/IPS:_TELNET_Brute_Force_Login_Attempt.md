# SOC Analyst Investigation Report

## Ticket Overview

| Field            | Details                               |
| ---------------- | ------------------------------------- |
| Ticket ID        | CS-018                                |
| Alert Name       | IPS: TELNET Brute Force Login Attempt |
| Ticket Status    | Closed                                |
| Priority / SLA   | Low / Default SLA                     |
| Created Date     | 4/25/25 3:52 PM                       |
| Closed By        | afzal pasha                           |
| Close Date       | 6/20/26 1:19 AM                       |
| Analyst Decision | **True Positive — Prevented by IPS**  |

## Executive Summary

An IPS alert was triggered for **TELNET Brute Force Login Attempt** involving inbound Telnet traffic from external source IP **138.84.41.252** to internal destination **10.0.15.31 / WinQAFileServer3** on **23/TCP**.

Firewall logs showed the Telnet traffic as **allowed**, but IPS logs detected brute-force activity and **blocked** it. Splunk review confirmed repeated activity between **20:20 and 20:23** on **4/19/2025**. No successful Telnet login, host compromise, malware activity, or service impact was confirmed from the provided evidence.

## Alert Details

| Field                | Value                                                             |
| -------------------- | ----------------------------------------------------------------- |
| Receive Time         | 4/19/2025 20:23                                                   |
| Source IP            | 138.84.41.252                                                     |
| Destination IP       | 10.0.15.31                                                        |
| Destination Port     | 23                                                                |
| Service              | Telnet                                                            |
| Protocol             | TCP                                                               |
| Direction            | Inbound                                                           |
| Threat Name          | TELNET Brute Force Login Attempt                                  |
| Initial Severity     | Low                                                               |
| Recommended Severity | Medium                                                            |
| Firewall Action      | Allowed                                                           |
| IPS Action           | Blocked                                                           |
| User                 | NA                                                                |
| IPS Device           | IPS_01                                                            |
| Source Reputation    | 100% abuse confidence                                             |
| Source Details       | Starlink Colombia S.A.S.; AS14593; starlink.com; Bogota, Colombia |

## Affected Assets

| Asset Field          | Details                                                           |
| -------------------- | ----------------------------------------------------------------- |
| Destination IP       | 10.0.15.31                                                        |
| Hostname             | WinQAFileServer3                                                  |
| Operating System     | Windows Server 2019                                               |
| Platform             | Windows                                                           |
| Asset Role           | File Server                                                       |
| Asset Type           | VM                                                                |
| Business Criticality | Not Provided                                                      |
| Exposure Concern     | External inbound Telnet traffic was allowed before IPS inspection |

## Evidence Reviewed

| Evidence Source          | Observation                                      |
| ------------------------ | ------------------------------------------------ |
| IPS Alert                | Telnet brute-force activity detected             |
| Firewall Logs            | Same inbound Telnet traffic shown as **allowed** |
| IPS Logs                 | Telnet brute-force activity shown as **blocked** |
| Event Window             | Repeated events observed between **20:20–20:23** |
| Successful Telnet Login  | Not Observed                                     |
| Host Compromise Evidence | Not Observed                                     |
| Endpoint/EDR Evidence    | Not Provided                                     |
| Service Impact           | Not Provided                                     |

## SIEM / Splunk Analysis

```spl id="u7k29m"
index=main "138.84.41.252" "10.0.15.31"
| stats count by _time, sourcetype, Action, srcIP, dstIP, dstPort, Threat_Name, Severity
| sort - count
```

| Log Source    | Action  | Threat_Name                      | Count |
| ------------- | ------- | -------------------------------- | ----: |
| IPS_logs      | blocked | TELNET Brute Force Login Attempt |     6 |
| firewall_logs | allowed | NA                               |     5 |

**Analysis Note:** Firewall policy allowed the Telnet flow, but IPS inspection blocked the suspicious brute-force behavior. No successful authentication is confirmed from the provided logs.

## MITRE ATT&CK Mapping

| Tactic            | Technique                | ID        | Reason                                                              |
| ----------------- | ------------------------ | --------- | ------------------------------------------------------------------- |
| Credential Access | Brute Force              | T1110     | IPS detected Telnet brute-force login attempts                      |
| Credential Access | Password Guessing        | T1110.001 | Login guessing behavior was observed; success not confirmed         |
| Initial Access    | External Remote Services | T1133     | External source attempted access to a remote administration service |

## Analyst Assessment

**Assessment:** **True Positive — Prevented Telnet Brute-Force Attempt**

The alert is valid because IPS detected and blocked repeated Telnet brute-force activity from a high-risk external source. The destination is a Windows file server, and Telnet is an insecure remote access protocol.

This is **not a confirmed compromise**. No successful Telnet authentication, host compromise, or service impact was observed.

## Impact Analysis

| Area            | Assessment                                                                   |
| --------------- | ---------------------------------------------------------------------------- |
| Confidentiality | No unauthorized access observed                                              |
| Integrity       | No system modification confirmed                                             |
| Availability    | No service disruption reported                                               |
| Business Impact | No confirmed impact; elevated concern due to file server and Telnet exposure |
| Current Risk    | Reduced by IPS block, but firewall rule update is required                   |

## Recommended Actions

1. Block **138.84.41.252 → 10.0.15.31:23/TCP** at the firewall.
2. Add **138.84.41.252** to a watchlist/blocklist as per policy.
3. Review and restrict any firewall rule allowing inbound Telnet to **10.0.15.31**.
4. Disable Telnet on **WinQAFileServer3** if not required.
5. Replace Telnet with secure administration through VPN, jump server, bastion host, or SSH where applicable.
6. Keep IPS prevention enabled for Telnet brute-force detection.
7. Escalate only if successful Telnet login, endpoint alert, repeated attempts after blocking, or service impact is observed.

## Escalation Decision

**Decision:** **No SOC L2 escalation required; close after firewall rule update.**

**Reason:** IPS blocked the Telnet brute-force activity, and no successful authentication, host compromise, malware activity, or service impact was confirmed from the reviewed evidence. Firewall rule review is required because the firewall initially allowed inbound Telnet traffic.

## Final Ticket Closure Comment

SOC investigated ticket **CS-018— IPS: TELNET Brute Force Login Attempt**. Inbound Telnet traffic from **138.84.41.252** to **10.0.15.31 / WinQAFileServer3** on **23/TCP** was allowed by firewall policy but blocked by IPS as Telnet brute-force activity. Splunk confirmed repeated IPS-blocked events between **20:20 and 20:23**. The source IP has **100% abuse confidence** and is associated with Starlink Colombia infrastructure. No successful Telnet login, host compromise, malware activity, or service impact was observed. Ticket closed as **True Positive — Prevented by IPS**, with firewall rule update and source IP block recommended.

## Skills Demonstrated

Firewall and IPS correlation, Telnet brute-force investigation, remote access exposure review, source reputation analysis, Windows file server risk assessment, MITRE ATT&CK mapping, impact analysis, escalation decision-making, and SOC ticket documentation.

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
