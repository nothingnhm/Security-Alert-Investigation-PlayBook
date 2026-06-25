# SOC Analyst Investigation Report

## Ticket Overview

| Field            | Details                                                                          |
| ---------------- | -------------------------------------------------------------------------------- |
| Ticket ID        | CS-014                                                                           |
| Alert Name       | IPS: RDP: Microsoft Windows Remote Desktop Protocol Server WebSocketServer Usage |
| Ticket Status    | Closed                                                                           |
| Priority / SLA   | Normal / Default SLA                                                             |
| Created Date     | 4/25/25 3:52 PM                                                                  |
| Closed By        | Ananda Das                                                                       |
| Analyst Decision | **True Positive — Prevented by IPS**                                             |

## Executive Summary

An IPS alert was triggered for **RDP: Microsoft Windows Remote Desktop Protocol Server WebSocketServer Usage** involving inbound RDP traffic from external source IP **45.91.171.220** to internal destination **10.0.14.29 / WinHRFileServer1** on **3389/TCP**.

Firewall logs showed the RDP traffic as **Allowed**, but IPS logs detected the suspicious RDP activity with **Critical** severity and **Blocked** it. Multiple related events were observed between **11:33 and 11:36** on **4/24/2025**.

No successful RDP login, malware execution, host compromise, or service impact was confirmed from the provided evidence.

## Alert Details

| Field                | Value                                                                                                         |
| -------------------- | ------------------------------------------------------------------------------------------------------------- |
| Receive Time         | 4/24/2025 11:33                                                                                               |
| Source IP            | 45.91.171.220                                                                                                 |
| Destination IP       | 10.0.14.29                                                                                                    |
| Destination Port     | 3389                                                                                                          |
| Service              | RDP                                                                                                           |
| Protocol             | TCP                                                                                                           |
| Direction            | Inbound                                                                                                       |
| Threat Name          | RDP: Microsoft Windows Remote Desktop Protocol Server WebSocketServer Usage                                   |
| IPS Severity         | Critical                                                                                                      |
| Recommended Severity | High                                                                                                          |
| Firewall Action      | Allowed                                                                                                       |
| IPS Action           | Blocked                                                                                                       |
| IPS Device           | IPS_01                                                                                                        |
| User                 | NA                                                                                                            |
| Source Reputation    | 100% abuse confidence                                                                                         |
| Source Details       | O.M.C. COMPUTERS & COMMUNICATIONS LTD; Data Center/Web Hosting/Transit; AS36007; omc.co.il; Stockholm, Sweden |

## Affected Assets

| Asset Field          | Details                                                        |
| -------------------- | -------------------------------------------------------------- |
| Destination IP       | 10.0.14.29                                                     |
| Hostname             | WinHRFileServer1                                               |
| Operating System     | Windows Server 2019                                            |
| Platform             | Windows                                                        |
| Asset Role           | File Server                                                    |
| Asset Type           | VM                                                             |
| Business Criticality | Not Provided                                                   |
| Exposure Concern     | External inbound RDP traffic was allowed before IPS inspection |

## Evidence Reviewed

| Evidence Source          | Observation                                                |
| ------------------------ | ---------------------------------------------------------- |
| IPS Logs                 | Critical RDP WebSocketServer activity detected and blocked |
| Firewall Logs            | Same inbound RDP traffic shown as **Allowed**              |
| Repeated Events          | Multiple events from **11:33–11:36**                       |
| Source Reputation        | **100% abuse confidence**                                  |
| Successful RDP Login     | Not Observed                                               |
| Endpoint/EDR Evidence    | Not Provided                                               |
| Host Compromise Evidence | Not Observed                                               |
| Service Impact           | Not Provided                                               |

## SIEM / Splunk Analysis

```spl id="r0a7zm"
index=main srcIP="45.91.171.220" dstIP="10.0.14.29"
| table _time sourcetype Action srcIP dstIP dstPort Threat_Name Severity
```

| Time Window            | Source IP     | Destination | Port | Firewall Result | IPS Result         | Event Pattern                   |
| ---------------------- | ------------- | ----------- | ---: | --------------- | ------------------ | ------------------------------- |
| 2025-04-24 11:33–11:36 | 45.91.171.220 | 10.0.14.29  | 3389 | Allowed         | Blocked / Critical | Repeated inbound RDP detections |

**Analysis Note:** Firewall policy allowed the RDP flow, but IPS inspection blocked the suspicious RDP request. This indicates the activity was prevented by the IPS layer, but the firewall rule allowing external RDP requires review.

## MITRE ATT&CK Mapping

| Tactic           | Technique                       | ID        | Reason                                                                                |
| ---------------- | ------------------------------- | --------- | ------------------------------------------------------------------------------------- |
| Initial Access   | External Remote Services        | T1133     | External source attempted inbound access to RDP                                       |
| Lateral Movement | Remote Services: RDP            | T1021.001 | RDP/3389 was targeted; successful login not confirmed                                 |
| Lateral Movement | Exploitation of Remote Services | T1210     | IPS detected suspicious RDP WebSocketServer usage; exploitation success not confirmed |

## Analyst Assessment

**Assessment:** **True Positive — Prevented by IPS**

The alert is valid because IPS detected and blocked suspicious inbound RDP activity from a high-risk external source. The destination is a Windows file server, and RDP is a sensitive remote administration service.

This is **not a confirmed compromise**. No successful RDP authentication, execution, persistence, or endpoint impact was observed from the provided logs.

## Impact Analysis

| Area            | Assessment                                                                |
| --------------- | ------------------------------------------------------------------------- |
| Confidentiality | No unauthorized access observed                                           |
| Integrity       | No malware execution or modification confirmed                            |
| Availability    | No service disruption reported                                            |
| Business Impact | No confirmed impact; elevated concern due to file server and RDP exposure |
| Current Risk    | Reduced by IPS block, but firewall rule update is required                |

## Recommended Actions

1. Block **45.91.171.220 → 10.0.14.29:3389/TCP** at the firewall.
2. Add **45.91.171.220** to a watchlist/blocklist as per policy.
3. Review and restrict any firewall rule allowing inbound RDP to **10.0.14.29**.
4. Allow RDP only through approved VPN, bastion host, jump server, or trusted admin IP ranges.
5. Review Windows logs for Event IDs **4624**, **4625**, **4776**, and RDP event **1149** if available.
6. Keep IPS/threat prevention enabled for RDP traffic.
7. Escalate only if successful RDP login, endpoint alert, repeated attempts after blocking, or service impact is observed.

## Escalation Decision

**Decision:** **No SOC L2 escalation required; close after firewall rule update.**

**Reason:** IPS blocked the suspicious RDP activity, and no successful login, compromise, malware execution, or service impact was confirmed. Firewall rule review is required because the firewall initially allowed the inbound RDP traffic.

## Final Ticket Closure Comment

SOC investigated ticket **CS-014 — IPS: RDP WebSocketServer Usage**. Inbound RDP traffic from **45.91.171.220** to **10.0.14.29 / WinHRFileServer1** on **3389/TCP** was allowed by firewall policy but blocked by IPS with Critical severity. Multiple related events were observed between **11:33 and 11:36**. The source IP has **100% abuse confidence** and is associated with data center/web-hosting infrastructure. No successful RDP login, host compromise, malware execution, or service impact was observed. Ticket closed as **True Positive — Prevented by IPS**, with firewall rule update and source IP block recommended.

## Skills Demonstrated

Firewall and IPS correlation, RDP attack investigation, exploit-signature triage, source reputation review, Windows server risk assessment, MITRE ATT&CK mapping, impact analysis, escalation decision-making, and SOC ticket documentation.

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
