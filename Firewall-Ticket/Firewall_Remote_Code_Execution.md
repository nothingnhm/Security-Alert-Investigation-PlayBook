# SOC Analyst Investigation Report

## Ticket Overview

| Field            | Details                                   |
| ---------------- | ----------------------------------------- |
| Ticket ID        | CS-08                                     |
| Alert Name       | Firewall: Remote Code Execution           |  
| Ticket Status    | Closed                                    |
| Priority / SLA   | Normal / Medium                           |
| Created Date     | 3/2/25 7:44 PM                            |
| Closed By        | Ananda Das                                |
| Analyst Decision | **True Positive — Prevented RCE Attempt** |

## Executive Summary

A firewall alert was triggered for **Remote Code Execution** involving inbound traffic from external source IP **14.103.115.234** to internal destination IP **10.0.2.45** on destination port **3389/RDP**.

The destination host is identified as **WinITFileServer1**, a **Windows Server 2019 File Server**. The firewall action was **reset-both**, indicating the session was terminated. Splunk review confirmed **1 RCE event** for the primary alert. No allowed connection, successful RDP session, code execution, compromise, or service impact was confirmed from the provided evidence.

## Alert Details

| Field            | Value                                                                                 |
| ---------------- | ------------------------------------------------------------------------------------- |
| Receive Time     | 2/1/2025 13:22                                                                        |
| Source IP        | 14.103.115.234                                                                        |
| Source Port      | 40653                                                                                 |
| Destination IP   | 10.0.2.45                                                                             |
| Destination Port | 3389                                                                                  |
| Service          | RDP                                                                                   |
| Threat Name      | Remote Code Execution                                                                 |
| Severity         | Medium in ticket / Critical in Splunk result                                          |
| Firewall Action  | reset-both                                                                            |
| Direction        | Inbound                                                                               |
| Source Details   | Beijing Volcano Engine Technology Co., Ltd.; AS137718; bytedance.com; Shanghai, China |
| Abuse Confidence | 100%                                                                                  |

## Affected Assets

| Asset Field          | Details                                         |
| -------------------- | ----------------------------------------------- |
| Destination IP       | 10.0.2.45                                       |
| Hostname             | WinITFileServer1                                |
| Operating System     | Windows Server 2019                             |
| Asset Role           | File Server                                     |
| Business Criticality | Not Provided                                    |
| Exposure Concern     | RDP/3389 targeted by external RCE-style traffic |

## Evidence Reviewed

| Evidence Source          | Observation                                                                                   |
| ------------------------ | --------------------------------------------------------------------------------------------- |
| Ticket Screenshot        | Firewall alert for **Remote Code Execution**                                                  |
| Firewall Event           | Inbound traffic from **14.103.115.234** to **10.0.2.45:3389**                                 |
| Firewall Action          | **reset-both**                                                                                |
| Splunk Result            | **1 RCE event** for primary destination                                                       |
| Related Source Activity  | Same source later observed in **Malware Command & Control** alert against **10.0.14.29:8080** |
| Allowed Traffic          | Not Observed                                                                                  |
| Successful RDP Login     | Not Observed                                                                                  |
| Endpoint/EDR Evidence    | Not Provided                                                                                  |
| Host Compromise Evidence | Not Observed                                                                                  |
| Service Impact           | Not Provided                                                                                  |

## SIEM / Splunk Analysis

```spl
index=main sourcetype="firewall_logs" srcIP="14.103.115.234" dstIP="10.0.2.45" dstPort=3389
| stats count by ReceiveTime, srcIP, dstIP, srcPort, dstPort, Severity, Action, Direction, Threat_Name
| sort - count
```

| ReceiveTime    | srcIP          | dstIP     | srcPort | dstPort | Severity | Action     | Direction | Threat_Name           | Count |
| -------------- | -------------- | --------- | ------: | ------: | -------- | ---------- | --------- | --------------------- | ----: |
| 2/1/2025 13:22 | 14.103.115.234 | 10.0.2.45 |   40653 |    3389 | critical | reset-both | Inbound   | Remote Code Execution |     1 |

```spl
index=main sourcetype="firewall_logs" srcIP="14.103.115.234"
| stats count by ReceiveTime, srcIP, dstIP, srcPort, dstPort, Severity, Action, Direction, Threat_Name
| sort - count
```

| ReceiveTime     | Destination | Port | Threat_Name               | Action     | Count |
| --------------- | ----------- | ---: | ------------------------- | ---------- | ----: |
| 2/1/2025 13:22  | 10.0.2.45   | 3389 | Remote Code Execution     | reset-both |     1 |
| 2/11/2025 06:13 | 10.0.14.29  | 8080 | Malware Command & Control | blocked    |     1 |

## MITRE ATT&CK Mapping

| Tactic              | Technique                         | ID    | Reason                                                                      |
| ------------------- | --------------------------------- | ----- | --------------------------------------------------------------------------- |
| Initial Access      | Exploit Public-Facing Application | T1190 | Firewall detected exploit-like RCE traffic toward an exposed remote service |
| Lateral Movement    | Exploitation of Remote Services   | T1210 | RCE attempt targeted RDP/3389 on a Windows server                           |
| Command and Control | Application Layer Protocol        | T1071 | Same source IP was later associated with a Malware C2 firewall alert        |

## Analyst Assessment

**Assessment:** **True Positive — Prevented RCE Attempt**

The alert is valid because the firewall detected exploit-like inbound traffic targeting **RDP/3389** on a Windows file server. The source IP has **100% abuse confidence**, and the same source later appeared in a separate **Malware Command & Control** alert.

No successful exploitation is confirmed because the firewall action was **reset-both**, and no endpoint or authentication evidence showed compromise.

## Impact Analysis

| Area            | Assessment                                                                 |
| --------------- | -------------------------------------------------------------------------- |
| Confidentiality | No unauthorized access observed                                            |
| Integrity       | No code execution or modification confirmed                                |
| Availability    | No service disruption reported                                             |
| Business Impact | No confirmed impact; elevated concern due to file server and RDP targeting |
| Current Risk    | Reduced because the firewall terminated the session                        |

## Recommended Actions

1. Continue monitoring source IP **14.103.115.234** for repeated activity.
2. Review firewall logs for any allowed traffic from this source.
3. Validate whether RDP/3389 should be externally reachable.
4. Review Windows logs on **10.0.2.45** around **2/1/2025 13:22** for Event IDs **4624**, **4625**, **4776**, and RDP event **1149** if available.
5. Review EDR telemetry for suspicious process execution, exploit indicators, or new services.
6. Add the source IP to a watchlist/blocklist if activity continues, following organizational policy.
7. Escalate if allowed traffic, successful authentication, endpoint alerts, or repeated RCE attempts are observed.

## Escalation Decision

**Decision:** **No immediate escalation required; close as True Positive — Prevented.**

**Reason:** The firewall terminated the suspicious RCE session using **reset-both**, and no allowed connection, successful RDP login, compromise, or service impact was observed from the provided evidence.

## Final Ticket Closure Comment

SOC investigated ticket **CS-08 — Firewall: Remote Code Execution**. Inbound traffic from external source IP **14.103.115.234** to **10.0.2.45 / WinITFileServer1** on **3389/RDP** was detected as Remote Code Execution. Splunk confirmed **1 event** with action **reset-both**. The same source IP was later associated with a blocked Malware Command & Control alert against another internal host. No allowed connection, successful RDP session, endpoint compromise, or service impact was observed. Ticket closed as **True Positive — Prevented**, with continued monitoring recommended.

## Skills Demonstrated

Firewall alert triage, RCE investigation, RDP exposure analysis, Splunk log validation, related-source correlation, MITRE ATT&CK mapping, impact assessment, escalation decision-making, and SOC ticket documentation.

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
