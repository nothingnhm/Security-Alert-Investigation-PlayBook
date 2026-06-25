# SOC Analyst Investigation Report

## Ticket Overview

| Field              | Details                                   |
| ------------------ | ----------------------------------------- |
| Ticket ID          | CS-0291                                   |
| Alert Name         | IPS: SSH Connection from Unusual Location | 
| Ticket Status      | Not Provided                              |
| Priority / SLA     | Not Provided                              |
| Analyst Decision   | **True Positive — Prevented by IPS**      |
| Required Follow-up | Firewall rule update / source IP block    |

## Executive Summary

An IPS alert was triggered for **SSH Connection from Unusual Location** involving inbound traffic from external source IP **210.209.137.144** to internal destination **10.0.11.11 / LinFDWebServer07** on **22/TCP**.

Firewall logs show the SSH connection attempt was **allowed**, but IPS logs detected suspicious SSH activity and **blocked** the request. The source IP has **100% abuse confidence** and is associated with **VEE TIME CORP.** in Taiwan.

No successful SSH login, command execution, compromise, or service impact was confirmed from the provided firewall/IPS evidence.

## Alert Details

| Field             | Value                                                                 |
| ----------------- | --------------------------------------------------------------------- |
| Receive Time      | 4/22/2025 19:31                                                       |
| Source IP         | 210.209.137.144                                                       |
| Destination IP    | 10.0.11.11                                                            |
| Destination Port  | 22                                                                    |
| Service           | SSH                                                                   |
| Protocol          | TCP                                                                   |
| Direction         | Inbound                                                               |
| Threat Name       | SSH Connection from Unusual Location                                  |
| Severity          | Critical in alert / High in IPS aggregation                           |
| Firewall Action   | Allowed                                                               |
| IPS Action        | Blocked                                                               |
| User              | admin                                                                 |
| IPS Sensor        | IPS_01                                                                |
| Source Reputation | 100% abuse confidence                                                 |
| Source Details    | VEE TIME CORP.; Fixed Line ISP; AS17809; vee.com.tw; Taichung, Taiwan |

## Affected Assets

| Asset Field          | Details                                                           |
| -------------------- | ----------------------------------------------------------------- |
| Destination IP       | 10.0.11.11                                                        |
| Hostname             | LinFDWebServer07                                                  |
| Operating System     | Linux - RHEL 8                                                    |
| Platform             | Linux                                                             |
| Asset Role           | Web Server                                                        |
| Hosting Location     | AWS Cloud                                                         |
| Business Criticality | Not Provided                                                      |
| Exposure Concern     | External SSH access was allowed by firewall before IPS inspection |

## Evidence Reviewed

| Evidence Source          | Observation                                                            |
| ------------------------ | ---------------------------------------------------------------------- |
| IPS Alert                | SSH unusual-location detection for **210.209.137.144 → 10.0.11.11:22** |
| Firewall Logs            | SSH traffic was **Allowed**                                            |
| IPS Logs                 | SSH unusual-location activity was **Blocked**                          |
| Source Reputation        | **100% abuse confidence**                                              |
| Additional Traffic       | **5 allowed inbound 443/TCP web traffic events** observed              |
| Successful SSH Login     | Not Observed                                                           |
| Command Execution        | Not Observed                                                           |
| Host Compromise Evidence | Not Observed                                                           |
| Service Impact           | Not Provided                                                           |

## SIEM / Splunk Analysis

```spl id="qfr82b"
index=main (sourcetype="firewall_logs" OR sourcetype="IPS_logs") srcIP="210.209.137.144" dstIP="10.0.11.11"
| stats count by sourcetype, srcIP, dstIP, dstPort, Threat_Name, Severity, Action, Protocol, Direction
| sort - count
```

| sourcetype    | srcIP           | dstIP      | dstPort | Threat_Name                          | Severity | Action  | Protocol | Direction | Count |
| ------------- | --------------- | ---------- | ------: | ------------------------------------ | -------- | ------- | -------- | --------- | ----: |
| IPS_logs      | 210.209.137.144 | 10.0.11.11 |     443 | Web Traffic                          | NA       | allowed | tcp      | Inbound   |     5 |
| firewall_logs | 210.209.137.144 | 10.0.11.11 |     443 | NA                                   | NA       | Allowed | tcp      | Inbound   |     5 |
| IPS_logs      | 210.209.137.144 | 10.0.11.11 |      22 | SSH Connection from Unusual Location | high     | blocked | tcp      | Inbound   |     1 |
| firewall_logs | 210.209.137.144 | 10.0.11.11 |      22 | NA                                   | NA       | Allowed | tcp      | Inbound   |     1 |

**Analysis Note:** The firewall allowed the SSH connection attempt, but IPS blocked the suspicious SSH activity during inspection. The 443/TCP web traffic was allowed and should be reviewed only if unexpected for this web server.

## MITRE ATT&CK Mapping

| Tactic            | Technique                | ID        | Reason                                                                 |
| ----------------- | ------------------------ | --------- | ---------------------------------------------------------------------- |
| Initial Access    | External Remote Services | T1133     | External source attempted SSH access to a cloud-hosted Linux server    |
| Lateral Movement  | Remote Services: SSH     | T1021.004 | SSH service was targeted; successful authentication not confirmed      |
| Credential Access | Valid Accounts           | T1078     | Alert referenced user **admin**; valid credential use is not confirmed |

## Analyst Assessment

**Assessment:** **True Positive — Prevented by IPS**

The alert is valid because IPS detected and blocked inbound SSH access from an unusual, high-abuse-confidence external source. Firewall policy allowed the flow, but IPS prevented the suspicious SSH request.

This is **not a confirmed compromise**. There is no evidence of successful SSH login, shell access, command execution, persistence, or impact from the provided logs.

## Impact Analysis

| Area            | Assessment                                                 |
| --------------- | ---------------------------------------------------------- |
| Confidentiality | No unauthorized access observed                            |
| Integrity       | No command execution or modification confirmed             |
| Availability    | No service disruption reported                             |
| Business Impact | No confirmed impact; elevated risk due to SSH exposure     |
| Current Risk    | Reduced by IPS block, but firewall rule update is required |

## Recommended Actions

1. Update firewall policy to block **210.209.137.144 → 10.0.11.11:22/TCP**.
2. Add **210.209.137.144** to a perimeter blocklist/watchlist as per policy.
3. Restrict SSH access to approved VPN, bastion host, jump server, or trusted admin IP ranges only.
4. Review Linux authentication logs on **LinFDWebServer07** for successful/failed SSH attempts.
5. Check `/var/log/secure` or equivalent RHEL authentication logs around **4/22/2025 19:31**.
6. Confirm whether the **admin** account is expected to be used for SSH login.
7. Review whether allowed **443/TCP** traffic from this source is expected.
8. Escalate only if successful SSH authentication, suspicious commands, endpoint alerts, or repeated attempts are observed.

## Escalation Decision

**Decision:** **No SOC L2 escalation required after IPS block validation; firewall rule update required.**

**Reason:** IPS blocked the unusual SSH connection attempt, and no successful SSH login, host compromise, command execution, or service impact was confirmed from the reviewed evidence. However, firewall rules should be updated because the firewall allowed inbound SSH before IPS inspection.

## Final Ticket Closure Comment

SOC investigated ticket **CS-0291 — IPS: SSH Connection from Unusual Location**. Inbound SSH traffic from external source IP **210.209.137.144** to **10.0.11.11 / LinFDWebServer07** on **22/TCP** was allowed by the firewall but blocked by **IPS_01** as **SSH Connection from Unusual Location**. The source IP has **100% abuse confidence** and is associated with VEE TIME CORP. in Taiwan. No successful SSH login, command execution, host compromise, or service impact was observed. Ticket can be closed as **True Positive — Prevented by IPS**, with firewall rule update and source IP block recommended.

## Skills Demonstrated

Firewall and IPS log correlation, SSH access investigation, unusual-location alert triage, Linux server risk assessment, source reputation review, MITRE ATT&CK mapping, impact analysis, escalation decision-making, and SOC ticket documentation.

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
