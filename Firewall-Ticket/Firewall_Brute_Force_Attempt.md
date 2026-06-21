# SOC Analyst Investigation Report

## Ticket Overview

| Field            | Details                                                        |
| ---------------- | -------------------------------------------------------------- |
| Ticket ID        | CS-05                                                          |
| Alert Name       | Firewall: Brute Force Attempt                                  |
| Ticket Status    | Closed                                                         |
| Priority / SLA   | Normal / High                                                  |
| Created Date     | 3/2/25 7:44 PM                                                 |
| Closed By        | sushanth P                                                     |
| Close Date       | 6/20/26 9:07 AM                                                |
| Analyst Decision | **Needs Escalation — Allowed Inbound SMB Brute Force Attempt** |

## Executive Summary

A firewall alert was triggered for a **Brute Force Attempt** involving inbound traffic from external source IP **103.221.232.118** to internal destination IP **10.0.2.45** on destination port **445/SMB**.

The firewall alert showed **Low** severity, but the action was **allowed**, which increases risk because the traffic may have reached the internal file server. Splunk review confirmed **22 allowed inbound events** from the same source IP to the same destination and port.

No Windows authentication logs, endpoint telemetry, SMB session logs, or file access evidence were provided. Therefore, compromise is **not confirmed**, but further validation is required.

## Alert Details

| Field            | Value                                                                                                                    |
| ---------------- | ------------------------------------------------------------------------------------------------------------------------ |
| Receive Time     | 2/11/2025 19:10                                                                                                          |
| Source IP        | 103.221.232.118                                                                                                          |
| Source Port      | 56232                                                                                                                    |
| Destination IP   | 10.0.2.45                                                                                                                |
| Destination Port | 445                                                                                                                      |
| Service          | SMB / Windows File Sharing                                                                                               |
| Direction        | Inbound                                                                                                                  |
| Threat Name      | Brute Force Attempt                                                                                                      |
| Severity         | Low                                                                                                                      |
| Firewall Action  | Allowed                                                                                                                  |
| Source Details   | HostRoyale Technologies India Network; Data Center/Web Hosting/Transit; AS203020; hostroyale.com; London, United Kingdom |

## Affected Assets

| Asset Field          | Details                                                 |
| -------------------- | ------------------------------------------------------- |
| Destination IP       | 10.0.2.45                                               |
| Hostname             | WinITFileServer1                                        |
| Operating System     | Windows Server 2019                                     |
| Asset Role           | File Server                                             |
| Business Criticality | Not Provided                                            |
| Exposure Concern     | External inbound access to SMB port **445** was allowed |

## Evidence Reviewed

| Evidence Source           | Observation                                                   |
| ------------------------- | ------------------------------------------------------------- |
| Ticket Screenshot         | Firewall alert for **Brute Force Attempt**                    |
| Firewall Event            | Inbound traffic from **103.221.232.118** to **10.0.2.45:445** |
| Firewall Action           | **Allowed**                                                   |
| Splunk Result             | **22 allowed inbound events**                                 |
| Windows Security Logs     | Not Provided                                                  |
| SMB/File Access Logs      | Not Provided                                                  |
| EDR Evidence              | Not Provided                                                  |
| Successful Login Evidence | Not Observed                                                  |
| Host Compromise Evidence  | Not Observed                                                  |

## SIEM / Splunk Analysis

```spl id="8kqp9z"
index=main sourcetype="firewall_logs" srcIP="103.221.232.118" dstIP="10.0.2.45" dstPort=445
| stats count by srcIP, dstIP, srcPort, dstPort, Threat_Name, Severity, Action, Direction
| sort - count
```

| srcIP           | dstIP     | srcPort | dstPort | Threat_Name | Severity | Action  | Direction | Count |
| --------------- | --------- | ------: | ------: | ----------- | -------- | ------- | --------- | ----: |
| 103.221.232.118 | 10.0.2.45 |   56232 |     445 | NA          | NA       | allowed | Inbound   |    22 |

**Analysis Note:** The ticket alert shows **Threat Name = Brute Force Attempt** and **Severity = Low**, while the Splunk aggregation shows **Threat_Name = NA** and **Severity = NA**. This may indicate field-normalization differences or incomplete logging in the aggregated events.

## MITRE ATT&CK Mapping

| Tactic            | Technique         | ID        | Reason                                                                                                 |
| ----------------- | ----------------- | --------- | ------------------------------------------------------------------------------------------------------ |
| Credential Access | Brute Force       | T1110     | Firewall alert classified the activity as a brute force attempt                                        |
| Credential Access | Password Guessing | T1110.001 | Inbound SMB access may indicate attempted credential guessing; authentication success is not confirmed |

## Analyst Assessment

**Assessment:** **Needs Escalation — Allowed Inbound SMB Activity**

The alert requires escalation because the traffic was **allowed**, targeted **SMB/445**, and involved an internal Windows file server. Firewall logs alone cannot confirm whether authentication attempts failed, succeeded, or resulted in file access.

This is **not confirmed compromise** based on the provided evidence, but it should not be closed as harmless without endpoint and authentication log validation.

## Impact Analysis

| Area            | Assessment                                                              |
| --------------- | ----------------------------------------------------------------------- |
| Confidentiality | Potential risk if SMB authentication succeeded; no data access observed |
| Integrity       | No file modification evidence provided                                  |
| Availability    | No service disruption provided                                          |
| Business Impact | Potentially high due to file server targeting                           |
| Current Risk    | Elevated because inbound SMB traffic was allowed                        |

## Recommended Actions

1. Escalate to SOC L2 for host and authentication log review.
2. Review Windows Security logs on **10.0.2.45** around **2/11/2025 19:10**.
3. Check Event IDs **4625**, **4624**, **4776**, and **4740** for failed logons, successful logons, NTLM authentication, and account lockouts.
4. Validate whether **103.221.232.118** is an approved vendor, scanner, or business source.
5. Review SMB/file-share access logs for suspicious access to shares, admin shares, or sensitive directories.
6. If inbound SMB from the internet is not required, block external access to port **445** at the perimeter.
7. If successful unauthorized access is confirmed, initiate containment, credential reset, and incident response actions.

## Escalation Decision

**Decision:** **Escalate to SOC L2.**

**Reason:** The activity was allowed through the firewall and targeted SMB on a Windows file server. No endpoint or authentication evidence was provided to confirm whether the activity resulted in failed authentication, successful login, or unauthorized file access.

## Final Ticket Closure Comment

SOC investigated ticket **CS-05— Firewall: Brute Force Attempt**. Inbound traffic from external source IP **103.221.232.118** to internal file server **10.0.2.45 / WinITFileServer1** on destination port **445/SMB** was observed. Splunk confirmed **22 allowed inbound events**. No Windows Security logs, SMB access logs, EDR telemetry, successful login evidence, or compromise evidence were provided. Due to allowed SMB traffic from an external source, escalation to SOC L2 is recommended for authentication and endpoint-level validation.

## Skills Demonstrated

Firewall alert triage, Splunk log analysis, SMB brute-force investigation, evidence gap identification, MITRE ATT&CK mapping, impact assessment, escalation decision-making, and SOC ticket documentation.


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
