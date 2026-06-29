# SOC Analyst Investigation Report

## Ticket Overview

| Field             | Details                                                                    |
| ----------------- | -------------------------------------------------------------------------- |
| Ticket ID         | CS-060                                                                    |
| Alert Name        | System Fault – Device Not Sending Logs to Splunk                           |
| Incident Category | System Fault / Log Forwarding Interruption                                 |
| Ticket Status     | Closed                                                                     |
| Priority / SLA    | Normal / Default SLA                                                       |
| Department        | Support                                                                    |
| Created Date      | 9/15/25 7:32 PM                                                            |
| Closed By         | Ananda Das                                                                 |
| Detection Source  | Automated Monitoring / Splunk                                              |
| Analyst Decision  | **True Positive — Proxy Log Forwarding Interruption Confirmed / Resolved** |

## Executive Summary

A system fault alert was triggered because the proxy security device **ZsProxy01** stopped forwarding logs to Splunk for more than **60 minutes**.

ZsProxy01 is a high-severity proxy security device used for web activity monitoring, threat detection, user browsing visibility, policy enforcement, and compliance logging. Missing proxy logs can reduce SOC visibility into phishing clicks, malware downloads, suspicious outbound connections, web policy violations, and user browsing activity.

SOC validated the alert in Splunk and confirmed that no new logs were received from **ZsProxy01** after the reported last log time:

`22-Sep-2025 20:35`

SOC also validated Splunk ingestion health and confirmed that Splunk infrastructure was operational. Other proxy and security devices continued forwarding logs successfully, confirming that the issue was isolated to **ZsProxy01**.

The case was escalated to the **Security Engineering Team** for device-side validation. Security Engineering restarted the proxy log forwarding service, verified the forwarding configuration, and confirmed connectivity to the Splunk receiver. SOC then revalidated ingestion and confirmed that logs resumed successfully.

Final assessment: **Resolved system fault caused by temporary proxy log forwarding service interruption on ZsProxy01. No malicious activity, Splunk infrastructure failure, or network-wide outage was identified.**

## Alert Details

| Field             | Value                                                       |
| ----------------- | ----------------------------------------------------------- |
| Device Name       | ZsProxy01                                                   |
| Host IP           | 10.0.2.14                                                   |
| Device Type       | Security Device                                             |
| Server Function   | Proxy                                                       |
| Splunk Index      | main                                                        |
| Asset Severity    | High                                                        |
| Custodian         | Security Engineering                                        |
| Last Log Time     | 22-Sep-2025 20:35                                           |
| Alert Condition   | Device did not send logs to Splunk for more than 60 minutes |
| Impacted Platform | Splunk                                                      |
| Initial Status    | No new logs observed                                        |
| Final Status      | Log forwarding restored                                     |

## Data Quality Note

The ticket create date is listed as **9/15/25 7:32 PM**, while the reported **LastLogTime** is **22-Sep-2025 20:35**. This timestamp order appears inconsistent and should be validated against the ticketing platform, timezone configuration, or alert generation source.

The investigation still treats the alert as valid because the alert condition stated that **ZsProxy01 did not send logs to Splunk for more than 60 minutes**, and SOC validation confirmed missing logs for the device.

## Affected Asset

| Parameter         | Details                                        |
| ----------------- | ---------------------------------------------- |
| Asset Name        | ZsProxy01                                      |
| IP Address        | 10.0.2.14                                      |
| Asset Type        | Security Device                                |
| Device Role       | Proxy                                          |
| Splunk Index      | main                                           |
| Asset Severity    | High                                           |
| Custodian / Owner | Security Engineering Team                      |
| Affected Function | Proxy log forwarding to Splunk                 |
| Security Impact   | Temporary proxy visibility gap                 |
| Business Impact   | Reduced monitoring visibility for web activity |

## IOCs / Technical Indicators Identified

| Indicator Type      | Indicator / Value                             |
| ------------------- | --------------------------------------------- |
| Affected Device     | ZsProxy01                                     |
| Affected IP Address | 10.0.2.14                                     |
| Device Type         | Security Device                               |
| Device Function     | Proxy                                         |
| Splunk Index        | main                                          |
| Log Destination     | Splunk                                        |
| Log Source Type     | Proxy Logs / Security Device Logs             |
| Asset Severity      | High                                          |
| Responsible Team    | Security Engineering                          |
| Root Cause Type     | Temporary log forwarding service interruption |

**IOC Assessment:** This was a system fault incident, not a malicious IOC-based security incident. The indicators above represent the affected asset, logging path, and monitoring components.

## Evidence Reviewed

### Alert Evidence

| Field               | Observed Value                    |
| ------------------- | --------------------------------- |
| Alert Type          | System Fault                      |
| Alert Reason        | Device not sending logs to Splunk |
| Detection Threshold | More than 60 minutes without logs |
| Affected Device     | ZsProxy01                         |
| Last Log Time       | 22-Sep-2025 20:35                 |
| Asset Severity      | High                              |
| Custodian           | Security Engineering              |

### Initial Splunk Validation Query

```spl id="cs0407_initial_validation"
index=main host=ZsProxy01
```

### Initial SOC Findings

| Check                                 | Result                 |
| ------------------------------------- | ---------------------- |
| Recent logs from ZsProxy01            | Not observed initially |
| Last known log timestamp              | 22-Sep-2025 20:35      |
| Alert validity                        | Confirmed              |
| Delayed indexing evidence             | Not observed           |
| Other proxy/security device ingestion | Working                |
| Scope                                 | Isolated to ZsProxy01  |

## SIEM / Splunk Analysis

### Investigation Flow

#### 1. Alert Review

SOC reviewed the automated monitoring alert and confirmed that the alert condition was related to missing logs from **ZsProxy01** for more than 60 minutes.

Because the affected device is a proxy security device, the alert was treated as important from a security visibility perspective. Proxy logs are important for investigating user web traffic, phishing access, suspicious downloads, command-and-control attempts, and web policy violations.

#### 2. Asset Identification

| Field                 | Details                   |
| --------------------- | ------------------------- |
| Hostname              | ZsProxy01                 |
| IP Address            | 10.0.2.14                 |
| Device Classification | Security Device           |
| Device Role           | Proxy                     |
| Splunk Index          | main                      |
| Custodian             | Security Engineering Team |
| Asset Severity        | High                      |

#### 3. Splunk Evidence Validation

SOC searched Splunk for logs from ZsProxy01:

```spl id="cs0407_host_search"
index=main host=ZsProxy01
```

The search confirmed that no new logs were received after the last reported log timestamp. This validated the alert as a genuine log forwarding interruption.

#### 4. Splunk Infrastructure Review

SOC reviewed whether the issue was related to Splunk ingestion or platform health.

| Component / Check         | Result                 |
| ------------------------- | ---------------------- |
| Splunk indexers           | Operational            |
| Splunk ingestion services | Operational            |
| Splunk index `main`       | Available              |
| Port 9993                 | Open and listening     |
| Other proxy devices       | Logs received normally |
| Other security devices    | Logs received normally |
| Delayed indexing          | Not observed           |
| Splunk-wide issue         | Not identified         |

#### 5. Network and Scope Validation

SOC reviewed whether the issue was caused by a wider connectivity problem.

| Check                         | Result                    |
| ----------------------------- | ------------------------- |
| Network-wide outage           | Not reported              |
| Connectivity issue            | Not identified            |
| Other devices in same segment | Sending logs successfully |
| Splunk receiver reachability  | Available                 |
| Network-side issue            | Not identified            |
| Final scope                   | Isolated to ZsProxy01     |

The evidence showed that Splunk was healthy and other proxy/security devices were forwarding logs normally. Therefore, the issue was not caused by Splunk infrastructure or a network-wide outage.

## Device-Level Investigation

SOC escalated the case to the **Security Engineering Team** and requested device-side validation for ZsProxy01.

The Security Engineering Team was asked to validate:

1. Proxy log forwarding service status.
2. Syslog/log forwarding process status.
3. Universal Forwarder service status, if applicable.
4. Temporary CPU, memory, or disk resource exhaustion.
5. Connectivity from ZsProxy01 to the Splunk receiver.
6. Recent configuration changes.
7. Recent maintenance activity.
8. Log forwarding configuration integrity.
9. Whether service restart was required.

## Corrective Action

The Security Engineering Team completed device-side remediation and confirmed the following actions:

1. Restarted the proxy log forwarding service on ZsProxy01.
2. Validated that the log forwarding configuration was intact.
3. Confirmed connectivity to the Splunk receiver.
4. Requested SOC to revalidate log ingestion.

## Post-Remediation Verification

SOC rechecked Splunk after remediation using:

```spl id="cs0407_post_remediation"
index=main host=ZsProxy01
```

### Verification Outcome

| Check                         | Result    |
| ----------------------------- | --------- |
| Logs resumed                  | Confirmed |
| Continuous ingestion          | Confirmed |
| Proxy visibility restored     | Confirmed |
| Security Engineering informed | Yes       |
| Ticket closure approved       | Yes       |

## Timeline of Events

| Time / Phase          | Event                                                           |
| --------------------- | --------------------------------------------------------------- |
| 22-Sep-2025 20:35     | Last reported log timestamp for ZsProxy01                       |
| 15-Sep-2025 19:32     | Ticket created for missing logs from ZsProxy01                  |
| Initial SOC Review    | SOC searched Splunk for ZsProxy01 logs                          |
| Initial SOC Review    | No logs observed after the reported LastLogTime                 |
| Infrastructure Review | Splunk indexer and ingestion health validated                   |
| Infrastructure Review | Port 9993 confirmed open and listening                          |
| Scope Validation      | Other proxy/security devices confirmed forwarding logs normally |
| Escalation            | SOC escalated the issue to Security Engineering Team            |
| Remediation           | Security Engineering restarted proxy log forwarding service     |
| Post-Remediation      | SOC confirmed logs resumed in Splunk                            |
| Closure               | Ticket closed after successful validation                       |

## Root Cause Analysis

| Area                  | Finding                                                       |
| --------------------- | ------------------------------------------------------------- |
| Root Cause            | Temporary interruption of log forwarding service on ZsProxy01 |
| Affected Component    | Proxy log forwarding / syslog forwarding service              |
| Splunk Infrastructure | No issue identified                                           |
| Network-Wide Outage   | Not identified                                                |
| Device Scope          | Isolated to ZsProxy01                                         |
| Permanent Data Loss   | Not confirmed from provided evidence                          |
| Final RCA             | Device-side proxy log forwarding interruption                 |

## MITRE ATT&CK Mapping

| Tactic | Technique | ID  | Reason                                                                     |
| ------ | --------- | --- | -------------------------------------------------------------------------- |
| N/A    | N/A       | N/A | No malicious activity confirmed                                            |
| N/A    | N/A       | N/A | Incident was caused by system/log forwarding fault, not adversary behavior |

**MITRE Note:** No MITRE ATT&CK mapping is assigned because this was an operational logging fault, not an attack.

## Analyst Assessment

**Assessment:** **True Positive — Proxy Device Not Sending Logs to Splunk**

The alert was valid. ZsProxy01 stopped sending logs to Splunk for more than 60 minutes, and SOC confirmed the log gap through direct Splunk validation.

The issue was not related to Splunk infrastructure because Splunk services were operational and other proxy/security devices continued forwarding logs. The issue was isolated to ZsProxy01 and required Security Engineering remediation.

No evidence of malicious activity, proxy compromise, unauthorized configuration change, Splunk infrastructure failure, or network-wide outage was identified from the provided evidence.

## Impact Analysis

| Impact Area                 | Status                                                   |
| --------------------------- | -------------------------------------------------------- |
| Proxy Log Forwarding        | Interrupted                                              |
| Web Activity Monitoring     | Temporarily reduced                                      |
| Threat Detection            | Temporarily limited for proxy events                     |
| Phishing Click Visibility   | Reduced during outage window                             |
| Malware Download Visibility | Reduced during outage window                             |
| Compliance Visibility       | Reduced during outage window                             |
| Splunk Infrastructure       | No impact observed                                       |
| Other Security Devices      | No impact observed                                       |
| Network Availability        | No outage confirmed                                      |
| Data Integrity              | No permanent data loss confirmed                         |
| Business Impact             | Low                                                      |
| Security Impact             | Temporary monitoring gap for a high-severity proxy asset |

## Recommended Actions

1. Monitor ZsProxy01 log ingestion for the next 24–48 hours.
2. Add ZsProxy01 to a proxy log ingestion health dashboard.
3. Maintain a Splunk alert for high-severity security devices not sending logs for more than 60 minutes.
4. Consider reducing the missing-log alert threshold to 15–30 minutes for critical/high-severity security devices.
5. Review proxy log forwarding service stability and restart history.
6. Review CPU, memory, and disk utilization around the outage window.
7. Validate log forwarding configuration persistence after restart or maintenance.
8. Review recent proxy configuration changes or maintenance activity around the outage window.
9. Configure redundant log forwarding destination if supported.
10. Document proxy log forwarding restart and validation steps in the Security Engineering runbook.
11. Track repeated log gaps from ZsProxy01 as a reliability issue.

## Suggested Splunk Detection Query

```spl id="proxy_log_gap_detection"
index=main host=ZsProxy01
| stats latest(_time) as last_seen by host
| eval minutes_since_last_log=round((now()-last_seen)/60,2)
| where minutes_since_last_log > 60
| convert ctime(last_seen)
```

## Escalation Decision

**Decision:** **Escalated to Security Engineering Team and resolved. No SOC L2 security escalation required.**

**Reason:** SOC confirmed that Splunk infrastructure and network connectivity were healthy. Since the issue was isolated to the proxy device log forwarding service, Security Engineering was the correct resolver group.

No SOC L2 escalation was required after log ingestion was restored and no compromise indicators were observed.

Escalate further only if:

1. ZsProxy01 stops forwarding logs again.
2. Proxy log forwarding repeatedly fails.
3. Unauthorized proxy configuration changes are identified.
4. Proxy connectivity becomes unstable.
5. Evidence of tampering or compromise appears.
6. Logs do not resume after Security Engineering remediation.

## Final Ticket Closure Comment

SOC investigated ticket **CS-060 — System Fault: Device Not Sending Logs to Splunk** after automated monitoring detected that **ZsProxy01** had not sent logs to Splunk for more than 60 minutes. The affected device was identified as a high-severity proxy security device with IP **10.0.2.14**, using Splunk index `main`, and owned by the **Security Engineering Team**. SOC validated the alert using `index=main host=ZsProxy01` and confirmed no new logs after the reported last log timestamp **22-Sep-2025 20:35**. Splunk indexers, ingestion services, and port **9993** were verified as operational. Other proxy/security devices continued forwarding logs successfully, confirming that the issue was isolated to ZsProxy01. The case was escalated to Security Engineering for proxy-side logging/syslog validation. Security Engineering restarted the proxy log forwarding service and verified the forwarding configuration. SOC revalidated Splunk ingestion and confirmed that logs resumed successfully. Ticket closed as **Resolved — Temporary Proxy Log Forwarding Service Interruption**, with no evidence of Splunk infrastructure failure, network-wide outage, malicious activity, or confirmed permanent data loss.

## Skills Demonstrated

System fault triage, Splunk log validation, proxy log monitoring, security device log forwarding investigation, SIEM health validation, log gap analysis, infrastructure issue scoping, Security Engineering escalation, post-remediation verification, root cause analysis, impact assessment, evidence limitation handling, closure documentation, and SOC operational monitoring.

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
