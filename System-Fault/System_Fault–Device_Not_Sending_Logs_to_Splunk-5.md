# SOC Analyst Investigation Report

## Ticket Overview

| Field             | Details                                                                                  |
| ----------------- | ---------------------------------------------------------------------------------------- |
| Ticket ID         | CS-063                                                                                   |
| Alert Name        | System Fault – Device Not Sending Logs to Splunk                                         |
| Incident Category | System Fault / Log Forwarding Interruption                                               |
| Ticket Status     | Closed                                                                                   |
| Priority / SLA    | Normal / Default SLA                                                                     |
| Department        | Support                                                                                  |
| Created Date      | 9/15/25 7:31 PM                                                                          |
| Closed By         | Ananda Das                                                                               |
| Detection Source  | Automated Monitoring / Splunk                                                            |
| Analyst Decision  | **True Positive — Linux Backup Server Log Forwarding Interruption Confirmed / Resolved** |

## Executive Summary

A system fault alert was triggered because the Linux backup server **LinFDBK02** stopped sending logs to Splunk for more than **60 minutes**.

The affected device is a medium-severity Linux Server with IP address:

`10.0.11.13`

LinFDBK02 functions as a **Backup Server**, so its logs are important for monitoring backup activity, system health, access events, service failures, operational errors, and possible security-related activity.

SOC validated the alert in Splunk and confirmed that logs were not being received from **LinFDBK02** within the expected time window after the reported last log time:

`9/16/2025 11:23`

SOC also validated Splunk infrastructure health, listener port availability, and ingestion status. Other devices continued forwarding logs successfully, confirming that the issue was isolated to **LinFDBK02**.

The case was escalated to the **Linux Team** for endpoint-level validation. The Linux Team restarted the **Splunk Universal Forwarder** service on the affected server. SOC then revalidated Splunk ingestion and confirmed that logs resumed successfully.

Final assessment: **Resolved system fault caused by Splunk Universal Forwarder service failure or unexpected stop on LinFDBK02. No malicious activity, Splunk infrastructure issue, or network-wide outage was identified.**

## Alert Details

| Field             | Value                                                       |
| ----------------- | ----------------------------------------------------------- |
| Device Name       | LinFDBK02                                                   |
| Host IP           | 10.0.11.13                                                  |
| Device Type       | Linux Server                                                |
| Server Function   | Backup Server                                               |
| Splunk Index      | main                                                        |
| Asset Severity    | Medium                                                      |
| Custodian         | Linux Team                                                  |
| Last Log Time     | 9/16/2025 11:23                                             |
| Alert Condition   | Device did not send logs to Splunk for more than 60 minutes |
| Impacted Platform | Splunk                                                      |
| Initial Status    | No new logs observed                                        |
| Final Status      | Log forwarding restored                                     |

## Data Quality Note

The ticket create date is listed as **9/15/25 7:31 PM**, while the reported **LastLogTime** is **9/16/2025 11:23**. This timestamp order appears inconsistent and should be validated against the ticketing platform, timezone settings, or alert generation source.

The investigation still treats the alert as valid because the alert condition stated that **LinFDBK02 did not send logs to Splunk for more than 60 minutes**, and SOC validation confirmed missing logs for the device.

## Affected Asset

| Parameter                | Details                                      |
| ------------------------ | -------------------------------------------- |
| Asset Name               | LinFDBK02                                    |
| IP Address               | 10.0.11.13                                   |
| Asset Type               | Linux Server                                 |
| Server Role              | Backup Server                                |
| Splunk Index             | main                                         |
| Asset Severity           | Medium                                       |
| Custodian / Owner        | Linux Team                                   |
| Log Forwarding Component | Splunk Universal Forwarder                   |
| Affected Function        | Linux backup server log forwarding to Splunk |
| Monitoring Impact        | Temporary backup server visibility gap       |
| Business Impact          | Reduced visibility into backup server events |

## IOCs / Technical Indicators Identified

| Indicator Type           | Indicator / Value                                       |
| ------------------------ | ------------------------------------------------------- |
| Affected Host            | LinFDBK02                                               |
| Affected IP Address      | 10.0.11.13                                              |
| Device Type              | Linux Server                                            |
| Server Role              | Backup Server                                           |
| Splunk Index             | main                                                    |
| Log Destination          | Splunk                                                  |
| Log Forwarding Component | Splunk Universal Forwarder                              |
| Log Source Type          | Linux System Logs / Backup Server Logs                  |
| Asset Severity           | Medium                                                  |
| Responsible Team         | Linux Team                                              |
| Root Cause Type          | Splunk Universal Forwarder service stopped unexpectedly |

**IOC Assessment:** This was a system fault incident, not a malicious IOC-based security incident. The indicators above represent the affected asset, forwarding component, and monitoring path.

## Evidence Reviewed

### Alert Evidence

| Field               | Observed Value                    |
| ------------------- | --------------------------------- |
| Alert Type          | System Fault                      |
| Alert Reason        | Device not sending logs to Splunk |
| Detection Threshold | More than 60 minutes without logs |
| Affected Device     | LinFDBK02                         |
| Last Log Time       | 9/16/2025 11:23                   |
| Asset Severity      | Medium                            |
| Custodian           | Linux Team                        |

### Initial Splunk Validation Query

```spl id="cs0404_initial_validation"
index=main hostname=LinFDBK02
```

### Initial SOC Findings

| Check                      | Result                 |
| -------------------------- | ---------------------- |
| Recent logs from LinFDBK02 | Not observed initially |
| Last known log timestamp   | 9/16/2025 11:23        |
| Alert validity             | Confirmed              |
| Delayed ingestion evidence | Not observed           |
| Other device ingestion     | Working                |
| Scope                      | Isolated to LinFDBK02  |

## SIEM / Splunk Analysis

### Investigation Flow

#### 1. Alert Review

SOC reviewed the automated monitoring alert and confirmed that the alert condition was related to missing logs from **LinFDBK02** for more than 60 minutes.

Because the affected system is a backup server, the alert was important from both operational and security monitoring perspectives. Backup server logs can help identify backup job failures, unauthorized access attempts, system errors, service failures, permission changes, and possible suspicious activity.

#### 2. Asset Identification

| Field                 | Details                    |
| --------------------- | -------------------------- |
| Hostname              | LinFDBK02                  |
| IP Address            | 10.0.11.13                 |
| Device Classification | Linux Server               |
| Server Role           | Backup Server              |
| Splunk Index          | main                       |
| Log Forwarding Method | Splunk Universal Forwarder |
| Custodian             | Linux Team                 |
| Asset Severity        | Medium                     |

#### 3. Splunk Evidence Validation

SOC searched Splunk for logs from LinFDBK02:

```spl id="cs0404_host_search"
index=main hostname=LinFDBK02
```

The search confirmed that no new logs were received within the expected time window after the reported LastLogTime. This validated the alert as a genuine log forwarding interruption.

#### 4. Splunk Infrastructure Review

SOC reviewed whether the issue was caused by Splunk server or ingestion issues.

| Component / Check           | Result                |
| --------------------------- | --------------------- |
| Splunk server health        | Verified              |
| Splunk ingestion services   | Operational           |
| Listener port 9993          | Up and reachable      |
| Ingestion errors            | Not observed          |
| Queue issues                | Not observed          |
| Other devices               | Actively sending logs |
| Splunk infrastructure issue | Not identified        |

#### 5. Network and Scope Validation

SOC reviewed whether the issue was caused by a wider connectivity problem.

| Check                           | Result                |
| ------------------------------- | --------------------- |
| Network outage                  | Not reported          |
| Connectivity to Splunk receiver | Available             |
| Other hosts sending logs        | Confirmed             |
| Network-wide issue              | Not identified        |
| Endpoint-specific issue         | Confirmed             |
| Final scope                     | Isolated to LinFDBK02 |

The evidence showed that Splunk was healthy and other devices were forwarding logs normally. Therefore, the issue was not caused by Splunk infrastructure or a network-wide outage.

## Endpoint-Level Investigation

SOC escalated the case to the **Linux Team** and requested endpoint-level validation for LinFDBK02.

The Linux Team was asked to validate:

1. Splunk Universal Forwarder service status.
2. Recent maintenance activity.
3. Possible Universal Forwarder service crash.
4. Server CPU, memory, and disk resource status.
5. Disk space or service failure indicators.
6. Connectivity from LinFDBK02 to the Splunk receiver.
7. Whether the Universal Forwarder service required restart.
8. Recent patching or reboot activity.

## Corrective Action

The Linux Team completed endpoint-side remediation and confirmed the following actions:

1. Restarted the Splunk Universal Forwarder service on LinFDBK02.
2. Confirmed no Splunk infrastructure issue was involved.
3. Requested SOC to verify log ingestion after the restart.

## Post-Remediation Verification

SOC rechecked Splunk after remediation using:

```spl id="cs0404_post_remediation"
index=main hostname=LinFDBK02
```

### Verification Outcome

| Check                                        | Result    |
| -------------------------------------------- | --------- |
| Logs resumed                                 | Confirmed |
| New real-time events observed                | Confirmed |
| Backup server monitoring visibility restored | Confirmed |
| Linux Team informed                          | Yes       |
| Ticket closure approved                      | Yes       |

## Timeline of Events

| Time / Phase          | Event                                                   |
| --------------------- | ------------------------------------------------------- |
| 9/16/2025 11:23       | Last reported log timestamp for LinFDBK02               |
| 9/15/2025 19:31       | Ticket created for missing logs from LinFDBK02          |
| Initial SOC Review    | SOC searched Splunk for LinFDBK02 logs                  |
| Initial SOC Review    | No logs observed within the expected time window        |
| Infrastructure Review | Splunk server health and ingestion services validated   |
| Infrastructure Review | Listener port 9993 confirmed up and reachable           |
| Scope Validation      | Other devices confirmed actively forwarding logs        |
| Escalation            | SOC escalated the issue to Linux Team                   |
| Remediation           | Linux Team restarted Splunk Universal Forwarder service |
| Post-Remediation      | SOC confirmed logs resumed successfully                 |
| Closure               | Ticket closed after successful validation               |

## Root Cause Analysis

| Area                           | Finding                                                              |
| ------------------------------ | -------------------------------------------------------------------- |
| Root Cause                     | Splunk Universal Forwarder service stopped unexpectedly on LinFDBK02 |
| Affected Component             | Endpoint-side Splunk Universal Forwarder                             |
| Splunk Infrastructure          | No issue identified                                                  |
| Central Logging Infrastructure | No issue identified                                                  |
| Network-Wide Outage            | Not identified                                                       |
| Device Scope                   | Isolated to LinFDBK02                                                |
| Permanent Data Loss            | Not confirmed from provided evidence                                 |
| Final RCA                      | Endpoint-side forwarding service issue                               |

## MITRE ATT&CK Mapping

| Tactic | Technique | ID  | Reason                                                                     |
| ------ | --------- | --- | -------------------------------------------------------------------------- |
| N/A    | N/A       | N/A | No malicious activity confirmed                                            |
| N/A    | N/A       | N/A | Incident was caused by system/log forwarding fault, not adversary behavior |

**MITRE Note:** No MITRE ATT&CK mapping is assigned because this was an operational log forwarding issue, not an attack.

## Analyst Assessment

**Assessment:** **True Positive — Linux Backup Server Not Sending Logs to Splunk**

The alert was valid. LinFDBK02 stopped sending logs to Splunk for more than 60 minutes, and SOC confirmed the log gap through Splunk validation.

The issue was not related to Splunk infrastructure because Splunk services were operational, listener port 9993 was reachable, no ingestion or queue issues were identified, and other devices continued forwarding logs successfully.

The issue was isolated to LinFDBK02 and required Linux Team remediation. No evidence of malicious activity, backup server compromise, unauthorized configuration change, Splunk infrastructure failure, or network-wide outage was identified from the provided evidence.

## Impact Analysis

| Impact Area                | Status                             |
| -------------------------- | ---------------------------------- |
| Linux Log Forwarding       | Interrupted                        |
| Backup Server Monitoring   | Temporarily reduced                |
| Security Monitoring        | Partially impacted                 |
| Backup Activity Visibility | Temporarily reduced                |
| System Health Visibility   | Temporarily reduced                |
| Access Event Visibility    | Temporarily reduced                |
| Splunk Infrastructure      | No impact observed                 |
| Other Devices              | No impact observed                 |
| Network Availability       | No outage confirmed                |
| Data Integrity             | No permanent data loss confirmed   |
| Business Impact            | Minimal to Low                     |
| Security Impact            | Moderate due to backup server role |

## Recommended Actions

1. Monitor LinFDBK02 log ingestion for the next 24–48 hours.
2. Enable service monitoring for Splunk Universal Forwarder on Linux backup servers.
3. Configure automatic restart recovery for the Splunk Universal Forwarder service.
4. Add LinFDBK02 to a backup server log ingestion health dashboard.
5. Configure missing-log alerts for backup servers after 15–30 minutes.
6. Review Linux system logs for Universal Forwarder service stop/crash events around the outage window.
7. Review recent maintenance, patching, or reboot activity on LinFDBK02.
8. Validate Universal Forwarder configuration persistence after reboot or service restart.
9. Document Universal Forwarder restart and recovery steps in the Linux Team runbook.
10. Perform periodic log source health checks for all backup servers and critical Linux hosts.

## Suggested Splunk Detection Query

```spl id="linux_backup_server_log_gap_detection"
index=main hostname=LinFDBK02
| stats latest(_time) as last_seen by hostname
| eval minutes_since_last_log=round((now()-last_seen)/60,2)
| where minutes_since_last_log > 60
| convert ctime(last_seen)
```

## Escalation Decision

**Decision:** **Escalated to Linux Team and resolved. No SOC L2 security escalation required.**

**Reason:** SOC confirmed that Splunk infrastructure and general log ingestion were healthy. Since the issue was isolated to the endpoint-side Splunk Universal Forwarder service, the Linux Team was the correct resolver group.

No SOC L2 escalation was required after log ingestion was restored and no compromise indicators were observed.

Escalate further only if:

1. LinFDBK02 stops forwarding logs again.
2. Splunk Universal Forwarder repeatedly fails.
3. Unauthorized configuration changes are identified.
4. Server connectivity becomes unstable.
5. Evidence of backup server tampering or compromise appears.
6. Logs do not resume after Linux Team remediation.

## Final Ticket Closure Comment

SOC investigated ticket **CS-063 — System Fault: Device Not Sending Logs to Splunk** after automated monitoring detected that **LinFDBK02** had not sent logs to Splunk for more than 60 minutes. The affected device was identified as a medium-severity Linux Backup Server with IP **10.0.11.13**, using Splunk index `main`, and owned by the **Linux Team**. SOC validated the alert using `index=main hostname=LinFDBK02` and confirmed missing logs within the expected monitoring window after the reported last log timestamp **9/16/2025 11:23**. Splunk server health was verified, listener port **9993** was up and reachable, no ingestion errors or queue issues were observed, and other devices continued forwarding logs successfully. The issue was confirmed as isolated to LinFDBK02 and escalated to the Linux Team for endpoint-side Splunk Universal Forwarder validation. The Linux Team restarted the Splunk Universal Forwarder service. SOC rechecked Splunk and confirmed that logs resumed successfully with new real-time events observed. Ticket closed as **Resolved — Splunk Universal Forwarder Service Stopped Unexpectedly**, with no evidence of Splunk infrastructure failure, network-wide outage, malicious activity, or confirmed permanent data loss.

## Skills Demonstrated

System fault triage, Splunk log validation, Linux Server log monitoring, backup server log forwarding investigation, Splunk Universal Forwarder troubleshooting, SIEM health validation, log gap analysis, endpoint issue scoping, Linux Team escalation, post-remediation verification, root cause analysis, impact assessment, evidence limitation handling, closure documentation, and SOC operational monitoring.

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
