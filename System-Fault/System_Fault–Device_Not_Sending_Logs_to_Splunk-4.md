# SOC Analyst Investigation Report

## Ticket Overview

| Field             | Details                                                                                      |
| ----------------- | -------------------------------------------------------------------------------------------- |
| Ticket ID         | CS-0405                                                                                      |
| Alert Name        | System Fault – Device Not Sending Logs to Splunk                                             |
| Incident Category | System Fault / Log Forwarding Interruption                                                   |
| Ticket Status     | Closed                                                                                       |
| Priority / SLA    | Normal / Default SLA                                                                         |
| Department        | Support                                                                                      |
| Created Date      | 9/15/25 7:31 PM                                                                              |
| Closed By         | Ananda Das                                                                                   |
| Detection Source  | Automated Monitoring / Splunk                                                                |
| Analyst Decision  | **True Positive — Active Directory Server Log Forwarding Interruption Confirmed / Resolved** |

## Executive Summary

A system fault alert was triggered because the Windows Active Directory server **WinITAD01** stopped sending logs to Splunk for more than **60 minutes**.

The affected device is a high-severity Windows Server with IP address:

`10.0.2.20`

WinITAD01 performs the **Active Directory** function, which makes its logs important for monitoring authentication activity, failed logins, account changes, privileged user activity, policy changes, and other security-relevant Windows events.

SOC validated the alert in Splunk and confirmed that no logs were observed from **WinITAD01** after the reported last log time:

`9/18/2025 12:24`

SOC also reviewed Splunk server health and confirmed that Splunk ingestion services were operational. Other endpoints were forwarding logs normally, confirming that the issue was isolated to **WinITAD01**.

The case was escalated to the **Wintel Team** for endpoint-level validation. The Wintel Team restarted the **Splunk Universal Forwarder** service on WinITAD01. SOC then revalidated log ingestion and confirmed that logs resumed successfully.

Final assessment: **Resolved system fault caused by Splunk Universal Forwarder service failure or unresponsiveness on WinITAD01. No malicious activity, Splunk server issue, or network-wide outage was identified.**

## Alert Details

| Field             | Value                                                       |
| ----------------- | ----------------------------------------------------------- |
| Device Name       | WinITAD01                                                   |
| Host IP           | 10.0.2.20                                                   |
| Device Type       | Windows Server                                              |
| Server Function   | Active Directory                                            |
| Splunk Index      | main                                                        |
| Asset Severity    | High                                                        |
| Custodian         | Wintel Team                                                 |
| Last Log Time     | 9/18/2025 12:24                                             |
| Alert Condition   | Device did not send logs to Splunk for more than 60 minutes |
| Impacted Platform | Splunk                                                      |
| Initial Status    | No new logs observed                                        |
| Final Status      | Log forwarding restored                                     |

## Data Quality Note

The ticket create date is listed as **9/15/25 7:31 PM**, while the reported **LastLogTime** is **9/18/2025 12:24**. This timestamp order appears inconsistent and should be validated against the ticketing platform, timezone settings, or alert generation source.

The investigation still treats the alert as valid because the alert condition stated that **WinITAD01 did not send logs to Splunk for more than 60 minutes**, and SOC validation confirmed missing logs for the device.

## Affected Asset

| Parameter                | Details                                                               |
| ------------------------ | --------------------------------------------------------------------- |
| Asset Name               | WinITAD01                                                             |
| IP Address               | 10.0.2.20                                                             |
| Asset Type               | Windows Server                                                        |
| Server Role              | Active Directory                                                      |
| Splunk Index             | main                                                                  |
| Asset Severity           | High                                                                  |
| Custodian / Owner        | Wintel Team                                                           |
| Log Forwarding Component | Splunk Universal Forwarder                                            |
| Affected Function        | Windows / AD log forwarding to Splunk                                 |
| Security Impact          | Temporary Active Directory visibility gap                             |
| Business Impact          | Reduced monitoring visibility for authentication and directory events |

## IOCs / Technical Indicators Identified

| Indicator Type           | Indicator / Value                                                 |
| ------------------------ | ----------------------------------------------------------------- |
| Affected Host            | WinITAD01                                                         |
| Affected IP Address      | 10.0.2.20                                                         |
| Device Type              | Windows Server                                                    |
| Server Role              | Active Directory                                                  |
| Splunk Index             | main                                                              |
| Log Destination          | Splunk                                                            |
| Log Forwarding Component | Splunk Universal Forwarder                                        |
| Log Source Type          | Windows Event Logs / Active Directory Logs                        |
| Asset Severity           | High                                                              |
| Responsible Team         | Wintel Team                                                       |
| Root Cause Type          | Splunk Universal Forwarder service stopped or became unresponsive |

**IOC Assessment:** This was a system fault incident, not a malicious IOC-based security incident. The indicators above represent the affected asset, forwarding component, and monitoring path.

## Evidence Reviewed

### Alert Evidence

| Field               | Observed Value                    |
| ------------------- | --------------------------------- |
| Alert Type          | System Fault                      |
| Alert Reason        | Device not sending logs to Splunk |
| Detection Threshold | More than 60 minutes without logs |
| Affected Device     | WinITAD01                         |
| Last Log Time       | 9/18/2025 12:24                   |
| Asset Severity      | High                              |
| Custodian           | Wintel Team                       |

### Initial Splunk Validation Query

```spl id="cs0405_initial_validation"
index=main hostname=WinITAD01
```

### Initial SOC Findings

| Check                      | Result                 |
| -------------------------- | ---------------------- |
| Recent logs from WinITAD01 | Not observed initially |
| Last known log timestamp   | 9/18/2025 12:24        |
| Alert validity             | Confirmed              |
| Delayed indexing evidence  | Not observed           |
| Other endpoint ingestion   | Working                |
| Scope                      | Isolated to WinITAD01  |

## SIEM / Splunk Analysis

### Investigation Flow

#### 1. Alert Review

SOC reviewed the automated monitoring alert and confirmed that the alert condition was related to missing logs from **WinITAD01** for more than 60 minutes.

Because the affected system is an **Active Directory server**, the alert was treated as important from a security visibility perspective. Missing AD logs can reduce visibility into authentication events, account lockouts, privilege changes, group membership changes, suspicious login attempts, and possible identity-based attacks.

#### 2. Asset Identification

| Field                 | Details                    |
| --------------------- | -------------------------- |
| Hostname              | WinITAD01                  |
| IP Address            | 10.0.2.20                  |
| Device Classification | Windows Server             |
| Server Role           | Active Directory           |
| Splunk Index          | main                       |
| Log Forwarding Method | Splunk Universal Forwarder |
| Custodian             | Wintel Team                |
| Asset Severity        | High                       |

#### 3. Splunk Evidence Validation

SOC searched Splunk for logs from WinITAD01:

```spl id="cs0405_host_search"
index=main hostname=WinITAD01
```

The search confirmed that no new logs were received after the reported LastLogTime. This validated the alert as a genuine log forwarding interruption.

#### 4. Splunk Infrastructure Review

SOC reviewed whether the issue was caused by Splunk server or ingestion issues.

| Component / Check                    | Result                |
| ------------------------------------ | --------------------- |
| Splunk server health                 | Verified              |
| Splunk ingestion services            | Operational           |
| Splunk index `main`                  | Available             |
| Port 9993                            | Active                |
| Other endpoints                      | Sending logs normally |
| Splunk server issue                  | Not identified        |
| Central logging infrastructure issue | Not identified        |

#### 5. Network and Scope Validation

SOC reviewed whether the issue was caused by a wider connectivity problem.

| Check                                       | Result                |
| ------------------------------------------- | --------------------- |
| Network outage                              | Not reported          |
| Connectivity between Splunk and other hosts | Confirmed             |
| Other hosts forwarding logs                 | Yes                   |
| Network-wide issue                          | Not identified        |
| Endpoint-specific issue                     | Confirmed             |
| Final scope                                 | Isolated to WinITAD01 |

The evidence showed that Splunk was healthy and other endpoints were forwarding logs normally. Therefore, the issue was not caused by Splunk infrastructure or a network-wide outage.

## Endpoint-Level Investigation

SOC escalated the case to the **Wintel Team** and requested endpoint-level validation for WinITAD01.

The Wintel Team was asked to validate:

1. Splunk Universal Forwarder service status.
2. Windows service failures.
3. Endpoint resource utilization.
4. Disk space or service crash indicators.
5. Recent maintenance activity.
6. Recent patching or reboot activity.
7. Connectivity from WinITAD01 to the Splunk receiver.
8. Whether the Splunk Universal Forwarder service required restart.

## Corrective Action

The Wintel Team completed endpoint-side remediation and confirmed the following actions:

1. Restarted the Splunk Universal Forwarder service on WinITAD01.
2. Confirmed the system was otherwise healthy.
3. No broader server health issue was identified.
4. Requested SOC to revalidate log ingestion.

## Post-Remediation Verification

SOC rechecked Splunk after remediation using:

```spl id="cs0405_post_remediation"
index=main hostname=WinITAD01
```

### Verification Outcome

| Check                             | Result    |
| --------------------------------- | --------- |
| Logs resumed                      | Confirmed |
| Real-time events received         | Confirmed |
| AD monitoring visibility restored | Confirmed |
| Wintel Team informed              | Yes       |
| Ticket closure approved           | Yes       |

## Timeline of Events

| Time / Phase          | Event                                                    |
| --------------------- | -------------------------------------------------------- |
| 9/18/2025 12:24       | Last reported log timestamp for WinITAD01                |
| 9/15/2025 19:31       | Ticket created for missing logs from WinITAD01           |
| Initial SOC Review    | SOC searched Splunk for WinITAD01 logs                   |
| Initial SOC Review    | No logs observed after the reported LastLogTime          |
| Infrastructure Review | Splunk server and ingestion services validated           |
| Infrastructure Review | Port 9993 confirmed active                               |
| Scope Validation      | Other endpoints confirmed forwarding logs normally       |
| Escalation            | SOC escalated the issue to Wintel Team                   |
| Remediation           | Wintel Team restarted Splunk Universal Forwarder service |
| Post-Remediation      | SOC confirmed logs resumed in Splunk                     |
| Closure               | Ticket closed after successful validation                |

## Root Cause Analysis

| Area                           | Finding                                                                        |
| ------------------------------ | ------------------------------------------------------------------------------ |
| Root Cause                     | Splunk Universal Forwarder service stopped or became unresponsive on WinITAD01 |
| Affected Component             | Endpoint-side Splunk Universal Forwarder                                       |
| Splunk Infrastructure          | No issue identified                                                            |
| Central Logging Infrastructure | No issue identified                                                            |
| Network-Wide Outage            | Not identified                                                                 |
| Device Scope                   | Isolated to WinITAD01                                                          |
| Permanent Data Loss            | Not confirmed from provided evidence                                           |
| Final RCA                      | Endpoint-side forwarding service issue                                         |

## MITRE ATT&CK Mapping

| Tactic | Technique | ID  | Reason                                                                     |
| ------ | --------- | --- | -------------------------------------------------------------------------- |
| N/A    | N/A       | N/A | No malicious activity confirmed                                            |
| N/A    | N/A       | N/A | Incident was caused by system/log forwarding fault, not adversary behavior |

**MITRE Note:** No MITRE ATT&CK mapping is assigned because this was an operational log forwarding issue, not an attack.

## Analyst Assessment

**Assessment:** **True Positive — Active Directory Server Not Sending Logs to Splunk**

The alert was valid. WinITAD01 stopped sending logs to Splunk for more than 60 minutes, and SOC confirmed the log gap through direct Splunk validation.

The issue was not related to Splunk infrastructure because Splunk services were operational and other endpoints continued forwarding logs. The issue was isolated to WinITAD01 and required Wintel Team remediation.

No evidence of malicious activity, AD server compromise, unauthorized configuration change, Splunk infrastructure failure, or network-wide outage was identified from the provided evidence.

## Impact Analysis

| Impact Area                              | Status                                       |
| ---------------------------------------- | -------------------------------------------- |
| Windows / AD Log Forwarding              | Interrupted                                  |
| Active Directory Monitoring              | Temporarily reduced                          |
| Authentication Monitoring                | Temporarily limited                          |
| Account Change Visibility                | Temporarily reduced                          |
| Privileged Activity Monitoring           | Temporarily reduced                          |
| Group Policy / Security Event Visibility | Temporarily reduced                          |
| Splunk Infrastructure                    | No impact observed                           |
| Other Endpoints                          | No impact observed                           |
| Network Availability                     | No outage confirmed                          |
| Data Integrity                           | No permanent data loss confirmed             |
| Business Impact                          | Low                                          |
| Security Impact                          | Elevated due to high-severity AD server role |

## Recommended Actions

1. Monitor WinITAD01 log ingestion for the next 24–48 hours.
2. Enable service monitoring for Splunk Universal Forwarder on high-severity Windows servers.
3. Configure automatic restart recovery for the Splunk Universal Forwarder service.
4. Add WinITAD01 to a critical AD server log ingestion health dashboard.
5. Configure missing-log alerts for high-severity AD servers after 15–30 minutes.
6. Review Windows Event Logs for service stop/crash events around the outage window.
7. Review recent patching, reboot, or maintenance activity on WinITAD01.
8. Validate Splunk Universal Forwarder configuration persistence after reboot.
9. Document Universal Forwarder restart and recovery steps in the Wintel Team runbook.
10. Perform periodic log source health checks for all critical AD servers.

## Suggested Splunk Detection Query

```spl id="ad_server_log_gap_detection"
index=main hostname=WinITAD01
| stats latest(_time) as last_seen by hostname
| eval minutes_since_last_log=round((now()-last_seen)/60,2)
| where minutes_since_last_log > 60
| convert ctime(last_seen)
```

## Escalation Decision

**Decision:** **Escalated to Wintel Team and resolved. No SOC L2 security escalation required.**

**Reason:** SOC confirmed that Splunk infrastructure and network connectivity were healthy. Since the issue was isolated to the endpoint-side Splunk Universal Forwarder service, the Wintel Team was the correct resolver group.

No SOC L2 escalation was required after log ingestion was restored and no compromise indicators were observed.

Escalate further only if:

1. WinITAD01 stops forwarding logs again.
2. Splunk Universal Forwarder repeatedly fails.
3. Unauthorized configuration changes are identified.
4. Server connectivity becomes unstable.
5. Evidence of AD server tampering or compromise appears.
6. Logs do not resume after Wintel Team remediation.

## Final Ticket Closure Comment

SOC investigated ticket **CS-0405 — System Fault: Device Not Sending Logs to Splunk** after automated monitoring detected that **WinITAD01** had not sent logs to Splunk for more than 60 minutes. The affected device was identified as a high-severity Windows Active Directory server with IP **10.0.2.20**, using Splunk index `main`, and owned by the **Wintel Team**. SOC validated the alert using `index=main hostname=WinITAD01` and confirmed no new logs after the reported last log timestamp **9/18/2025 12:24**. Splunk server health and ingestion services were verified as operational, port **9993** was active, and other endpoints continued forwarding logs successfully. The issue was confirmed as isolated to WinITAD01 and escalated to the Wintel Team for endpoint-side Splunk Universal Forwarder validation. The Wintel Team restarted the Splunk Universal Forwarder service and confirmed the system was otherwise healthy. SOC rechecked Splunk and confirmed that logs resumed successfully with real-time events received. Ticket closed as **Resolved — Splunk Universal Forwarder Service Stopped or Became Unresponsive**, with no evidence of Splunk infrastructure failure, network-wide outage, malicious activity, or confirmed permanent data loss.

## Skills Demonstrated

System fault triage, Splunk log validation, Active Directory log monitoring, Windows Server log forwarding investigation, Splunk Universal Forwarder troubleshooting, SIEM health validation, log gap analysis, endpoint issue scoping, Wintel Team escalation, post-remediation verification, root cause analysis, impact assessment, evidence limitation handling, closure documentation, and SOC operational monitoring.
