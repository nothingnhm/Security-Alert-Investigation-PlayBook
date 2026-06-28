# SOC Analyst Investigation Report

## Ticket Overview

| Field             | Details                                                                     |
| ----------------- | --------------------------------------------------------------------------- |
| Ticket ID         | CS-0421                                                                     |
| Alert Name        | System Fault – Device Not Sending Logs to Splunk                            |
| Incident Category | System Fault / Log Forwarding Interruption                                  |
| Ticket Status     | Closed                                                                      |
| Priority / SLA    | Normal / Default SLA                                                        |
| Department        | Support                                                                     |
| Created Date      | 9/15/25 7:41 PM                                                             |
| Closed By         | Ananda Das                                                                  |
| Source            | Email / Automated Monitoring Alert                                          |
| Analyst Decision  | **True Positive — Device Log Forwarding Interruption Confirmed / Resolved** |

## Executive Summary

A system fault alert was triggered because the critical network device **CiscoRouter01** stopped sending logs to Splunk for more than **60 minutes**.

The affected device is a critical network router with IP address:

`10.0.0.1`

Since router logs are important for network visibility, security monitoring, troubleshooting, and incident investigation, SOC validated the alert in Splunk and confirmed that no new logs were received after the last recorded log time:

`9/15/2025 8:30`

SOC checked Splunk-side ingestion and confirmed that the issue was not caused by a Splunk platform failure. Other network devices continued forwarding logs successfully, which confirmed that the issue was isolated to **CiscoRouter01**.

The case was escalated to the **Network Team** for device-side validation. After the Network Team restored the router’s log forwarding/syslog service, SOC confirmed that logs resumed successfully in Splunk.

Final assessment: **Resolved system fault caused by temporary log forwarding interruption from CiscoRouter01. No malicious activity or Splunk infrastructure failure was identified.**

## Alert Details

| Field             | Value                                                       |
| ----------------- | ----------------------------------------------------------- |
| Device Name       | CiscoRouter01                                               |
| Host IP           | 10.0.0.1                                                    |
| Device Type       | Network                                                     |
| Server Function   | Router                                                      |
| Splunk Index      | main                                                        |
| Asset Severity    | Critical                                                    |
| Custodian         | Network Team                                                |
| Last Log Time     | 9/15/2025 8:30                                              |
| Alert Condition   | Device did not send logs to Splunk for more than 60 minutes |
| Impacted Platform | Splunk                                                      |
| Initial Status    | No new logs observed                                        |
| Final Status      | Log forwarding restored                                     |

## Affected Asset

| Parameter         | Details                                 |
| ----------------- | --------------------------------------- |
| Asset Name        | CiscoRouter01                           |
| IP Address        | 10.0.0.1                                |
| Asset Type        | Network Infrastructure                  |
| Device Role       | Router                                  |
| Splunk Index      | main                                    |
| Asset Criticality | Critical                                |
| Custodian / Owner | Network Team                            |
| Affected Function | Log forwarding to Splunk                |
| Business Impact   | Temporary monitoring and visibility gap |

## Evidence Reviewed

### Alert Evidence

| Field               | Observed Value                             |
| ------------------- | ------------------------------------------ |
| Alert Type          | System Fault                               |
| Alert Reason        | Device not sending logs to Splunk          |
| Detection Threshold | More than 60 minutes without logs          |
| Affected Device     | CiscoRouter01                              |
| Last Log Time       | 9/15/2025 8:30                             |
| Severity Context    | Critical asset with normal ticket priority |

### Initial Splunk Validation Query

```spl id="cs0421_initial_validation"
index=main host=CiscoRouter01
```

### Initial SOC Findings

| Check                          | Result                    |
| ------------------------------ | ------------------------- |
| Recent logs from CiscoRouter01 | Not observed initially    |
| Last known log timestamp       | 9/15/2025 8:30            |
| Alert validity                 | Confirmed                 |
| Delayed indexing evidence      | Not observed              |
| Other device log ingestion     | Working                   |
| Scope                          | Isolated to CiscoRouter01 |

## SIEM / Splunk Analysis

### Investigation Flow

#### 1. Alert Review

SOC reviewed the automated monitoring alert and confirmed that the alert condition was related to missing logs from **CiscoRouter01** for more than 60 minutes.

Because the affected device is a **critical router**, the alert was treated as important from a monitoring and visibility perspective.

#### 2. Asset Identification

| Field                 | Details       |
| --------------------- | ------------- |
| Hostname              | CiscoRouter01 |
| IP Address            | 10.0.0.1      |
| Device Classification | Network       |
| Device Role           | Router        |
| Splunk Index          | main          |
| Custodian             | Network Team  |
| Criticality           | Critical      |

#### 3. Splunk Evidence Validation

SOC searched Splunk for logs from CiscoRouter01:

```spl id="cs0421_host_search"
index=main host=CiscoRouter01
```

The search confirmed that no new logs were received after the last known timestamp. This validated the alert as a genuine log forwarding interruption.

#### 4. Splunk Infrastructure Review

SOC reviewed whether the issue was related to Splunk ingestion or platform health.

| Component / Check                     | Result         |
| ------------------------------------- | -------------- |
| Splunk indexers                       | Operational    |
| Ingestion service                     | Operational    |
| Splunk index `main`                   | Available      |
| Other network devices forwarding logs | Yes            |
| Delayed indexing                      | Not observed   |
| Splunk-wide issue                     | Not identified |

#### 5. Scope and Correlation

The issue was scoped as device-specific because other routers and switches continued forwarding logs to Splunk. No evidence suggested a broader network disruption or Splunk platform failure.

| Evidence                                | Interpretation                      |
| --------------------------------------- | ----------------------------------- |
| Only CiscoRouter01 stopped sending logs | Device-specific issue               |
| Other devices continued sending logs    | Splunk ingestion was healthy        |
| No delayed indexing observed            | Not a Splunk delay issue            |
| Device custodian is Network Team        | Escalation required to Network Team |

## Network / Device-Level Validation

SOC escalated the case to the **Network Team** and requested device-side checks for CiscoRouter01.

The Network Team was asked to validate:

1. Syslog/logging configuration on CiscoRouter01.
2. Router-side syslog service status.
3. Connectivity from CiscoRouter01 to the Splunk receiver.
4. Any recent device configuration changes.
5. Any recent maintenance or reload activity.
6. Logging destination configuration.
7. Device-side errors related to log forwarding.
8. Whether syslog/log forwarding service restart was required.

## Corrective Action

The Network Team completed device-side remediation and confirmed the following actions:

1. Restarted the syslog/log forwarding service on CiscoRouter01.
2. Verified logging configuration settings.
3. Confirmed connectivity to the Splunk receiver.
4. Requested SOC to validate log ingestion after remediation.

## Post-Remediation Verification

SOC rechecked Splunk after remediation using:

```spl id="cs0421_post_remediation"
index=main host=CiscoRouter01
```

### Verification Outcome

| Check                      | Result    |
| -------------------------- | --------- |
| Logs resumed               | Confirmed |
| Continuous ingestion       | Confirmed |
| Splunk visibility restored | Confirmed |
| Network Team informed      | Yes       |
| Ticket closure approved    | Yes       |

## Timeline of Events

| Time / Phase          | Event                                                              |
| --------------------- | ------------------------------------------------------------------ |
| 9/15/2025 8:30        | Last log timestamp observed for CiscoRouter01                      |
| 9/15/2025 7:41 PM     | Ticket created for system fault alert                              |
| Initial SOC Review    | SOC searched Splunk for CiscoRouter01 logs                         |
| Initial SOC Review    | No logs observed after last recorded timestamp                     |
| Infrastructure Review | Splunk ingestion and other device log forwarding checked           |
| Scope Validation      | Issue confirmed as isolated to CiscoRouter01                       |
| Escalation            | SOC escalated the issue to Network Team                            |
| Remediation           | Network Team validated device-side logging and restored forwarding |
| Post-Remediation      | SOC confirmed logs resumed in Splunk                               |
| Closure               | Ticket closed after successful validation                          |

## Root Cause Analysis

| Area                  | Finding                                                     |
| --------------------- | ----------------------------------------------------------- |
| Root Cause            | Temporary interruption in log forwarding from CiscoRouter01 |
| Affected Component    | Router-side logging/syslog forwarding                       |
| Splunk Infrastructure | No issue identified                                         |
| Network-Wide Outage   | Not identified                                              |
| Device Scope          | Isolated to CiscoRouter01                                   |
| Permanent Data Loss   | Not confirmed from provided evidence                        |
| Final RCA             | Device-side log forwarding interruption                     |

## MITRE ATT&CK Mapping

| Tactic | Technique | ID  | Reason                                                                     |
| ------ | --------- | --- | -------------------------------------------------------------------------- |
| N/A    | N/A       | N/A | No malicious activity confirmed                                            |
| N/A    | N/A       | N/A | Incident was caused by system/log forwarding fault, not adversary behavior |

**MITRE Note:** No MITRE ATT&CK mapping is assigned because the evidence indicates an operational logging fault, not an attack.

## Analyst Assessment

**Assessment:** **True Positive — Device Not Sending Logs to Splunk**

The alert was valid. CiscoRouter01 did not send logs to Splunk for more than 60 minutes, and SOC confirmed the log gap through direct Splunk validation.

The issue was not related to Splunk infrastructure because other devices continued forwarding logs successfully. The issue was isolated to CiscoRouter01 and required Network Team remediation.

No evidence of malicious activity, compromise, unauthorized configuration change, or network-wide outage was identified from the provided details.

## Impact Analysis

| Impact Area             | Status                                         |
| ----------------------- | ---------------------------------------------- |
| Log Forwarding          | Interrupted                                    |
| Network Monitoring      | Temporarily reduced visibility                 |
| Security Event Tracking | Limited for CiscoRouter01 during outage window |
| Threat Detection        | Reduced visibility for router-related events   |
| Splunk Infrastructure   | No impact observed                             |
| Other Devices           | No impact observed                             |
| Network Availability    | No outage confirmed                            |
| Data Integrity          | No permanent data loss confirmed               |
| Business Impact         | Low to Medium due to temporary visibility gap  |

## Recommended Actions

1. Monitor CiscoRouter01 log ingestion for the next 24–48 hours.
2. Maintain a Splunk alert for critical devices not sending logs for more than 60 minutes.
3. Create a critical network device log-forwarding dashboard.
4. Document CiscoRouter01 syslog restart and validation steps in the Network Team runbook.
5. Review whether redundant log forwarding should be configured for critical network devices.
6. Track repeated log gaps from CiscoRouter01 as a potential device reliability issue.
7. Validate router logging configuration after maintenance windows.
8. Escalate repeated failures to Network Engineering for deeper device health review.

## Suggested Splunk Detection Query

```spl id="critical_device_log_gap_detection"
index=main host=CiscoRouter01
| stats latest(_time) as last_seen by host
| eval minutes_since_last_log=round((now()-last_seen)/60,2)
| where minutes_since_last_log > 60
| convert ctime(last_seen)
```

## Escalation Decision

**Decision:** **Escalated to Network Team and resolved. No SOC L2 security escalation required.**

**Reason:** The issue was confirmed as a device-side log forwarding interruption. Splunk infrastructure was healthy, other devices continued forwarding logs, and logging was restored after Network Team remediation.

Escalate further only if:

1. CiscoRouter01 stops forwarding logs again.
2. Log forwarding repeatedly fails.
3. Unauthorized configuration changes are identified.
4. Device connectivity becomes unstable.
5. Evidence of tampering or compromise appears.
6. Logs do not resume after Network Team remediation.

## Final Ticket Closure Comment

SOC investigated ticket **CS-0421 — System Fault: Device Not Sending Logs to Splunk** after automated monitoring detected that **CiscoRouter01** had not sent logs to Splunk for more than 60 minutes. The affected device was identified as a critical network router with IP **10.0.0.1**, using Splunk index `main`, and owned by the **Network Team**. SOC validated the alert using `index=main host=CiscoRouter01` and confirmed no new logs after the last recorded timestamp **9/15/2025 8:30**. Splunk ingestion was verified as healthy, and other routers/switches continued forwarding logs successfully, confirming the issue was isolated to CiscoRouter01. The case was escalated to the Network Team for router-side logging/syslog validation. After remediation, SOC confirmed that logs resumed successfully in Splunk. Ticket closed as **Resolved — Temporary Device Log Forwarding Interruption**, with no evidence of Splunk infrastructure failure, network-wide outage, malicious activity, or confirmed permanent data loss.

## Skills Demonstrated

Splunk log validation, system fault triage, critical asset monitoring, network device log forwarding investigation, SIEM health validation, log gap analysis, infrastructure issue scoping, Network Team escalation, post-remediation verification, root cause analysis, impact assessment, closure documentation, and SOC operational monitoring.
