# SOC Analyst Investigation Report

## Ticket Overview

| Field             | Details                                                                                                   |
| ----------------- | --------------------------------------------------------------------------------------------------------- |
| Ticket ID         | CS-076                                                                                                    |
| Alert Name        | Linux:- Failed SSH Login – Account Brute Force Detection                                                  |
| Incident Category | Linux / SSH Brute Force Detection                                                                         |
| Ticket Status     | Closed                                                                                                    |
| Priority / SLA    | Normal / Default SLA                                                                                      |
| Department        | Support                                                                                                   |
| Created Date      | 5/12/25 6:41 PM                                                                                           |
| Closed By         | Ananda Das                                                                                                |
| Detection Source  | Linux Logs / SIEM Splunk                                                                                  |
| Affected Host     | LinOPWebServer03                                                                                          |
| Host IP           | 10.0.16.22                                                                                                |
| Affected User     | Ryan Doe / `ryan.doe`                                                                                     |
| Analyst Decision  | **True Positive Alert Condition — Repeated Failed SSH Login Attempts / No Successful SSH Login Observed** |

## Executive Summary

A Linux security alert was generated for host **LinOPWebServer03** after repeated failed SSH login attempts were observed for user **Ryan Doe**.

The affected server was:

`LinOPWebServer03 / 10.0.16.22`

The server function was:

`Web Server`

The failed SSH authentication attempts originated from source address:

`10.1.4.111`

The SSH daemon process involved was:

`sshd`

The authentication failures were recorded in:

`/var/log/secure`

Splunk Linux logs confirmed repeated SSH pre-authentication failures between **2025-05-08 14:00** and **2025-05-08 14:04**. All observed events showed result `failed`. No successful SSH login was observed in the provided logs.

The source address `10.1.4.111` is a private/internal IP address, so SOC should validate whether it belongs to an approved admin workstation, jump server, automation host, scanner, or an unauthorized internal system.

Final assessment: **True positive failed SSH brute-force indicator. No successful login or confirmed compromise was observed, but user and source-host validation are required.**

## Alert Details

| Field                  | Value                    |
| ---------------------- | ------------------------ |
| Timestamp              | 5/8/2025 14:00           |
| Hostname               | LinOPWebServer03         |
| Host IP                | 10.0.16.22               |
| Server Function        | Web Server               |
| User                   | Ryan Doe                 |
| Linux Account Observed | ryan.doe                 |
| Process                | sshd                     |
| Executable             | /usr/sbin/sshd           |
| Command                | sshd: ryan.doe [preauth] |
| Source Address         | 10.1.4.111               |
| Log Path               | /var/log/secure          |
| Event Key              | log_auth_failure         |
| Result                 | Failed                   |

## Affected Asset Details

| Field            | Value            |
| ---------------- | ---------------- |
| Hostname         | LinOPWebServer03 |
| IP Address       | 10.0.16.22       |
| Operating System | Linux — RHEL 8   |
| Platform         | AWS Cloud        |
| Server Role      | Web Server       |
| Service Involved | SSH              |
| Process Name     | sshd             |
| Executable Path  | /usr/sbin/sshd   |
| Log Source       | /var/log/secure  |
| User Role        | Linux Admin      |

## IOCs / Indicators Identified

| Indicator Type       | Indicator                                        |
| -------------------- | ------------------------------------------------ |
| Source Address       | 10.1.4.111                                       |
| Destination Host     | LinOPWebServer03                                 |
| Destination IP       | 10.0.16.22                                       |
| Affected User        | Ryan Doe                                         |
| Linux Account        | ryan.doe                                         |
| User Role            | Linux Admin                                      |
| Process              | sshd                                             |
| Executable           | /usr/sbin/sshd                                   |
| Command              | sshd: ryan.doe [preauth]                         |
| Log File             | /var/log/secure                                  |
| Event Key            | log_auth_failure                                 |
| Result               | failed                                           |
| Attack Type          | SSH Brute Force / Repeated Failed Login Attempts |
| Successful SSH Login | Not observed in provided logs                    |

## SIEM / Splunk Analysis

### Investigation Flow

#### 1. Alert Review

SOC reviewed the Linux failed SSH login alert for host `LinOPWebServer03`. The alert indicated repeated authentication failures against a Linux admin user account.

Because the activity targeted SSH access on a web server, SOC treated the event as a possible account brute-force or repeated failed login attempt.

#### 2. Entity Identification

| Entity          | Value            |
| --------------- | ---------------- |
| Hostname        | LinOPWebServer03 |
| Host IP         | 10.0.16.22       |
| Server Function | Web Server       |
| User            | Ryan Doe         |
| Linux Account   | ryan.doe         |
| Source Address  | 10.1.4.111       |
| Process         | sshd             |
| Log Path        | /var/log/secure  |
| Event Key       | log_auth_failure |

#### 3. Splunk Query Used

```spl id="cs0339_linux_ssh_query"
index=main sourcetype="linux_logs" "Ryan Doe" "LinOPWebServer03" "sshd"
| table _time auid hostname ip_address user_role server_function user comm exe cmd addr path key res
```

#### 4. Full Unique Splunk Log Results

```text id="cs0339_linux_ssh_results"
_time	auid	hostname	ip_address	user_role	server_function	user	comm	exe	cmd	addr	path	key	res
2025-05-08 14:04:00	1001	LinOPWebServer03	10.0.16.22	Linux Admin	Web Server	Ryan Doe	sshd	/usr/sbin/sshd	sshd: ryan.doe [preauth]	10.1.4.111	/var/log/secure	log_auth_failure	failed
2025-05-08 14:03:00	1001	LinOPWebServer03	10.0.16.22	Linux Admin	Web Server	Ryan Doe	sshd	/usr/sbin/sshd	sshd: ryan.doe [preauth]	10.1.4.111	/var/log/secure	log_auth_failure	failed
2025-05-08 14:02:00	1001	LinOPWebServer03	10.0.16.22	Linux Admin	Web Server	Ryan Doe	sshd	/usr/sbin/sshd	sshd: ryan.doe [preauth]	10.1.4.111	/var/log/secure	log_auth_failure	failed
2025-05-08 14:01:00	1001	LinOPWebServer03	10.0.16.22	Linux Admin	Web Server	Ryan Doe	sshd	/usr/sbin/sshd	sshd: ryan.doe [preauth]	10.1.4.111	/var/log/secure	log_auth_failure	failed
2025-05-08 14:00:00	1001	LinOPWebServer03	10.0.16.22	Linux Admin	Web Server	Ryan Doe	sshd	/usr/sbin/sshd	sshd: ryan.doe [preauth]	10.1.4.111	/var/log/secure	log_auth_failure	failed
```

**Evidence Note:** Exact duplicate log rows were removed. All unique failed SSH authentication events provided for this ticket were preserved.

### 5. SSH Authentication Pattern Review

| Observation                           | Analyst Interpretation                          |
| ------------------------------------- | ----------------------------------------------- |
| Multiple SSH failures observed        | Brute-force indicator confirmed                 |
| Same source address used              | Single-source repeated attempt pattern          |
| Same Linux account targeted           | Account-specific authentication failure pattern |
| Events occurred within 5 minutes      | Short-duration repeated failures                |
| SSH pre-authentication state observed | Login did not complete successfully             |
| All events resulted in `failed`       | No successful SSH access confirmed              |
| Source address is private/internal    | Source host ownership must be validated         |

## Investigation Findings

1. Multiple failed SSH login attempts were observed on host `LinOPWebServer03`.
2. The affected host IP was `10.0.16.22`.
3. The server function was `Web Server`.
4. The operating system was Linux RHEL 8.
5. The server was hosted in AWS Cloud.
6. The affected user was `Ryan Doe`.
7. The Linux account observed in the SSH command was `ryan.doe`.
8. The login attempts originated from source address `10.1.4.111`.
9. The SSH daemon process `sshd` generated the authentication failure events.
10. Events were recorded in `/var/log/secure`.
11. Multiple failures occurred between `2025-05-08 14:00` and `2025-05-08 14:04`.
12. All observed events had result `failed`.
13. No successful SSH login was observed in the provided logs.
14. Activity is consistent with repeated failed SSH login attempts or a possible SSH brute-force attempt.
15. User verification and source-host validation are required.

## Timeline of Events

| Time               | Event                                                               |
| ------------------ | ------------------------------------------------------------------- |
| 2025-05-08 14:00   | Failed SSH pre-authentication event observed for `ryan.doe`         |
| 2025-05-08 14:01   | Additional failed SSH login attempt observed                        |
| 2025-05-08 14:02   | Additional failed SSH login attempt observed                        |
| 2025-05-08 14:03   | Additional failed SSH login attempt observed                        |
| 2025-05-08 14:04   | Additional failed SSH login attempt observed                        |
| Investigation Time | SOC reviewed Linux SSH logs in Splunk                               |
| Investigation Time | SOC confirmed repeated failed SSH authentication events             |
| Validation Time    | User verification with Ryan Doe recommended                         |
| Closure Time       | Ticket closed after documenting validation and containment guidance |

## MITRE ATT&CK Mapping

| Tactic            | Technique         | ID        | Reason                                                        |
| ----------------- | ----------------- | --------- | ------------------------------------------------------------- |
| Credential Access | Brute Force       | T1110     | Multiple failed SSH authentication attempts were observed     |
| Credential Access | Password Guessing | T1110.001 | Repeated failed login attempts may indicate password guessing |
| Initial Access    | Valid Accounts    | T1078     | Attempts targeted a valid Linux admin account                 |
| Lateral Movement  | SSH               | T1021.004 | SSH was the remote access service targeted for authentication |

**MITRE Note:** Failed SSH authentication activity was observed. Successful login, privilege escalation, lateral movement, persistence, and data exfiltration were not observed in the provided logs.

## Analyst Assessment

**Assessment:** **True Positive Alert Condition — Suspicious SSH Brute Force Indicator / No Successful Login Observed**

The alert condition is valid because repeated failed SSH authentication attempts were observed against the same Linux admin account from the same source address within a short duration.

The evidence supporting the alert includes:

1. Multiple failed SSH authentication events.
2. Same source address `10.1.4.111`.
3. Same destination host `LinOPWebServer03`.
4. Same targeted Linux account `ryan.doe`.
5. Events occurred repeatedly from `14:00` to `14:04`.
6. SSH daemon logged the attempts as pre-authentication failures.
7. No successful login was observed in the provided logs.

The source address `10.1.4.111` is internal/private, so the investigation should validate whether the activity came from an approved admin workstation, jump server, automation host, vulnerability scanner, or unauthorized internal host.

## User Verification Questions

SOC should contact user **Ryan Doe** and confirm:

1. Did you attempt to SSH into `LinOPWebServer03` between `2025-05-08 14:00–14:04`?
2. Were the failed attempts caused by entering an incorrect password?
3. Were you using source system `10.1.4.111`?
4. Is `10.1.4.111` your assigned admin workstation, jump host, or approved access system?
5. Were you performing maintenance or troubleshooting activity?
6. Did you experience an account lockout or SSH access issue?
7. Did you notice any suspicious activity on your account?
8. Did you recently reuse or enter your credentials on any suspicious system?

If Ryan Doe confirms the activity, document the confirmation and close as benign user error or authorized admin activity. If Ryan Doe denies the activity, treat the account as targeted and proceed with containment.

## Source Host Validation

Because `10.1.4.111` is a private/internal IP, SOC should validate the source system.

### Validate the following:

1. Asset owner of `10.1.4.111`.
2. Whether it is an approved admin workstation or jump host.
3. Whether it belongs to Ryan Doe.
4. Whether it is an automation server, monitoring host, scanner, or deployment system.
5. Whether the source host generated similar attempts against other Linux servers.
6. Whether the source host shows malware, script abuse, or unauthorized SSH tooling.
7. Whether the source host should be isolated or investigated.

## Impact Analysis

| Impact Area               | Status                                                        |
| ------------------------- | ------------------------------------------------------------- |
| Failed SSH login attempts | Confirmed                                                     |
| Brute-force indicator     | Confirmed                                                     |
| Targeted host             | LinOPWebServer03                                              |
| Targeted IP               | 10.0.16.22                                                    |
| Targeted user             | Ryan Doe / ryan.doe                                           |
| User role                 | Linux Admin                                                   |
| Successful SSH login      | Not observed                                                  |
| Account compromise        | Not confirmed                                                 |
| Privilege escalation      | Not observed                                                  |
| Lateral movement          | Not observed                                                  |
| Data exfiltration         | Not observed                                                  |
| Business impact           | Low                                                           |
| Security impact           | Medium until validation                                       |
| Residual risk             | Low if user confirms activity; Medium if user denies activity |

### Impact Summary

The incident involved repeated failed SSH authentication attempts against a Linux admin account. No successful SSH login was observed in the provided logs. The main risk is potential credential guessing or unauthorized access attempt against a privileged Linux account.

## Containment and Remediation

| Scenario                              | Action                                              |
| ------------------------------------- | --------------------------------------------------- |
| User confirms activity                | No containment required; document user confirmation |
| User confirms wrong password attempts | Close as benign user error                          |
| User denies activity                  | Temporarily disable or isolate the account          |
| User denies activity                  | Reset credentials for Ryan Doe / `ryan.doe`         |
| User denies activity                  | Validate source host `10.1.4.111`                   |
| Source host unauthorized              | Isolate or investigate source host `10.1.4.111`     |
| Successful login found                | Escalate to SOC L2 / Linux Team                     |
| Further suspicious activity found     | Escalate to Incident Response                       |

## Additional Splunk Queries for Follow-Up

### Check Successful SSH Logins for Same User

```spl id="cs0339_successful_ssh_check"
index=main sourcetype="linux_logs" hostname="LinOPWebServer03" user="Ryan Doe" ("log_auth_success" OR res="success")
| table _time hostname ip_address user comm exe cmd addr path key res
```

### Check All SSH Events from Same Source Address

```spl id="cs0339_source_host_ssh_activity"
index=main sourcetype="linux_logs" addr="10.1.4.111" comm="sshd"
| table _time hostname ip_address user comm exe cmd addr path key res
| sort _time
```

### Count Failed SSH Attempts by Source Address and User

```spl id="cs0339_failed_ssh_count"
index=main sourcetype="linux_logs" comm="sshd" key="log_auth_failure"
| stats count by addr user hostname
| sort - count
```

### Check Other Hosts Targeted by Same Source

```spl id="cs0339_other_hosts_targeted"
index=main sourcetype="linux_logs" addr="10.1.4.111" key="log_auth_failure"
| stats count values(user) as targeted_users values(hostname) as targeted_hosts by addr
| sort - count
```

## Recommended Actions

1. Contact Ryan Doe and confirm whether the SSH attempts were legitimate.
2. Validate whether `10.1.4.111` is an approved admin workstation or jump host.
3. Check whether any successful SSH login occurred before or after the failed attempts.
4. Review all SSH events from the same source address.
5. Reset Ryan Doe’s credentials if the activity was not user-initiated.
6. Temporarily disable or isolate the account if unauthorized use is suspected.
7. Investigate source host `10.1.4.111` if unauthorized or suspicious.
8. Monitor `LinOPWebServer03` for further SSH failures.
9. Configure SSH brute-force thresholds and alerting.
10. Enforce key-based authentication or MFA for SSH where applicable.
11. Restrict SSH access to approved jump hosts and admin subnets.
12. Consider fail2ban or equivalent lockout controls if approved by the Linux team.
13. Review Linux admin account access hygiene.

## Escalation Decision

**Decision:** **User verification required. Escalate only if Ryan Doe denies the activity, the source host is unauthorized, or successful login is later identified.**

**Reason:** The logs show repeated failed SSH authentication attempts but no successful login or confirmed compromise. If the user confirms the activity, it can be treated as benign failed login activity. If the user denies it, the event should be escalated because a Linux admin account may be targeted.

Escalate to **SOC L2 / Linux Team / Incident Response** if:

1. Ryan Doe denies the activity.
2. Source host `10.1.4.111` is not approved.
3. A successful SSH login is later identified.
4. Failed SSH attempts continue.
5. Multiple users are targeted from the same source.
6. Privileged commands are observed after login.
7. Suspicious process execution, persistence, or lateral movement is detected.

## Final Ticket Closure Comment

SOC investigated ticket **CS-076 — Linux Failed SSH Login / Account Brute Force Detection** for host `LinOPWebServer03 / 10.0.16.22`. Linux logs showed repeated SSH pre-authentication failures for user `Ryan Doe` / `ryan.doe` from source address `10.1.4.111`. The events were generated by `sshd`, executed from `/usr/sbin/sshd`, and recorded in `/var/log/secure` with event key `log_auth_failure`. The failures occurred from `2025-05-08 14:00` to `14:04`, and all observed events resulted in `failed`. No successful SSH login, privilege escalation, lateral movement, endpoint compromise, or data exfiltration was observed in the provided logs. SOC recommended validating the activity with Ryan Doe and confirming whether `10.1.4.111` is an approved admin workstation or jump host. If the user denies the activity or the source host is unauthorized, reset credentials, isolate/disable the account, investigate the source host, and escalate to SOC L2 / Linux Team. Ticket closed as **True Positive Alert Condition — Repeated Failed SSH Login Attempts / User Verification Required / No Successful SSH Login Observed**.

## Skills Demonstrated

Linux log analysis, SSH brute-force triage, Splunk investigation, `/var/log/secure` review, failed authentication analysis, source-host validation, privileged account risk assessment, IOC extraction, MITRE ATT&CK mapping, containment planning, user verification, escalation criteria definition, and SOC ticket documentation.

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
