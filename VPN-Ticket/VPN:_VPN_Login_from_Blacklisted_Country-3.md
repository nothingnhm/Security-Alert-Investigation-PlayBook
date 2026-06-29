# SOC Analyst Investigation Report

## Ticket Overview

| Field             | Details                                                                                               |
| ----------------- | ----------------------------------------------------------------------------------------------------- |
| Ticket ID         | CS-072                                                                                               |
| Alert Name        | VPN:- VPN Login from Blacklisted Country                                                              |
| Incident Category | VPN / Suspicious Authentication                                                                       |
| Ticket Status     | Closed                                                                                                |
| Priority / SLA    | High / Default SLA                                                                                    |
| Department        | Support                                                                                               |
| Created Date      | 3/23/25 4:35 PM                                                                                       |
| Closed By         | Ananda Das                                                                                            |
| Detection Source  | VPN Logs / SIEM Splunk                                                                                |
| Affected User     | `sneha.khanna`                                                                                        |
| Affected Host     | MAC-12432                                                                                             |
| Analyst Decision  | **True Positive — Suspicious VPN Login from Blacklisted Country / MFA Prevented Unauthorized Access** |

## Executive Summary

A VPN security alert was triggered for user **sneha.khanna** after multiple VPN authentication attempts were observed from the external source IP:

`185.7.214.37`

The alert was generated because the VPN login originated from a **blacklisted country / high-risk geo-location**. The source IP also had **100% abuse confidence** and was associated with data center / web hosting / transit infrastructure.

The authentication attempts targeted the corporate VPN service:

`Corporate_VPN`

The VPN destination was:

`10.0.2.12`

Splunk VPN logs confirmed repeated password authentication initiation, MFA OTP challenge generation, and MFA failures due to incorrect OTP entries. No successful VPN session was observed in the provided evidence.

SOC assessed the activity as a **True Positive suspicious VPN authentication attempt**, likely related to credential abuse, credential stuffing, brute force, or attempted unauthorized VPN access.

Final assessment: **MFA prevented unauthorized access. No successful VPN login, endpoint compromise, lateral movement, or data exfiltration was observed from the provided evidence.**

## Alert Details

| Field          | Value                                                                |
| -------------- | -------------------------------------------------------------------- |
| Timestamp      | 1/29/2025 11:20                                                      |
| Source IP      | 185.7.214.37                                                         |
| Destination IP | 10.0.2.12                                                            |
| User           | sneha.khanna                                                         |
| Hostname       | MAC-12432                                                            |
| Device Type    | MACOS                                                                |
| VPN Device     | IvantiVPN01                                                          |
| VPN Realm      | Corporate_VPN                                                        |
| Session Status | Authentication initiated                                             |
| Message        | User `sneha.khanna` Realm `Corporate_VPN` - Authentication initiated |
| Final Verdict  | True Positive                                                        |

## Source IP Reputation Analysis

| Field            | Value                                |
| ---------------- | ------------------------------------ |
| Source IP        | 185.7.214.37                         |
| Abuse Confidence | 100%                                 |
| ISP              | Chang Way Technologies Co. Limited   |
| Usage Type       | Data Center / Web Hosting / Transit  |
| ASN              | Unknown                              |
| Domain Name      | changway.hk                          |
| Country          | Hong Kong                            |
| City             | Queen's Terrace, Central and Western |

### Source IP Assessment

The source IP `185.7.214.37` had **100% abuse confidence** and was associated with hosting/transit infrastructure. VPN authentication attempts from high-risk hosting infrastructure and blacklisted regions are suspicious, especially when the login targets a valid corporate VPN account.

The activity was treated as a likely credential abuse, brute-force, or credential-stuffing attempt.

## Affected Assets / Entities

| Asset / Entity     | Details                                       |
| ------------------ | --------------------------------------------- |
| Affected User      | sneha.khanna                                  |
| Hostname           | MAC-12432                                     |
| Device Type        | macOS / MACOS                                 |
| VPN Device         | IvantiVPN01                                   |
| VPN Destination IP | 10.0.2.12                                     |
| VPN Server OS      | Windows Server 2022                           |
| VPN Realm          | Corporate_VPN                                 |
| Source IP          | 185.7.214.37                                  |
| Asset Severity     | High                                          |
| Department         | IT                                            |
| Attack Type        | Suspicious VPN login from blacklisted country |

## IOCs / Indicators Identified

| IOC Type              | Indicator                                                 |
| --------------------- | --------------------------------------------------------- |
| Source IP             | 185.7.214.37                                              |
| Destination IP        | 10.0.2.12                                                 |
| Affected User         | sneha.khanna                                              |
| Hostname              | MAC-12432                                                 |
| Device Type           | macOS 13x                                                 |
| VPN Device            | IvantiVPN01                                               |
| VPN Realm             | Corporate_VPN                                             |
| Source ISP            | Chang Way Technologies Co. Limited                        |
| Source Domain         | changway.hk                                               |
| Source Country        | Hong Kong                                                 |
| Abuse Confidence      | 100%                                                      |
| Authentication Method | Password / MFA                                            |
| MFA Status            | Failed                                                    |
| Session Status        | No successful VPN session observed                        |
| Attack Type           | Suspicious VPN Authentication / Possible Credential Abuse |

## SIEM / Splunk Analysis

### Investigation Flow

#### 1. Alert Review

SOC reviewed the VPN alert for user `sneha.khanna`. The alert indicated that VPN authentication was initiated from a source IP associated with a blacklisted country / high-risk region.

Because the attempt involved a valid corporate VPN account, SOC treated the activity as a potential unauthorized access attempt.

#### 2. Entity Identification

| Entity         | Value         |
| -------------- | ------------- |
| User           | sneha.khanna  |
| Hostname       | MAC-12432     |
| Device Type    | macOS / MACOS |
| Source IP      | 185.7.214.37  |
| Destination IP | 10.0.2.12     |
| VPN Device     | IvantiVPN01   |
| Realm          | Corporate_VPN |

#### 3. Splunk Query Used

```spl id="cs0271_vpn_query"
index=main "185.7.214.37" "sneha.khanna" sourcetype=vpn_logs
| table _time alert_status authentication_method destination_ip device_name device_type disconnect_reason session_status mfa_status realm Hostname source_ip Message user
```

#### 4. Full Unique Splunk Log Results

```text id="cs0271_vpn_results"
_time	alert_status	authentication_method	destination_ip	device_name	device_type	disconnect_reason	session_status	mfa_status	realm	Hostname	source_ip	Message	user
2025-01-29 11:25:00	Suspicious	MFA	10.0.2.12	IvantiVPN01	macOS 13x	Failed Authentication	None	Failed	Corporate_VPN	MAC-12432	185.7.214.37	User 'sneha.khanna' Realm 'Corporate_VPN' - MFA Challenge failed: Incorrect OTP entered	sneha.khanna
2025-01-29 11:25:00	Normal	MFA	10.0.2.12	IvantiVPN01	macOS 13x	None	Pending Authentication	OTP Sent	Corporate_VPN	MAC-12432	185.7.214.37	User 'sneha.khanna' Realm 'Corporate_VPN' - MFA Challenge initiated: OTP sent to registered mobile number	sneha.khanna
2025-01-29 11:25:00	suspiicous	Password	10.0.2.12	IvantiVPN01	macOS 13x	None	Authentication initiated	Prompted	Corporate_VPN	MAC-12432	185.7.214.37	User 'sneha.khanna' Realm 'Corporate_VPN' - Authentication initiated	sneha.khanna
2025-01-29 11:21:00	Suspicious	MFA	10.0.2.12	IvantiVPN01	macOS 13x	Failed Authentication	None	Failed	Corporate_VPN	MAC-12432	185.7.214.37	User 'sneha.khanna' Realm 'Corporate_VPN' - MFA Challenge failed: Incorrect OTP entered	sneha.khanna
2025-01-29 11:21:00	Normal	MFA	10.0.2.12	IvantiVPN01	macOS 13x	None	Pending Authentication	OTP Sent	Corporate_VPN	MAC-12432	185.7.214.37	User 'sneha.khanna' Realm 'Corporate_VPN' - MFA Challenge initiated: OTP sent to registered mobile number	sneha.khanna
2025-01-29 11:21:00	suspiicous	Password	10.0.2.12	IvantiVPN01	macOS 13x	None	Authentication initiated	Prompted	Corporate_VPN	MAC-12432	185.7.214.37	User 'sneha.khanna' Realm 'Corporate_VPN' - Authentication initiated	sneha.khanna
2025-01-29 11:20:00	Suspicious	MFA	10.0.2.12	IvantiVPN01	macOS 13x	Failed Authentication	None	Failed	Corporate_VPN	MAC-12432	185.7.214.37	User 'sneha.khanna' Realm 'Corporate_VPN' - MFA Challenge failed: Incorrect OTP entered	sneha.khanna
2025-01-29 11:20:00	Normal	MFA	10.0.2.12	IvantiVPN01	macOS 13x	None	Pending Authentication	OTP Sent	Corporate_VPN	MAC-12432	185.7.214.37	User 'sneha.khanna' Realm 'Corporate_VPN' - MFA Challenge initiated: OTP sent to registered mobile number	sneha.khanna
2025-01-29 11:20:00	suspiicous	Password	10.0.2.12	IvantiVPN01	macOS 13x	None	Authentication initiated	Prompted	Corporate_VPN	MAC-12432	185.7.214.37	User 'sneha.khanna' Realm 'Corporate_VPN' - Authentication initiated	sneha.khanna
```

**Evidence Note:** All unique VPN log rows provided for this ticket were preserved. No successful VPN session was observed in the provided evidence.

### 5. Authentication Pattern Review

| Observation                                              | Analyst Interpretation                 |
| -------------------------------------------------------- | -------------------------------------- |
| Multiple password authentication attempts observed       | Repeated suspicious VPN login activity |
| MFA challenges generated                                 | Authentication reached MFA stage       |
| MFA failures due to incorrect OTP                        | Unauthorized access was not completed  |
| Source IP had 100% abuse confidence                      | Strong malicious reputation indicator  |
| Source IP associated with hosting/transit infrastructure | Suspicious for normal VPN user login   |
| No successful VPN session observed                       | No confirmed VPN compromise            |

## Investigation Findings

1. VPN authentication attempts were observed for user `sneha.khanna`.
2. All attempts originated from source IP `185.7.214.37`.
3. The source IP is associated with a blacklisted/high-risk country or region.
4. The source IP has **100% abuse confidence**.
5. The source IP belongs to data center / web hosting / transit infrastructure.
6. The VPN destination was `10.0.2.12`.
7. The VPN device involved was `IvantiVPN01`.
8. Authentication was attempted against realm `Corporate_VPN`.
9. Password authentication was initiated multiple times.
10. MFA OTP challenges were generated.
11. MFA validation failed due to incorrect OTP entries.
12. No successful VPN session was observed.
13. Activity is consistent with suspicious VPN login behavior, possible credential stuffing, brute force, or attempted credential abuse.
14. MFA successfully prevented unauthorized access.

## Timeline of Events

| Time               | Event                                                                                   |
| ------------------ | --------------------------------------------------------------------------------------- |
| 2025-01-29 11:20   | Password authentication initiated for `sneha.khanna`                                    |
| 2025-01-29 11:20   | MFA challenge initiated and OTP sent to registered mobile number                        |
| 2025-01-29 11:20   | MFA challenge failed due to incorrect OTP                                               |
| 2025-01-29 11:21   | Additional password authentication and MFA failure observed                             |
| 2025-01-29 11:25   | Further authentication attempt and MFA failure observed                                 |
| Investigation Time | SOC reviewed VPN logs in Splunk                                                         |
| Investigation Time | SOC reviewed source IP reputation and confirmed 100% abuse confidence                   |
| Containment Time   | Source IP block and user credential reset completed/recommended                         |
| Closure Time       | Ticket closed after confirming no successful VPN session or harm from provided evidence |

## MITRE ATT&CK Mapping

| Tactic            | Technique                                      | ID    | Reason                                                                                         |
| ----------------- | ---------------------------------------------- | ----- | ---------------------------------------------------------------------------------------------- |
| Initial Access    | Valid Accounts                                 | T1078 | Attempted login against a valid corporate VPN account was observed                             |
| Initial Access    | External Remote Services                       | T1133 | Corporate VPN service was targeted as an external remote access service                        |
| Credential Access | Brute Force                                    | T1110 | Repeated authentication attempts were observed against the VPN account                         |
| Credential Access | Multi-Factor Authentication Request Generation | T1621 | MFA OTP challenges were generated during suspicious login attempts                             |
| Defense Evasion   | Proxy                                          | T1090 | Source IP belongs to hosting/transit infrastructure, which may be used to hide attacker origin |

**MITRE Note:** Suspicious VPN authentication and MFA challenge generation were observed. Successful VPN access, MFA bypass, endpoint compromise, lateral movement, and data exfiltration were not observed.

## Analyst Assessment

**Assessment:** **True Positive — Suspicious VPN Login from Blacklisted Country / No Successful Login**

The alert is valid because VPN authentication attempts were initiated from a blacklisted/high-risk source IP with **100% abuse confidence**.

The login attempts targeted a valid corporate VPN user account and reached the MFA stage. MFA failed due to incorrect OTP entries, which prevented unauthorized access.

The activity is consistent with:

1. Credential-stuffing attempt.
2. Password brute-force attempt.
3. Attempted use of exposed credentials.
4. Unauthorized VPN login attempt.
5. Use of high-risk hosting infrastructure to attempt access.

No successful VPN session was established.

## Impact Analysis

| Impact Area                            | Status                        |
| -------------------------------------- | ----------------------------- |
| Suspicious VPN login                   | Confirmed                     |
| Blacklisted country / high-risk source | Confirmed                     |
| Targeted user                          | sneha.khanna                  |
| Credential exposure                    | Possible                      |
| MFA challenge generated                | Confirmed                     |
| MFA failure                            | Confirmed                     |
| MFA bypass                             | Not observed                  |
| Successful VPN access                  | Not observed                  |
| Active VPN session                     | Not observed                  |
| Endpoint compromise                    | Not observed                  |
| Lateral movement                       | Not observed                  |
| Data exfiltration                      | Not observed                  |
| Business impact                        | Low                           |
| Security impact                        | Limited due to MFA protection |
| Residual risk                          | Low after containment         |

## Containment and Remediation

| Control Area   | Action                                                           |
| -------------- | ---------------------------------------------------------------- |
| VPN / Firewall | Block source IP `185.7.214.37`                                   |
| Identity       | Reset credentials for `sneha.khanna`                             |
| VPN            | Confirm no active session from suspicious IP                     |
| MFA            | Confirm MFA prevented unauthorized access                        |
| SIEM           | Add source IP and affected user to monitoring/watchlist          |
| SOC            | Monitor for repeated attempts against same user                  |
| SOC            | Monitor for similar attempts from related hosting infrastructure |

## Recommended Actions

1. Keep source IP `185.7.214.37` blocked on VPN/firewall controls.
2. Reset credentials for user `sneha.khanna`.
3. Revoke any active VPN sessions for the affected user.
4. Monitor `sneha.khanna` for additional failed or successful VPN attempts.
5. Review VPN logs for the same source IP targeting other users.
6. Review VPN logs for successful sessions from the same source IP.
7. Enforce account lockout or rate limiting for repeated VPN failures.
8. Keep MFA mandatory for all VPN access.
9. Review conditional access policies for risky IP reputation and blacklisted geographies.
10. Add high-abuse hosting IPs to VPN denylist after validation.
11. Educate the user about phishing, credential reuse, and unexpected MFA prompts.
12. Monitor for authentication attempts from related IP ranges or the same hosting provider.

## User Validation Questions

SOC should contact user `sneha.khanna` and confirm:

1. Were you attempting to log in to VPN between `2025-01-29 11:20–11:25`?
2. Were you using any third-party VPN, proxy, or privacy service?
3. Were you travelling or working from an unusual location?
4. Did you receive unexpected OTP or MFA notifications?
5. Did you approve, reject, or ignore any MFA prompt?
6. Did you recently enter your corporate credentials on any suspicious website?
7. Is `MAC-12432` your assigned device?
8. Did you notice any suspicious activity on your Mac device?

If the user confirms the activity was not initiated by them, the credential reset and source IP block should remain enforced.

## Escalation Decision

**Decision:** **No further escalation required after containment, unless new suspicious activity is identified.**

**Reason:** The login attempts came from a blacklisted/high-risk source and targeted a valid corporate VPN account. MFA blocked the attempts, and no successful VPN session, endpoint compromise, lateral movement, or data loss was observed.

Escalate to **SOC L2 / Identity Team / Endpoint Security** if any of the following occur:

1. Successful VPN login from the suspicious IP.
2. MFA approval from an unknown source.
3. Multiple users are targeted by the same source IP.
4. Repeated attempts continue after IP block.
5. User confirms the activity was not initiated by them and reports suspicious device behavior.
6. Suspicious mailbox, endpoint, or cloud activity appears.
7. Evidence of credential theft is identified.
8. Endpoint compromise indicators are found on `MAC-12432`.

## Final Ticket Closure Comment

SOC investigated ticket **CS-072 — VPN Login from Blacklisted Country** for user `sneha.khanna`. VPN logs showed repeated password authentication initiation from source IP `185.7.214.37` toward destination `10.0.2.12` on VPN device `IvantiVPN01` under realm `Corporate_VPN`. The alert triggered because the login originated from a blacklisted/high-risk region. Source IP `185.7.214.37` had **100% abuse confidence** and was associated with data center / web hosting / transit infrastructure. Splunk evidence confirmed repeated authentication initiation, MFA OTP challenge generation, and MFA failures due to incorrect OTP entries. No successful VPN session, MFA bypass, endpoint compromise, lateral movement, or data exfiltration was observed. Source IP blocking, user credential reset, user validation, and continued monitoring were completed/recommended. Ticket closed as **True Positive — Suspicious VPN Login from Blacklisted Country / MFA Prevented Unauthorized Access / No Confirmed Compromise**.

## Skills Demonstrated

VPN log analysis, Splunk investigation, blacklisted country login triage, bad-reputation IP review, suspicious authentication investigation, MFA failure analysis, IOC extraction, identity risk validation, MITRE ATT&CK mapping, containment recommendation, user validation, escalation decision-making, and SOC ticket documentation.

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
