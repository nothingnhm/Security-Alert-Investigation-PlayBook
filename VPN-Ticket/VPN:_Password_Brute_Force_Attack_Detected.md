# SOC Analyst Investigation Report

## Ticket Overview

| Field             | Details                                                                         |
| ----------------- | ------------------------------------------------------------------------------- |
| Ticket ID         | CS-068                                                                         |
| Alert Name        | VPN:- Password Brute Force Attack Detected                                      |
| Incident Category | VPN / Authentication Attack                                                     |
| Ticket Status     | Closed                                                                          |
| Priority / SLA    | Normal / Default SLA                                                            |
| Department        | Support                                                                         |
| Created Date      | 3/23/25 2:13 PM                                                                 |
| Closed By         | Ananda Das                                                                      |
| Detection Source  | VPN Logs / SIEM Splunk                                                          |
| Affected User     | `ajay.malhotra`                                                                 |
| Affected Host     | SHDM5433                                                                        |
| Analyst Decision  | **True Positive — VPN Brute Force Attempt / MFA Prevented Unauthorized Access** |

## Executive Summary

A VPN brute-force alert was triggered for user **ajay.malhotra** after repeated authentication attempts were observed against the corporate VPN service.

All attempts originated from the external source IP:

`103.91.136.18`

The authentication attempts targeted the VPN destination:

`10.0.2.12`

The affected VPN realm was:

`Corporate_VPN`

Splunk VPN logs showed repeated password authentication initiation events followed by MFA OTP challenges. Multiple MFA failures were recorded because incorrect OTP values were entered. No successful VPN session was observed in the provided evidence.

Source IP reputation showed **100% abuse confidence**, making the source highly suspicious. The activity is consistent with a VPN brute-force or credential-stuffing attempt against a valid user account.

Final assessment: **True Positive VPN brute-force attempt. MFA prevented unauthorized access, and no confirmed VPN compromise was observed.**

## Alert Details

| Field          | Value                                                                 |
| -------------- | --------------------------------------------------------------------- |
| Timestamp      | 3/16/2025 17:11                                                       |
| Source IP      | 103.91.136.18                                                         |
| Destination IP | 10.0.2.12                                                             |
| User           | ajay.malhotra                                                         |
| Hostname       | SHDM5433                                                              |
| Device Type    | Windows 11                                                            |
| VPN Device     | IvantiVPN01                                                           |
| VPN Realm      | Corporate_VPN                                                         |
| Session Status | Authentication initiated                                              |
| Message        | User `ajay.malhotra` Realm `Corporate_VPN` - Authentication initiated |
| Final Verdict  | True Positive                                                         |

## Affected Assets

| Asset / Entity     | Details                                                |
| ------------------ | ------------------------------------------------------ |
| Affected User      | `ajay.malhotra`                                        |
| Hostname           | SHDM5433                                               |
| Device Type        | Windows 11                                             |
| VPN Device         | IvantiVPN01                                            |
| VPN Destination IP | 10.0.2.12                                              |
| VPN Realm          | Corporate_VPN                                          |
| Source IP          | 103.91.136.18                                          |
| Attack Type        | VPN password brute-force / credential-stuffing attempt |

## Evidence Reviewed

### Source IP Reputation

| Field            | Value                       |
| ---------------- | --------------------------- |
| Source IP        | 103.91.136.18               |
| Abuse Confidence | 100%                        |
| ISP              | Trinn Techologies Pvt. Ltd. |
| Usage Type       | Unknown                     |
| ASN              | Unknown                     |
| Domain Name      | trinn.in                    |
| Country          | India                       |
| City             | Chhawala, Delhi             |

### Source IP Assessment

The source IP `103.91.136.18` had a **100% abuse confidence score** and was associated with repeated VPN authentication attempts against the same user account. Based on the suspicious authentication pattern and high-risk IP reputation, the source was treated as malicious and recommended for blocking.

## IOCs / Indicators Identified

| IOC Type       | Indicator                                        |
| -------------- | ------------------------------------------------ |
| Source IP      | 103.91.136.18                                    |
| Destination IP | 10.0.2.12                                        |
| Affected User  | ajay.malhotra                                    |
| Hostname       | SHDM5433                                         |
| VPN Device     | IvantiVPN01                                      |
| VPN Realm      | Corporate_VPN                                    |
| Device Type    | Windows 11                                       |
| ISP            | Trinn Techologies Pvt. Ltd.                      |
| Domain         | trinn.in                                         |
| Attack Type    | Password Brute Force / VPN Authentication Attack |
| MFA Status     | Failed                                           |
| Session Status | No successful VPN session observed               |

## SIEM / Splunk Analysis

### Investigation Flow

#### 1. Alert Review

SOC reviewed the VPN brute-force alert for user `ajay.malhotra`. The alert indicated authentication activity from external source IP `103.91.136.18` against the corporate VPN.

The activity was suspicious because the same user account was repeatedly targeted, MFA challenges were generated, and multiple MFA failures were observed.

#### 2. Entity Identification

| Entity         | Value         |
| -------------- | ------------- |
| User           | ajay.malhotra |
| Hostname       | SHDM5433      |
| Device Type    | Windows 11    |
| Source IP      | 103.91.136.18 |
| Destination IP | 10.0.2.12     |
| VPN Device     | IvantiVPN01   |
| Realm          | Corporate_VPN |

#### 3. Splunk Query Used

```spl id="cs0264_vpn_query"
index=main "103.91.136.18" "ajay.malhotra" sourcetype=vpn_logs
| table _time alert_status authentication_method destination_ip device_name device_type disconnect_reason session_status mfa_status realm Hostname source_ip Message user
```

#### 4. Full Unique Splunk Log Results

```text id="cs0264_vpn_results"
_time	alert_status	authentication_method	destination_ip	device_name	device_type	disconnect_reason	session_status	mfa_status	realm	Hostname	source_ip	Message	user
2025-03-16 17:27:00	Suspicious	MFA	10.0.2.12	IvantiVPN01	Windows 11	Failed Authentication	None	Failed	Corporate_VPN	SHDM5433	103.91.136.18	User 'ajay.malhotra' Realm 'Corporate_VPN' - MFA Challenge failed: Incorrect OTP entered	ajay.malhotra
2025-03-16 17:25:00	Normal	MFA	10.0.2.12	IvantiVPN01	Windows 11	None	Pending Authentication	OTP Sent	Corporate_VPN	SHDM5433	103.91.136.18	User 'ajay.malhotra' Realm 'Corporate_VPN' - MFA Challenge initiated: OTP sent to registered mobile number	ajay.malhotra
2025-03-16 17:14:00	Suspicious	MFA	10.0.2.12	IvantiVPN01	Windows 11	Failed Authentication	None	Failed	Corporate_VPN	SHDM5433	103.91.136.18	User 'ajay.malhotra' Realm 'Corporate_VPN' - MFA Challenge failed: Incorrect OTP entered	ajay.malhotra
2025-03-16 17:14:00	Normal	MFA	10.0.2.12	IvantiVPN01	Windows 11	None	Pending Authentication	OTP Sent	Corporate_VPN	SHDM5433	103.91.136.18	User 'ajay.malhotra' Realm 'Corporate_VPN' - MFA Challenge initiated: OTP sent to registered mobile number	ajay.malhotra
2025-03-16 17:13:00	Suspicious	MFA	10.0.2.12	IvantiVPN01	Windows 11	Failed Authentication	None	Failed	Corporate_VPN	SHDM5433	103.91.136.18	User 'ajay.malhotra' Realm 'Corporate_VPN' - MFA Challenge failed: Incorrect OTP entered	ajay.malhotra
2025-03-16 17:13:00	Normal	MFA	10.0.2.12	IvantiVPN01	Windows 11	None	Pending Authentication	OTP Sent	Corporate_VPN	SHDM5433	103.91.136.18	User 'ajay.malhotra' Realm 'Corporate_VPN' - MFA Challenge initiated: OTP sent to registered mobile number	ajay.malhotra
2025-03-16 17:12:00	Suspicious	MFA	10.0.2.12	IvantiVPN01	Windows 11	Failed Authentication	None	Failed	Corporate_VPN	SHDM5433	103.91.136.18	User 'ajay.malhotra' Realm 'Corporate_VPN' - MFA Challenge failed: Incorrect OTP entered	ajay.malhotra
2025-03-16 17:12:00	Normal	MFA	10.0.2.12	IvantiVPN01	Windows 11	None	Pending Authentication	OTP Sent	Corporate_VPN	SHDM5433	103.91.136.18	User 'ajay.malhotra' Realm 'Corporate_VPN' - MFA Challenge initiated: OTP sent to registered mobile number	ajay.malhotra
2025-03-16 17:11:00	Suspicious	MFA	10.0.2.12	IvantiVPN01	Windows 11	Failed Authentication	None	Failed	Corporate_VPN	SHDM5433	103.91.136.18	User 'ajay.malhotra' Realm 'Corporate_VPN' - MFA Challenge failed: Incorrect OTP entered	ajay.malhotra
2025-03-16 17:11:00	Normal	MFA	10.0.2.12	IvantiVPN01	Windows 11	None	Pending Authentication	OTP Sent	Corporate_VPN	SHDM5433	103.91.136.18	User 'ajay.malhotra' Realm 'Corporate_VPN' - MFA Challenge initiated: OTP sent to registered mobile number	ajay.malhotra
2025-03-16 17:14:00	suspiicous	Password	10.0.2.12	IvantiVPN01	Windows 11	None	Authentication initiated	Prompted	Corporate_VPN	SHDM5433	103.91.136.18	User 'ajay.malhotra' Realm 'Corporate_VPN' - Authentication initiated	ajay.malhotra
2025-03-16 17:13:00	suspiicous	Password	10.0.2.12	IvantiVPN01	Windows 11	None	Authentication initiated	Prompted	Corporate_VPN	SHDM5433	103.91.136.18	User 'ajay.malhotra' Realm 'Corporate_VPN' - Authentication initiated	ajay.malhotra
2025-03-16 17:12:00	suspiicous	Password	10.0.2.12	IvantiVPN01	Windows 11	None	Authentication initiated	Prompted	Corporate_VPN	SHDM5433	103.91.136.18	User 'ajay.malhotra' Realm 'Corporate_VPN' - Authentication initiated	ajay.malhotra
2025-03-16 17:11:00	suspiicous	Password	10.0.2.12	IvantiVPN01	Windows 11	None	Authentication initiated	Prompted	Corporate_VPN	SHDM5433	103.91.136.18	User 'ajay.malhotra' Realm 'Corporate_VPN' - Authentication initiated	ajay.malhotra
```

**Evidence Note:** Exact duplicate VPN log rows were removed from the final evidence table. Unique evidence was preserved.

### 5. VPN Authentication Pattern Review

| Observation                                        | Analyst Interpretation                                  |
| -------------------------------------------------- | ------------------------------------------------------- |
| Multiple password authentication attempts observed | Indicates brute-force or credential-stuffing behavior   |
| Same source IP used repeatedly                     | Supports single-source attack pattern                   |
| Same user targeted repeatedly                      | Account-specific attack attempt                         |
| MFA OTP challenges generated                       | Password step may have passed or triggered MFA workflow |
| MFA failures due to incorrect OTP                  | Unauthorized access was not completed                   |
| No successful VPN session observed                 | No confirmed VPN compromise                             |
| Source IP has 100% abuse confidence                | Strong malicious reputation indicator                   |

### 6. Timeline of Events

| Time               | Event                                                        |
| ------------------ | ------------------------------------------------------------ |
| 2025-03-16 17:11   | Password authentication initiated for `ajay.malhotra`        |
| 2025-03-16 17:11   | MFA challenge initiated and OTP sent                         |
| 2025-03-16 17:11   | MFA challenge failed due to incorrect OTP                    |
| 2025-03-16 17:12   | Repeated password authentication and MFA failure observed    |
| 2025-03-16 17:13   | Additional authentication attempts and MFA failures observed |
| 2025-03-16 17:14   | Further authentication attempt and MFA failure observed      |
| 2025-03-16 17:25   | Another MFA challenge initiated and OTP sent                 |
| 2025-03-16 17:27   | MFA challenge failed due to incorrect OTP                    |
| Investigation Time | SOC confirmed no successful VPN session                      |
| Containment Time   | Source IP blocked and user credentials reset                 |
| Closure Time       | Ticket closed after no successful compromise was observed    |

## MITRE ATT&CK Mapping

| Tactic            | Technique                                      | ID    | Reason                                                                                           |
| ----------------- | ---------------------------------------------- | ----- | ------------------------------------------------------------------------------------------------ |
| Credential Access | Brute Force                                    | T1110 | Multiple repeated VPN authentication attempts were observed                                      |
| Initial Access    | Valid Accounts                                 | T1078 | A valid user account was targeted against the corporate VPN; successful access was not confirmed |
| Credential Access | Multi-Factor Authentication Request Generation | T1621 | MFA challenges were repeatedly generated during the authentication attempts                      |
| Initial Access    | External Remote Services                       | T1133 | VPN service was targeted as an external remote access service                                    |

**MITRE Note:** Brute-force activity and MFA challenge generation were observed. Successful VPN access, MFA bypass, lateral movement, endpoint compromise, and data exfiltration were not observed.

## Analyst Assessment

**Assessment:** **True Positive — VPN Brute Force Attempt / No Successful Login**

The alert is valid because multiple VPN authentication attempts were observed against the same user account from a suspicious external IP with **100% abuse confidence**.

The activity is consistent with a VPN brute-force or credential-stuffing attempt. MFA prevented the attacker from completing authentication, and no successful VPN session was identified in the provided logs.

The possibility of password exposure cannot be fully ruled out because the authentication flow reached MFA challenge stages. For this reason, user credential reset and account monitoring were appropriate containment actions.

## Impact Analysis

| Impact Area             | Status                        |
| ----------------------- | ----------------------------- |
| Brute-force attempt     | Confirmed                     |
| Targeted user           | ajay.malhotra                 |
| Credential exposure     | Possible                      |
| MFA challenge generated | Confirmed                     |
| MFA failure             | Confirmed                     |
| MFA bypass              | Not observed                  |
| Successful VPN access   | Not observed                  |
| Active VPN session      | Not observed                  |
| Endpoint compromise     | Not observed                  |
| Lateral movement        | Not observed                  |
| Data exfiltration       | Not observed                  |
| Business impact         | Low                           |
| Security impact         | Limited due to MFA protection |

## Recommended Actions

1. Keep source IP `103.91.136.18` blocked on VPN/firewall controls.
2. Reset the password for user `ajay.malhotra`.
3. Revoke any active VPN sessions for the affected user.
4. Review VPN logs for successful sessions from the same source IP.
5. Review VPN logs for the same source IP targeting other users.
6. Monitor `ajay.malhotra` for additional failed login attempts.
7. Monitor for login attempts from related IP ranges or the same ISP.
8. Keep MFA enforced for all VPN users.
9. Review conditional access or VPN access policies for high-abuse IPs.
10. Enable account lockout or rate limiting for repeated VPN failures.
11. Educate the user about phishing, credential reuse, and unexpected MFA prompts.
12. Add source IP, user, and VPN realm to SIEM watchlists for short-term monitoring.

## Containment and Remediation

| Control Area   | Action                                              |
| -------------- | --------------------------------------------------- |
| VPN / Firewall | Block source IP `103.91.136.18`                     |
| Identity       | Reset user credentials for `ajay.malhotra`          |
| VPN            | Confirm no active session from suspicious IP        |
| MFA            | Confirm MFA prevented unauthorized access           |
| SIEM           | Add source IP and user to monitoring/watchlist      |
| SOC            | Monitor for repeated attempts against same user     |
| SOC            | Monitor for similar attempts from related IP ranges |

## User Validation Questions

SOC should contact user `ajay.malhotra` and confirm:

1. Were you attempting to log in to VPN around `2025-03-16 17:11–17:27`?
2. Did you receive unexpected OTP or MFA notifications?
3. Did you approve, reject, or ignore any MFA prompt?
4. Did you recently enter your password on any suspicious website?
5. Have you reused this password on any external website?
6. Did you notice any suspicious activity on your account or endpoint?
7. Were you located near the source IP region at the time of the attempts?

If the user confirms the activity was not initiated by them, the password reset and IP block should remain enforced.

## Escalation Decision

**Decision:** **No further escalation required after containment.**

**Reason:** The incident was confirmed as a VPN brute-force attempt, but MFA prevented unauthorized access. No successful VPN session, MFA bypass, endpoint compromise, lateral movement, or data exfiltration was observed in the provided logs.

Escalate to **SOC L2 / Identity Team** if any of the following are identified:

1. Successful VPN login from suspicious IP.
2. MFA approval from unknown source.
3. Multiple users targeted by the same source IP.
4. Repeated attempts continue after IP block.
5. Suspicious mailbox, endpoint, or cloud activity appears.
6. Evidence of credential theft is identified.
7. User confirms the login attempts were not legitimate and additional suspicious activity is found.

## Final Ticket Closure Comment

SOC investigated ticket **CS-068 — VPN Password Brute Force Attack Detected** for user `ajay.malhotra`. VPN logs showed repeated password authentication initiation from external source IP `103.91.136.18` toward VPN destination `10.0.2.12` on VPN device `IvantiVPN01` under realm `Corporate_VPN`. The activity generated multiple MFA OTP challenges, followed by repeated MFA failures due to incorrect OTP entries. The source IP had **100% abuse confidence**, and the pattern was consistent with a brute-force or credential-stuffing attempt against a valid VPN account. No successful VPN session, MFA bypass, endpoint compromise, lateral movement, or data exfiltration was observed. Source IP `103.91.136.18` was blocked, user credentials for `ajay.malhotra` were reset, and continued monitoring was recommended. Ticket closed as **True Positive — VPN Brute Force Attempt / MFA Prevented Unauthorized Access / No Confirmed Compromise**.

## Skills Demonstrated

VPN log analysis, Splunk investigation, authentication event triage, brute-force detection, MFA failure analysis, source IP reputation review, IOC extraction, account compromise validation, MITRE ATT&CK mapping, containment planning, user validation, escalation decision-making, and SOC ticket documentation.

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
