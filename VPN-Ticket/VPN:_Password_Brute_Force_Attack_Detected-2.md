# SOC Analyst Investigation Report

## Ticket Overview

| Field             | Details                                                                          |
| ----------------- | -------------------------------------------------------------------------------- |
| Ticket ID         | CS-0273                                                                          |
| Alert Name        | VPN:- Password Brute Force Attack Detected                                       |
| Incident Category | VPN / Password Brute Force                                                       |
| Ticket Status     | Closed                                                                           |
| Priority / SLA    | High / Default SLA                                                               |
| Department        | Support                                                                          |
| Created Date      | 3/25/25 8:01 AM                                                                  |
| Closed By         | Ananda Das                                                                       |
| Detection Source  | VPN Logs / SIEM Splunk                                                           |
| Affected User     | `samuel.green`                                                                   |
| Affected Host     | ASD34365                                                                         |
| Analyst Decision  | **True Positive — VPN Password Brute Force Attempt / Account Lockout Triggered** |

## Executive Summary

A VPN brute-force alert was triggered for user **samuel.green** after multiple failed VPN authentication attempts were observed from the external source IP:

`185.141.132.26`

The authentication attempts targeted the corporate VPN realm:

`Corporate_VPN`

The VPN destination was:

`10.0.2.12`

Splunk VPN logs confirmed repeated password authentication initiation events, failed password authentication events due to incorrect password entry, and an account lockout event after the retry limit was exceeded.

The source IP had a low abuse confidence score of **8%**, but it was associated with **data center / web hosting / transit infrastructure** from Iran. Due to repeated failed authentication attempts and account lockout, SOC treated the activity as suspicious.

No successful VPN session was observed in the provided logs.

Final assessment: **True Positive VPN password brute-force attempt. Account lockout prevented further authentication attempts, and no successful VPN access or confirmed compromise was observed.**

## Alert Details

| Field          | Value                                                                                                                            |
| -------------- | -------------------------------------------------------------------------------------------------------------------------------- |
| Timestamp      | 3/24/2025 11:22                                                                                                                  |
| Source IP      | 185.141.132.26                                                                                                                   |
| Destination IP | 10.0.2.12                                                                                                                        |
| User           | samuel.green                                                                                                                     |
| Hostname       | ASD34365                                                                                                                         |
| Device Type    | MACOS                                                                                                                            |
| VPN Device     | IvantiVPN01                                                                                                                      |
| VPN Realm      | Corporate_VPN                                                                                                                    |
| Session Status | Authentication initiated / Failed Authentication / Account Lockout                                                               |
| Message        | User `samuel.green` Realm `Corporate_VPN` - Authentication initiated, failed, and account locked due to multiple failed attempts |
| Final Verdict  | True Positive                                                                                                                    |

## Source IP Reputation Analysis

| Field            | Value                               |
| ---------------- | ----------------------------------- |
| Source IP        | 185.141.132.26                      |
| Abuse Confidence | 8%                                  |
| ISP              | Sefroyek Pardaz Engineering Company |
| Usage Type       | Data Center / Web Hosting / Transit |
| ASN              | AS48715                             |
| Domain Name      | shahrad.net                         |
| Country          | Iran                                |
| City             | Tehran, Tehran                      |

### Source IP Assessment

The source IP `185.141.132.26` had only **8% abuse confidence**, but the activity was still suspicious because the IP belongs to hosting/transit infrastructure and generated repeated failed VPN authentication attempts against a valid corporate account.

The account lockout event confirms that multiple failed authentication attempts occurred within a short time window.

## Affected Assets / Entities

| Asset / Entity              | Details                          |
| --------------------------- | -------------------------------- |
| Affected User               | samuel.green                     |
| Hostname                    | ASD34365                         |
| Device Type                 | macOS / MACOS                    |
| VPN Device                  | IvantiVPN01                      |
| VPN Destination IP          | 10.0.2.12                        |
| VPN Realm                   | Corporate_VPN                    |
| Source IP                   | 185.141.132.26                   |
| Attack Type                 | VPN password brute-force attempt |
| Authentication Method       | Password                         |
| Final Authentication Result | Account lockout                  |
| Successful VPN Session      | Not observed                     |

## IOCs / Indicators Identified

| IOC Type               | Indicator                               |
| ---------------------- | --------------------------------------- |
| Source IP              | 185.141.132.26                          |
| Destination IP         | 10.0.2.12                               |
| Affected User          | samuel.green                            |
| Hostname               | ASD34365                                |
| Device Type            | macOS 13x                               |
| VPN Device             | IvantiVPN01                             |
| VPN Realm              | Corporate_VPN                           |
| Source ISP             | Sefroyek Pardaz Engineering Company     |
| Source Domain          | shahrad.net                             |
| Source Country         | Iran                                    |
| Abuse Confidence       | 8%                                      |
| Authentication Method  | Password                                |
| Session Status         | Failed Authentication / Account Lockout |
| Attack Type            | VPN Password Brute Force                |
| Successful VPN Session | Not observed                            |

## SIEM / Splunk Analysis

### Investigation Flow

#### 1. Alert Review

SOC reviewed the VPN brute-force alert for user `samuel.green`. The alert indicated repeated VPN authentication failures from source IP `185.141.132.26`.

The alert was treated as suspicious because the activity targeted a valid corporate VPN user account and resulted in account lockout.

#### 2. Entity Identification

| Entity         | Value          |
| -------------- | -------------- |
| User           | samuel.green   |
| Hostname       | ASD34365       |
| Device Type    | macOS / MACOS  |
| Source IP      | 185.141.132.26 |
| Destination IP | 10.0.2.12      |
| VPN Device     | IvantiVPN01    |
| VPN Realm      | Corporate_VPN  |

#### 3. Splunk Query Used

```spl id="cs0273_vpn_query"
index=main "185.141.132.26" user="samuel.green" sourcetype=vpn_logs
| table _time alert_status authentication_method destination_ip device_name device_type disconnect_reason session_status mfa_status realm Hostname source_ip Message user
```

#### 4. Full Unique Splunk Log Results

```text id="cs0273_vpn_results"
_time	alert_status	authentication_method	destination_ip	device_name	device_type	disconnect_reason	session_status	mfa_status	realm	Hostname	source_ip	Message	user
2025-03-24 11:22:00	High	None	10.0.2.12	IvantiVPN01	macOS 13x	Account Lockout Exceeded Retry Limit	Account Lockout	None	Corporate_VPN	ASD34365	185.141.132.26	User 'samuel.green' Realm 'Corporate_VPN' - Account locked due to multiple failed authentication attempts	samuel.green
2025-03-24 11:22:00	Normal	Password	10.0.2.12	IvantiVPN01	macOS 13x	None	Failed Authentication	Failed	Corporate_VPN	ASD34365	185.141.132.26	User 'samuel.green' Realm 'Corporate_VPN' - Authentication failed: Incorrect password entered	samuel.green
2025-03-24 11:22:00	suspiicous	Password	10.0.2.12	IvantiVPN01	macOS 13x	None	Authentication initiated	Prompted	Corporate_VPN	ASD34365	185.141.132.26	User 'samuel.green' Realm 'Corporate_VPN' - Authentication initiated	samuel.green
2025-03-24 11:21:00	Normal	Password	10.0.2.12	IvantiVPN01	macOS 13x	None	Failed Authentication	Failed	Corporate_VPN	ASD34365	185.141.132.26	User 'samuel.green' Realm 'Corporate_VPN' - Authentication failed: Incorrect password entered	samuel.green
2025-03-24 11:21:00	suspiicous	Password	10.0.2.12	IvantiVPN01	macOS 13x	None	Authentication initiated	Prompted	Corporate_VPN	ASD34365	185.141.132.26	User 'samuel.green' Realm 'Corporate_VPN' - Authentication initiated	samuel.green
```

**Evidence Note:** Exact duplicate VPN log rows were removed. All unique VPN log events provided for this ticket were preserved.

### 5. Authentication Pattern Review

| Observation                               | Analyst Interpretation                |
| ----------------------------------------- | ------------------------------------- |
| Multiple authentication attempts observed | Indicates brute-force behavior        |
| Failed password events observed           | Incorrect password attempts confirmed |
| Same source IP used repeatedly            | Single-source attack pattern          |
| Same user targeted repeatedly             | Account-specific brute-force attempt  |
| Account lockout triggered                 | Retry limit exceeded                  |
| No successful VPN session observed        | No confirmed VPN compromise           |
| Source IP tied to hosting infrastructure  | Suspicious for normal VPN user login  |

## Investigation Findings

1. Multiple VPN authentication attempts were observed for user `samuel.green`.
2. All attempts originated from source IP `185.141.132.26`.
3. The VPN destination was `10.0.2.12`.
4. The VPN device involved was `IvantiVPN01`.
5. Authentication was attempted against realm `Corporate_VPN`.
6. Password authentication was initiated multiple times.
7. Multiple failed password authentication events were observed.
8. The account was locked due to exceeding the retry limit.
9. No successful VPN session was observed.
10. Source IP reputation score was low at 8%, but the IP belongs to data center / hosting infrastructure.
11. Activity is consistent with a VPN password brute-force attempt.
12. Account lockout helped prevent further authentication attempts.

## Timeline of Events

| Time               | Event                                                             |
| ------------------ | ----------------------------------------------------------------- |
| 2025-03-24 11:21   | Password authentication initiated for `samuel.green`              |
| 2025-03-24 11:21   | Authentication failed due to incorrect password                   |
| 2025-03-24 11:22   | Additional password authentication attempt observed               |
| 2025-03-24 11:22   | Repeated failed authentication event observed                     |
| 2025-03-24 11:22   | Account locked due to multiple failed authentication attempts     |
| Investigation Time | SOC reviewed VPN logs in Splunk                                   |
| Investigation Time | SOC reviewed source IP reputation and hosting details             |
| Containment Time   | IT Helpdesk contacted for credential reset/account unlock process |
| Containment Time   | Source IP block requested/performed                               |
| Closure Time       | Ticket closed after confirming no successful VPN session or harm  |

## MITRE ATT&CK Mapping

| Tactic            | Technique                | ID        | Reason                                                                                         |
| ----------------- | ------------------------ | --------- | ---------------------------------------------------------------------------------------------- |
| Credential Access | Brute Force              | T1110     | Multiple failed password attempts were observed against the VPN account                        |
| Credential Access | Password Guessing        | T1110.001 | Repeated incorrect password attempts were observed                                             |
| Initial Access    | Valid Accounts           | T1078     | Attempted use of valid corporate user account `samuel.green` was observed                      |
| Initial Access    | External Remote Services | T1133     | Corporate VPN service was targeted as an external remote access service                        |
| Defense Evasion   | Proxy                    | T1090     | Source IP belongs to hosting/transit infrastructure, which may be used to hide attacker origin |

**MITRE Note:** Password-based brute-force activity was observed. MFA activity was not observed in the provided log set, and the account lockout occurred before any successful VPN session was established.

## Analyst Assessment

**Assessment:** **True Positive — VPN Password Brute Force Attempt / Account Lockout Triggered**

The alert is valid because multiple failed VPN password authentication attempts were observed against the same user account from the same external source IP.

The evidence shows authentication initiation, incorrect password failures, and account lockout due to multiple failed authentication attempts. No successful VPN session was observed.

Although the source IP reputation score was low, the use of data center / hosting infrastructure and the failed authentication pattern support a suspicious brute-force assessment.

The activity is consistent with:

1. Password brute-force attempt.
2. Password guessing attempt.
3. Credential-stuffing attempt.
4. Attempted use of exposed credentials.
5. Unauthorized VPN access attempt.

## Impact Analysis

| Impact Area                  | Status                         |
| ---------------------------- | ------------------------------ |
| Password brute-force attempt | Confirmed                      |
| Targeted user                | samuel.green                   |
| Account lockout              | Confirmed                      |
| Credential exposure          | Possible                       |
| Successful VPN login         | Not observed                   |
| MFA bypass                   | Not applicable / not reached   |
| Endpoint compromise          | Not observed                   |
| Lateral movement             | Not observed                   |
| Data exfiltration            | Not observed                   |
| Business impact              | Low to Medium                  |
| Security impact              | Limited due to account lockout |
| Residual risk                | Low after containment          |

### Impact Summary

The attack caused an account lockout for user `samuel.green`, which may have temporarily impacted the user’s VPN access. However, no successful VPN session was observed, and no endpoint compromise, lateral movement, or data exfiltration was identified from the provided logs.

## Containment and Remediation

| Control Area           | Action                                                                  |
| ---------------------- | ----------------------------------------------------------------------- |
| VPN / Firewall         | Block source IP `185.141.132.26`                                        |
| Identity / IT Helpdesk | Reset credentials for `samuel.green`                                    |
| Identity / IT Helpdesk | Unlock account after validation                                         |
| VPN                    | Confirm no successful active VPN session from suspicious IP             |
| SIEM                   | Add source IP and user to monitoring/watchlist                          |
| SOC                    | Monitor for repeated attempts against same user                         |
| SOC                    | Monitor for similar attempts from related IP ranges or hosting provider |

## Recommended Actions

1. Keep source IP `185.141.132.26` blocked on VPN/firewall controls.
2. Reset and re-enable the user account through IT Helpdesk after user validation.
3. Monitor `samuel.green` for additional failed or successful VPN attempts.
4. Review VPN logs for the same source IP targeting other users.
5. Review VPN logs for successful sessions from the same source IP.
6. Enforce account lockout and rate-limiting policies for repeated VPN failures.
7. Keep MFA enforced for all VPN access.
8. Review conditional access rules for data center / hosting IP sources.
9. Educate the user about phishing, credential reuse, and password hygiene.
10. Review whether the user’s credentials may have been exposed.
11. Monitor related IP ranges from the same ISP or hosting provider.

## User Validation Questions

SOC should contact user `samuel.green` and confirm:

1. Were you attempting to log in to VPN around `2025-03-24 11:21–11:22`?
2. Did you face an account lockout at that time?
3. Were you entering the wrong password repeatedly?
4. Were you travelling or using any third-party VPN/proxy service?
5. Did you recently enter your corporate password on any suspicious website?
6. Did you receive any suspicious email or link before the lockout?
7. Is `ASD34365` your assigned device?
8. Did you notice any suspicious activity on your Mac device?

If the user denies the activity, the password reset and IP block should remain enforced, and endpoint validation should be considered.

## Escalation Decision

**Decision:** **IT Helpdesk coordination required. No further SOC escalation required after containment unless additional suspicious activity is identified.**

**Reason:** The incident was confirmed as a password brute-force attempt resulting in account lockout. No successful VPN session, endpoint compromise, lateral movement, or data loss was observed. IT Helpdesk support was required to reset/unlock the affected account credentials.

Escalate to **SOC L2 / Identity Team / Endpoint Security** if any of the following occur:

1. Successful VPN login from suspicious IP.
2. Repeated attempts continue after IP block.
3. Same source IP targets multiple users.
4. User denies the activity and reports suspicious device behavior.
5. Suspicious mailbox, endpoint, or cloud activity appears.
6. Evidence of credential theft is identified.
7. Account lockouts continue repeatedly for the same user.
8. Endpoint compromise indicators are identified on `ASD34365`.

## Final Ticket Closure Comment

SOC investigated ticket **CS-0273 — VPN Password Brute Force Attack Detected** for user `samuel.green`. VPN logs showed repeated password authentication initiation from source IP `185.141.132.26` toward destination `10.0.2.12` on VPN device `IvantiVPN01` under realm `Corporate_VPN`. The activity included multiple failed password authentication events due to incorrect password entry and resulted in account lockout after the retry limit was exceeded. The source IP had **8% abuse confidence**, but it was associated with data center / web hosting / transit infrastructure from Iran, making the activity suspicious when combined with the failed login pattern. No successful VPN session, endpoint compromise, lateral movement, or data exfiltration was observed. IT Helpdesk coordination was required to reset/unlock the account, the source IP was blocked/recommended for blocking, and continued monitoring was advised. Ticket closed as **True Positive — VPN Password Brute Force Attempt / Account Lockout Triggered / No Successful VPN Session Observed**.

## Skills Demonstrated

VPN log analysis, Splunk investigation, password brute-force triage, failed authentication review, account lockout analysis, source IP reputation review, IOC extraction, identity risk validation, MITRE ATT&CK mapping, IT Helpdesk coordination, containment recommendation, user validation, escalation decision-making, and SOC ticket documentation.
