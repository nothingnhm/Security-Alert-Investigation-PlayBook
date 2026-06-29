# SOC Analyst Investigation Report

## Ticket Overview

| Field                      | Details                                                                                    |
| -------------------------- | ------------------------------------------------------------------------------------------ |
| Ticket ID                  | CS-0275                                                                                    |
| Alert Name                 | VPN:- User Login from Geographically Distant Locations in Short Duration                   |
| Incident Category          | VPN / Impossible Travel Indicator                                                          |
| Ticket Status              | Closed                                                                                     |
| Priority / SLA             | High / Default SLA                                                                         |
| Department                 | Support                                                                                    |
| Created Date               | 3/25/25 8:38 AM                                                                            |
| Closed By                  | Ananda Das                                                                                 |
| Detection Source           | VPN Logs / SIEM Splunk                                                                     |
| Affected User              | `sumer.dewan`                                                                              |
| Primary Known Hostname     | ENDP-774                                                                                   |
| Additional Device Observed | Samsung-G991B                                                                              |
| Analyst Decision           | **True Positive Alert Condition — Impossible Travel Indicator / User Validation Required** |

## Executive Summary

A VPN security alert was triggered for user **sumer.dewan** after two successful VPN sessions were observed from geographically distant locations within a short time window.

The first VPN session was observed from the user’s usual source IP:

`49.205.10.20`

This IP was associated with **Vijayawada, Andhra Pradesh, India**.

A second VPN session was observed approximately **11 minutes later** from:

`89.187.160.12`

This IP was associated with **Tokyo, Japan** and belonged to **data center / web hosting / transit infrastructure**.

The second login used an Android device:

`Samsung-G991B`

Splunk logs showed password authentication initiation, MFA challenge generation, successful authentication, active VPN session creation with `FullAccess`, and later idle timeout.

Because the same user account logged in from India and Japan within approximately 11 minutes, the alert condition was valid and consistent with an **impossible travel indicator**. The second source IP being tied to data center infrastructure increased suspicion.

Final assessment: **Suspicious VPN login / impossible travel indicator. No brute-force pattern, MFA failure, endpoint compromise, lateral movement, or data exfiltration was observed from the provided logs, but user validation and device compliance review were required.**

## Alert Details

| Field              | Value                                               |
| ------------------ | --------------------------------------------------- |
| First Timestamp    | 3/25/2025 10:34                                     |
| First Source IP    | 49.205.10.20                                        |
| First Location     | Vijayawada, Andhra Pradesh, India                   |
| First Hostname     | ENDP-774                                            |
| First Device Type  | Windows 11                                          |
| Second Timestamp   | 3/25/2025 10:45                                     |
| Second Source IP   | 89.187.160.12                                       |
| Second Location    | Tokyo, Japan                                        |
| Second Hostname    | Samsung-G991B                                       |
| Second Device Type | Android OS                                          |
| User               | sumer.dewan                                         |
| Destination IP     | 10.0.2.12                                           |
| VPN Realm          | Corporate_VPN                                       |
| VPN Role           | FullAccess                                          |
| Session Status     | Active                                              |
| Alert Reason       | Geographically distant VPN logins in short duration |

## Source IP and Location Analysis

### First / Usual Login Source

| Field       | Value                      |
| ----------- | -------------------------- |
| Source IP   | 49.205.10.20               |
| ISP         | ACT-Guntur                 |
| Usage Type  | Unknown                    |
| ASN         | Unknown                    |
| Hostname    | broadband.actcorp.in       |
| Domain Name | actcorp.in                 |
| Country     | India                      |
| City        | Vijayawada, Andhra Pradesh |
| Assessment  | User usual login source    |

### Second / Suspicious Login Source

| Field       | Value                                                          |
| ----------- | -------------------------------------------------------------- |
| Source IP   | 89.187.160.12                                                  |
| ISP         | CDN77 Tokyo                                                    |
| Usage Type  | Data Center / Web Hosting / Transit                            |
| ASN         | AS60068                                                        |
| Hostname    | 181461758.tyo.cdn77.com                                        |
| Domain Name | cdn77.com                                                      |
| Country     | Japan                                                          |
| City        | Tokyo                                                          |
| Assessment  | Suspicious due to impossible travel and hosting infrastructure |

### Location Assessment

The user had VPN activity from **India** and then from **Japan** within approximately **11 minutes**. This is not physically possible under normal travel conditions.

The second source IP was also linked to **data center / hosting / transit infrastructure**, which may indicate VPN/proxy usage, anonymization service usage, or unauthorized access using valid credentials.

## Affected Assets / Entities

| Asset / Entity         | Details                                               |
| ---------------------- | ----------------------------------------------------- |
| Affected User          | sumer.dewan                                           |
| Usual Hostname         | ENDP-774                                              |
| Suspicious Hostname    | Samsung-G991B                                         |
| Usual Device Type      | Windows 11                                            |
| Suspicious Device Type | Android OS                                            |
| VPN Device             | IvantiVPN01                                           |
| VPN Destination IP     | 10.0.2.12                                             |
| VPN Realm              | Corporate_VPN                                         |
| VPN Role               | FullAccess                                            |
| Usual Source IP        | 49.205.10.20                                          |
| Suspicious Source IP   | 89.187.160.12                                         |
| Alert Type             | Impossible Travel / Geographically Distant Login      |
| Final Assessment       | User validation and device compliance review required |

## IOCs / Indicators Identified

| Indicator Type            | Indicator                                        |
| ------------------------- | ------------------------------------------------ |
| User                      | sumer.dewan                                      |
| Usual Source IP           | 49.205.10.20                                     |
| Suspicious Source IP      | 89.187.160.12                                    |
| Destination IP            | 10.0.2.12                                        |
| VPN Device                | IvantiVPN01                                      |
| VPN Realm                 | Corporate_VPN                                    |
| VPN Role                  | FullAccess                                       |
| Usual Hostname            | ENDP-774                                         |
| Suspicious Hostname       | Samsung-G991B                                    |
| Usual Device Type         | Windows 11                                       |
| Suspicious Device Type    | Android OS                                       |
| Usual Location            | Vijayawada, Andhra Pradesh, India                |
| Suspicious Location       | Tokyo, Japan                                     |
| Suspicious ISP            | CDN77 Tokyo                                      |
| Suspicious Domain         | cdn77.com                                        |
| Suspicious PTR / Hostname | 181461758.tyo.cdn77.com                          |
| Authentication Result     | Successful                                       |
| MFA Status                | Success                                          |
| Session Status            | Active / Idle Timeout                            |
| Alert Type                | Impossible Travel / Geographically Distant Login |
| Final Classification      | Suspicious VPN Login / User Validation Required  |

## SIEM / Splunk Analysis

### Investigation Flow

#### 1. Alert Review

SOC reviewed the VPN alert for user `sumer.dewan`. The alert triggered because two VPN logins for the same user were observed from geographically distant locations within a short duration.

The event was treated as suspicious because the second login was successful, used an Android device, originated from Japan, and received `FullAccess`.

#### 2. Entity Identification

| Entity             | Value         |
| ------------------ | ------------- |
| User               | sumer.dewan   |
| First Source IP    | 49.205.10.20  |
| Second Source IP   | 89.187.160.12 |
| Destination IP     | 10.0.2.12     |
| First Hostname     | ENDP-774      |
| Second Hostname    | Samsung-G991B |
| First Device Type  | Windows 11    |
| Second Device Type | Android OS    |
| VPN Realm          | Corporate_VPN |
| VPN Role           | FullAccess    |

#### 3. Splunk Query — Usual Source IP

```spl id="cs0275_usual_source_query"
index=main "sumer.dewan" "49.205.10.20" sourcetype=vpn_logs
| table _time alert_status authentication_method destination_ip device_name device_type disconnect_reason session_status mfa_status realm Hostname source_ip Message user
```

#### 4. Evidence — Usual Source IP

```text id="cs0275_usual_source_result"
timestamp	source_ip	destination_ip	user	Hostname	device_type	session_status	Message
2025-03-25 10:34	49.205.10.20	10.0.2.12	sumer.dewan	ENDP-774	Windows 11	Active	User 'sumer.dewan' Realm 'Corporate_VPN' Role 'FullAccess' - Session started from device 'iOS'
```

**Data Quality Note:** The row shows `device_type` as `Windows 11`, while the message states that the session started from device `iOS`. This mismatch should be validated against raw VPN logs, asset inventory, or VPN device fingerprint data if exact device attribution is required.

#### 5. Splunk Query — Suspicious Source IP

```spl id="cs0275_suspicious_source_query"
index=main "sumer.dewan" "89.187.160.12" sourcetype=vpn_logs
| table _time alert_status authentication_method destination_ip device_name device_type disconnect_reason session_status mfa_status realm Hostname source_ip Message user
```

#### 6. Full Unique Splunk Log Results — Suspicious Source IP

```text id="cs0275_suspicious_source_results"
_time	alert_status	authentication_method	destination_ip	device_name	device_type	disconnect_reason	session_status	mfa_status	realm	Hostname	source_ip	Message	user
2025-03-25 10:55:00	Normal	None	10.0.2.12	IvantiVPN01	Android OS	Idle Timeout	Idle Timeout	Success	Corporate_VPN	Samsung-G991B	89.187.160.12	User 'sumer.dewan' - Session timed out due to inactivity (30 minutes)	sumer.dewan
2025-03-25 10:45:00	Normal	None	10.0.2.12	IvantiVPN01	Android OS	None	Active	Success	Corporate_VPN	Samsung-G991B	89.187.160.12	User 'sumer.dewan' Realm 'Corporate_VPN' Role 'FullAccess' - Session started from device 'Android OS'	sumer.dewan
2025-03-25 10:45:00	Normal	None	10.0.2.12	IvantiVPN01	Android OS	None	Authenticated	Success	Corporate_VPN	Samsung-G991B	89.187.160.12	User 'sumer.dewan' Realm 'Corporate_VPN' - Authentication successful	sumer.dewan
2025-03-25 10:45:00	Normal	MFA	10.0.2.12	IvantiVPN01	Android OS	None	Pending Authentication	OTP Sent	Corporate_VPN	Samsung-G991B	89.187.160.12	User 'sumer.dewan' Realm 'Corporate_VPN' - MFA Challenge initiated: OTP sent to registered mobile number	sumer.dewan
2025-03-25 10:45:00	Normal	Password	10.0.2.12	IvantiVPN01	Android OS	None	Authentication initiated	Prompted	Corporate_VPN	Samsung-G991B	89.187.160.12	User 'sumer.dewan' Realm 'Corporate_VPN' - Authentication initiated	sumer.dewan
```

**Evidence Note:** All unique VPN log rows provided for this ticket were preserved.

### 7. Authentication and Session Pattern Review

| Observation                                               | Analyst Interpretation                              |
| --------------------------------------------------------- | --------------------------------------------------- |
| Two VPN sessions observed for same user                   | Alert condition confirmed                           |
| Locations were India and Japan                            | Geographically distant locations                    |
| Time gap was approximately 11 minutes                     | Impossible travel indicator                         |
| Second source IP was data center / hosting infrastructure | Suspicious for normal user VPN access               |
| Second device was Android `Samsung-G991B`                 | Requires device ownership and compliance validation |
| MFA challenge was generated                               | MFA workflow occurred                               |
| Authentication was successful                             | Valid account access occurred                       |
| VPN session received `FullAccess`                         | Higher risk because access was successful           |
| Session ended due to idle timeout                         | No suspicious disconnect reason observed            |
| No brute-force pattern observed                           | No repeated failures in second-login logs           |
| No MFA failure observed                                   | MFA bypass not observed                             |

## Investigation Findings

1. VPN login activity was observed for user `sumer.dewan`.
2. The user’s usual login source was identified as `49.205.10.20`.
3. The usual source IP is associated with **Vijayawada, Andhra Pradesh, India**.
4. A second successful VPN login occurred from `89.187.160.12`.
5. The second source IP is associated with **Tokyo, Japan**.
6. The time difference between the two logins was approximately **11 minutes**.
7. The second source IP belongs to data center / hosting / transit infrastructure.
8. The second login used device hostname `Samsung-G991B`.
9. The second login used device type `Android OS`.
10. Password authentication was initiated.
11. MFA OTP challenge was generated.
12. Authentication was successful.
13. VPN session became active with `FullAccess`.
14. The VPN session later ended due to idle timeout.
15. No brute-force pattern was observed in the second-login logs.
16. No MFA failure was observed in the second-login logs.
17. The activity is suspicious due to impossible travel, data center source IP, successful authentication, and Android device usage.
18. User validation is required to determine whether the Android login was legitimate.

## Timeline of Events

| Time               | Event                                                                  |
| ------------------ | ---------------------------------------------------------------------- |
| 2025-03-25 10:34   | VPN session observed from usual source IP `49.205.10.20` in India      |
| 2025-03-25 10:45   | Password authentication initiated from `89.187.160.12` in Tokyo, Japan |
| 2025-03-25 10:45   | MFA challenge initiated and OTP sent                                   |
| 2025-03-25 10:45   | Authentication successful                                              |
| 2025-03-25 10:45   | VPN session started from `Samsung-G991B` with `FullAccess`             |
| 2025-03-25 10:55   | Session timed out due to inactivity                                    |
| Investigation Time | SOC reviewed VPN logs for both source IPs                              |
| Investigation Time | SOC identified impossible travel and data center IP usage              |
| Validation Time    | User validation recommended for Android device login                   |
| Closure Time       | Ticket closed after validation and containment guidance was documented |

## MITRE ATT&CK Mapping

| Tactic            | Technique                                      | ID    | Reason                                                                                     |
| ----------------- | ---------------------------------------------- | ----- | ------------------------------------------------------------------------------------------ |
| Initial Access    | Valid Accounts                                 | T1078 | Successful VPN login occurred using a valid corporate account                              |
| Initial Access    | External Remote Services                       | T1133 | Corporate VPN service was accessed as an external remote service                           |
| Defense Evasion   | Proxy                                          | T1090 | Tokyo source IP belongs to hosting/transit infrastructure and may indicate VPN/proxy usage |
| Credential Access | Multi-Factor Authentication Request Generation | T1621 | MFA challenge was generated during the suspicious login flow                               |

**MITRE Assessment:** Mapping is included for investigation reference. The event is not confirmed malicious, but the pattern is suspicious due to impossible travel, data center IP usage, successful authentication, and FullAccess VPN session creation.

## Analyst Assessment

**Assessment:** **Suspicious VPN Login / Impossible Travel Indicator — User Validation Required**

The alert condition is valid because the same user account was used from geographically distant locations within a very short duration.

The evidence supporting suspicion includes:

1. Login from India at `2025-03-25 10:34`.
2. Login from Japan at `2025-03-25 10:45`.
3. Approximate time gap of only 11 minutes.
4. Second source IP belongs to data center / hosting / transit infrastructure.
5. Second session used Android device `Samsung-G991B`.
6. Second VPN session received `FullAccess`.
7. Authentication was successful.

Possible explanations include:

1. User used a VPN/proxy service with a Japan exit location.
2. User logged in from a personal Android device.
3. User account credentials were used by an unauthorized party.
4. Device fingerprint or hostname mapping is inaccurate.
5. User mobile device may be compromised.
6. User approved MFA for an unexpected login.

No brute-force pattern, MFA failure, lateral movement, endpoint compromise, or data exfiltration was observed from the provided logs.

## User Validation Questions

SOC should contact user `sumer.dewan` and confirm:

1. Did you log in to VPN at `2025-03-25 10:34` from the usual India source?
2. Did you log in again at `2025-03-25 10:45` using `Samsung-G991B`?
3. Is `Samsung-G991B` your personal or corporate Android device?
4. Were you using any third-party VPN or proxy service that may show a Japan location?
5. Did you receive and approve the MFA prompt?
6. Did you intentionally access VPN with `FullAccess`?
7. Were you using a company-approved device?
8. Did you notice any suspicious login notification or unexpected MFA prompt?
9. Did you recently enter your corporate credentials on any suspicious website?

If the user denies the Android login, treat the event as possible unauthorized VPN access and begin containment.

## Device Compliance Review

Because the suspicious login used Android device `Samsung-G991B`, IT / Endpoint Management should validate:

1. Whether `Samsung-G991B` is registered in MDM.
2. Whether Android devices are allowed for corporate VPN access.
3. Whether the device is compliant with organizational policy.
4. Whether the VPN profile is authorized.
5. Whether `FullAccess` should be granted to Android devices.
6. Whether the device signature should be blocked.
7. Whether conditional access should restrict unmanaged mobile devices.
8. Whether only company-approved laptop/device access should be enforced for VPN login.

## Impact Analysis

| Impact Area                 | Status                                      |
| --------------------------- | ------------------------------------------- |
| Impossible travel indicator | Confirmed                                   |
| Distant geo login           | Confirmed                                   |
| Usual source IP             | 49.205.10.20                                |
| Suspicious source IP        | 89.187.160.12                               |
| Suspicious source country   | Japan                                       |
| Suspicious source type      | Data Center / Hosting / Transit             |
| Successful authentication   | Confirmed                                   |
| MFA success                 | Confirmed                                   |
| FullAccess session          | Confirmed                                   |
| Targeted user               | sumer.dewan                                 |
| Device involved             | Samsung-G991B                               |
| Credential exposure         | Possible                                    |
| MFA abuse                   | Possible, not confirmed                     |
| Endpoint compromise         | Not confirmed                               |
| Data exfiltration           | Not observed                                |
| Business impact             | Low                                         |
| Security impact             | Medium to High until user validation        |
| Residual risk               | Low after validation and device restriction |

### Impact Summary

The incident involved a successful VPN login from a geographically distant location shortly after a login from the user’s usual region. Because the second login received `FullAccess`, the incident required user validation and device compliance review.

No confirmed data exfiltration, lateral movement, endpoint compromise, brute-force pattern, or MFA bypass was observed from the provided logs. However, the successful login from a data center IP makes the event suspicious until validated.

## Containment and Remediation

| Scenario                    | Action                                                   |
| --------------------------- | -------------------------------------------------------- |
| User confirms Android login | Document confirmation and close as policy-related        |
| User confirms Android login | Instruct user to use company-approved laptop/device only |
| Android device not approved | Block device signature for `Samsung-G991B`               |
| Android device not approved | Enforce MDM/device compliance policy                     |
| User denies login           | Reset credentials for `sumer.dewan`                      |
| User denies login           | Block source IP `89.187.160.12`                          |
| User denies login           | Terminate any active VPN sessions                        |
| User denies login           | Isolate/review suspected user device                     |
| Monitoring                  | Add user, source IP, and device to watchlist             |

## Recommended Actions

1. Validate the login directly with user `sumer.dewan`.
2. Confirm whether the user owns or used `Samsung-G991B`.
3. Confirm whether the user used any VPN/proxy service with Japan exit location.
4. Instruct the user to access organization resources only using the company-approved laptop/device.
5. Block the device signature if `Samsung-G991B` is not approved.
6. Restrict `FullAccess` VPN role from unmanaged Android devices.
7. Enforce device compliance and MDM checks for VPN access.
8. Block source IP `89.187.160.12` if the user denies the login.
9. Reset user credentials if the login was not user-initiated.
10. Review VPN logs for additional logins from `89.187.160.12`.
11. Monitor `sumer.dewan` for future impossible-travel alerts.
12. Tune VPN correlation rules for geo-distance, ISP type, source IP reputation, and device compliance.

## Escalation Decision

**Decision:** **User validation and device compliance review required. Escalate if the user denies the Android login or if the device is not approved.**

**Reason:** The login pattern showed geographically distant VPN sessions within a short duration, and the second login came from a data center IP in Japan using Android device `Samsung-G991B` with `FullAccess`. This requires validation to determine whether the event was legitimate user behavior, proxy/VPN usage, device compliance issue, or unauthorized access.

Escalate to **SOC L2 / Identity / Endpoint Team** if:

1. User denies the Android login.
2. User reports unexpected MFA prompts.
3. `Samsung-G991B` is not recognized by the user.
4. Device is unmanaged or non-compliant.
5. Corporate VPN policy does not allow Android access.
6. Any active VPN session remains open unexpectedly.
7. Suspicious internal activity is observed after the VPN session.
8. Evidence of credential theft or endpoint compromise appears.

## Final Ticket Closure Comment

SOC investigated ticket **CS-0275 — User Login from Geographically Distant Locations in Short Duration** for user `sumer.dewan`. VPN logs showed an active session from usual source IP `49.205.10.20` associated with Vijayawada, India, followed approximately 11 minutes later by a successful VPN login from source IP `89.187.160.12` associated with Tokyo, Japan. The second source IP belonged to data center / hosting / transit infrastructure and used Android device `Samsung-G991B`. Splunk evidence confirmed password authentication, MFA challenge generation, successful authentication, active VPN session with `FullAccess`, and idle timeout. No brute-force pattern, MFA failure, endpoint compromise, lateral movement, or data exfiltration was observed from the provided logs. However, the India-to-Japan login pattern within 11 minutes is suspicious and consistent with an impossible travel indicator. User validation and device compliance review were recommended. Ticket closed as **Suspicious VPN Login / Impossible Travel Indicator — User Validation Required / No Confirmed Malicious Activity from Provided Logs**.

## Skills Demonstrated

VPN log analysis, Splunk investigation, impossible-travel alert triage, geo-location comparison, source IP reputation review, hosting infrastructure identification, authentication event validation, MFA success review, VPN session analysis, device compliance assessment, IOC extraction, user validation planning, MITRE ATT&CK reference mapping, containment decision-making, escalation criteria definition, and SOC ticket documentation.
