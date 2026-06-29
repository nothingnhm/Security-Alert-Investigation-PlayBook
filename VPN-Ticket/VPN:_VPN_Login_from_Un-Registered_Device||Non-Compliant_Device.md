# SOC Analyst Investigation Report

## Ticket Overview

| Field             | Details                                                                                          |
| ----------------- | ------------------------------------------------------------------------------------------------ |
| Ticket ID         | CS-074                                                                                          |
| Alert Name        | VPN:- VPN Login from Un-Registered Device / Non-Compliant Device                                 |
| Incident Category | VPN / Device Compliance Alert                                                                    |
| Ticket Status     | Closed                                                                                           |
| Priority / SLA    | Normal / Default SLA                                                                             |
| Department        | IT / Cyber Security Department                                                                   |
| Created Date      | 3/25/25 8:38 AM                                                                                  |
| Closed By         | Ananda Das                                                                                       |
| Detection Source  | VPN Logs / SIEM Splunk                                                                           |
| Affected User     | `willam.dam`                                                                                     |
| Affected Device   | iPhone14Pro                                                                                      |
| Device Type       | iOS                                                                                              |
| Analyst Decision  | **User Validation Required — Successful VPN Login from Unregistered / Non-Compliant iOS Device** |

## Executive Summary

A VPN security alert was triggered for user **willam.dam** after a successful VPN session was observed from an iOS mobile device:

`iPhone14Pro`

The login originated from the external source IP:

`172.58.20.30`

The alert was generated because the VPN session was started from an **unregistered or non-compliant device**. The user successfully authenticated, completed MFA, and obtained a VPN session with:

`FullAccess`

The VPN destination was:

`10.0.2.12`

The VPN realm was:

`Corporate_VPN`

Splunk logs showed password authentication initiation, MFA challenge generation, successful authentication, active VPN session creation, and later idle timeout due to inactivity. No brute-force pattern, MFA failure, suspicious disconnect reason, or confirmed compromise indicator was observed from the provided logs.

Final assessment: **No confirmed malicious activity was observed, but the login requires user validation and IT/Endpoint compliance review because the VPN session was established from an unregistered/non-compliant iOS device with FullAccess.**

## Alert Details

| Field          | Value                                                                                         |
| -------------- | --------------------------------------------------------------------------------------------- |
| Timestamp      | 3/25/2025 9:34                                                                                |
| Source IP      | 172.58.20.30                                                                                  |
| Destination IP | 10.0.2.12                                                                                     |
| User           | willam.dam                                                                                    |
| Hostname       | iPhone14Pro                                                                                   |
| Device Type    | iOS                                                                                           |
| VPN Device     | IvantiVPN01                                                                                   |
| VPN Realm      | Corporate_VPN                                                                                 |
| VPN Role       | FullAccess                                                                                    |
| Session Status | Active                                                                                        |
| Message        | User `willam.dam` Realm `Corporate_VPN` Role `FullAccess` - Session started from device `iOS` |
| Final Verdict  | User Validation Required / Policy-Related Event                                               |

## Source IP and Location Analysis

### Current Login Source

| Field       | Value                    |
| ----------- | ------------------------ |
| Source IP   | 172.58.20.30             |
| ISP         | T-Mobile USA, Inc.       |
| Usage Type  | Mobile ISP               |
| ASN         | AS21928                  |
| Domain Name | t-mobile.com             |
| Country     | United States of America |
| City        | New Orleans, Louisiana   |

### User Usual Login Source

| Field           | Value                                |
| --------------- | ------------------------------------ |
| Usual Source IP | 67.86.22.212                         |
| ISP             | Optimum Online / Cablevision Systems |
| Usage Type      | Fixed Line ISP                       |
| ASN             | AS6128                               |
| Hostname        | ool-435616d4.dyn.optonline.net       |
| Domain Name     | optimum.net                          |
| Country         | United States of America             |
| City            | Dix Hills, New York                  |

### Location and ISP Assessment

The current VPN login originated from a **mobile ISP** in New Orleans, Louisiana, while the user’s usual login source is a **fixed-line ISP** in Dix Hills, New York.

This may be legitimate if the user was travelling or using mobile data. However, because the device was identified as **unregistered/non-compliant**, user validation and device compliance review are required before the event can be fully closed as benign.

## Affected Assets / Entities

| Asset / Entity     | Details                                               |
| ------------------ | ----------------------------------------------------- |
| Affected User      | willam.dam                                            |
| Hostname           | iPhone14Pro                                           |
| Device Type        | iOS                                                   |
| VPN Device         | IvantiVPN01                                           |
| VPN Destination IP | 10.0.2.12                                             |
| VPN Realm          | Corporate_VPN                                         |
| VPN Role           | FullAccess                                            |
| Current Source IP  | 172.58.20.30                                          |
| Usual Source IP    | 67.86.22.212                                          |
| Alert Reason       | Unregistered / non-compliant device                   |
| Final Assessment   | User validation and device compliance review required |

## IOCs / Indicators Identified

| Indicator Type       | Indicator                                            |
| -------------------- | ---------------------------------------------------- |
| Current Source IP    | 172.58.20.30                                         |
| Usual Source IP      | 67.86.22.212                                         |
| Destination IP       | 10.0.2.12                                            |
| Affected User        | willam.dam                                           |
| Hostname             | iPhone14Pro                                          |
| Device Type          | iOS                                                  |
| VPN Device           | IvantiVPN01                                          |
| VPN Realm            | Corporate_VPN                                        |
| VPN Role             | FullAccess                                           |
| Current ISP          | T-Mobile USA, Inc.                                   |
| Current Location     | New Orleans, Louisiana, United States                |
| Usual ISP            | Optimum Online                                       |
| Usual Location       | Dix Hills, New York, United States                   |
| Session Status       | Authenticated / Active / Idle Timeout                |
| Alert Reason         | Unregistered or non-compliant device                 |
| Final Classification | User validation required / possible policy violation |

## SIEM / Splunk Analysis

### Investigation Flow

#### 1. Alert Review

SOC reviewed the VPN alert for user `willam.dam`. The alert indicated a successful VPN session from an iOS device marked as unregistered or non-compliant.

Because the session received `FullAccess`, SOC treated the event as important from a device compliance and access control perspective.

#### 2. Entity Identification

| Entity         | Value         |
| -------------- | ------------- |
| User           | willam.dam    |
| Hostname       | iPhone14Pro   |
| Device Type    | iOS           |
| Source IP      | 172.58.20.30  |
| Destination IP | 10.0.2.12     |
| VPN Device     | IvantiVPN01   |
| VPN Realm      | Corporate_VPN |
| VPN Role       | FullAccess    |

#### 3. Splunk Query Used

```spl id="cs0274_vpn_query"
index=main user="willam.dam" sourcetype=vpn_logs source_ip="172.58.20.30"
| table _time alert_status authentication_method destination_ip device_name device_type disconnect_reason session_status mfa_status realm Hostname source_ip Message user
```

#### 4. Full Unique Splunk Log Results

```text id="cs0274_vpn_results"
_time	alert_status	authentication_method	destination_ip	device_name	device_type	disconnect_reason	session_status	mfa_status	realm	Hostname	source_ip	Message	user
2025-03-25 10:05:00	Normal	None	10.0.2.12	IvantiVPN01	iOS	Idle Timeout	Idle Timeout	Success	Corporate_VPN	iPhone14Pro	172.58.20.30	User 'willam.dam' - Session timed out due to inactivity (30 minutes)	willam.dam
2025-03-25 09:34:00	Normal	None	10.0.2.12	IvantiVPN01	iOS	None	Active	Success	Corporate_VPN	iPhone14Pro	172.58.20.30	User 'willam.dam' Realm 'Corporate_VPN' Role 'FullAccess' - Session started from device 'iOS'	willam.dam
2025-03-25 09:34:00	Normal	None	10.0.2.12	IvantiVPN01	iOS	None	Authenticated	Success	Corporate_VPN	iPhone14Pro	172.58.20.30	User 'willam.dam' Realm 'Corporate_VPN' - Authentication successful	willam.dam
2025-03-25 09:34:00	Normal	MFA	10.0.2.12	IvantiVPN01	iOS	None	Pending Authentication	OTP Sent	Corporate_VPN	iPhone14Pro	172.58.20.30	User 'willam.dam' Realm 'Corporate_VPN' - MFA Challenge initiated: OTP sent to registered mobile number	willam.dam
2025-03-25 09:34:00	Normal	Password	10.0.2.12	IvantiVPN01	iOS	None	Authentication initiated	Prompted	Corporate_VPN	iPhone14Pro	172.58.20.30	User 'willam.dam' Realm 'Corporate_VPN' - Authentication initiated	willam.dam
```

**Evidence Note:** All unique VPN log rows provided for this ticket were preserved.

### 5. Authentication and Session Pattern Review

| Observation                              | Analyst Interpretation                         |
| ---------------------------------------- | ---------------------------------------------- |
| Password authentication initiated        | Normal VPN login flow started                  |
| MFA challenge generated                  | MFA workflow was triggered                     |
| Authentication successful                | Login was completed                            |
| VPN session became active                | Successful VPN access confirmed                |
| Role assigned was `FullAccess`           | Elevated access risk from non-compliant device |
| Device was iOS / iPhone14Pro             | Mobile device involved                         |
| Session ended by idle timeout            | Normal disconnect reason                       |
| No failed password attempts observed     | No brute-force pattern                         |
| No MFA failure observed                  | No MFA abuse pattern                           |
| Device marked unregistered/non-compliant | Policy and compliance issue confirmed          |

## Investigation Findings

1. VPN login activity was observed for user `willam.dam`.
2. The login originated from source IP `172.58.20.30`.
3. The source IP belongs to **T-Mobile USA, Inc.**, a mobile ISP.
4. The user’s usual login source was identified as `67.86.22.212`.
5. The usual login source is associated with **Optimum Online** in Dix Hills, New York.
6. The current login source was from New Orleans, Louisiana.
7. The login was performed from iOS device `iPhone14Pro`.
8. The device was identified as unregistered or non-compliant.
9. Password authentication was initiated normally.
10. MFA OTP challenge was generated.
11. Authentication was successful.
12. VPN session started with `FullAccess`.
13. Session ended due to idle timeout after 30 minutes.
14. No brute-force pattern was observed.
15. No MFA failure was observed.
16. No suspicious disconnect reason was observed.
17. User validation and device compliance review are required.

## Timeline of Events

| Time               | Event                                                               |
| ------------------ | ------------------------------------------------------------------- |
| 2025-03-25 09:34   | Password authentication initiated for `willam.dam`                  |
| 2025-03-25 09:34   | MFA challenge initiated and OTP sent                                |
| 2025-03-25 09:34   | Authentication successful                                           |
| 2025-03-25 09:34   | VPN session started from iOS device `iPhone14Pro` with `FullAccess` |
| 2025-03-25 10:05   | VPN session timed out due to inactivity after 30 minutes            |
| Investigation Time | SOC reviewed VPN logs in Splunk                                     |
| Investigation Time | SOC compared current login source with usual login source           |
| Validation Time    | User validation recommended to confirm mobile login                 |
| Compliance Review  | IT/Endpoint team review recommended for device compliance           |
| Closure Time       | Ticket closed after no confirmed malicious behavior was identified  |

## MITRE ATT&CK Mapping

| Tactic          | Technique                | ID    | Reason                                                                                 |
| --------------- | ------------------------ | ----- | -------------------------------------------------------------------------------------- |
| Initial Access  | Valid Accounts           | T1078 | VPN login used a valid corporate account, but compromise was not confirmed             |
| Initial Access  | External Remote Services | T1133 | VPN service was accessed remotely                                                      |
| Defense Evasion | Proxy                    | T1090 | Mobile ISP/unusual network usage should be validated only if the user denies the login |

**MITRE Assessment:** MITRE mapping is included for investigation reference only. Based on the provided evidence, this incident is not confirmed as malicious. The primary concern is device compliance and access control.

## Analyst Assessment

**Assessment:** **User Validation Required — Successful VPN Login from Non-Compliant iOS Device**

The VPN login was successful and originated from a mobile iOS device. The main reason for the alert was the use of an **unregistered or non-compliant device**.

The evidence does not strongly indicate malicious activity because:

1. Authentication was successful.
2. MFA was initiated and completed successfully.
3. No incorrect password attempts were observed.
4. No MFA failure was observed.
5. The source IP belongs to a mobile ISP.
6. The session ended due to normal idle timeout.
7. No suspicious disconnect reason was observed.
8. No brute-force pattern was observed.

However, the login still requires validation because:

1. The device was unregistered or non-compliant.
2. The user’s normal login location was different.
3. The VPN session received `FullAccess`.
4. The source IP came from a mobile network in a different state.
5. Unauthorized use of a personal or unmanaged mobile device can create security risk.

Current assessment: **Likely benign if confirmed by user, but policy-related due to non-compliant device access.**

## User Validation Questions

SOC should contact user `willam.dam` and confirm:

1. Did you log in to VPN on `2025-03-25 09:34`?
2. Was the login performed from your mobile phone?
3. Is `iPhone14Pro` your personal or corporate device?
4. Were you located in or near New Orleans, Louisiana during the login?
5. Were you using T-Mobile mobile data?
6. Did you receive and approve the MFA prompt?
7. Did you intentionally access VPN with `FullAccess` role?
8. Is this device registered with IT/MDM?
9. Did you notice any suspicious login notification or account activity?

If the user denies the login, treat the event as possible unauthorized access and start containment.

## Device Compliance Review

Because the alert was related to an unregistered or non-compliant device, IT / Endpoint Management should validate:

1. Whether `iPhone14Pro` is registered in MDM.
2. Whether the device is approved for corporate VPN access.
3. Whether the device meets compliance requirements.
4. Whether the VPN profile is authorized.
5. Whether OS version and security controls meet policy.
6. Whether corporate data was accessed during the VPN session.
7. Whether `FullAccess` should be allowed from mobile devices.
8. Whether conditional access should restrict unmanaged mobile devices.

## Impact Analysis

| Impact Area                | Status                                                 |
| -------------------------- | ------------------------------------------------------ |
| Non-compliant device login | Confirmed                                              |
| Successful VPN login       | Confirmed                                              |
| MFA success                | Confirmed                                              |
| FullAccess session         | Confirmed                                              |
| Targeted user              | willam.dam                                             |
| Credential exposure        | Not confirmed                                          |
| MFA bypass                 | Not observed                                           |
| Brute force                | Not observed                                           |
| Endpoint compromise        | Not confirmed                                          |
| Data exfiltration          | Not observed                                           |
| Business impact            | Low                                                    |
| Security impact            | Medium due to non-compliant FullAccess device          |
| Residual risk              | Low after user validation and device compliance review |

### Impact Summary

A successful VPN login occurred from an iOS device marked as unregistered or non-compliant. No malicious activity was confirmed from the provided logs. The primary risk is policy and device compliance, especially because the VPN session received `FullAccess`.

## Containment and Remediation

| Scenario                   | Action                                                   |
| -------------------------- | -------------------------------------------------------- |
| User confirms login        | Close as benign / policy-related                         |
| User confirms login        | Validate device compliance with IT / MDM team            |
| User confirms login        | Register or enroll device if allowed by policy           |
| User denies login          | Block source IP `172.58.20.30`                           |
| User denies login          | Reset credentials for `willam.dam`                       |
| User denies login          | Terminate any active VPN sessions                        |
| User denies login          | Isolate or review the device if compromise is suspected  |
| Compliance issue confirmed | Restrict VPN access from unmanaged/non-compliant devices |
| Monitoring                 | Add user and device to short-term watchlist              |

## Recommended Actions

1. Contact the user and confirm whether the login was legitimate.
2. Document the user confirmation in the ticket.
3. Validate whether `iPhone14Pro` is a registered and compliant device.
4. Enforce MDM enrollment for mobile devices accessing VPN.
5. Restrict `FullAccess` VPN role from unmanaged mobile devices.
6. Apply conditional access policies for device compliance.
7. Review whether personal mobile devices are allowed for VPN.
8. Monitor `willam.dam` for additional unusual device logins.
9. Block the source IP only if the user denies the login.
10. Reset credentials only if the login was not user-initiated.
11. Isolate or review the device if compromise indicators are identified.
12. Maintain MFA enforcement for all VPN access.

## Escalation Decision

**Decision:** **User validation and IT / Endpoint compliance review required.**

**Reason:** The VPN login was successful and did not show brute-force or failed authentication behavior. However, the login came from an unregistered/non-compliant iOS device and received `FullAccess`, which requires validation against corporate device compliance policy.

Escalate to **SOC L2 / Identity / Endpoint Team** if:

1. User denies the login.
2. User reports unexpected MFA prompts.
3. Device is not recognized by the user.
4. Device is not registered or approved for VPN access.
5. Any active VPN session remains open unexpectedly.
6. Suspicious activity is observed after the VPN session.
7. Endpoint or mobile device compromise is suspected.
8. Corporate data access from the session appears abnormal.

## Final Ticket Closure Comment

SOC investigated ticket **CS-074 — VPN Login from Un-Registered Device / Non-Compliant Device** for user `willam.dam`. VPN logs showed password authentication initiation from source IP `172.58.20.30` toward destination `10.0.2.12` on VPN device `IvantiVPN01` under realm `Corporate_VPN`. The login was performed from iOS device `iPhone14Pro`, which was identified as unregistered or non-compliant. Splunk evidence confirmed MFA challenge generation, successful authentication, active VPN session creation with `FullAccess`, and idle timeout after 30 minutes. No brute-force activity, MFA failure, suspicious disconnect reason, endpoint compromise, lateral movement, or data exfiltration was observed from the provided logs. User validation and IT/Endpoint device compliance review were recommended. Ticket closed as **User Validation Required — Successful VPN Login from Unregistered / Non-Compliant iOS Device / No Confirmed Malicious Activity**.

## Skills Demonstrated

VPN log analysis, Splunk investigation, non-compliant device login triage, mobile device access review, authentication event validation, MFA success review, VPN session analysis, device compliance assessment, IOC extraction, user validation planning, MITRE ATT&CK reference mapping, containment decision-making, escalation criteria definition, and SOC ticket documentation.

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
