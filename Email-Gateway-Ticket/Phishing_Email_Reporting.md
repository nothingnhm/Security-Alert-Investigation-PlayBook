# SOC Analyst Investigation Report

## Ticket Overview

| Field            | Details                                                                                                        |
| ---------------- | -------------------------------------------------------------------------------------------------------------- |
| Ticket ID        | CS-046                                                                                                         |
| Alert Name       | Phishing Email                                                                                                 |
| Category         | Phishing Email Reporting                                                                                       |
| Status           | Closed                                                                                                         |
| Priority         | Normal                                                                                                         |
| Severity         | High                                                                                                           |
| Logs Received    | 29-JAN-2025                                                                                                    |
| Ticket Raised    | 12-MARCH-2025                                                                                                  |
| Reported By      | Ananda Das — SOC Team                                                                                          |
| Initial Reporter | Sneha Rathod                                                                                                   |
| Analyst Decision | **True Positive — Phishing Campaign with Possible Credential Harvesting / MFA-Protected VPN Attempts Blocked** |

## Executive Summary

A phishing email alert was reported by **Sneha Rathod**. The email used a financial/remittance-themed subject and was delivered to multiple users.

The suspicious email appeared to come from:

`No Reply Via Xerox Scanner <rebecca@princetonmercer.org>`

The subject was:

`Distribution Remittance 84,300.09 Process_Ref.3hdhbsnn34n24jszmfbshn4vahdeh4`

The email contained a URL hosted under **growthzoneapp.com**. Email authentication checks showed **SPF Pass**, **DKIM Pass**, and **DMARC Pass**. Reputation checks showed the domain as legitimate in the provided sources. However, email authentication and legitimate domain reputation do not prove the email is safe because attackers may abuse trusted third-party platforms, compromised accounts, or legitimate infrastructure.

Proxy logs confirmed that multiple users accessed the GrowthZoneApp domain. Several users generated **POST** requests with HTTP **200** responses, indicating possible form submission. VPN logs later showed authentication attempts from suspicious source IP **185.7.214.37** against impacted users. MFA challenges were triggered and failed due to incorrect OTP entries. No successful VPN session was observed.

This case is assessed as a **True Positive phishing campaign with possible credential harvesting**, where MFA prevented full VPN compromise.

## Alert Details

| Field                   | Value                                                                          |
| ----------------------- | ------------------------------------------------------------------------------ |
| Email Time              | 2025-01-29 04:13                                                               |
| Sender                  | `rebecca@princetonmercer.org`                                                  |
| Display Name            | No Reply Via Xerox Scanner                                                     |
| Receiver                | Multiple Users                                                                 |
| Subject                 | `Distribution Remittance 84,300.09 Process_Ref.3hdhbsnn34n24jszmfbshn4vahdeh4` |
| Return Path             | `reply-nkog9dp2@princetonmercerregionalchamberofcommerce.growthzoneapp.com`    |
| Sender IP               | 52.101.10.18                                                                   |
| SPF                     | Pass                                                                           |
| DKIM                    | Pass                                                                           |
| DMARC                   | Pass                                                                           |
| Email Status            | Delivered                                                                      |
| Email Action            | Allowed                                                                        |
| Primary Domain          | growthzoneapp.com                                                              |
| Web Server IP           | 172.170.249.2                                                                  |
| Malicious VPN Source IP | 185.7.214.37                                                                   |
| IPS Detected IP         | 248.192.27.119                                                                 |

## Affected Assets

| User           | Evidence Observed                                              | Asset / Role Details                                             |
| -------------- | -------------------------------------------------------------- | ---------------------------------------------------------------- |
| Rakesh Chauhan | Proxy GET/POST activity and VPN MFA failure observed           | Data Center Engineer, IT Infrastructure, ENDP-278, Windows 11-64 |
| Sneha Khanna   | Proxy GET/POST activity and repeated VPN MFA failures observed | Not Provided                                                     |
| Brian Lee      | Proxy GET/POST activity and repeated VPN MFA failures observed | Helpdesk Analyst L1, IT Infrastructure, ENDP-257, Windows 11-64  |
| Myra Raju      | Proxy GET activity observed                                    | Not Provided                                                     |
| Samuel Jain    | Proxy GET activity observed                                    | Not Provided                                                     |
| Sneha Rathod   | Reported phishing email                                        | Not Provided                                                     |

## Evidence Reviewed

### IOC Summary

| Indicator Type          | Indicator                                                                                                  |
| ----------------------- | ---------------------------------------------------------------------------------------------------------- |
| Phishing URL            | `hxxps://princetonmercerregionalchamberofcommerce.growthzoneapp.com/ap/Form/FillV2/pV28jf5p?cid=r6ZXwEbr`  |
| Email Log URL           | `https://princetonmercerregionalchamberofcommerce.growthzoneapp.com/ap/r/99a0a6caa8a74d3b9e2e07ecc4ce9bf1` |
| Domain                  | growthzoneapp.com                                                                                          |
| Email Sender            | `rebecca@princetonmercer.org`                                                                              |
| Email Domain            | princetonmercer.org                                                                                        |
| Return Path Domain      | princetonmercerregionalchamberofcommerce.growthzoneapp.com                                                 |
| Email Sender IP         | 52.101.10.18                                                                                               |
| Web Server IP           | 172.170.249.2                                                                                              |
| Malicious VPN Source IP | 185.7.214.37                                                                                               |
| IPS Detected IP         | 248.192.27.119                                                                                             |

## SIEM / Splunk Analysis

### 1. Email Log Review

```spl id="cs0586_email_query"
index=main "princetonmercer.org" sourcetype=email_logs 
| table _time Email_Subject Sender SenderIP URL Status Action
```

```text id="cs0586_email_results"
_time	Email_Subject	Sender	SenderIP	URL	Status	Action
2025-01-29 04:13:00	Distribution Remittance 84,300.09 Process_Ref.3hdhbsnn34n24jszmfbshn4vahdeh4	No Reply Via Xerox Scanner <rebecca@princetonmercer.org>	52.101.10.18	https://princetonmercerregionalchamberofcommerce.growthzoneapp.com/ap/r/99a0a6caa8a74d3b9e2e07ecc4ce9bf1	Delivered	Allowed
```

**Evidence Note:** Multiple identical email log entries were provided. Exact duplicate rows were removed, and the unique evidence row was preserved.

### 2. Proxy Log Review

```spl id="cs0586_proxy_query"
index=main sourcetype="proxy_logs" "https://princetonmercerregionalchamberofcommerce.growthzoneapp.com"
| table _time "Destination IP" "HTTP Method" "Response Code" "URL Domain" "Username"
```

```text id="cs0586_proxy_results"
_time	Destination IP	HTTP Method	Response Code	URL Domain	Username
2025-01-29 11:45:00	172.170.249.2	GET	200	growthzoneapp.com	Rakesh Chauhan
2025-01-29 11:45:00	172.170.249.2	GET	200	growthzoneapp.com	Sneha Khanna
2025-01-29 10:46:00	172.170.249.2	POST	200	growthzoneapp.com	Rakesh Chauhan
2025-01-29 10:46:00	172.170.249.2	POST	200	growthzoneapp.com	Sneha Khanna
2025-01-29 10:24:00	172.170.249.2	POST	200	growthzoneapp.com	Brian Lee
2025-01-29 10:23:00	172.170.249.2	GET	200	growthzoneapp.com	Brian Lee
2025-01-29 09:15:00	172.170.249.2	GET	200	growthzoneapp.com	Myra Raju
2025-01-29 09:15:00	172.170.249.2	GET	200	growthzoneapp.com	Samuel Jain
```

### 3. VPN Log Review — Rakesh Chauhan

```spl id="cs0586_vpn_rakesh_query"
index=main sourcetype="vpn_logs" "Rakesh.Chauhan" "185.7.214.37" 
| table authentication_method device_type Hostname realm Message mfa_status session_status user
```

```text id="cs0586_vpn_rakesh_results"
authentication_method	device_type	Hostname	realm	Message	mfa_status	session_status	user
MFA	macOS 13x	MAC-12432	Corporate_VPN	User 'rakesh.chauhan' Realm 'Corporate_VPN' - MFA Challenge failed: Incorrect OTP entered	Failed	None	rakesh.chauhan
MFA	macOS 13x	MAC-12432	Corporate_VPN	User 'rakesh.chauhan' Realm 'Corporate_VPN' - MFA Challenge initiated: OTP sent to registered mobile number	OTP Sent	Pending Authentication	rakesh.chauhan
Password	macOS 13x	MAC-12432	Corporate_VPN	User 'rakesh.chauhan' Realm 'Corporate_VPN' - Authentication initiated	Prompted	Authentication initiated	rakesh.chauhan
```

### 4. VPN Log Review — Sneha Khanna

```spl id="cs0586_vpn_sneha_query"
index=main sourcetype="vpn_logs" "Sneha.Khanna" "185.7.214.37" 
| table _time authentication_method device_type Hostname realm Message mfa_status session_status user
```

```text id="cs0586_vpn_sneha_results"
_time	authentication_method	device_type	Hostname	realm	Message	mfa_status	session_status	user
2025-01-29 11:25:00	MFA	macOS 13x	MAC-12432	Corporate_VPN	User 'sneha.khanna' Realm 'Corporate_VPN' - MFA Challenge failed: Incorrect OTP entered	Failed	None	sneha.khanna
2025-01-29 11:25:00	MFA	macOS 13x	MAC-12432	Corporate_VPN	User 'sneha.khanna' Realm 'Corporate_VPN' - MFA Challenge initiated: OTP sent to registered mobile number	OTP Sent	Pending Authentication	sneha.khanna
2025-01-29 11:25:00	Password	macOS 13x	MAC-12432	Corporate_VPN	User 'sneha.khanna' Realm 'Corporate_VPN' - Authentication initiated	Prompted	Authentication initiated	sneha.khanna
2025-01-29 11:21:00	MFA	macOS 13x	MAC-12432	Corporate_VPN	User 'sneha.khanna' Realm 'Corporate_VPN' - MFA Challenge failed: Incorrect OTP entered	Failed	None	sneha.khanna
2025-01-29 11:21:00	MFA	macOS 13x	MAC-12432	Corporate_VPN	User 'sneha.khanna' Realm 'Corporate_VPN' - MFA Challenge initiated: OTP sent to registered mobile number	OTP Sent	Pending Authentication	sneha.khanna
2025-01-29 11:21:00	Password	macOS 13x	MAC-12432	Corporate_VPN	User 'sneha.khanna' Realm 'Corporate_VPN' - Authentication initiated	Prompted	Authentication initiated	sneha.khanna
2025-01-29 11:20:00	MFA	macOS 13x	MAC-12432	Corporate_VPN	User 'sneha.khanna' Realm 'Corporate_VPN' - MFA Challenge failed: Incorrect OTP entered	Failed	None	sneha.khanna
2025-01-29 11:20:00	MFA	macOS 13x	MAC-12432	Corporate_VPN	User 'sneha.khanna' Realm 'Corporate_VPN' - MFA Challenge initiated: OTP sent to registered mobile number	OTP Sent	Pending Authentication	sneha.khanna
2025-01-29 11:20:00	Password	macOS 13x	MAC-12432	Corporate_VPN	User 'sneha.khanna' Realm 'Corporate_VPN' - Authentication initiated	Prompted	Authentication initiated	sneha.khanna
```

### 5. VPN Log Review — Brian Lee

```spl id="cs0586_vpn_brian_query"
index=main sourcetype="vpn_logs" "Brian.Lee" "185.7.214.37" 
| table _time authentication_method device_type Hostname realm Message mfa_status session_status user
```

```text id="cs0586_vpn_brian_results"
_time	authentication_method	device_type	Hostname	realm	Message	mfa_status	session_status	user
2025-01-29 11:13:00	MFA	macOS 13x	MAC-12432	Corporate_VPN	User 'brian.lee' Realm 'Corporate_VPN' - MFA Challenge failed: Incorrect OTP entered	Failed	None	brian.lee
2025-01-29 11:12:00	MFA	macOS 13x	MAC-12432	Corporate_VPN	User 'brian.lee' Realm 'Corporate_VPN' - MFA Challenge initiated: OTP sent to registered mobile number	OTP Sent	Pending Authentication	brian.lee
2025-01-29 11:12:00	Password	macOS 13x	MAC-12432	Corporate_VPN	User 'brian.lee' Realm 'Corporate_VPN' - Authentication initiated	Prompted	Authentication initiated	brian.lee
2025-01-29 11:07:00	MFA	macOS 13x	MAC-12432	Corporate_VPN	User 'brian.lee' Realm 'Corporate_VPN' - MFA Challenge failed: Incorrect OTP entered	Failed	None	brian.lee
2025-01-29 11:07:00	MFA	macOS 13x	MAC-12432	Corporate_VPN	User 'brian.lee' Realm 'Corporate_VPN' - MFA Challenge initiated: OTP sent to registered mobile number	OTP Sent	Pending Authentication	brian.lee
2025-01-29 11:07:00	Password	macOS 13x	MAC-12432	Corporate_VPN	User 'brian.lee' Realm 'Corporate_VPN' - Authentication initiated	Prompted	Authentication initiated	brian.lee
2025-01-29 11:05:00	MFA	macOS 13x	MAC-12432	Corporate_VPN	User 'brian.lee' Realm 'Corporate_VPN' - MFA Challenge failed: Incorrect OTP entered	Failed	None	brian.lee
2025-01-29 11:05:00	MFA	macOS 13x	MAC-12432	Corporate_VPN	User 'brian.lee' Realm 'Corporate_VPN' - MFA Challenge initiated: OTP sent to registered mobile number	OTP Sent	Pending Authentication	brian.lee
2025-01-29 11:05:00	Password	macOS 13x	MAC-12432	Corporate_VPN	User 'brian.lee' Realm 'Corporate_VPN' - Authentication initiated	Prompted	Authentication initiated	brian.lee
```

## Investigation Flow

### 1. Alert Review

The alert was reviewed as a phishing email incident because the email used a financial/remittance lure and included an external URL. Although SPF, DKIM, and DMARC passed, the subject, link behavior, multiple recipient scope, and follow-up VPN activity made the case high risk.

### 2. Email Delivery Validation

Email logs confirmed that the suspicious email was **Delivered** and **Allowed**. This means the message reached user mailboxes and required containment through email quarantine/removal.

### 3. URL and Domain Analysis

The phishing URL used **growthzoneapp.com**, a domain reported as legitimate in the provided reputation checks. The key risk was not domain reputation alone but suspected abuse of a trusted third-party platform to host or redirect users to a phishing form.

### 4. Proxy Access Validation

Proxy logs confirmed that multiple users accessed **growthzoneapp.com** after the email was delivered. GET requests confirmed page access. POST requests from **Brian Lee**, **Rakesh Chauhan**, and **Sneha Khanna** increased the risk because POST traffic may indicate form submission.

### 5. VPN Correlation

VPN logs showed suspicious authentication attempts from **185.7.214.37** against users who interacted with the phishing domain. MFA challenges were initiated and failed. No successful VPN session was observed.

### 6. Timeline Reconstruction

| Time                   | Event                                                                                |
| ---------------------- | ------------------------------------------------------------------------------------ |
| 2025-01-29 04:13       | Phishing email delivered and allowed                                                 |
| 2025-01-29 09:15       | Myra Raju and Samuel Jain accessed growthzoneapp.com using GET                       |
| 2025-01-29 10:23       | Brian Lee accessed growthzoneapp.com using GET                                       |
| 2025-01-29 10:24       | Brian Lee generated POST request to growthzoneapp.com                                |
| 2025-01-29 10:46       | Rakesh Chauhan and Sneha Khanna generated POST requests to growthzoneapp.com         |
| 2025-01-29 11:05–11:13 | VPN authentication attempts observed for Brian Lee from 185.7.214.37; MFA failed     |
| 2025-01-29 11:20–11:25 | VPN authentication attempts observed for Sneha Khanna from 185.7.214.37; MFA failed  |
| Time Not Provided      | VPN authentication attempt observed for Rakesh Chauhan from 185.7.214.37; MFA failed |

### 7. Attack Chain Correlation

The evidence supports the following attack chain:

1. Phishing email was delivered to multiple users.
2. Multiple users accessed the phishing-related domain.
3. POST requests were observed from selected users, indicating possible submitted data.
4. VPN authentication attempts followed from suspicious IP **185.7.214.37**.
5. MFA challenges were triggered.
6. MFA challenges failed due to incorrect OTP entries.
7. No successful VPN session was confirmed.

This sequence is consistent with phishing-driven credential harvesting followed by attempted VPN login using harvested credentials.

## MITRE ATT&CK Mapping

| Tactic              | Technique                                      | ID        | Reason                                                        |
| ------------------- | ---------------------------------------------- | --------- | ------------------------------------------------------------- |
| Initial Access      | Phishing                                       | T1566     | Suspicious email delivered to multiple users                  |
| Initial Access      | Spearphishing Link                             | T1566.002 | Email contained a link that users accessed                    |
| Credential Access   | Input Capture                                  | T1056     | POST requests may indicate submitted credentials or form data |
| Credential Access   | Valid Accounts                                 | T1078     | VPN attempts suggest possible credential reuse                |
| Initial Access      | External Remote Services                       | T1133     | VPN service was targeted                                      |
| Credential Access   | Multi-Factor Authentication Request Generation | T1621     | MFA challenges were generated during suspicious VPN attempts  |
| Command and Control | Application Layer Protocol: Web Protocols      | T1071.001 | Web traffic to phishing-related infrastructure was observed   |

## Analyst Assessment

**Assessment:** **True Positive — Phishing Campaign with Possible Credential Harvesting**

The alert is valid because the email was delivered, multiple users accessed the linked domain, POST requests were observed, and suspicious VPN authentication attempts followed from an external IP.

MFA prevented successful VPN access, but possible credential exposure cannot be ruled out. The users with POST activity and VPN MFA failures should be treated as high-risk impacted accounts.

## Impact Analysis

| Area                     | Assessment                                                 |
| ------------------------ | ---------------------------------------------------------- |
| Email Delivery           | Confirmed delivered and allowed                            |
| User Interaction         | Confirmed through proxy GET requests                       |
| Possible Form Submission | Confirmed through proxy POST requests                      |
| Credential Exposure      | Possible, not fully confirmed                              |
| VPN Abuse Attempt        | Confirmed                                                  |
| MFA Protection           | Effective; MFA failed                                      |
| Successful VPN Session   | Not Observed                                               |
| Malware Download         | Not Observed                                               |
| Endpoint Compromise      | Not confirmed from provided logs                           |
| Data Exfiltration        | Not Observed                                               |
| Business Risk            | High due to multiple impacted users and VPN login attempts |

## Impacted User Risk Classification

| User           | Evidence                               | Risk Level    | Required Action                                                          |
| -------------- | -------------------------------------- | ------------- | ------------------------------------------------------------------------ |
| Brian Lee      | GET + POST + repeated VPN MFA failures | High          | Isolate endpoint, reset password, revoke sessions, review VPN/auth logs  |
| Sneha Khanna   | GET + POST + repeated VPN MFA failures | High          | Identify endpoint, isolate if available, reset password, revoke sessions |
| Rakesh Chauhan | GET + POST + VPN MFA failure           | High          | Isolate ENDP-278, reset password, revoke sessions, review VPN/auth logs  |
| Myra Raju      | GET only                               | Medium        | Validate user interaction; reset password if credentials were entered    |
| Samuel Jain    | GET only                               | Medium        | Validate user interaction; reset password if credentials were entered    |
| Sneha Rathod   | Reported phishing email                | Low to Medium | Validate whether link was clicked                                        |

## Recommended Actions

1. Isolate impacted endpoints for users with POST activity and VPN MFA failures.
2. Reset passwords for **Brian Lee**, **Sneha Khanna**, and **Rakesh Chauhan**.
3. Revoke active sessions and tokens for high-risk impacted users.
4. Review MFA logs for all impacted users.
5. Quarantine or remove the phishing email from all recipient mailboxes.
6. Block the phishing URL paths in email gateway, proxy, and IPS.
7. Block **185.7.214.37** in firewall, VPN, and IPS controls.
8. Block **248.192.27.119** in firewall and IPS as the provided IPS-detected IOC.
9. Block **172.170.249.2** if no business requirement exists.
10. Treat **52.101.10.18** cautiously because it is the email sender IP; block only if policy confirms it as malicious or not business-required.
11. Hunt for additional users who accessed the same URL or generated POST requests.
12. Escalate to SOC L2 / Incident Response for credential exposure investigation.

## Containment / Blocking Plan

| Control              | Indicator                          | Recommended Action                                   |
| -------------------- | ---------------------------------- | ---------------------------------------------------- |
| Email Gateway        | `rebecca@princetonmercer.org`      | Quarantine/block if not business-required            |
| Email Gateway        | `princetonmercer.org`              | Add to watchlist; block only if policy approves      |
| Email Gateway        | GrowthZoneApp phishing URL paths   | Block/quarantine                                     |
| Proxy / SWG          | GrowthZoneApp phishing URL path    | Block                                                |
| IPS                  | GrowthZoneApp phishing URL pattern | Add detection/block rule                             |
| Firewall / IPS       | 172.170.249.2                      | Block outbound if not business-required              |
| Firewall / IPS       | 52.101.10.18                       | Block only if confirmed malicious or policy-approved |
| Firewall / VPN / IPS | 185.7.214.37                       | Block immediately                                    |
| Firewall / IPS       | 248.192.27.119                     | Block as provided IOC                                |
| SIEM                 | All IOCs and impacted users        | Add to watchlist and correlation rules               |

**Blocking Note:** Since **growthzoneapp.com** may be a legitimate third-party platform, broad domain blocking may cause business impact. Prefer blocking exact phishing URL paths and the related subdomain unless policy approves full domain blocking.

## Escalation Decision

**Decision:** **Escalate to SOC L2 / Incident Response.**

**Reason:** This case involves phishing email delivery, multiple user interactions, POST requests, and suspicious VPN authentication attempts from **185.7.214.37**. Even though MFA blocked successful VPN access, credential exposure cannot be ruled out.

## Final Ticket Closure Comment

SOC investigated ticket **CS-046 — Phishing Email**. The phishing email was reported by **Sneha Rathod** and used a remittance-themed subject. The email was sent from `rebecca@princetonmercer.org` with display name **No Reply Via Xerox Scanner** and contained a GrowthZoneApp URL. Email authentication checks showed SPF, DKIM, and DMARC passed; however, proxy logs confirmed multiple users accessed **growthzoneapp.com**, and POST requests were observed for **Brian Lee**, **Rakesh Chauhan**, and **Sneha Khanna**. VPN logs then showed suspicious authentication attempts from **185.7.214.37**, with MFA challenges initiated and failed due to incorrect OTP entries. No successful VPN session, malware download, endpoint compromise, or data exfiltration was confirmed. The incident is assessed as **True Positive — Phishing Campaign with Possible Credential Harvesting / MFA-Protected VPN Attempts Blocked**. Recommended containment includes endpoint isolation, password resets, session revocation, phishing email quarantine, URL/domain path blocking, and firewall/IPS/VPN blocking for identified malicious IPs.

## Skills Demonstrated

Phishing email triage, email authentication review, URL reputation analysis, email log investigation, proxy log correlation, VPN authentication analysis, MFA failure investigation, timeline reconstruction, IOC extraction, affected user scoping, MITRE ATT&CK mapping, impact validation, containment planning, escalation decision-making, and SOC incident documentation.

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
