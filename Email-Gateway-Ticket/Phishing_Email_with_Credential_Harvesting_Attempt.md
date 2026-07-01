# SOC Analyst Investigation Report

## Ticket Overview

| Field                | Details                                                                                   |
| -------------------- | ----------------------------------------------------------------------------------------- |
| Ticket ID            | CS-058                                                                                    |
| Incident Title       | Phishing Email with Credential Harvesting Attempt                                         |
| Ticket Status        | Closed                                                                                    |
| Priority / SLA       | Normal / Medium                                                                           |
| Created Date         | 3/12/25 10:32 PM                                                                          |
| Reported By          | Brian Lee                                                                                 |
| Reporter Email       | `brian.lee@abc.com`                                                                       |
| Closed By            | Ananda Das                                                                                |
| Detection Source     | Email Gateway / Proxy Logs / VPN Logs, Splunk                                             |
| Severity             | High                                                                                      |
| Submitted Attachment | `Distribution Remittance 84,300.09 Process_Ref.3hdhbsnn34n24jszmfbshn4vahdeh4.eml`        |
| Analyst Decision     | **True Positive — Credential Harvesting Attempt / MFA Prevented Unauthorized VPN Access** |

## Executive Summary

A phishing email campaign was reported by **Brian Lee** for analysis. The email used a financial remittance theme and attempted to lure users into opening a suspicious URL hosted through legitimate third-party infrastructure.

The phishing email was sent from:

`No Reply Via Xerox Scanner <reb@tonmercer.org>`

The subject was:

`Distribution Remittance 84,300.09 Process_Ref.3hdhbsnn34n24jszmfbshn4vahdeh4`

The embedded URL was:

`https://princetonmercerregionalchamberofcommerce.growthzoneapp.com/ap/r/99a0a6caa8a74d3b9e2e07ecc4ce9bf1`

Email gateway logs confirmed that the email was delivered to **seven internal users**. Proxy logs confirmed that multiple users accessed the phishing URL. Repeated user interaction was observed for **Brian Lee**, **Sneha Khanna**, and **Rakesh Chauhan**. POST activity was also observed during the investigation, indicating possible credential or form submission.

Following the user interaction, suspicious VPN authentication attempts were observed from external IP:

`185.7.214.37`

The VPN attempts reached the password authentication stage and triggered MFA challenges. MFA validation failed, and no successful VPN session was established.

Based on the delivered phishing email, multiple user interactions, possible credential submission, and suspicious VPN MFA failures, this incident is assessed as a **true positive credential-harvesting phishing attempt**. MFA prevented unauthorized VPN access. No endpoint compromise, malware execution, lateral movement, or data exfiltration was confirmed from the provided evidence.

## Alert Details

| Field                  | Value                                                                        |
| ---------------------- | ---------------------------------------------------------------------------- |
| Detection Time         | 2025-01-29                                                                   |
| Sender Display Name    | No Reply Via Xerox Scanner                                                   |
| Sender Email           | `reb@tonmercer.org`                                                |
| Sender IP              | 149.72.32.71                                                                 |
| Sender Infrastructure  | SendGrid / GrowthZone                                                        |
| Sender Hostname        | o4.sgsending.growthzoneapp.com                                               |
| Parent Domain          | twilio.com                                                                   |
| Email Subject          | Distribution Remittance 84,300.09 Process_Ref.3hdhbsnn34n24jszmfbshn4vahdeh4 |
| Delivery Status        | Delivered                                                                    |
| Email Action           | Allowed                                                                      |
| Total Recipients       | 7 Internal Users                                                             |
| URL Domain             | growthzoneapp.com                                                            |
| Attachment             | None                                                                         |
| Suspicious VPN IP      | 185.7.214.37                                                                 |
| Attack Type            | Phishing / Credential Harvesting                                             |
| Authentication Control | MFA                                                                          |

## Affected Assets

| User / Mailbox | Evidence Observed                                                | Risk Level    |
| -------------- | ---------------------------------------------------------------- | ------------- |
| Brian Lee      | Email delivered, repeated proxy access, password reset initiated | High          |
| Sneha Khanna   | Email delivered, repeated proxy access, password reset initiated | High          |
| Rakesh Chauhan | Email delivered, repeated proxy access, password reset initiated | High          |
| Myra Raju      | Email delivered, proxy access observed                           | Medium        |
| Samuel Jain    | Email delivered, proxy access observed                           | Medium        |
| William Rao    | Email delivered, no proxy activity provided                      | Low to Medium |
| Ajay Collins   | Email delivered, no proxy activity provided                      | Low to Medium |

## Evidence Reviewed

### Source IP Analysis

| Field              | Value                            |
| ------------------ | -------------------------------- |
| Source IP          | 149.72.32.71                     |
| ISP                | SendGrid, Inc.                   |
| ASN                | AS11377                          |
| Hostname           | o4.sgsending.growthzoneapp.com   |
| Parent Domain      | twilio.com                       |
| Location           | Las Vegas, Nevada, United States |
| Abuse Confidence   | 0%                               |
| Reputation Reports | 5                                |

### Source Analysis

The sender infrastructure belongs to **SendGrid**, a legitimate email delivery service. The phishing campaign appears to have abused trusted third-party email infrastructure to improve delivery success and reduce the chance of reputation-based blocking.

The use of legitimate infrastructure does not make the email benign. The final assessment is based on the message theme, user interaction, URL behavior, and VPN correlation.

### IOC Summary

| IOC Type               | Indicator                                                                                                  |
| ---------------------- | ---------------------------------------------------------------------------------------------------------- |
| Sender Email           | `reb@tonmercer.org`                                                                              |
| Sender Display Name    | No Reply Via Xerox Scanner                                                                                 |
| Sender IP              | 149.72.32.71                                                                                               |
| Sender Hostname        | o4.sgsending.growthzoneapp.com                                                                             |
| Sender Infrastructure  | SendGrid / GrowthZone                                                                                      |
| Parent Domain          | twilio.com                                                                                                 |
| Phishing URL           | `https://princetonmercerregionalchamberofcommerce.growthzoneapp.com/ap/r/99a0a6caa8a74d3b9e2e07ecc4ce9bf1` |
| URL Domain             | growthzoneapp.com                                                                                          |
| Suspicious VPN IP      | 185.7.214.37                                                                                               |
| Email Subject          | Distribution Remittance 84,300.09 Process_Ref.3hdhbsnn34n24jszmfbshn4vahdeh4                               |
| Recipient              | `myra.raju@abc.com`                                                                                        |
| Recipient              | `william.rao@abc.com`                                                                                      |
| Recipient              | `ajay.collins@abc.com`                                                                                     |
| Recipient              | `samuel.jain@abc.com`                                                                                      |
| Recipient              | `rakesh.chauhan@abc.com`                                                                                   |
| Recipient              | `sneha.khanna@abc.com`                                                                                     |
| Recipient              | `brian.lee@abc.com`                                                                                        |
| Affected User          | Brian Lee                                                                                                  |
| Affected User          | Sneha Khanna                                                                                               |
| Affected User          | Rakesh Chauhan                                                                                             |
| Threat Type            | Phishing / Credential Harvesting                                                                           |
| Authentication Control | MFA                                                                                                        |
| Final Outcome          | MFA Prevented Unauthorized Access                                                                          |

## SIEM / Splunk Analysis

### Investigation Flow

#### 1. Alert Review

The ticket was reviewed as a user-reported suspicious email. The subject used a financial remittance theme, which is commonly used in phishing campaigns to create business urgency and make users open links quickly.

Key suspicious indicators:

| Indicator              | Observation                           |
| ---------------------- | ------------------------------------- |
| Subject Theme          | Financial remittance                  |
| Sender Display Name    | No Reply Via Xerox Scanner            |
| Sender Infrastructure  | SendGrid / GrowthZone                 |
| URL Domain             | growthzoneapp.com                     |
| Delivery Scope         | Seven users                           |
| User Interaction       | Multiple users accessed the URL       |
| VPN Correlation        | Suspicious attempts from 185.7.214.37 |
| MFA Result             | Failed                                |
| Successful VPN Session | Not observed                          |

#### 2. Email Gateway Review

```spl id="cs0242_email_query"
index=main sourcetype="email_logs" reb@tonmercer.org
| table _time Sender Recipient Email_Subject Action Status MessageID URL Attachment_Hash
```

### Full Unique Email Gateway Log Results

```text id="cs0242_email_results"
_time	Recipient	Status
2025-01-29 04:13:00	myra.raju@abc.com	Delivered
2025-01-29 04:13:00	william.rao@abc.com	Delivered
2025-01-29 04:13:00	ajay.collins@abc.com	Delivered
2025-01-29 04:13:00	samuel.jain@abc.com	Delivered
2025-01-29 04:13:00	rakesh.chauhan@abc.com	Delivered
2025-01-29 04:13:00	sneha.khanna@abc.com	Delivered
2025-01-29 04:13:00	brian.lee@abc.com	Delivered
```

### Email Gateway Findings

| Finding                | Assessment                   |
| ---------------------- | ---------------------------- |
| Total delivered emails | 7                            |
| Same phishing URL used | Confirmed                    |
| Attachment present     | No                           |
| Email delivery         | Successful                   |
| Campaign scope         | Multiple internal recipients |
| Sender infrastructure  | Legitimate platform abused   |

#### 3. Proxy Log Review

```spl id="cs0242_proxy_query"
index=main sourcetype="proxy_logs" "growthzoneapp.com"
| table _time Username Source_IP Destination_IP URL HTTP_Method Action Response_Code Web_Category
```

### Full Unique Proxy Log Results

```text id="cs0242_proxy_results"
_time	User	Action
2025-01-29 09:15:00	Myra Raju	Allowed
2025-01-29 09:15:00	Samuel Jain	Allowed
2025-01-29 10:46:00	Rakesh Chauhan	Allowed
2025-01-29 11:45:00	Rakesh Chauhan	Allowed
2025-01-29 10:46:00	Sneha Khanna	Allowed
2025-01-29 11:45:00	Sneha Khanna	Allowed
2025-01-29 10:23:00	Brian Lee	Allowed
2025-01-29 10:24:00	Brian Lee	Allowed
```

### Proxy Findings

| Observation                                 | Analyst Interpretation                          |
| ------------------------------------------- | ----------------------------------------------- |
| Eight proxy events identified               | Multiple users interacted with the phishing URL |
| Brian Lee accessed the URL twice            | Repeated interaction confirmed                  |
| Sneha Khanna accessed the URL twice         | Repeated interaction confirmed                  |
| Rakesh Chauhan accessed the URL twice       | Repeated interaction confirmed                  |
| Myra Raju and Samuel Jain accessed the URL  | User exposure confirmed                         |
| Proxy action was Allowed                    | Users were able to reach the phishing page      |
| POST activity observed during investigation | Possible credential or form submission          |

#### 4. VPN Log Review

```spl id="cs0242_vpn_query"
index=main sourcetype="vpn_logs" source_ip="185.7.214.37"
| table _time User source_ip session_status mfa_status authentication_method
```

### Full Unique VPN Log Results

```text id="cs0242_vpn_results"
_time	Source IP	Session Status	MFA Status
2025-01-29 11:05:00	185.7.214.37	Authentication Initiated	Prompted
2025-01-29 11:05:00	185.7.214.37	Pending Authentication	OTP Sent
2025-01-29 11:05:00	185.7.214.37	None	Failed
2025-01-29 11:07:00	185.7.214.37	Authentication Initiated	Prompted
2025-01-29 11:07:00	185.7.214.37	Pending Authentication	OTP Sent
2025-01-29 11:07:00	185.7.214.37	None	Failed
2025-01-29 11:12:00	185.7.214.37	Authentication Initiated	Prompted
2025-01-29 11:12:00	185.7.214.37	Pending Authentication	OTP Sent
2025-01-29 11:13:00	185.7.214.37	None	Failed
2025-01-29 11:20:00	185.7.214.37	Authentication Initiated	Prompted
2025-01-29 11:20:00	185.7.214.37	Pending Authentication	OTP Sent
2025-01-29 11:20:00	185.7.214.37	None	Failed
2025-01-29 11:21:00	185.7.214.37	Authentication Initiated	Prompted
2025-01-29 11:21:00	185.7.214.37	Pending Authentication	OTP Sent
2025-01-29 11:21:00	185.7.214.37	None	Failed
2025-01-29 11:25:00	185.7.214.37	Authentication Initiated	Prompted
2025-01-29 11:25:00	185.7.214.37	Pending Authentication	OTP Sent
2025-01-29 11:25:00	185.7.214.37	None	Failed
```

### VPN Findings

| Observation                                  | Analyst Interpretation                      |
| -------------------------------------------- | ------------------------------------------- |
| Multiple VPN attempts from 185.7.214.37      | Suspicious external authentication activity |
| Password authentication initiated            | Possible use of harvested credentials       |
| MFA challenges generated                     | Login reached MFA stage                     |
| OTP sent                                     | MFA prompt was triggered                    |
| MFA failed                                   | Unauthorized access was blocked             |
| No successful VPN session                    | Account takeover not confirmed              |
| Repeated attempts across multiple timestamps | Credential abuse attempt likely             |

#### 5. Timeline Reconstruction

| Time                   | Event                                                            |
| ---------------------- | ---------------------------------------------------------------- |
| 2025-01-29 04:13:00    | Phishing emails delivered to seven internal users                |
| 2025-01-29 09:15:00    | Myra Raju and Samuel Jain accessed the phishing URL              |
| 2025-01-29 10:23:00    | Brian Lee accessed the phishing URL                              |
| 2025-01-29 10:24:00    | Brian Lee accessed the phishing URL again                        |
| 2025-01-29 10:46:00    | Rakesh Chauhan and Sneha Khanna accessed the phishing URL        |
| 2025-01-29 11:05:00    | Suspicious VPN authentication attempts began from `185.7.214.37` |
| 2025-01-29 11:20–11:25 | Repeated VPN MFA failures continued from `185.7.214.37`          |
| 2025-01-29 11:45:00    | Rakesh Chauhan and Sneha Khanna accessed the phishing URL again  |

#### 6. Attack Chain Correlation

The evidence supports the following attack chain:

1. Financial remittance-themed phishing email was delivered to seven users.
2. The email used trusted third-party infrastructure to increase delivery success.
3. Multiple users accessed the embedded GrowthZone URL.
4. Repeated user interaction was observed for Brian Lee, Sneha Khanna, and Rakesh Chauhan.
5. POST activity was observed during investigation, indicating possible credential or form submission.
6. Suspicious VPN authentication attempts began from external IP `185.7.214.37`.
7. VPN login attempts reached the MFA stage.
8. MFA failed and prevented successful VPN access.
9. No endpoint compromise, malware execution, or data exfiltration was observed.

## MITRE ATT&CK Mapping

| Tactic              | Technique                                      | ID        | Reason                                                        |
| ------------------- | ---------------------------------------------- | --------- | ------------------------------------------------------------- |
| Initial Access      | Phishing                                       | T1566     | Phishing email was delivered to multiple users                |
| Initial Access      | Spearphishing Link                             | T1566.002 | Email contained a link to suspicious hosted infrastructure    |
| Credential Access   | Input Capture                                  | T1056     | POST activity may indicate submitted credentials or form data |
| Credential Access   | Valid Accounts                                 | T1078     | VPN attempts suggest possible use of harvested credentials    |
| Initial Access      | External Remote Services                       | T1133     | Corporate VPN was targeted                                    |
| Credential Access   | Multi-Factor Authentication Request Generation | T1621     | MFA challenges and OTP prompts were generated                 |
| Command and Control | Application Layer Protocol: Web Protocols      | T1071.001 | Users accessed phishing infrastructure over web protocols     |

## Analyst Assessment

**Assessment:** **True Positive — Credential Harvesting Attempt**

The alert is valid because the email was delivered to seven internal users, multiple users accessed the embedded URL, repeated proxy activity was observed, and suspicious VPN authentication attempts followed from `185.7.214.37`.

The activity strongly suggests credential harvesting or attempted credential abuse. MFA prevented unauthorized VPN access because all MFA attempts failed and no successful VPN session was observed.

This is not confirmed endpoint compromise because no malware execution, endpoint alert, lateral movement, or data exfiltration was identified from the provided logs.

## Impact Analysis

| Impact Area                  | Status                        |
| ---------------------------- | ----------------------------- |
| Phishing email delivered     | Confirmed                     |
| Multiple recipients targeted | Confirmed                     |
| User interaction             | Confirmed                     |
| Repeated proxy access        | Confirmed                     |
| POST activity                | Observed during investigation |
| Credential exposure          | Likely / Possible             |
| Suspicious VPN attempts      | Confirmed                     |
| MFA challenge generated      | Confirmed                     |
| MFA failed                   | Confirmed                     |
| Successful VPN access        | Not Observed                  |
| MFA bypass                   | Not Observed                  |
| Endpoint compromise          | Not Observed                  |
| Malware execution            | Not Observed                  |
| Data exfiltration            | Not Observed                  |
| Business impact              | Low to Medium                 |

Current impact: **Credential exposure risk is high, but MFA prevented confirmed unauthorized VPN access. No endpoint or data impact was confirmed.**

## Recommended Actions

1. Reset passwords for users with repeated proxy access and likely credential exposure:

   * Brian Lee
   * Sneha Khanna
   * Rakesh Chauhan
2. Revoke active sessions and refresh tokens for impacted users.
3. Review VPN, MFA, and authentication logs for all users who clicked the phishing URL.
4. Block suspicious VPN source IP `185.7.214.37` in VPN, firewall, and IPS controls.
5. Block the phishing URL path in proxy/SWG controls.
6. Block sender email `reb@tonmercer.org` in the email gateway.
7. Block sender domain `princetonmercer.org` if no business requirement exists.
8. Search and quarantine/remove related emails from all affected mailboxes.
9. Add all IOCs to SIEM watchlists and correlation rules.
10. Contact affected users and confirm whether credentials, OTP, or MFA details were entered.
11. Review mailbox forwarding rules and inbox rules if credential entry is confirmed.
12. Monitor impacted users for **2–3 days** after containment.
13. Escalate to SOC L2 / Identity Team if successful login, MFA approval, mailbox rule creation, or endpoint compromise indicators are found.

**Blocking Note:** Since `growthzoneapp.com` may host legitimate third-party content, avoid broad global blocking unless approved. Prefer blocking the specific malicious URL/path and related sender indicators.

## Escalation Decision

**Decision:** **Closed after containment; conditional SOC L2 escalation if additional compromise indicators appear.**

**Reason:** Credential harvesting is likely due to user interaction and suspicious VPN attempts. However, MFA prevented successful VPN access, and no endpoint compromise, malware execution, or data exfiltration was observed.

Escalate to **SOC L2 / Identity Team** if any of the following are identified:

1. Successful VPN login from suspicious IP.
2. MFA approval from unknown location.
3. Suspicious mailbox forwarding rule creation.
4. Suspicious OAuth consent activity.
5. Endpoint compromise indicators.
6. Additional credential use from external IPs.
7. Data exfiltration indicators.
8. Additional users confirm credential submission.

## Final Ticket Closure Comment

SOC investigated ticket **CS-058 — Phishing Email with Credential Harvesting Attempt** reported by **Brian Lee**. The phishing email was sent from `reb@tonmercer.org` with the subject **Distribution Remittance 84,300.09 Process_Ref.3hdhbsnn34n24jszmfbshn4vahdeh4**. Email gateway logs confirmed delivery to seven internal users: `myra.raju@abc.com`, `william.rao@abc.com`, `ajay.collins@abc.com`, `samuel.jain@abc.com`, `rakesh.chauhan@abc.com`, `sneha.khanna@abc.com`, and `brian.lee@abc.com`. The embedded URL used GrowthZone infrastructure and pointed to `https://princetonmercerregionalchamberofcommerce.growthzoneapp.com/ap/r/99a0a6caa8a74d3b9e2e07ecc4ce9bf1`. Proxy logs confirmed multiple users accessed the phishing page, with repeated activity for Brian Lee, Sneha Khanna, and Rakesh Chauhan. POST activity was observed during investigation, indicating possible credential submission. Suspicious VPN authentication attempts were later observed from `185.7.214.37`, where password authentication was initiated, MFA challenges were generated, OTP prompts were sent, and MFA failed. No successful VPN session, endpoint compromise, malware execution, lateral movement, or data exfiltration was confirmed. Ticket closed as **True Positive — Credential Harvesting Attempt / MFA Prevented Unauthorized VPN Access**, with password reset, session revocation, phishing email quarantine, IOC blocking, user awareness, and 2–3 days of monitoring recommended.

## Skills Demonstrated

User-reported phishing triage, email gateway investigation, third-party infrastructure abuse analysis, proxy log correlation, user interaction validation, VPN authentication investigation, MFA failure analysis, credential exposure assessment, IOC extraction, MITRE ATT&CK mapping, timeline reconstruction, impact validation, containment planning, and SOC ticket documentation.

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
