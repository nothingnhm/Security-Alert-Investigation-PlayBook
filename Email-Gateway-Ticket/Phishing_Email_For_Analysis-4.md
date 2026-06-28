# SOC Analyst Investigation Report

## Ticket Overview

| Field                | Details                                                                                                           |
| -------------------- | ----------------------------------------------------------------------------------------------------------------- |
| Ticket ID            | CS-0238                                                                                                           |
| Alert Name           | Phishing Email For Analysis                                                                                       |
| Category             | Email Phishing / Credential Harvesting                                                                            |
| Ticket Status        | Closed                                                                                                            |
| Priority / SLA       | High / Default SLA                                                                                                |
| Created Date         | 3/12/25 9:39 PM                                                                                                   |
| Reported By          | Rachel Moore                                                                                                      |
| Reporter Email       | `rachel.moore@abc.com`                                                                                            |
| Closed By            | Ananda Das                                                                                                        |
| Submitted Attachment | `URGENT confirm account activity.eml`                                                                             |
| Analyst Decision     | **True Positive — Credential Harvesting Phishing with Possible Credential Submission / MFA Prevented VPN Access** |

## Executive Summary

User **Rachel Moore** reported a suspicious email for analysis. The email used an urgent account-verification theme with the subject:

`URGENT: confirm account activity`

The email impersonated account security activity and was delivered to multiple internal recipients:

* `rahul.joshi@abc.com`
* `rachel.moore@abc.com`
* `info@abc.com`

The phishing email used a redirect path through:

`secure.adnxs.com`

and redirected users to the credential-harvesting domain:

`maxloglogistica.com`

Email gateway logs confirmed that the phishing email was delivered to three recipients. Proxy logs confirmed that **Rahul Joshi** accessed the phishing URL using **GET** and then submitted a **POST** request. The POST request returned HTTP **200**, which indicates possible form or credential submission. **Rachel Moore** accessed the phishing page using **GET**, but no POST activity was observed for her in the provided evidence.

VPN logs showed suspicious authentication attempts for **Rahul Joshi** from external IP:

`186.23.212.74`

The authentication flow reached the MFA stage, OTP was sent, and MFA failed. No successful VPN session was established. Based on the available evidence, MFA prevented unauthorized VPN access.

No endpoint compromise, malware execution, lateral movement, or data exfiltration was confirmed from the provided logs.

## Alert Details

| Field                        | Value                                  |
| ---------------------------- | -------------------------------------- |
| Email Subject                | `URGENT: confirm account activity`     |
| Sender                       | `cybersecxperts@zimbramail.serino.com` |
| Sender Domain                | zimbramail.serino.com                  |
| Sender IP                    | 5.62.56.113                            |
| Delivery Status              | Delivered                              |
| Redirect Domain              | secure.adnxs.com                       |
| Credential Harvesting Domain | maxloglogistica.com                    |
| Malicious VPN Source IP      | 186.23.212.74                          |
| Primary Affected User        | Rahul Joshi                            |
| Additional User              | Rachel Moore                           |
| Attack Type                  | Credential Harvesting Phishing         |
| Authentication Control       | MFA                                    |

## Affected Assets

| User / Mailbox                      | Evidence Observed                                                       | Risk Level    |
| ----------------------------------- | ----------------------------------------------------------------------- | ------------- |
| Rahul Joshi                         | Email delivered, GET request, POST request, suspicious VPN MFA failures | High          |
| Rachel Moore                        | Email delivered, GET request observed, no POST observed                 | Medium        |
| [info@abc.com](mailto:info@abc.com) | Email delivered, no proxy activity provided                             | Low to Medium |

## Evidence Reviewed

### IOC Summary

| IOC Type                     | Indicator                              |
| ---------------------------- | -------------------------------------- |
| Sender Email                 | `cybersecxperts@zimbramail.serino.com` |
| Sender Domain                | zimbramail.serino.com                  |
| Sender IP                    | 5.62.56.113                            |
| Redirect Domain              | secure.adnxs.com                       |
| Credential Harvesting Domain | maxloglogistica.com                    |
| Phishing URL                 | secure.adnxs.com → maxloglogistica.com |
| Malicious VPN Source IP      | 186.23.212.74                          |
| Recipient                    | `rahul.joshi@abc.com`                  |
| Recipient                    | `rachel.moore@abc.com`                 |
| Recipient                    | `info@abc.com`                         |
| Email Subject                | `URGENT: confirm account activity`     |
| Threat Type                  | Phishing / Credential Harvesting       |

## SIEM / Splunk Analysis

### Investigation Flow

#### 1. Alert Review

The ticket was reviewed as a user-reported phishing email. The email subject used urgent account activity wording, which is commonly used in credential-harvesting campaigns to pressure users into clicking links and validating credentials.

Key suspicious indicators:

| Indicator        | Observation                             |
| ---------------- | --------------------------------------- |
| Subject Theme    | Urgent account activity confirmation    |
| Sender Domain    | zimbramail.serino.com                   |
| Redirect Domain  | secure.adnxs.com                        |
| Final Domain     | maxloglogistica.com                     |
| Delivery Scope   | Three recipients                        |
| User Interaction | Rahul Joshi and Rachel Moore            |
| POST Activity    | Rahul Joshi                             |
| VPN Activity     | Suspicious MFA failures for Rahul Joshi |

#### 2. Email Gateway Review

Email gateway logs confirmed the phishing email was delivered to three internal recipients.

```spl id="cs0238_email_query"
index="main" "zimbramail.serino.com" sourcetype=email_logs
| table _time Sender Recipient Status URL
```

```text id="cs0238_email_results"
_time	Sender	Recipient	Status
2025-02-24 10:39:00	Cybersecxperts cybersecxperts@zimbramail.serino.com	rahul.joshi@abc.com	Delivered
2025-02-24 10:39:00	Cybersecxperts cybersecxperts@zimbramail.serino.com	rachel.moore@abc.com	Delivered
2025-02-24 10:39:00	Cybersecxperts cybersecxperts@zimbramail.serino.com	info@abc.com	Delivered
```

### Email Gateway Findings

| Finding                         | Assessment                              |
| ------------------------------- | --------------------------------------- |
| Total delivered phishing emails | 3                                       |
| Recipients identified           | Rahul Joshi, Rachel Moore, Info Mailbox |
| Email delivery status           | Delivered                               |
| Embedded URL behavior           | Redirected to phishing infrastructure   |
| Campaign type                   | Credential harvesting                   |

#### 3. URL Analysis

| Field                        | Value                           |
| ---------------------------- | ------------------------------- |
| Redirect Domain              | secure.adnxs.com                |
| Credential Harvesting Domain | maxloglogistica.com             |
| Reputation                   | Malicious                       |
| Objective                    | Credential Theft                |
| Final URL Behavior           | Redirect to phishing login page |

The URL redirection through **secure.adnxs.com** appears to be used to hide the final phishing destination and bypass basic security detection. The final landing domain was identified as **maxloglogistica.com**, associated with credential-harvesting behavior.

#### 4. Proxy Log Review

Proxy logs confirmed that users accessed the phishing URL.

```spl id="cs0238_proxy_query"
index="main" "secure.adnxs.com" sourcetype=proxy_logs
| table _time Username URL "HTTP Method" "Response Code" "Web Category" Action
```

```text id="cs0238_proxy_results"
_time	Username	HTTP Method	Response Code	Action
2025-02-24 11:46:00	Rahul Joshi	POST	200	Allowed
2025-02-24 11:45:00	Rahul Joshi	GET	200	Allowed
2025-02-24 10:39:00	Rachel Moore	GET	200	Allowed
```

### Proxy Findings

| Observation                        | Analyst Interpretation                               |
| ---------------------------------- | ---------------------------------------------------- |
| Rahul Joshi generated GET request  | User opened the phishing page                        |
| Rahul Joshi generated POST request | Possible form or credential submission               |
| POST response code 200             | Phishing server successfully responded               |
| Rachel Moore generated GET request | User accessed the phishing page                      |
| No POST for Rachel Moore           | No credential submission evidence from provided logs |
| Proxy action allowed               | Web access was not blocked at time of activity       |

#### 5. VPN Authentication Review

VPN logs were reviewed for Rahul Joshi and suspicious source IP **186.23.212.74**.

```spl id="cs0238_vpn_query"
index="main" "Rahul.Joshi" sourcetype="vpn_logs" source_ip="186.23.212.74"
| table _time user source_ip Hostname session_status authentication_method mfa_status disconnect_reason
```

```text id="cs0238_vpn_results"
_time	user	source_ip	session_status	authentication_method	mfa_status
2025-02-23 08:29:00	rahul.joshi	186.23.212.74	Authentication Initiated	Password	Prompted
2025-02-23 08:29:00	rahul.joshi	186.23.212.74	Pending Authentication	MFA	OTP Sent
2025-02-23 08:29:00	rahul.joshi	186.23.212.74	None	MFA	Failed
```

**Evidence Note:** Exact duplicate VPN rows were observed in the provided logs and removed from the final evidence table. Unique evidence was preserved.

### VPN Findings

| Observation                       | Analyst Interpretation                    |
| --------------------------------- | ----------------------------------------- |
| Source IP `186.23.212.74`         | Suspicious external authentication source |
| Password authentication initiated | Account login attempt occurred            |
| MFA challenge generated           | Login reached MFA stage                   |
| OTP sent                          | MFA prompt was triggered                  |
| MFA failed                        | Unauthorized access was blocked           |
| No successful VPN session         | Account takeover not confirmed            |

#### 6. Timeline Reconstruction

| Time                | Event                                                                                     |
| ------------------- | ----------------------------------------------------------------------------------------- |
| 2025-02-23 08:29:00 | Suspicious VPN authentication attempts observed for Rahul Joshi from `186.23.212.74`      |
| 2025-02-24 10:39:00 | Phishing email delivered to Rahul Joshi, Rachel Moore, and info mailbox                   |
| 2025-02-24 10:39:00 | Rachel Moore accessed the phishing URL using GET                                          |
| 2025-02-24 11:45:00 | Rahul Joshi accessed the phishing URL using GET                                           |
| 2025-02-24 11:46:00 | Rahul Joshi submitted POST request to phishing URL; possible credential submission        |
| Investigation Time  | IOC blocking, password reset, session termination, and user awareness actions recommended |

**Timestamp Note:** VPN activity is dated **2025-02-23**, while phishing email and proxy activity occurred on **2025-02-24**. This may indicate timezone/log normalization differences, copied timestamp mismatch, or a separate suspicious authentication event. The VPN activity should still be reviewed because it targeted Rahul Joshi from an external source IP and included MFA failure.

#### 7. Attack Chain Correlation

The evidence supports the following attack chain:

1. Phishing email was delivered to multiple recipients.
2. Email used urgent account activity wording.
3. Link redirected through secure.adnxs.com.
4. Final destination was maxloglogistica.com.
5. Rachel Moore accessed the phishing URL using GET.
6. Rahul Joshi accessed the phishing URL using GET.
7. Rahul Joshi generated a POST request, indicating possible submitted data.
8. Suspicious VPN authentication attempts were observed for Rahul Joshi from 186.23.212.74.
9. MFA challenge was triggered and failed.
10. No successful VPN access was confirmed.

## MITRE ATT&CK Mapping

| Tactic              | Technique                                      | ID        | Reason                                                                              |
| ------------------- | ---------------------------------------------- | --------- | ----------------------------------------------------------------------------------- |
| Initial Access      | Phishing                                       | T1566     | Phishing email was delivered to multiple users                                      |
| Initial Access      | Spearphishing Link                             | T1566.002 | Email contained a phishing link with redirect behavior                              |
| Credential Access   | Input Capture                                  | T1056     | Rahul Joshi generated POST request to phishing page; possible credential submission |
| Credential Access   | Valid Accounts                                 | T1078     | Suspicious VPN authentication suggests possible credential use                      |
| Initial Access      | External Remote Services                       | T1133     | Corporate VPN was targeted                                                          |
| Credential Access   | Multi-Factor Authentication Request Generation | T1621     | MFA challenge was generated during suspicious VPN authentication                    |
| Command and Control | Application Layer Protocol: Web Protocols      | T1071.001 | Web traffic to phishing infrastructure was observed                                 |

## Analyst Assessment

**Assessment:** **True Positive — Credential Harvesting Phishing with Possible Credential Submission**

The alert is valid because the suspicious email was delivered to multiple recipients, redirected users to a credential-harvesting domain, and proxy logs confirmed user interaction.

Rahul Joshi’s **POST** request to the phishing page is the highest-risk evidence and indicates possible credential or form submission. Suspicious VPN authentication attempts from **186.23.212.74** further increase the risk. MFA blocked unauthorized VPN access, and no successful VPN session was confirmed.

Rachel Moore clicked the phishing page, but no POST request or credential submission evidence was observed for her from the provided logs.

## Impact Analysis

| Impact Area                            | Status        |
| -------------------------------------- | ------------- |
| Phishing email delivered               | Confirmed     |
| Multiple recipients targeted           | Confirmed     |
| Rahul Joshi accessed phishing page     | Confirmed     |
| Rahul Joshi POST request observed      | Confirmed     |
| Possible credential submission         | Possible      |
| Rachel Moore accessed phishing page    | Confirmed     |
| Suspicious VPN attempt for Rahul Joshi | Confirmed     |
| MFA challenge generated                | Confirmed     |
| MFA failed                             | Confirmed     |
| Successful VPN access                  | Not Confirmed |
| Malware execution                      | Not Confirmed |
| Endpoint compromise                    | Not Confirmed |
| Lateral movement                       | Not Confirmed |
| Data exfiltration                      | Not Confirmed |

Current impact: **Credential exposure is possible for Rahul Joshi. MFA prevented confirmed VPN account takeover. No endpoint or data impact was confirmed.**

## Recommended Actions

1. Reset Rahul Joshi’s password due to POST activity and possible credential submission.
2. Revoke active sessions and refresh tokens for Rahul Joshi.
3. Review Rahul Joshi’s VPN, MFA, and authentication logs before and after the event.
4. Block suspicious VPN source IP `186.23.212.74` in VPN, firewall, and IPS controls.
5. Block phishing domains and URLs related to `secure.adnxs.com` redirect chain and `maxloglogistica.com`.
6. Remove/quarantine delivered phishing emails from all affected mailboxes.
7. Search for additional recipients of the same sender, subject, and URL.
8. Contact Rahul Joshi and confirm whether credentials, OTP, MFA code, or sensitive data were entered.
9. Contact Rachel Moore and confirm whether she clicked the link and entered any information.
10. Review mailbox forwarding rules and inbox rules for Rahul Joshi if credential submission is confirmed.
11. Add all IOCs and affected users to SIEM watchlists and correlation rules.
12. Monitor Rahul Joshi and Rachel Moore for **2–3 days** after containment.
13. Escalate to SOC L2 / Identity Team if suspicious authentication, credential compromise, or additional impacted users are identified.

## Escalation Decision

**Decision:** **Closed after containment; conditional SOC L2 escalation if further suspicious activity is observed.**

**Reason:** Rahul Joshi interacted with the phishing site and generated a POST request, creating possible credential exposure risk. However, MFA prevented successful VPN access, and no endpoint compromise, malware activity, or data exfiltration was identified from the provided logs.

Escalate to **SOC L2 / Identity Team** if any of the following are found:

1. Successful login from suspicious IP.
2. MFA approval from an unknown location.
3. Suspicious mailbox forwarding rules.
4. Suspicious OAuth consent activity.
5. Endpoint compromise indicators.
6. Additional credential use from external IPs.
7. Data exfiltration indicators.
8. Additional users submit credentials.

## Final Ticket Closure Comment

SOC investigated ticket **CS-0238 — Phishing Email For Analysis** reported by **Rachel Moore**. The submitted email used the subject **URGENT: confirm account activity** and was delivered to `rahul.joshi@abc.com`, `rachel.moore@abc.com`, and `info@abc.com`. The phishing URL redirected through `secure.adnxs.com` and led to the credential-harvesting domain `maxloglogistica.com`. Proxy logs confirmed that **Rahul Joshi** accessed the phishing page using GET and generated a POST request, indicating possible credential or form submission. **Rachel Moore** accessed the phishing page using GET, but no POST activity was observed for her. VPN logs showed suspicious authentication attempts for Rahul Joshi from `186.23.212.74`, where password authentication was initiated, MFA challenge was generated, OTP was sent, and MFA failed. No successful VPN session, endpoint compromise, malware execution, lateral movement, or data exfiltration was confirmed. Ticket closed as **True Positive — Credential Harvesting Phishing with Possible Credential Submission / MFA Prevented VPN Access**, with password reset, session revocation, phishing email quarantine, IOC blocking, user awareness, and 2–3 days of monitoring recommended.

## Skills Demonstrated

User-reported phishing triage, email gateway analysis, phishing URL redirect investigation, proxy log correlation, POST request interpretation, VPN authentication review, MFA failure analysis, credential exposure assessment, IOC extraction, MITRE ATT&CK mapping, timeline reconstruction, impact validation, containment planning, and SOC ticket documentation.
