# SOC Analyst Investigation Report

## Ticket Overview

| Field            | Details                                                                                     |
| ---------------- | ------------------------------------------------------------------------------------------- |
| Ticket ID        | CS-050                                                                                      |
| Alert Name       | Email Gateway: Newly Registered Domains in Sender Address                                   |
| Ticket Status    | Resolved                                                                                    |
| Priority / SLA   | Normal / Medium                                                                             |
| Created Date     | 3/16/25 3:40 PM                                                                             |
| Closed By        | Ananda Das                                                                                  |
| Analyst Decision | **True Positive — Phishing Email with User Interaction and Possible Credential Submission** |

## Executive Summary

An email gateway alert was triggered for an email sent from a suspicious newly registered sender domain:

`bestoacmoaltou.net`

The email was sent from:

`"Paylogin" <Payloginehfih@bestoavdnk.net>`

The message was delivered to:

`rohit.shah@abc.com`

The subject was:

`Finance Login Payment`

The email contained a suspicious login URL:

`http://bestoacmoaltou.net/login.php`

Email gateway logs confirmed the message was **Delivered** and **allowed**. Proxy logs confirmed that user **Rohit Shah** accessed the suspicious URL and generated both **GET** and **POST** requests. The POST request returned HTTP **200**, which may indicate form submission or possible credential entry.

The URL was categorized as a **Security Risk** and was flagged as **Phishing/Malicious** by multiple security vendors. Based on the delivered phishing email, confirmed user interaction, POST request, and malicious URL reputation, this case is assessed as a **true positive phishing incident with possible credential harvesting**.

## Alert Details

| Field               | Value                                         |
| ------------------- | --------------------------------------------- |
| Timestamp           | 2024-04-06 19:06:55+00:00                     |
| Sender Display Name | Paylogin                                      |
| Sender Email        | `Payloginehfih@bestoavdnk.net`                 |
| Sender Domain       | bestoacmoaltou.net                            |
| Recipient           | `rohit.shah@abc.com`                          |
| Email Subject       | Finance Login Payment                         |
| Sender IP           | 172.64.146.197                                |
| Status              | Delivered                                     |
| Action              | allowed                                       |
| Reason              | NA                                            |
| Suspicious URL      | `http://bestoacmoaltou.net/login.php`         |
| URL Category        | Security Risk                                 |
| Primary Risk        | Credential phishing / fake finance login page |

## Affected Assets

| Asset / Entity                 | Details                               |
| ------------------------------ | ------------------------------------- |
| Affected User                  | Rohit Shah                            |
| Recipient Mailbox              | `rohit.shah@abc.com`                  |
| Sender Email                   | `Payloginehfih@bestoavdnk.net`         |
| Sender Domain                  | bestoacmoaltou.net                    |
| Sender IP                      | 172.64.146.197                        |
| Phishing URL                   | `http://bestoacmoaltou.net/login.php` |
| Endpoint                       | Not Provided                          |
| User Interaction               | Confirmed                             |
| Possible Credential Submission | Possible due to POST request          |
| Confirmed Account Compromise   | Not Confirmed                         |

## Evidence Reviewed

### IOC Summary

| IOC Type       | Indicator                             |
| -------------- | ------------------------------------- |
| Sender Email   | `Payloginehfih@bestoavdnk.net`         |
| Sender Domain  | bestoacmoaltou.net                    |
| Sender IP      | 172.64.146.197                        |
| Recipient      | `rohit.shah@abc.com`                  |
| Email Subject  | Finance Login Payment                 |
| Phishing URL   | `http://bestoacmoaltou.net/login.php` |
| Destination IP | 172.64.146.197                        |
| Affected User  | Rohit Shah                            |

### URL Reputation Evidence

| Vendor                  | Detection |
| ----------------------- | --------- |
| alphaMountain.ai        | Phishing  |
| CyRadar                 | Malicious |
| Forcepoint ThreatSeeker | Phishing  |
| Lionic                  | Malicious |
| Seclookup               | Malicious |
| Webroot                 | Malicious |

## SIEM / Splunk Analysis

### Investigation Flow

#### 1. Alert Review

The alert was reviewed as an email gateway event involving a **newly registered sender domain**. Newly registered domains are commonly abused in phishing campaigns because attackers can quickly create disposable domains for fake login pages, payment lures, and credential harvesting.

Key suspicious indicators:

| Indicator           | Observation           |
| ------------------- | --------------------- |
| Sender Display Name | Paylogin              |
| Sender Domain       | bestoacmoaltou.net    |
| Subject Theme       | Finance Login Payment |
| Email Status        | Delivered             |
| Gateway Action      | allowed               |
| URL Path            | `/login.php`          |
| Vendor Reputation   | Phishing/Malicious    |

The sender display name and subject suggest a finance/payment login lure intended to make the recipient interact with the link.

#### 2. Email Delivery Validation

Email gateway logs confirmed that the message was delivered to **Rohit Shah** and allowed by the email gateway. This confirms mailbox exposure.

```spl id="cs0247_email_query"
index=main sourcetype="email_logs" "Finance Login Payment"
| table _time Sender SenderIP Recipient Email_Subject URL Status Action
```

```text id="cs0247_email_results"
_time	Sender	SenderIP	Recipient	Email_Subject	URL	Status	Action
2024-04-06 06:55:00	"Paylogin" <Payloginehfih@bestoavdnk.net>	172.64.146.197	rohit.shah@abc.com	Finance Login Payment	bestoacmoaltou.net/login.php	Delivered	allowed
```

#### 3. Proxy Activity Validation

Proxy logs confirmed that **Rohit Shah** accessed the suspicious URL. A GET request was followed by a POST request to the same login page.

```spl id="cs0247_proxy_query"
index=main sourcetype="proxy_logs" "172.64.146.197"
| table _time "Destination IP" "HTTP Method" "Response Code" URL "User Agent" Username
```

```text id="cs0247_proxy_results"
_time	Destination IP	HTTP Method	Response Code	URL	User Agent	Username
2024-04-07 09:21:00	172.64.146.197	POST	200	bestoacmoaltou.net/login.php	Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/123.0.0.0 Safari/537.36	Rohit Shah
2024-04-07 09:20:00	172.64.146.197	GET	200	bestoacmoaltou.net/login.php	Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/123.0.0.0 Safari/537.36	Rohit Shah
```

#### 4. Timeline Reconstruction

| Time                      | Event                                                                                  |
| ------------------------- | -------------------------------------------------------------------------------------- |
| 2024-04-06 06:55:00       | Email gateway log shows phishing email delivered to Rohit Shah                         |
| 2024-04-06 19:06:55+00:00 | Alert triggered for newly registered domain in sender address                          |
| 2024-04-07 09:20:00       | Rohit Shah accessed `bestoacmoaltou.net/login.php` using GET; response code 200        |
| 2024-04-07 09:21:00       | Rohit Shah submitted POST request to `bestoacmoaltou.net/login.php`; response code 200 |
| Investigation Time        | URL reputation confirmed phishing/malicious detections from multiple vendors           |

#### 5. Evidence Interpretation

| Observation                               | Analyst Interpretation                 |
| ----------------------------------------- | -------------------------------------- |
| Email delivered and allowed               | User mailbox exposure confirmed        |
| Sender domain newly registered/suspicious | Possible phishing infrastructure       |
| Subject references finance login/payment  | Social engineering lure                |
| URL path contains `login.php`             | Possible fake login page               |
| GET request observed                      | User opened the phishing page          |
| POST request observed                     | Possible form or credential submission |
| Response code 200                         | Server accepted/responded to request   |
| Vendor detections show phishing/malicious | Supports true positive classification  |

#### 6. Impact Validation

The logs confirm that Rohit Shah interacted with the phishing URL. The POST request is the highest-risk evidence because it may indicate that credentials or form data were submitted.

However, the provided evidence does **not** confirm the exact data entered, successful account compromise, MFA approval, suspicious login activity, malware download, or endpoint compromise.

## MITRE ATT&CK Mapping

| Tactic              | Technique                                 | ID        | Reason                                                                     |
| ------------------- | ----------------------------------------- | --------- | -------------------------------------------------------------------------- |
| Initial Access      | Phishing                                  | T1566     | Phishing email was delivered to the user                                   |
| Initial Access      | Spearphishing Link                        | T1566.002 | Email contained a phishing login URL                                       |
| Credential Access   | Input Capture                             | T1056     | POST request to login page may indicate submitted credentials or form data |
| Credential Access   | Valid Accounts                            | T1078     | Potential risk if corporate credentials were submitted; not confirmed      |
| Defense Evasion     | Masquerading                              | T1036     | Sender used payment/login-themed identity to appear legitimate             |
| Command and Control | Application Layer Protocol: Web Protocols | T1071.001 | User interacted with phishing infrastructure using web traffic             |

## Analyst Assessment

**Assessment:** **True Positive — Phishing Email with User Interaction and Possible Credential Submission**

The alert is valid because the email originated from a suspicious newly registered sender domain, contained a finance/login-themed lure, and led the user to a phishing URL flagged by multiple vendors.

Proxy logs confirmed that Rohit Shah accessed the URL and generated a POST request. This indicates possible credential or form submission, but the exact submitted data is not visible in the provided logs.

This is **not confirmed account compromise** because no authentication logs, MFA activity, mailbox rule changes, endpoint alerts, or confirmed credential misuse were provided.

## Impact Analysis

| Impact Area                          | Status        |
| ------------------------------------ | ------------- |
| Suspicious external email delivered  | Confirmed     |
| Email gateway allowed message        | Confirmed     |
| Phishing login URL present           | Confirmed     |
| User accessed phishing URL           | Confirmed     |
| GET request observed                 | Confirmed     |
| POST request observed                | Confirmed     |
| URL categorized as security risk     | Confirmed     |
| Phishing/malicious vendor detections | Confirmed     |
| Exact credentials entered            | Not Confirmed |
| Successful account compromise        | Not Confirmed |
| MFA approval                         | Not Confirmed |
| Suspicious login after POST          | Not Provided  |
| Malware download                     | Not Confirmed |
| Endpoint compromise                  | Not Confirmed |
| Data exfiltration                    | Not Confirmed |

Current impact: **User interaction confirmed. Credential compromise is possible but not fully confirmed.**

## Recommended Actions

1. Contact **Rohit Shah** immediately and confirm whether credentials, OTP, MFA code, or finance/payment details were entered.
2. Reset Rohit Shah’s corporate password as a precaution due to POST activity.
3. Revoke active sessions and refresh tokens for Rohit Shah.
4. Review authentication logs, VPN logs, and MFA logs after **2024-04-07 09:21:00**.
5. Review mailbox forwarding rules and inbox rules for suspicious changes.
6. Quarantine or remove the phishing email from Rohit Shah’s mailbox.
7. Search all mailboxes for the same sender, subject, URL, sender domain, and sender IP.
8. Block `Payloginehfih@bestoavdnk.net` in the email gateway.
9. Block or quarantine emails from `bestoacmoaltou.net`.
10. Block `http://bestoacmoaltou.net/login.php` in proxy/SWG.
11. Block `bestoacmoaltou.net` in DNS security.
12. Block destination IP `172.64.146.197` only if policy allows and business impact is reviewed.
13. Add the sender, URL, domain, IP, and affected user to SIEM watchlist.
14. Review Rohit Shah’s endpoint for downloads, suspicious browser activity, or EDR alerts.
15. Monitor Rohit Shah’s account for 2–3 days after password reset and containment.

## Escalation Decision

**Decision:** **Conditional escalation to SOC L2 / Identity Team.**

**Reason:** The phishing email was delivered, the user clicked the link, and a POST request was observed. This creates a credible risk of credential submission.

Escalate to **SOC L2 / Identity Team** if any of the following are confirmed:

1. Rohit Shah entered corporate credentials.
2. MFA/OTP was entered or approved.
3. Suspicious login activity is found.
4. VPN/authentication anomalies are observed.
5. Mailbox forwarding or inbox rules were created.
6. Endpoint compromise indicators are found.
7. Similar emails were delivered to other users.
8. Additional users clicked the phishing URL.

If Rohit confirms no credentials were entered and authentication logs are clean, close after email removal, IOC blocking, password reset decision, and monitoring documentation.

## Final Ticket Closure Comment

SOC investigated ticket **CS-050 — Email Gateway: Newly Registered Domains in Sender Address**. The email was sent from `"Paylogin" <Payloginehfih@bestoavdnk.net>` to `rohit.shah@abc.com` with the subject **Finance Login Payment**. Email gateway logs confirmed the message was **Delivered** and **allowed** and contained the URL `bestoacmoaltou.net/login.php`. Proxy logs confirmed that **Rohit Shah** accessed the URL using a GET request and later generated a POST request to the same login page. The URL was categorized as a security risk and was flagged as phishing/malicious by multiple vendors. No confirmed credential compromise, MFA approval, endpoint compromise, malware download, or data exfiltration was identified from the provided logs. Ticket closed as **True Positive — Phishing Email with User Interaction and Possible Credential Submission**, with user validation, password reset/session revocation review, mailbox cleanup, IOC blocking, authentication log review, and conditional SOC L2 escalation recommended.

## Skills Demonstrated

Email gateway alert triage, newly registered domain investigation, phishing email analysis, user interaction validation, proxy log correlation, POST request interpretation, credential exposure risk assessment, IOC extraction, MITRE ATT&CK mapping, containment planning, identity validation, escalation decision-making, and SOC ticket documentation.
