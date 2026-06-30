# SOC Analyst Investigation Report

## Ticket Overview

| Field            | Details                                                                                                       |
| ---------------- | ------------------------------------------------------------------------------------------------------------- |
| Ticket ID        | CS-051                                                                                                       |
| Alert Name       | Email Gateway: Detection of Suspicious External Emails Targeting Corporate Domains                            |
| Ticket Status    | Resolved                                                                                                      |
| Priority / SLA   | Normal / Medium                                                                                               |
| Created Date     | 3/11/25 6:51 PM                                                                                               |
| Closed By        | Ananda Das                                                                                                    |
| Severity         | High                                                                                                          |
| Analyst Decision | **True Positive — SharePoint-Themed Phishing Email with User Interaction and Possible Credential Submission** |

## Executive Summary

An email gateway alert was triggered for suspicious external emails targeting corporate mailboxes. The campaign used a **Microsoft SharePoint / purchase order** theme to trick users into opening a phishing URL.

The primary sender observed was:

`Microsoft Sharepoint <codex@thino.cfd>`

The emails were delivered to multiple recipients:

* `ajay.joshi@abc.com`
* `david.patel@abc.com`
* `info@abc.com`

The email contained a suspicious GitHub Pages-hosted URL under:

`jjjjjefta.github.io`

The phishing URL was categorized as a **Security Risk** and classified as **Phishing**. A related earlier suspicious SharePoint-themed email was also observed from:

`Noreply@abc.com`

This related email contained a Glitch-hosted URL:

`bird-rattle-sundial.glitch.me`

Proxy logs confirmed that user **David Patel** accessed the suspicious `jjjjjefta.github.io` domain using a **GET** request and later submitted a **POST** request. The POST request returned HTTP **200**, which may indicate form submission or possible credential entry.

Based on the external sender, SharePoint impersonation, purchase order lure, phishing URL reputation, delivered email status, and confirmed POST activity, this case is assessed as a **true positive phishing incident with user interaction and possible credential submission**.

## Alert Details

| Field                    | Value                         |
| ------------------------ | ----------------------------- |
| Initial Alert Timestamp  | 2024-04-23 03:25:10-07:00     |
| Sender Display Name      | Microsoft Sharepoint          |
| Sender Email             | `codex@thino.cfd`      |
| Sender Domain            | trangthino.cfd                |
| Initial Recipient        | `info@abc.com`                |
| Email Subject            | Purchase Order Ref :64167     |
| Sender IP                | 193.239.86.150                |
| Status                   | Delivered                     |
| Action                   | allowed                       |
| Reason                   | NA                            |
| Primary Phishing Domain  | jjjjjefta.github.io           |
| Related Malicious Domain | bird-rattle-sundial.glitch.me |
| Proxy Destination IP     | 185.199.109.153               |
| Confirmed Clicked User   | David Patel                   |
| POST Request Observed    | Yes                           |
| Current Assessment       | True Positive Phishing        |

## Affected Assets

| User / Mailbox                                             | Evidence Observed                                                  | Risk Level |
| ---------------------------------------------------------- | ------------------------------------------------------------------ | ---------- |
| Ajay Joshi                                                 | Email delivered with phishing URL                                  | Medium     |
| David Patel                                                | Email delivered, GET and POST requests to phishing domain observed | High       |
| [info@abc.com](mailto:info@abc.com)                        | Email delivered with phishing URL                                  | Medium     |
| [Noreply@abc.com](mailto:Noreply@abc.com) related activity | Earlier related SharePoint-themed suspicious email observed        | Medium     |

## Evidence Reviewed

### IOC Summary

| IOC Type                  | Indicator                                                                                             |
| ------------------------- | ----------------------------------------------------------------------------------------------------- |
| Sender Display Name       | Microsoft Sharepoint                                                                                  |
| Sender Email              | `codex@thino.cfd`                                                                              |
| Sender Domain             | trangthino.cfd                                                                                        |
| Sender IP                 | 193.239.86.150                                                                                        |
| Related Sender            | `Noreply@abc.com`                                                                                     |
| Related Sender IP         | 52.101.194.10                                                                                         |
| Recipient                 | `ajay.joshi@abc.com`                                                                                  |
| Recipient                 | `david.patel@abc.com`                                                                                 |
| Recipient                 | `info@abc.com`                                                                                        |
| Email Subject             | Purchase Order Ref :64189                                                                             |
| Email Subject             | Purchase Order Ref :64132                                                                             |
| Email Subject             | Purchase Order Ref :64167                                                                             |
| Related Email Subject     | Microsoft Sharepoint                                                                                  |
| Phishing Domain           | jjjjjefta.github.io                                                                                   |
| Phishing URL              | `https://jjjjjefta.github.io/gined-eurekakhnudbnuhgjNBFtyjhkb-gdhkhnb-cgdhjhknchjyuhjbfgGHGFghjknbv/` |
| Related Malicious Domain  | bird-rattle-sundial.glitch.me                                                                         |
| Related Malicious URL     | `https://bird-rattle-sundial.glitch.me/?amnx=info@abc.com"><FONT`                                     |
| Proxy Destination IP      | 185.199.109.153                                                                                       |
| Affected User             | David Patel                                                                                           |
| Threat Type               | Phishing / Credential Harvesting                                                                      |
| Hosting Platform Observed | GitHub Pages / Glitch                                                                                 |

## URL Analysis

### Primary Phishing URL

| Field          | Details                                                                                                                                                                                                        |
| -------------- | -------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| URL Domain     | jjjjjefta.github.io                                                                                                                                                                                            |
| Full URL       | `https://jjjjjefta.github.io/gined-eurekakhnudbnuhgjNBFtyjhkb-gdhkhnb-cgdhjhknchjyuhjbfgGHGFghjknbv/?dkdld;pdlclllf;frdsxcvmail=ajay.joshi@abc.com&cbvghdjlkjhgfLIuytredvmM Cfghjmcxdfghjkmnbvmjolkdfdlkjhgfc` |
| Category       | Security Risk                                                                                                                                                                                                  |
| Classification | Phishing                                                                                                                                                                                                       |
| Risk           | Possible credential harvesting page                                                                                                                                                                            |
| Observation    | URL contains recipient email address as a parameter                                                                                                                                                            |

### Related Malicious URL

| Field          | Details                                                           |
| -------------- | ----------------------------------------------------------------- |
| URL Domain     | bird-rattle-sundial.glitch.me                                     |
| Full URL       | `https://bird-rattle-sundial.glitch.me/?amnx=info@abc.com"><FONT` |
| Category       | Security Risk                                                     |
| Classification | Malicious Sources/Malnets                                         |
| Risk           | Suspicious hosted phishing/malicious page                         |
| Observation    | URL contains suspicious HTML-like string `"><FONT`                |

## SIEM / Splunk Analysis

### Investigation Flow

#### 1. Alert Review

The alert was reviewed as a suspicious external email targeting corporate domains. The campaign used the trusted brand name **Microsoft SharePoint** and a purchase order theme, which is commonly used in phishing campaigns to make users open links or documents.

Key suspicious indicators:

| Indicator          | Observation               |
| ------------------ | ------------------------- |
| Display Name       | Microsoft Sharepoint      |
| Sender Domain      | trangthino.cfd            |
| Brand Theme        | Microsoft SharePoint      |
| Email Theme        | Purchase Order            |
| Email Status       | Delivered                 |
| Gateway Action     | allowed                   |
| URL Hosting        | GitHub Pages              |
| URL Classification | Phishing                  |
| User Interaction   | Confirmed for David Patel |
| POST Request       | Observed                  |

#### 2. Sender and Brand Impersonation Review

The sender used the display name **Microsoft Sharepoint**, but the actual sender address was:

`codex@thino.cfd`

This sender domain does not match Microsoft or the organization. The mismatch between display name and sender domain is a strong phishing indicator.

#### 3. Email Delivery Validation

Email gateway logs confirmed that similar SharePoint-themed emails were delivered to multiple corporate recipients.

```spl id="cs0234_email_query"
index=main "Microsoft Sharepoint" sourcetype=email_logs
| table _time Sender SenderIP Recipient Email_Subject URL Status Action
```

```text id="cs0234_email_results"
_time	Sender	SenderIP	Recipient	Email_Subject	URL	Status	Action
2024-04-23 07:00:00	Microsoft Sharepoint <codex@thino.cfd>	193.239.86.150	ajay.joshi@abc.com	Purchase Order Ref :64189	https://jjjjjefta.github.io/gined-eurekakhnudbnuhgjNBFtyjhkb-gdhkhnb-cgdhjhknchjyuhjbfgGHGFghjknbv/?dkdld;pdlclllf;frdsxcvmail=ajay.joshi@abc.com&cbvghdjlkjhgfLIuytredvmM%20Cfghjmcxdfghjkmnbvmjolkdfdlkjhgfc	Delivered	allowed
2024-04-23 07:00:00	Microsoft Sharepoint <codex@thino.cfd>	193.239.86.150	david.patel@abc.com	Purchase Order Ref :64132	https://jjjjjefta.github.io/gined-eurekakhnudbnuhgjNBFtyjhkb-gdhkhnb-cgdhjhknchjyuhjbfgGHGFghjknbv/?dkdld;pdlclllf;frdsxcvmail=david.patel@abc.com&cbvghdjlkjhgfLIuytredvmM%20Cfghjmcxdfghjkmnbvmjolkdfdlkjhgfc	Delivered	allowed
2024-04-23 07:00:00	Microsoft Sharepoint <codex@thino.cfd>	193.239.86.150	info@abc.com	Purchase Order Ref :64167	https://jjjjjefta.github.io/gined-eurekakhnudbnuhgjNBFtyjhkb-gdhkhnb-cgdhjhknchjyuhjbfgGHGFghjknbv/?dkdld;pdlclllf;frdsxcvmail=info@abc.com&cbvghdjlkjhgfLIuytredvmM%20Cfghjmcxdfghjkmnbvmjolkdfdlkjhgfc	Delivered	allowed
2024-04-03 13:14:00	Noreply@abc.com	52.101.194.10	info@abc.com	Microsoft Sharepoint	https://bird-rattle-sundial.glitch.me/?amnx=info@abc.com"><FONT	Delivered	allowed
```

#### 4. Initial Email Gateway Alert Evidence

| Timestamp                 | Sender               | Recipient      | Email Subject             | Sender IP      | Status    | Action  | Reason |
| ------------------------- | -------------------- | -------------- | ------------------------- | -------------- | --------- | ------- | ------ |
| 2024-04-23 03:25:10-07:00 | Microsoft Sharepoint | `info@abc.com` | Purchase Order Ref :64167 | 193.239.86.150 | Delivered | allowed | NA     |

#### 5. Proxy Activity Review

Proxy logs confirmed user interaction from **David Patel**.

```spl id="cs0234_proxy_query"
index=main sourcetype="proxy_logs" "jjjjjefta.github.io"
| table _time "Destination IP" "HTTP Method" "Response Code" "URL Domain" "Username"
```

```text id="cs0234_proxy_results"
_time	Destination IP	HTTP Method	Response Code	URL Domain	Username
2024-04-24 09:16:00	185.199.109.153	POST	200	jjjjjefta.github.io	David Patel
2024-04-24 09:15:00	185.199.109.153	GET	200	jjjjjefta.github.io	David Patel
```

#### 6. Timeline Reconstruction

| Time                      | Event                                                                                     |
| ------------------------- | ----------------------------------------------------------------------------------------- |
| 2024-04-03 13:14:00       | Related suspicious SharePoint-themed email observed with Glitch-hosted URL                |
| 2024-04-23 03:25:10-07:00 | Email gateway alert triggered for suspicious external email targeting corporate domain    |
| 2024-04-23 07:00:00       | Microsoft SharePoint-themed emails delivered to Ajay Joshi, David Patel, and info mailbox |
| 2024-04-24 09:15:00       | David Patel accessed `jjjjjefta.github.io` using GET request; response code 200           |
| 2024-04-24 09:16:00       | David Patel submitted POST request to `jjjjjefta.github.io`; response code 200            |

#### 7. Evidence Interpretation

| Observation                             | Analyst Interpretation                         |
| --------------------------------------- | ---------------------------------------------- |
| Microsoft SharePoint display name used  | Brand impersonation                            |
| Sender domain `trangthino.cfd`          | External and unrelated to Microsoft            |
| Purchase order subject                  | Business email compromise / invoice-style lure |
| Emails delivered to multiple recipients | Multi-user targeting                           |
| URL hosted on GitHub Pages              | Abuse of legitimate hosting platform           |
| Recipient email included in URL         | Possible phishing page personalization         |
| Related Glitch-hosted URL observed      | Similar hosted phishing pattern                |
| David Patel GET request                 | User opened phishing page                      |
| David Patel POST request                | Possible credential or form submission         |
| HTTP 200 response                       | Web server successfully responded              |

## MITRE ATT&CK Mapping

| Tactic              | Technique                                 | ID        | Reason                                                                |
| ------------------- | ----------------------------------------- | --------- | --------------------------------------------------------------------- |
| Initial Access      | Phishing                                  | T1566     | Suspicious external email was delivered to users                      |
| Initial Access      | Spearphishing Link                        | T1566.002 | Email contained a phishing URL                                        |
| Credential Access   | Input Capture                             | T1056     | POST request may indicate submitted credentials or form data          |
| Credential Access   | Valid Accounts                            | T1078     | Potential risk if corporate credentials were submitted; not confirmed |
| Defense Evasion     | Masquerading                              | T1036     | Sender impersonated Microsoft SharePoint                              |
| Command and Control | Application Layer Protocol: Web Protocols | T1071.001 | Web traffic to phishing infrastructure was observed; C2 not confirmed |

## Analyst Assessment

**Assessment:** **True Positive — SharePoint-Themed Phishing Email with User Interaction**

The alert is valid because the email impersonated Microsoft SharePoint, used purchase order references, targeted multiple corporate recipients, and delivered phishing URLs hosted on GitHub Pages. The phishing URL was categorized as a security risk and classified as phishing.

The highest-risk evidence is the **POST** request from **David Patel**, which may indicate form or credential submission. However, the exact submitted data is not visible from proxy logs.

No successful account compromise, MFA approval, suspicious VPN/login activity, malware download, endpoint compromise, or data exfiltration was confirmed from the provided evidence.

## Impact Analysis

| Impact Area                                      | Status        |
| ------------------------------------------------ | ------------- |
| Suspicious external email delivered              | Confirmed     |
| Multiple corporate users targeted                | Confirmed     |
| Email gateway allowed the messages               | Confirmed     |
| Phishing URL present                             | Confirmed     |
| URL categorized as security risk                 | Confirmed     |
| URL classified as phishing                       | Confirmed     |
| David Patel accessed phishing URL                | Confirmed     |
| David Patel GET request observed                 | Confirmed     |
| David Patel POST request observed                | Confirmed     |
| Related malicious SharePoint-themed URL observed | Confirmed     |
| Exact credentials entered                        | Not Confirmed |
| Successful account compromise                    | Not Confirmed |
| MFA approval                                     | Not Confirmed |
| Suspicious VPN/login activity                    | Not Provided  |
| Endpoint compromise                              | Not Confirmed |
| Malware download                                 | Not Confirmed |
| Data exfiltration                                | Not Confirmed |

Current impact: **User interaction confirmed for David Patel. Credential submission is possible due to POST activity, but account compromise is not confirmed.**

## Recommended Actions

1. Contact **David Patel** immediately and confirm whether credentials, OTP, MFA code, or sensitive information were entered.
2. Reset David Patel’s password as a precaution due to POST activity.
3. Revoke active sessions and refresh tokens for David Patel.
4. Review authentication, VPN, and MFA logs for David Patel after **2024-04-24 09:16:00**.
5. Review mailbox forwarding rules and inbox rules for David Patel if credential submission is confirmed.
6. Contact **Ajay Joshi** and the owner of `info@abc.com` to confirm whether the phishing URL was clicked.
7. Quarantine/remove delivered emails from all affected mailboxes.
8. Search all mailboxes for the same sender, subject pattern, URLs, sender IP, and sender domain.
9. Block `codex@thino.cfd` in the email gateway.
10. Block or quarantine emails from `trangthino.cfd`.
11. Block `jjjjjefta.github.io` in proxy/SWG and DNS security.
12. Block `bird-rattle-sundial.glitch.me` in proxy/SWG and DNS security.
13. Block destination IP `185.199.109.153` only if policy allows and business impact is reviewed.
14. Add all IOCs to SIEM watchlists and correlation rules.
15. Monitor affected users for **2–3 days** after containment.

**Blocking Note:** Since GitHub Pages and Glitch can be used for legitimate hosting, avoid broad blocking of all `github.io` or `glitch.me` unless policy approves. Prefer blocking the exact malicious subdomains and full URL paths.

## Escalation Decision

**Decision:** **Conditional escalation to SOC L2 / Identity Team.**

**Reason:** The phishing email was delivered to multiple users, and David Patel interacted with the phishing URL using both GET and POST requests. The POST request creates a credible risk of credential submission.

Escalate to **SOC L2 / Identity Team** if any of the following are confirmed:

1. David Patel entered corporate credentials.
2. David Patel entered OTP or approved MFA.
3. Suspicious authentication activity is found.
4. Mailbox forwarding or suspicious inbox rules are created.
5. Additional users clicked the phishing URL.
6. Endpoint compromise indicators are identified.
7. Phishing emails remain in user mailboxes.
8. Similar campaign activity continues.

If David confirms no credentials were entered and authentication logs are clean, close after mailbox cleanup, IOC blocking, and monitoring documentation.

## Final Ticket Closure Comment

SOC investigated ticket **CS-051 — Email Gateway: Detection of Suspicious External Emails Targeting Corporate Domains**. The campaign used a Microsoft SharePoint and purchase order theme and was sent from `Microsoft Sharepoint <codex@thino.cfd>`. Email gateway logs confirmed delivery to `ajay.joshi@abc.com`, `david.patel@abc.com`, and `info@abc.com`. The emails contained phishing URLs hosted on `jjjjjefta.github.io`. A related earlier SharePoint-themed suspicious email used `bird-rattle-sundial.glitch.me`. Proxy logs confirmed that **David Patel** accessed `jjjjjefta.github.io` and performed both GET and POST requests with HTTP response code 200. The POST request creates a possible credential submission risk. No successful account compromise, MFA approval, endpoint compromise, malware download, or data exfiltration was confirmed from the provided logs. Ticket closed as **True Positive — SharePoint-Themed Phishing Email with User Interaction and Possible Credential Submission**, with email quarantine, IOC blocking, David Patel user validation, password/session review, authentication log review, and conditional SOC L2/Identity Team escalation recommended if credential submission or suspicious login activity is confirmed.

## Skills Demonstrated

Email gateway alert triage, suspicious external email investigation, SharePoint-themed phishing analysis, sender impersonation review, URL reputation analysis, hosted phishing infrastructure review, Splunk email log analysis, proxy log correlation, POST request interpretation, credential exposure risk assessment, IOC extraction, MITRE ATT&CK mapping, impact validation, containment planning, and conditional escalation decision-making.

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
