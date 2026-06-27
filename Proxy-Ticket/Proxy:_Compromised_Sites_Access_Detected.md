# SOC Analyst Investigation Report

## Ticket Overview

| Field            | Details                                                                       |
| ---------------- | ----------------------------------------------------------------------------- |
| Ticket ID        | CS-037                                                                        |
| Alert Name       | Proxy: Compromised Sites Access Detected                                      |
| Ticket Status    | Closed                                                                        |
| Priority / SLA   | Normal / Default SLA                                                          |
| Created Date     | 3/16/25 7:42 PM                                                               |
| Closed By        | ananda das                                                                    |
| Analyst Decision | **True Positive — Compromised Site Access Attempt / No Confirmed Compromise** |

## Executive Summary

A proxy alert was triggered for **Compromised Sites Access Detected** involving user **Alice Gupta** from internal source IP **10.1.2.47** accessing external destination IP **203.0.86.25**.

The accessed URL was **http://accounts.instagram.com.bb3.in**, categorized by the proxy as **Compromised Sites**. The domain appears suspicious because it impersonates Instagram using a lookalike subdomain pattern under **bb3.in**.

The proxy action was **Allowed**, but additional proxy validation showed HTTP **403**, indicating the request did not successfully load normal content or may have been denied by the destination/proxy/security layer.

Email log correlation identified that the same URL was delivered to **[Alice.Gupta@abc.com](mailto:Alice.Gupta@abc.com)** from **[shreyas.kumar@bb3.in](mailto:shreyas.kumar@bb3.in)** with a crypto/bitcoin-themed subject. This suggests the proxy access was likely related to a phishing or malicious email link.

No confirmed credential submission, malware download, endpoint compromise, C2 callback, or data exfiltration was identified from the provided logs.

## Alert Details

| Field               | Value                                                                   |
| ------------------- | ----------------------------------------------------------------------- |
| Timestamp           | 3/15/2025 09:49                                                         |
| Username            | Alice Gupta                                                             |
| Source IP           | 10.1.2.47                                                               |
| Destination IP      | 203.0.86.25                                                             |
| URL Domain          | accounts.instagram.com.bb3.in                                           |
| URL                 | http://accounts.instagram.com.bb3.in                                    |
| Web Category        | Compromised Sites                                                       |
| Proxy Action        | Allowed                                                                 |
| HTTP Method         | GET                                                                     |
| Response Code       | 403                                                                     |
| Destination Details | Chevron Corporation; Data Center/Web Hosting/Transit; Sydney, Australia |

## Affected Assets

| Asset Field       | Details                       |
| ----------------- | ----------------------------- |
| User              | Alice Gupta                   |
| Source IP         | 10.1.2.47                     |
| Endpoint          | ENDP-590                      |
| Endpoint OS       | Windows 11-64                 |
| User Role         | Security Engineer L1          |
| Department        | Cybersecurity                 |
| Destination IP    | 203.0.86.25                   |
| Suspicious Domain | accounts.instagram.com.bb3.in |

## Evidence Reviewed

| Evidence Source       | Observation                                                        |
| --------------------- | ------------------------------------------------------------------ |
| Proxy Alert           | User accessed a URL categorized as **Compromised Sites**           |
| Proxy Response        | HTTP **403** observed                                              |
| Email Logs            | Same URL delivered to Alice via email                              |
| Suspicious Sender     | `shreyas.kumar@bb3.in`                                             |
| Suspicious Subject    | Crypto / Bitcoin earning lure                                      |
| Related Sender        | `debra.grant@ibm.com` observed in related bounced email evidence   |
| Related Malicious URL | `almex.rs/login.php?cmd=login_submit...`                           |
| Attachment Hash       | `869cf49215bc69204dc118027b36c9f81136f6bb6e2de3863d0525e188c570cb` |
| Credential Submission | Not Observed                                                       |
| Malware Download      | Not Observed                                                       |
| C2 Callback           | Not Observed                                                       |
| Endpoint Compromise   | Not Observed                                                       |

## SIEM / Splunk Analysis

### Proxy Log Query

```spl id="cs0257_proxy_query"
index=main sourcetype="proxy_logs" "Source IP"="10.1.2.47" "URL Domain"="accounts.instagram.com.bb3.in"
| table Timestamp, Username, "Source IP", "Destination IP", "URL Domain", URL, "Web Category", Action, "HTTP Method"
| sort - Timestamp
```

### Proxy Log Result

```text id="cs0257_proxy_result"
Timestamp	Username	Source IP	Destination IP	URL Domain	URL	Web Category	Action	HTTP Method
3/15/2025 9:49	Alice Gupta	10.1.2.47	203.0.86.25	accounts.instagram.com.bb3.in	http://accounts.instagram.com.bb3.in	Compromised Sites	Allowed	GET
```

### Email Log Query for Suspicious Domain

```spl id="cs0257_email_domain_query"
index=main "accounts.instagram.com.bb3.in" sourcetype="email_logs"
| table _time, SenderIP, Sender, Recipient, URL, Action, Email_Subject, Status, MessageID
| sort - _time
```

### Email Log Results for Suspicious Domain

```text id="cs0257_email_domain_results"
_time	SenderIP	Sender	Recipient	URL	Action	Email_Subject	Status	MessageID
2025-03-14 19:23:00	162.255.118.51	shreyas.kumar@bb3.in	Alice.Gupta@abc.com	http://accounts.instagram.com.bb3.in	allowed	Work From Home – Start Earning in Crypto" - "Join Our Bitcoin Mining Program	delivered	545ghhrhssdhdfvcfd@bb3.in
2025-02-03 09:49:00	104.69.173.25	debra.grant@ibm.com	arun.cooper@abc.com	http://accounts.instagram.com.bb3.in	allowed	Action Required: Policy Update	bounced	<4bc39fcc-a586-4984-ab3a-2078029a050c@ibm.com>
```

### Related Email Log Results

```text id="cs0257_related_email_results"
_time	SenderIP	Sender	Recipient	URL	Action	Email_Subject	Status	MessageID	Attachment_Hash	Attachment_Name
2025-02-03 09:49:00	104.69.173.25	debra.grant@ibm.com	arun.cooper@abc.com	NA	allowed	Payment Confirmation Required	bounced	<4bc39fcc-a586-4984-ab3a-2078029a050c@ibm.com>	869cf49215bc69204dc118027b36c9f81136f6bb6e2de3863d0525e188c570cb	action_plan_Q2_2024.pdf
2025-02-03 09:49:00	104.69.173.25	debra.grant@ibm.com	arun.cooper@abc.com	http://almex.rs/login.php?cmd=login_submit&id=fc341f527c2186d639c06aec3e2f4f92fc341f527c2186d639c06aec3e2f4f92&session=fc341f527c2186d639c06aec3e2f4f92fc341f527c2186d639c06aec3e2f4f92	allowed	Action Required: Policy Update	bounced	<4bc39fcc-a586-4984-ab3a-2078029a050c@ibm.com>	869cf49215bc69204dc118027b36c9f81136f6bb6e2de3863d0525e188c570cb	action_plan_Q2_2024.pdf
2025-02-03 09:49:00	104.69.173.25	debra.grant@ibm.com	arun.cooper@abc.com	http://accounts.instagram.com.bb3.in	allowed	Action Required: Policy Update	bounced	<4bc39fcc-a586-4984-ab3a-2078029a050c@ibm.com>	NA	NA
```

## MITRE ATT&CK Mapping

| Tactic              | Technique                                 | ID        | Reason                                                                                |
| ------------------- | ----------------------------------------- | --------- | ------------------------------------------------------------------------------------- |
| Initial Access      | Phishing                                  | T1566     | Suspicious URL was delivered to the user by email                                     |
| Initial Access      | Drive-by Compromise                       | T1189     | User accessed a compromised/security-risk URL                                         |
| Command and Control | Application Layer Protocol: Web Protocols | T1071.001 | HTTP web traffic to suspicious external infrastructure was observed; C2 not confirmed |

## Analyst Assessment

**Assessment:** **True Positive — Likely Phishing / Compromised Site Access Attempt**

The alert is valid because the user accessed a suspicious domain categorized as **Compromised Sites**, and email logs show the same URL was delivered to the user through a suspicious crypto-themed email.

This is **not confirmed compromise**. The proxy response was HTTP **403**, and no evidence confirmed credential submission, malware download, endpoint compromise, C2 callback, or data exfiltration.

## Impact Analysis

| Area            | Assessment                                                                |
| --------------- | ------------------------------------------------------------------------- |
| Confidentiality | No credential submission or data exposure confirmed                       |
| Integrity       | No endpoint modification confirmed                                        |
| Availability    | No service impact reported                                                |
| Business Impact | No confirmed impact                                                       |
| Current Risk    | Medium until user validation confirms no interaction or download occurred |

## Recommended Actions

1. Contact **Alice Gupta** to confirm whether she clicked the email link.
2. Confirm whether any credentials, OTP, MFA code, or personal information were entered.
3. Confirm whether any file was downloaded or opened.
4. Remove/quarantine the delivered email from the mailbox if still present.
5. Block **accounts.instagram.com.bb3.in** in proxy/DNS security controls.
6. Block **bb3.in** and **[shreyas.kumar@bb3.in](mailto:shreyas.kumar@bb3.in)** in the email gateway if no business requirement exists.
7. Block sender IP **162.255.118.51** if supported by policy.
8. Block destination IP **203.0.86.25** if no business requirement exists.
9. Add related malicious URL **almex.rs/login.php** and attachment hash to watchlist/blocklist.
10. Validate related sender **[debra.grant@ibm.com](mailto:debra.grant@ibm.com)** through trusted channels before making any external compromise claim.
11. Escalate to SOC L2 only if credential entry, file download, EDR alert, C2 callback, or endpoint compromise is confirmed.

## Escalation Decision

**Decision:** **Conditional escalation; close after user validation and blocking if no impact is confirmed.**

**Reason:** The event is suspicious and likely phishing-related, but the provided logs do not confirm credential theft, malware execution, C2 communication, or endpoint compromise. SOC L2 escalation is required only if user interaction or endpoint indicators confirm impact.

## Final Ticket Closure Comment

SOC investigated ticket **CS-037 — Proxy: Compromised Sites Access Detected**. Proxy logs show user **Alice Gupta** from **10.1.2.47 / ENDP-590** accessed **http://accounts.instagram.com.bb3.in**, categorized as **Compromised Sites**. The proxy action was Allowed, but additional validation showed HTTP **403**. Email logs confirmed the same URL was delivered to **[Alice.Gupta@abc.com](mailto:Alice.Gupta@abc.com)** from **[shreyas.kumar@bb3.in](mailto:shreyas.kumar@bb3.in)** with a crypto/bitcoin-themed subject, indicating a likely phishing link. Related bounced email evidence also contained the same URL, another malicious URL under **almex.rs**, and attachment hash **869cf49215bc69204dc118027b36c9f81136f6bb6e2de3863d0525e188c570cb**. No confirmed credential submission, malware download, C2 callback, endpoint compromise, or data exfiltration was identified. Ticket closed as **True Positive — Compromised Site Access Attempt / No Confirmed Compromise**, with user validation, email quarantine, IOC blocking, and monitoring recommended.

## Skills Demonstrated

Proxy alert triage, phishing investigation, URL/domain analysis, email log correlation, user and endpoint validation, IOC handling, Splunk log review, MITRE ATT&CK mapping, impact assessment, escalation decision-making, and SOC ticket documentation.

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
