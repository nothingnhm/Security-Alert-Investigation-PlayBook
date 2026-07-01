# SOC Analyst Investigation Report

## Ticket Overview

| Field                | Details                                                                                               |
| -------------------- | ----------------------------------------------------------------------------------------------------- |
| Ticket ID            | CS-053                                                                                               |
| Alert Name           | Phishing Email                                                                                        |
| Category             | Suspicious Email / Malicious Attachment                                                               |
| Ticket Status        | Closed                                                                                                |
| Priority / SLA       | Normal / Medium                                                                                       |
| Department           | Support                                                                                               |
| Created Date         | 3/12/25 9:56 PM                                                                                       |
| Reported By          | Arun Gupta                                                                                            |
| Reporter Email       | `arun.gupta@abc.com`                                                                                  |
| Closed By            | Ananda Das                                                                                            |
| Submitted Attachment | `City of Lake Forest 2025-02-12 - Sign order_ 09098897- GP - PI - INVo. 24ST CV33846 - AIR130259.eml` |
| Analyst Decision     | **True Positive — Malicious Excel Attachment Delivered / No Execution Observed**                      |

## Executive Summary

User **Arun Gupta** reported a suspicious email containing a malicious Excel attachment. The email used a purchase order / invoice signing theme and appeared to come from:

`Juan Ramirez <Rami@cityhack.com>`

The subject was:

`City of Lake Forest 2025-02-12 - Sign order# 09098897-GP - PI - INVo. 24ST CV33846 - AIR130259`

Email gateway logs confirmed that the email was delivered to three internal recipients:

* `arun.gupta@abc.com`
* `inaaya.ramachandran@abc.com`
* `shalv.keer@abc.com`

The attachment observed in the email logs was:

`The City of Lake Forest.xlsx`

The attachment SHA1 hash was:

`2a3a695210d13068a765f03bcd2ae8e3d43006eb`

Reputation analysis confirmed the attachment as malicious, with **24/64 security vendors** detecting the file as malicious. The file was categorized as a **Trojan / phishing-related payload**.

EDR investigation did not identify attachment execution, suspicious process creation, persistence, malware activity, or endpoint compromise. IPS investigation identified a historical detection for a similar phishing attachment pattern, but no active exploitation or further malicious communication was observed.

Based on the delivered malicious attachment and vendor reputation, this case is assessed as a **True Positive malicious attachment delivery**. However, no execution or endpoint compromise was confirmed from the provided evidence.

## Alert Details

| Field                | Value                                                                                          |
| -------------------- | ---------------------------------------------------------------------------------------------- |
| Email Time           | 2025-02-13 05:55:00                                                                            |
| Sender Name          | Juan Ramirez                                                                                   |
| Sender Email         | `Rami@cityhack.com`                                                                |
| Sender Domain        | cityoflakeforest.com                                                                           |
| Sender IP            | 52.101.194.18                                                                                  |
| Subject              | City of Lake Forest 2025-02-12 - Sign order# 09098897-GP - PI - INVo. 24ST CV33846 - AIR130259 |
| Recipients           | `arun.gupta@abc.com`, `inaaya.ramachandran@abc.com`, `shalv.keer@abc.com`                      |
| Return Path          | Not Found                                                                                      |
| SPF                  | Not Found                                                                                      |
| DKIM                 | Not Found                                                                                      |
| DMARC                | Not Found                                                                                      |
| Action               | Allowed                                                                                        |
| Status               | Delivered                                                                                      |
| URL                  | No URL identified                                                                              |
| Attachment Name      | The City of Lake Forest.xlsx                                                                   |
| Attachment Hash      | 2a3a695210d13068a765f03bcd2ae8e3d43006eb                                                       |
| Attachment Execution | Not Observed                                                                                   |
| Final Verdict        | True Positive                                                                                  |

## Affected Assets

| User / Mailbox      | Evidence Observed                               | Risk Level |
| ------------------- | ----------------------------------------------- | ---------- |
| Arun Gupta          | Email delivered with malicious Excel attachment | Medium     |
| Inaaya Ramachandran | Email delivered with malicious Excel attachment | Medium     |
| Shalv Keer          | Email delivered with malicious Excel attachment | Medium     |

## Evidence Reviewed

### IOC Summary

| IOC Type             | Indicator                                                                                      |
| -------------------- | ---------------------------------------------------------------------------------------------- |
| Sender Name          | Juan Ramirez                                                                                   |
| Sender Email         | `Rami@cityhack.com`                                                                |
| Sender Domain        | cityoflakeforest.com                                                                           |
| Sender IP            | 52.101.194.18                                                                                  |
| Recipient            | `arun.gupta@abc.com`                                                                           |
| Recipient            | `inaaya.ramachandran@abc.com`                                                                  |
| Recipient            | `shalv.keer@abc.com`                                                                           |
| Email Subject        | City of Lake Forest 2025-02-12 - Sign order# 09098897-GP - PI - INVo. 24ST CV33846 - AIR130259 |
| Attachment Name      | The City of Lake Forest.xlsx                                                                   |
| SHA1 Hash            | 2a3a695210d13068a765f03bcd2ae8e3d43006eb                                                       |
| IPS Source IP        | 65.55.127.67                                                                                   |
| Threat Signature     | SMTP: Malicious Attachment with Phishing Payload                                               |
| Threat Category      | Trojan / Phishing Payload                                                                      |
| URL                  | No URL identified                                                                              |
| Attachment Execution | Not observed                                                                                   |
| Malware Execution    | Not observed                                                                                   |

## SIEM / Splunk Analysis

### Investigation Flow

#### 1. Alert Review

The ticket was reviewed as a user-reported phishing email with a suspicious attachment. The email used a purchase order / invoice signing theme, which is commonly used in phishing campaigns to convince users to open attachments.

Key suspicious indicators:

| Indicator             | Observation                           |
| --------------------- | ------------------------------------- |
| Sender                | `Rami@cityhack.com`       |
| Subject Theme         | Purchase order / invoice / sign order |
| Attachment Type       | Excel spreadsheet                     |
| Attachment Reputation | Malicious                             |
| Detection Ratio       | 24/64 security vendors                |
| Email Gateway Action  | Allowed                               |
| Delivery Status       | Delivered                             |
| User Execution        | Not observed                          |
| Endpoint Compromise   | Not observed                          |

#### 2. Email Gateway Review

Email gateway logs confirmed that the same malicious attachment was delivered to three internal users.

```spl id="cs0239_email_query"
index=main sourcetype="email_logs" "Rami@cityhack.com"
| table _time Sender SenderIP Recipient Email_Subject Attachment_Name Attachment_Hash Action Status MessageID
```

```text id="cs0239_email_results"
_time	Sender	SenderIP	Recipient	Email_Subject	Attachment_Name	Attachment_Hash	Action	Status
2025-02-13 05:55:00	Rami@cityhack.com	52.101.194.18	shalv.keer@abc.com	City of Lake Forest 2025-02-12 - Sign order# 09098897-GP - PI - INVo. 24ST CV33846 - AIR130259	The City of Lake Forest.xlsx	2a3a695210d13068a765f03bcd2ae8e3d43006eb	Allowed	Delivered
2025-02-13 05:55:00	Rami@cityhack.com	52.101.194.18	inaaya.ramachandran@abc.com	City of Lake Forest 2025-02-12 - Sign order# 09098897-GP - PI - INVo. 24ST CV33846 - AIR130259	The City of Lake Forest.xlsx	2a3a695210d13068a765f03bcd2ae8e3d43006eb	Allowed	Delivered
2025-02-13 05:55:00	Rami@cityhack.com	52.101.194.18	arun.gupta@abc.com	City of Lake Forest 2025-02-12 - Sign order# 09098897-GP - PI - INVo. 24ST CV33846 - AIR130259	The City of Lake Forest.xlsx	2a3a695210d13068a765f03bcd2ae8e3d43006eb	Allowed	Delivered
```

### Email Gateway Findings

| Finding                                | Assessment                            |
| -------------------------------------- | ------------------------------------- |
| Total delivered emails                 | 3                                     |
| Attachment delivered to all recipients | Confirmed                             |
| Same attachment hash across recipients | Confirmed                             |
| Email gateway action                   | Allowed                               |
| Email status                           | Delivered                             |
| URL in email body                      | Not identified from provided evidence |
| Attachment risk                        | Malicious based on reputation         |

#### 3. Attachment Reputation Review

| Indicator            | Value                                     |
| -------------------- | ----------------------------------------- |
| Attachment Name      | The City of Lake Forest.xlsx              |
| SHA1 Hash            | 2a3a695210d13068a765f03bcd2ae8e3d43006eb  |
| Reputation           | Malicious                                 |
| VirusTotal Detection | 24/64 security vendors                    |
| Threat Category      | Trojan / Phishing Payload                 |
| File Type            | Excel Spreadsheet                         |
| Risk                 | Malware execution / credential theft risk |

### Attachment Findings

The attachment was identified as malicious by multiple security vendors. The detection category indicates a phishing-related Trojan payload. Because the file is an Excel spreadsheet, the risk includes potential macro execution, malicious embedded content, credential theft, or payload delivery if opened by the user.

#### 4. EDR Review

EDR investigation was performed for the affected users/endpoints.

### EDR Findings

| Check                             | Result       |
| --------------------------------- | ------------ |
| Attachment execution              | Not observed |
| Suspicious process creation       | Not observed |
| Excel child processes             | Not observed |
| Persistence mechanisms            | Not observed |
| Malware-related endpoint activity | Not observed |
| Endpoint compromise               | Not observed |

The EDR review did not confirm execution of the malicious attachment. No suspicious child processes, persistence, malware behavior, or endpoint compromise were observed from the provided evidence.

#### 5. IPS Review

A historical IPS alert was identified for a similar phishing attachment detection pattern.

| Field       | Value                                            |
| ----------- | ------------------------------------------------ |
| Threat Name | SMTP: Malicious Attachment with Phishing Payload |
| Source IP   | 65.55.127.67                                     |
| Category    | Phishing Payload                                 |
| Status      | Historical Event                                 |

### IPS Findings

| Observation                                 | Analyst Interpretation             |
| ------------------------------------------- | ---------------------------------- |
| Similar phishing payload signature observed | Supports malicious attachment risk |
| Event was historical                        | Does not confirm active compromise |
| No further communication observed           | No active exploitation confirmed   |
| No hash-related network activity observed   | No follow-on activity confirmed    |

#### 6. Timeline Reconstruction

| Time                | Event                                                                |
| ------------------- | -------------------------------------------------------------------- |
| 2025-02-13 05:55:00 | Malicious email delivered to `shalv.keer@abc.com`                    |
| 2025-02-13 05:55:00 | Malicious email delivered to `inaaya.ramachandran@abc.com`           |
| 2025-02-13 05:55:00 | Malicious email delivered to `arun.gupta@abc.com`                    |
| Investigation Time  | Attachment reputation confirmed malicious detection by 24/64 vendors |
| Investigation Time  | EDR review found no attachment execution or endpoint compromise      |
| Investigation Time  | IPS review identified historical similar phishing payload detection  |
| Closure Time        | IOC blocking and user notification completed/recommended             |

#### 7. Attack Chain Assessment

The evidence supports the following attempted attack chain:

1. External sender delivered a purchase order / invoice-themed email.
2. The email contained a malicious Excel attachment.
3. The attachment was delivered to three internal recipients.
4. Attachment reputation identified the file as malicious.
5. EDR review found no execution.
6. No process creation, persistence, malware execution, or endpoint compromise was observed.
7. The incident remained limited to malicious attachment delivery based on the provided evidence.

## MITRE ATT&CK Mapping

| Tactic              | Technique                                 | ID        | Reason                                                                                      |
| ------------------- | ----------------------------------------- | --------- | ------------------------------------------------------------------------------------------- |
| Initial Access      | Phishing                                  | T1566     | Malicious email was delivered to users                                                      |
| Initial Access      | Spearphishing Attachment                  | T1566.001 | Email contained a malicious Excel attachment                                                |
| Execution           | User Execution: Malicious File            | T1204.002 | Execution would require the user to open/run the malicious file; execution was not observed |
| Defense Evasion     | Obfuscated Files or Information           | T1027     | Malicious Office documents may contain hidden payload logic; macro/code review not provided |
| Credential Access   | Input Capture                             | T1056     | Possible if phishing payload was executed; not confirmed                                    |
| Command and Control | Application Layer Protocol: Web Protocols | T1071.001 | Possible if payload executed and communicated externally; not confirmed                     |

**MITRE Note:** Only delivery of the malicious attachment was confirmed. Execution, credential access, C2, and endpoint compromise were not observed from the provided evidence.

## Analyst Assessment

**Assessment:** **True Positive — Malicious Excel Attachment Delivered / No Execution Observed**

The alert is valid because the email delivered a malicious Excel attachment to three internal users. The attachment hash was consistently observed across all recipients and was flagged by **24/64 security vendors** as malicious.

The incident did not progress to confirmed endpoint compromise because EDR investigation found no attachment execution, suspicious process creation, persistence, or malware activity.

This case should be treated as a contained malicious attachment delivery incident, with continued monitoring and user validation required.

## Impact Analysis

| Impact Area                 | Status                |
| --------------------------- | --------------------- |
| Email Delivery              | Confirmed             |
| Malicious Attachment        | Confirmed             |
| Multiple Users Targeted     | Confirmed             |
| Attachment Hash Identified  | Confirmed             |
| Attachment Execution        | Not Observed          |
| Suspicious Process Creation | Not Observed          |
| Endpoint Compromise         | Not Observed          |
| Credential Theft            | Not Observed          |
| Malware Execution           | Not Observed          |
| Data Exfiltration           | Not Observed          |
| Business Impact             | Low                   |
| User Impact                 | Low to Medium         |
| Residual Risk               | Low after containment |

Current impact: **Malicious attachment delivery confirmed. No execution or endpoint compromise observed.**

## Recommended Actions

1. Quarantine or remove the delivered email from all affected mailboxes.
2. Block sender email `Rami@cityhack.com` in the email gateway.
3. Block sender domain `cityoflakeforest.com` if no business requirement exists.
4. Block sender IP `52.101.194.18` if policy allows.
5. Add SHA1 hash `2a3a695210d13068a765f03bcd2ae8e3d43006eb` to EDR blocklists.
6. Add sender, sender IP, attachment name, hash, and IPS source IP to SIEM watchlist.
7. Search historical email logs for the same sender, subject, attachment name, and hash.
8. Hunt endpoints for presence of `The City of Lake Forest.xlsx`.
9. Contact affected users and confirm whether the attachment was opened or downloaded.
10. Instruct affected users not to open the attachment, not to enable macros/content, and to report suspicious system behavior.
11. Continue monitoring for similar phishing attachment campaigns.
12. Escalate to SOC L2 / IR if execution or compromise indicators appear.

## User Validation Questions

SOC should contact **Arun Gupta**, **Inaaya Ramachandran**, and **Shalv Keer** and confirm:

1. Did you open the email from `Rami@cityhack.com`?
2. Did you download or open `The City of Lake Forest.xlsx`?
3. Did Excel show any warning or security prompt?
4. Did you enable macros or click “Enable Content”?
5. Did the file request credentials or open a login page?
6. Did your system show unusual behavior after receiving or opening the email?
7. Did you forward the email or attachment to anyone else?

## Escalation Decision

**Decision:** **No immediate SOC L2 escalation required after containment; conditional escalation if execution or compromise indicators appear.**

**Reason:** The attachment was confirmed malicious, but there was no evidence of execution, endpoint compromise, credential theft, malware activity, or data exfiltration from the provided logs.

Escalate to **SOC L2 / Incident Response** if any of the following are identified:

1. User opened or executed the attachment.
2. Excel spawned suspicious child processes.
3. Macros or embedded content were enabled.
4. EDR detects malware execution.
5. Network callback activity is observed.
6. Credential theft indicators are identified.
7. Additional users receive or execute the file.
8. Persistence or lateral movement indicators are found.

## Final Ticket Closure Comment

SOC investigated ticket **CS-053 — Phishing Email** reported by **Arun Gupta**. The email was sent from `Rami@cityhack.com` with the subject **City of Lake Forest 2025-02-12 - Sign order# 09098897-GP - PI - INVo. 24ST CV33846 - AIR130259**. Email gateway logs confirmed delivery to `arun.gupta@abc.com`, `inaaya.ramachandran@abc.com`, and `shalv.keer@abc.com`. The attachment was `The City of Lake Forest.xlsx` with SHA1 hash `2a3a695210d13068a765f03bcd2ae8e3d43006eb`. Reputation analysis confirmed the attachment as malicious, with **24/64 security vendors** flagging it as a Trojan / phishing payload. EDR investigation found no attachment execution, suspicious process creation, persistence, malware-related endpoint activity, or endpoint compromise. IPS review identified a historical detection for a similar phishing payload, but no active exploitation or related malicious communication was observed. Ticket closed as **True Positive — Malicious Excel Attachment Delivered / No Execution Observed**, with email quarantine, sender/IP/hash blocking, EDR hash blocklisting, user notification, IOC hunting, and continued monitoring recommended.

## Skills Demonstrated

User-reported phishing triage, malicious attachment investigation, Excel malware risk analysis, email gateway log review, file hash reputation analysis, EDR validation, IPS event review, IOC extraction, MITRE ATT&CK mapping, impact validation, containment planning, user validation planning, escalation decision-making, and SOC ticket documentation.

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
