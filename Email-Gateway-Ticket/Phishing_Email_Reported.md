# SOC Analyst Investigation Report

## Ticket Overview

| Field                | Details                                                                               |
| -------------------- | ------------------------------------------------------------------------------------- |
| Ticket ID            | CS-055                                                                                |
| Alert Name           | Phishing Email Reported                                                               |
| Incident Title       | Phishing Email with Malicious HTML Attachment                                         |
| Ticket Status        | Closed                                                                                |
| Priority / SLA       | Normal / Medium                                                                       |
| Department           | Support                                                                               |
| Created Date         | 3/12/25 10:13 PM                                                                      |
| Reported By          | Ryan Thomas                                                                           |
| Reporter Email       | `ryan.thomas@abc.com`                                                                 |
| Closed By            | Ananda Das                                                                            |
| Submitted Attachment | `Remittance advice 32493682b1baea9eaf8f52a84870de14.eml`                              |
| Detection Source     | Email Gateway / IPS Logs / EDR                                                        |
| Severity             | High                                                                                  |
| Analyst Decision     | **True Positive — Malicious Phishing Attachment Delivered / No User Impact Observed** |

## Executive Summary

User **Ryan Thomas** reported a suspicious phishing email for analysis. The email impersonated a QuickBooks financial remittance notification using the display name:

`ePayment EFT@quickbooks.com`

The actual sender was:

`robart.brown@hdjusa.com`

The subject was:

`Remittance advice 32493682b1baea9eaf8f52a84870de14`

The email contained a malicious HTML attachment:

`ELECTRONIC RECEIPT_Slgreen.html`

Email authentication checks failed:

* SPF: Fail
* DKIM: Fail
* DMARC: Fail

Splunk email gateway logs confirmed that the email was delivered to two internal users:

* `diya.bahri@abc.com`
* `ryan.thomas@abc.com`

The attachment hash was:

`74bc436a1442e54f352c3bed2e50f53170f0e14f`

Attachment reputation analysis confirmed the file as malicious, with **17/61 security vendors** detecting it as phishing or credential theft-related content.

IPS logs also showed a related historical detection using the signature:

`SMTP: Malicious Attachment with Phishing Payload`

No proxy activity, attachment execution, suspicious outbound traffic, credential theft, malware execution, or endpoint compromise was observed from the provided evidence.

Based on the failed authentication, QuickBooks impersonation, malicious HTML attachment, vendor detections, and delivered status, this case is assessed as a **True Positive malicious phishing attachment delivery**. No user impact or endpoint compromise was confirmed.

## Alert Details

| Field               | Value                                                            |
| ------------------- | ---------------------------------------------------------------- |
| Detection Time      | 2025-02-13                                                       |
| Sender Display Name | `ePayment EFT@quickbooks.com`                                    |
| Actual Sender       | `robart.brown@hdjusa.com`                                       |
| Sender Domain       | hbgusa.com                                                       |
| Sender IP           | 207.54.92.90                                                     |
| Sender Hostname     | esa9.intuit.iphmx.com                                            |
| Email Subject       | Remittance advice 32493682b1baea9eaf8f52a84870de14               |
| Recipients          | `diya.bahri@abc.com`, `ryan.thomas@abc.com`                      |
| SPF                 | Fail                                                             |
| DKIM                | Fail                                                             |
| DMARC               | Fail                                                             |
| Attachment Name     | ELECTRONIC RECEIPT_Slgreen.html                                  |
| Attachment Hash     | 74bc436a1442e54f352c3bed2e50f53170f0e14f                         |
| Additional Hash     | 05cb1ab1991ba8400886214252b6ee2ed225e806461d3a7505eaa91671d2485b |
| Delivery Status     | Delivered                                                        |
| Final Verdict       | True Positive                                                    |

## Affected Assets

| User / Mailbox | Evidence Observed                              | Risk Level |
| -------------- | ---------------------------------------------- | ---------- |
| Ryan Thomas    | Email delivered with malicious HTML attachment | Medium     |
| Diya Bahri     | Email delivered with malicious HTML attachment | Medium     |

## Evidence Reviewed

### Source IP Analysis

| Field            | Value                               |
| ---------------- | ----------------------------------- |
| Source IP        | 207.54.92.90                        |
| Hostname         | esa9.intuit.iphmx.com               |
| ISP              | Cisco Systems, IronPort Division    |
| ASN              | AS16417                             |
| Location         | San Jose, California, United States |
| Abuse Confidence | 0%                                  |
| Reputation       | Not Reported                        |

### Source Analysis

The sender infrastructure appears to belong to a legitimate relay service associated with email delivery systems. However, the actual sender was `robart.brown@hdjusa.com`, while the display name impersonated QuickBooks. SPF, DKIM, and DMARC all failed, which strongly supports the phishing assessment.

### IOCs Identified

| IOC Type               | Indicator                                                        |
| ---------------------- | ---------------------------------------------------------------- |
| Sender Display Name    | `ePayment EFT@quickbooks.com`                                    |
| Sender Email           | `robart.brown@hdjusa.com`                                       |
| Sender Domain          | hbgusa.com                                                       |
| Sender IP              | 207.54.92.90                                                     |
| Sender Hostname        | esa9.intuit.iphmx.com                                            |
| Recipient              | `diya.bahri@abc.com`                                             |
| Recipient              | `ryan.thomas@abc.com`                                            |
| Email Subject          | Remittance advice 32493682b1baea9eaf8f52a84870de14               |
| Attachment Name        | ELECTRONIC RECEIPT_Slgreen.html                                  |
| Malicious File Hash    | 74bc436a1442e54f352c3bed2e50f53170f0e14f                         |
| Additional Hash        | 05cb1ab1991ba8400886214252b6ee2ed225e806461d3a7505eaa91671d2485b |
| IPS Source IP          | 65.55.127.67                                                     |
| IPS Threat Name        | SMTP: Malicious Attachment with Phishing Payload                 |
| Related Malicious File | The City of Lake Forest.xlsx                                     |
| Threat Type            | Phishing / Credential Theft                                      |
| Attachment Type        | HTML                                                             |
| URL                    | No URL observed in email body                                    |
| Endpoint Execution     | Not observed                                                     |
| User Impact            | Not observed                                                     |

## SIEM / Splunk Analysis

### Investigation Flow

#### 1. Alert Review

The ticket was reviewed as a user-reported phishing email. The email used a financial remittance theme and impersonated QuickBooks, which is commonly used in phishing attempts to make users open attachments or login pages.

Key suspicious indicators:

| Indicator             | Observation                 |
| --------------------- | --------------------------- |
| Brand Impersonation   | QuickBooks / ePayment       |
| Actual Sender         | `robart.brown@hdjusa.com`  |
| Authentication        | SPF, DKIM, and DMARC failed |
| Attachment Type       | HTML attachment             |
| Attachment Reputation | Malicious                   |
| Detection Ratio       | 17/61 vendors               |
| Email Status          | Delivered                   |
| Proxy Activity        | Not observed                |
| EDR Execution         | Not observed                |

#### 2. Email Authentication Review

| Control | Result | Analyst Interpretation                           |
| ------- | ------ | ------------------------------------------------ |
| SPF     | Fail   | Sender infrastructure was not authorized/aligned |
| DKIM    | Fail   | Message signature validation failed              |
| DMARC   | Fail   | Domain alignment/authentication failed           |

The combination of brand impersonation and failed SPF, DKIM, and DMARC checks increases confidence that the email was spoofed or maliciously crafted.

#### 3. Email Gateway Review

Email gateway logs confirmed two delivered messages with the same malicious HTML attachment and hash.

```spl id="cs0241_email_query"
index=main "Remittance advice 32493682b1baea9eaf8f52a84870de14" sourcetype=email_logs
| table _time Action SenderIP Sender Recipient Email_Subject URL Attachment_Name Attachment_Hash MessageID Status
```

```text id="cs0241_email_results"
_time	Recipient	Attachment	Attachment_Hash	Status
2025-02-13 04:51:00	diya.bahri@abc.com	ELECTRONIC RECEIPT_Slgreen.html	74bc436a1442e54f352c3bed2e50f53170f0e14f	Delivered
2025-02-13 04:51:00	ryan.thomas@abc.com	ELECTRONIC RECEIPT_Slgreen.html	74bc436a1442e54f352c3bed2e50f53170f0e14f	Delivered
```

### Email Gateway Findings

| Finding                                 | Assessment                      |
| --------------------------------------- | ------------------------------- |
| Total delivered emails                  | 2                               |
| Same attachment delivered to both users | Confirmed                       |
| Same attachment hash observed           | Confirmed                       |
| URL in email body                       | Not observed from provided logs |
| Email bypassed controls                 | Confirmed                       |
| Attachment risk                         | Malicious based on reputation   |

#### 4. Attachment Reputation Review

| Indicator      | Value                                    |
| -------------- | ---------------------------------------- |
| File Name      | ELECTRONIC RECEIPT_Slgreen.html          |
| SHA1 Hash      | 74bc436a1442e54f352c3bed2e50f53170f0e14f |
| Detection Rate | 17/61 security vendors                   |
| Classification | Malicious                                |
| Threat Type    | Phishing / Credential Theft              |
| File Type      | HTML Attachment                          |

### Attachment Findings

The HTML attachment was flagged by multiple vendors as malicious. HTML attachments are commonly used in phishing attempts to open local or hosted fake login pages, redirect users to credential harvesting infrastructure, or collect sensitive information through embedded forms.

No user interaction with the attachment was confirmed from proxy or EDR telemetry.

#### 5. IPS Review

IPS logs showed a related historical malicious attachment signature.

```spl id="cs0241_ips_query"
index=main "Remittance advice 32493682b1baea9eaf8f52a84870de14" sourcetype=IPS_logs
| table _time Action Direction srcIP dstIP dstPort Protocol Threat_Name User
```

```text id="cs0241_ips_results"
_time	srcIP	dstIP	dstPort	Threat_Name
2024-12-25 05:06:00	65.55.127.67	10.0.2.28	587	SMTP: Malicious Attachment with Phishing Payload
```

### IPS Findings

| Observation                                        | Analyst Interpretation                              |
| -------------------------------------------------- | --------------------------------------------------- |
| IPS signature matched malicious attachment pattern | Supports phishing attachment classification         |
| Event was historical                               | Does not confirm active exploitation in this ticket |
| No active exploitation observed                    | No endpoint impact confirmed                        |
| No follow-on communication observed                | No callback or compromise evidence found            |

#### 6. Additional Malicious File Context

| Field                | Value                                          |
| -------------------- | ---------------------------------------------- |
| File Name            | The City of Lake Forest.xlsx                   |
| Detection            | 24/64 security vendors                         |
| Behavioral Indicator | WMI-based execution activity observed          |
| Assessment           | Related phishing/malicious attachment behavior |

A related malicious file, `The City of Lake Forest.xlsx`, was identified in previous or related detection context. This strengthens the assessment that the environment has seen malicious attachment delivery patterns, but no WMI execution was observed on the impacted endpoints for this specific ticket.

#### 7. Proxy Review

| Data Source | Events |
| ----------- | ------ |
| Proxy Logs  | 0      |

### Proxy Findings

| Check                 | Result       |
| --------------------- | ------------ |
| URL access            | Not observed |
| External callback     | Not observed |
| Credential submission | Not observed |
| Suspicious download   | Not observed |
| User interaction      | Not observed |

No proxy activity was identified. This suggests users did not interact with a web-based phishing page or that no external network activity was generated from the attachment in the available telemetry.

#### 8. EDR Review

EDR investigation was performed for the affected endpoints.

| Check                                | Result       |
| ------------------------------------ | ------------ |
| Attachment execution                 | Not observed |
| Process creation linked to HTML file | Not observed |
| Suspicious child processes           | Not observed |
| Browser execution from attachment    | Not observed |
| Persistence mechanism                | Not observed |
| Malware-related activity             | Not observed |
| Endpoint compromise                  | Not observed |

The EDR review found no evidence that the malicious HTML attachment was opened or executed.

#### 9. Timeline Reconstruction

| Time                | Event                                                                |
| ------------------- | -------------------------------------------------------------------- |
| 2025-02-13 04:51:00 | Phishing email delivered to `diya.bahri@abc.com`                     |
| 2025-02-13 04:51:00 | Phishing email delivered to `ryan.thomas@abc.com`                    |
| Investigation Time  | Attachment reputation confirmed malicious detection by 17/61 vendors |
| Investigation Time  | IPS logs identified historical malicious attachment signature        |
| Investigation Time  | Proxy logs reviewed; no activity observed                            |
| Investigation Time  | EDR reviewed; no execution or endpoint compromise observed           |
| Closure Time        | IOC blocking and user notification completed/recommended             |

#### 10. Attack Chain Assessment

The evidence supports the following attempted attack chain:

1. QuickBooks-themed remittance email was delivered to two users.
2. Sender authentication failed across SPF, DKIM, and DMARC.
3. The email contained a malicious HTML attachment.
4. Attachment reputation confirmed phishing/credential theft classification.
5. No proxy activity was observed.
6. EDR found no attachment execution or process activity.
7. No endpoint compromise or credential theft was confirmed.

## MITRE ATT&CK Mapping

| Tactic              | Technique                                 | ID        | Reason                                                                                        |
| ------------------- | ----------------------------------------- | --------- | --------------------------------------------------------------------------------------------- |
| Initial Access      | Phishing                                  | T1566     | Phishing email was delivered to users                                                         |
| Initial Access      | Spearphishing Attachment                  | T1566.001 | Email contained a malicious HTML attachment                                                   |
| Execution           | User Execution: Malicious File            | T1204.002 | Opening the HTML attachment would require user action; execution was not observed             |
| Defense Evasion     | Masquerading                              | T1036     | Email impersonated QuickBooks/ePayment branding                                               |
| Credential Access   | Input Capture                             | T1056     | Possible if HTML attachment displayed a credential-harvesting page; not confirmed             |
| Command and Control | Application Layer Protocol: Web Protocols | T1071.001 | Possible only if the attachment contacted external infrastructure; no proxy activity observed |

**MITRE Note:** Delivery of the malicious attachment was confirmed. User execution, credential capture, external callback, endpoint compromise, and C2 were not observed from the provided evidence.

## Analyst Assessment

**Assessment:** **True Positive — Malicious Phishing Attachment Delivered / No User Impact Observed**

The alert is valid because the email impersonated QuickBooks, failed SPF/DKIM/DMARC, delivered a malicious HTML attachment to two users, and the attachment was flagged by **17/61 security vendors**.

However, there is no evidence that users opened the attachment or submitted credentials. Proxy logs showed no activity, and EDR logs showed no attachment execution, suspicious child processes, persistence, or endpoint compromise.

The incident appears contained at the email delivery stage.

## Impact Analysis

| Impact Area                         | Status                |
| ----------------------------------- | --------------------- |
| Phishing email delivered            | Confirmed             |
| Malicious HTML attachment delivered | Confirmed             |
| Multiple users targeted             | Confirmed             |
| SPF/DKIM/DMARC failed               | Confirmed             |
| Attachment hash identified          | Confirmed             |
| Attachment reputation malicious     | Confirmed             |
| Proxy activity                      | Not observed          |
| User interaction                    | Not observed          |
| Attachment execution                | Not observed          |
| Credential theft                    | Not observed          |
| Malware execution                   | Not observed          |
| Endpoint compromise                 | Not observed          |
| Data exfiltration                   | Not observed          |
| Business impact                     | Low                   |
| Residual risk                       | Low after containment |

Current impact: **Malicious attachment delivery confirmed. No user interaction or endpoint impact observed.**

## Recommended Actions

1. Quarantine or remove the delivered emails from `diya.bahri@abc.com` and `ryan.thomas@abc.com`.
2. Block sender email `robart.brown@hdjusa.com` in the email gateway.
3. Block sender domain `hbgusa.com`.
4. Block sender IP `207.54.92.90` if policy allows.
5. Add hash `74bc436a1442e54f352c3bed2e50f53170f0e14f` to EDR blocklists.
6. Add hash `05cb1ab1991ba8400886214252b6ee2ed225e806461d3a7505eaa91671d2485b` to monitoring/blocklists where applicable.
7. Add sender, domain, IP, attachment name, and hashes to SIEM watchlists.
8. Search historical email logs for the same sender, subject, attachment name, and hashes.
9. Contact affected users and confirm whether the HTML attachment was opened.
10. Continue monitoring for similar phishing attachments or related IPS signatures.
11. Escalate to SOC L2 / IR if user interaction, credential submission, or endpoint execution is later confirmed.

## User Validation Questions

SOC should contact **Ryan Thomas** and **Diya Bahri** and confirm:

1. Did you receive the QuickBooks remittance email?
2. Did you open the email?
3. Did you open `ELECTRONIC RECEIPT_Slgreen.html`?
4. Did the attachment open a browser window or login page?
5. Did you enter any credentials?
6. Did you download any additional file?
7. Did your endpoint show any warning or suspicious behavior?
8. Did you forward the email to anyone else?

## Containment / Remediation Decision

| Action             | Decision                           | Reason                                                             |
| ------------------ | ---------------------------------- | ------------------------------------------------------------------ |
| Block Sender       | Required / Recommended             | Sender delivered malicious attachment                              |
| Block Domain       | Required / Recommended             | Sender domain associated with this phishing delivery               |
| Block Sender IP    | Recommended if policy allows       | Source IP observed in malicious delivery                           |
| Remove Email       | Required / Recommended             | Delivered malicious attachment should be removed                   |
| Reset Password     | Not required from current evidence | No credential submission or user interaction observed              |
| Isolate Endpoint   | Not required from current evidence | No execution or compromise observed                                |
| Escalate to SOC L2 | Conditional                        | Escalate if user interaction or endpoint impact is later confirmed |

## Escalation Decision

**Decision:** **No immediate SOC L2 escalation required after containment; conditional escalation if interaction or endpoint impact is later confirmed.**

**Reason:** The phishing attachment was confirmed malicious and delivered to two users, but proxy and EDR evidence did not show user interaction, attachment execution, credential theft, endpoint compromise, or suspicious outbound communication.

Escalate to **SOC L2 / Incident Response** if any of the following are identified:

1. User opened the HTML attachment.
2. Credential submission occurred.
3. EDR detects process execution linked to the attachment.
4. Suspicious browser or script activity is observed.
5. External callback or download activity is found.
6. New related phishing emails are delivered.
7. Additional users interact with the attachment.
8. Any endpoint compromise indicator appears.

## Final Ticket Closure Comment

SOC investigated ticket **CS-055 — Phishing Email Reported** reported by **Ryan Thomas**. The email impersonated QuickBooks/ePayment branding using the display name `ePayment EFT@quickbooks.com`, while the actual sender was `robart.brown@hdjusa.com`. The subject was **Remittance advice 32493682b1baea9eaf8f52a84870de14**. Email authentication checks failed for SPF, DKIM, and DMARC. Email gateway logs confirmed delivery to `diya.bahri@abc.com` and `ryan.thomas@abc.com`. The malicious HTML attachment was `ELECTRONIC RECEIPT_Slgreen.html` with hash `74bc436a1442e54f352c3bed2e50f53170f0e14f`, detected by **17/61 security vendors** as phishing or credential theft-related content. IPS logs showed a related historical signature `SMTP: Malicious Attachment with Phishing Payload`. Proxy logs showed no activity, and EDR review found no attachment execution, suspicious process creation, persistence, malware activity, endpoint compromise, or credential theft. Ticket closed as **True Positive — Malicious Phishing Attachment Delivered / No User Impact Observed**, with email quarantine, IOC blocking, EDR hash blocklisting, user notification, and continued monitoring recommended.

---

## Skills Demonstrated

User-reported phishing triage, email authentication review, sender impersonation analysis, malicious HTML attachment investigation, file hash reputation review, Splunk email gateway analysis, IPS event correlation, proxy validation, EDR validation, IOC extraction, MITRE ATT&CK mapping, impact validation, containment planning, user validation planning, escalation decision-making, and SOC ticket documentation.

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
