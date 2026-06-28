# SOC Analyst Investigation Report

## Ticket Overview

| Field                | Details                                                                         |
| -------------------- | ------------------------------------------------------------------------------- |
| Ticket ID            | CS-0236                                                                         |
| Alert Name           | Phishing Email Reporting                                                        |
| Ticket Status        | closed                                                                          |
| Priority / SLA       | Normal / Default SLA                                                            |
| Created Date         | 3/12/25 9:25 PM                                                                 |
| Assigned To          | Ananda Das                                                                      |
| Reported By          | Karthik Gupta                                                                   |
| Reporter Email       | `karthik.gupta@abc.com`                                                         |
| Attachment Submitted | `Still Searching for the Perfect AI-Powered Customer Support Tool_.eml`         |
| Analyst Decision     | **False Positive — Legitimate Marketing Email / No Security Threat Identified** |

## Executive Summary

User **Karthik Gupta** reported a suspicious email for analysis. The email was reviewed to determine whether it contained phishing indicators, malicious URLs, malware attachments, credential harvesting behavior, suspicious redirects, or indicators of compromise.

The reported email was sent by:

`ashlyn.saju@freshworks.com`

The subject was:

`Still Searching for the Perfect AI-Powered Customer Support Tool?`

The email was delivered to:

* `hr@abc.com`
* `meera.sharma@abc.com`

The email contained Freshworks tracking infrastructure that redirected to a Calendly scheduling page:

`https://calendly.com/ashlyn-saju-/30min`

Email authentication showed **SPF Pass** and **DMARC Pass**. DKIM failed due to body hash verification mismatch, but no malicious indicators were identified in the email content, URL chain, attachments, proxy logs, or user activity.

No malicious attachment, phishing page, credential harvesting page, malware delivery, suspicious proxy activity, endpoint compromise, or account compromise was observed. Based on the evidence, this ticket is assessed as a **False Positive — Legitimate Marketing Email**.

## Alert Details

| Field              | Value                                                             |
| ------------------ | ----------------------------------------------------------------- |
| Email Time         | 2025-03-03 23:56:00                                               |
| Sender Name        | Ashlyn Saju                                                       |
| Sender Email       | `ashlyn.saju@freshworks.com`                                      |
| Sender Domain      | freshworks.com                                                    |
| Recipients         | `hr@abc.com`, `meera.sharma@abc.com`                              |
| Subject            | Still Searching for the Perfect AI-Powered Customer Support Tool? |
| Return Path        | Freshworks Infrastructure                                         |
| Sender IPs         | 52.1.79.135, 209.85.222.171                                       |
| SPF                | Pass                                                              |
| DKIM               | Fail — Body Hash Verification Failed                              |
| DMARC              | Pass                                                              |
| Email Action       | Delivered                                                         |
| Attachment Present | No                                                                |
| Final Verdict      | False Positive                                                    |

## Affected Assets

| Asset / Entity            | Details                                   |
| ------------------------- | ----------------------------------------- |
| Reporting User            | Karthik Gupta                             |
| Reporter Email            | `karthik.gupta@abc.com`                   |
| Recipient 1               | `hr@abc.com`                              |
| Recipient 2               | `meera.sharma@abc.com`                    |
| Sender                    | `ashlyn.saju@freshworks.com`              |
| Sender Domain             | freshworks.com                            |
| Tracking Domain           | fwtrackinte.freshworks.com                |
| Final URL                 | `https://calendly.com/ashlyn-saju-/30min` |
| Endpoint Impact           | Not Observed                              |
| Account Impact            | Not Observed                              |
| Confirmed Security Threat | No                                        |

## Evidence Reviewed

### IOC / Indicator Summary

| Indicator Type  | Indicator                                                         | Classification                     | Status             |
| --------------- | ----------------------------------------------------------------- | ---------------------------------- | ------------------ |
| Sender Email    | `ashlyn.saju@freshworks.com`                                      | Legitimate marketing sender        | Benign             |
| Sender Domain   | freshworks.com                                                    | SaaS / marketing platform          | Benign             |
| Tracking Domain | fwtrackinte.freshworks.com                                        | Freshworks tracking infrastructure | Benign             |
| Effective URL   | `https://calendly.com/ashlyn-saju-/30min`                         | Calendly scheduling page           | Benign             |
| Domain          | calendly.com                                                      | Scheduling platform                | Benign             |
| Sender IP       | 52.1.79.135                                                       | Cloud / mail infrastructure        | Benign             |
| Sender IP       | 209.85.222.171                                                    | Mail infrastructure                | Benign             |
| Recipient       | `hr@abc.com`                                                      | Internal recipient                 | No impact observed |
| Recipient       | `meera.sharma@abc.com`                                            | Internal recipient                 | No impact observed |
| Email Subject   | Still Searching for the Perfect AI-Powered Customer Support Tool? | Marketing subject                  | Benign             |

**IOC Assessment:** No malicious IOCs were identified during the investigation.

## SIEM / Splunk Analysis

### Investigation Flow

#### 1. Alert Review

The alert was reviewed as a user-reported suspicious email. Since the user submitted an `.eml` file, the investigation focused on sender legitimacy, email authentication, URL behavior, attachments, delivery scope, and any user interaction.

Key review points:

| Check                | Result                                     |
| -------------------- | ------------------------------------------ |
| Sender identity      | Freshworks marketing sender                |
| Email theme          | AI-powered customer support tool marketing |
| Attachment           | None                                       |
| URL                  | Freshworks tracking redirect to Calendly   |
| Credential request   | Not observed                               |
| Malicious redirect   | Not observed                               |
| Proxy click activity | Not observed                               |
| Endpoint impact      | Not observed                               |

#### 2. Email Authentication Review

| Control | Result | Analyst Interpretation                |
| ------- | ------ | ------------------------------------- |
| SPF     | Pass   | Sending infrastructure was authorized |
| DKIM    | Fail   | Body hash mismatch observed           |
| DMARC   | Pass   | Domain alignment passed               |

The DKIM failure alone does not confirm phishing. DKIM body hash failures can occur due to message modification, forwarding, email security processing, or marketing platform formatting changes. Since SPF and DMARC passed and no malicious indicators were found, the DKIM result was treated as a non-blocking anomaly.

#### 3. URL Review

The embedded URL redirected through Freshworks tracking infrastructure to a Calendly meeting page.

| Field                 | Value                                     |
| --------------------- | ----------------------------------------- |
| Tracking Domain       | fwtrackinte.freshworks.com                |
| Effective URL         | `https://calendly.com/ashlyn-saju-/30min` |
| Domains Identified    | freshworks.com, calendly.com              |
| Malicious Redirects   | Not Observed                              |
| Phishing Page         | Not Observed                              |
| Credential Harvesting | Not Observed                              |
| URL Risk              | Benign                                    |

The URL behavior was consistent with normal marketing email tracking and meeting scheduling activity.

#### 4. Body and Attachment Review

| Check               | Result       |
| ------------------- | ------------ |
| Attachment Present  | No           |
| Executable Content  | No           |
| Credential Request  | No           |
| Malicious Link      | No           |
| Phishing Page       | Not observed |
| Suspicious Download | Not observed |
| Marketing Content   | Yes          |

The email content promoted AI-powered customer support solutions and encouraged recipients to schedule a meeting. No phishing form, credential prompt, malicious attachment, or suspicious payload was identified.

#### 5. Email Log Review

```spl id="cs0236_email_query"
index=main "ashlyn.saju@freshworks.com" sourcetype=email_logs
| table _time Sender Recipient Status URL Attachment_Name Email_Subject MessageID
```

### Full Unique Splunk Log Results

```text id="cs0236_email_results"
_time	Sender	Recipient	Status	Email_Subject
2025-03-03 23:56:00	ashlyn.saju@freshworks.com	meera.sharma@abc.com	Delivered	Still Searching for the Perfect AI-Powered Customer Support Tool?
2025-03-03 23:56:00	ashlyn.saju@freshworks.com	hr@abc.com	Delivered	Still Searching for the Perfect AI-Powered Customer Support Tool?
```

#### 6. Proxy Log Review

No proxy events were identified for the embedded URL.

Proxy findings:

| Check                                            | Result       |
| ------------------------------------------------ | ------------ |
| User clicked embedded URL                        | Not observed |
| Outbound connection to suspicious infrastructure | Not observed |
| Credential submission                            | Not observed |
| Suspicious download                              | Not observed |
| Endpoint impact                                  | Not observed |

#### 7. Timeline Reconstruction

| Time                   | Event                                                                      |
| ---------------------- | -------------------------------------------------------------------------- |
| 2025-03-03 23:56:00    | Freshworks marketing email delivered to `meera.sharma@abc.com`             |
| 2025-03-03 23:56:00    | Freshworks marketing email delivered to `hr@abc.com`                       |
| 2025-03-12 21:25       | Karthik Gupta reported the suspicious email for analysis                   |
| Investigation Time     | Email authentication, URL behavior, body content, and Splunk logs reviewed |
| Investigation Time     | No malicious indicators or user interaction found                          |
| Closure Recommendation | Close as false positive / legitimate marketing email                       |

## MITRE ATT&CK Mapping

| Tactic | Technique | ID  | Reason                                                                                  |
| ------ | --------- | --- | --------------------------------------------------------------------------------------- |
| N/A    | N/A       | N/A | No malicious behavior confirmed                                                         |
| N/A    | N/A       | N/A | No phishing, malware delivery, credential harvesting, or compromise indicators observed |

**MITRE Note:** No ATT&CK technique is assigned because the investigation did not confirm adversary behavior.

## Analyst Assessment

**Assessment:** **False Positive — Legitimate Marketing Email**

The reported email does not show malicious characteristics. The sender domain was consistent with Freshworks, the email content was marketing-related, no attachment was present, and the embedded link redirected to a Calendly scheduling page.

SPF and DMARC passed. DKIM failed, but the failure was not enough to classify the email as malicious because no supporting suspicious behavior was found.

No user click activity, credential submission, suspicious proxy traffic, endpoint compromise, or account compromise was identified.

## Impact Analysis

| Impact Area          | Status      |
| -------------------- | ----------- |
| Malware Infection    | No Evidence |
| Credential Theft     | No Evidence |
| User Interaction     | No Evidence |
| Data Exposure        | No Evidence |
| System Compromise    | No Evidence |
| Endpoint Impact      | No Evidence |
| Account Compromise   | No Evidence |
| Phishing Campaign    | No Evidence |
| Malicious Attachment | No Evidence |
| Malicious Redirect   | No Evidence |

Current impact: **No security impact identified.**

## Recommended Actions

1. No sender block is required.
2. No domain block is required for `freshworks.com` or `calendly.com`.
3. No password reset is required.
4. No endpoint isolation is required.
5. No SOC L2 escalation is required.
6. Inform the reporting user that the email appears to be legitimate marketing communication.
7. Optionally remove the email if the recipient considers it unwanted marketing/spam.
8. Continue standard monitoring for future suspicious emails.

## Escalation Decision

**Decision:** **No escalation required.**

**Reason:** The email was determined to be legitimate marketing communication. No malicious attachments, phishing URLs, credential harvesting pages, suspicious redirects, endpoint alerts, user clicks, or compromise indicators were identified.

## Final Ticket Closure Comment

SOC investigated ticket **CS-0236 — Phishing Email Reporting** submitted by **Karthik Gupta**. The reported email was sent from `ashlyn.saju@freshworks.com` to `hr@abc.com` and `meera.sharma@abc.com` with the subject **Still Searching for the Perfect AI-Powered Customer Support Tool?**. The email contained Freshworks tracking links that redirected to a legitimate Calendly scheduling page at `https://calendly.com/ashlyn-saju-/30min`. SPF and DMARC passed. DKIM failed due to body hash verification mismatch, but no malicious indicators were identified. No attachments were present, no phishing page or credential harvesting behavior was observed, and no proxy click activity, endpoint compromise, malware delivery, or account compromise was found. Ticket closed as **False Positive — Legitimate Marketing Email / No Security Threat Identified**.

## Skills Demonstrated

User-reported phishing triage, email header review, SPF/DKIM/DMARC interpretation, URL redirect analysis, marketing email validation, Splunk email log review, proxy activity validation, IOC assessment, false positive determination, impact validation, escalation decision-making, and SOC ticket documentation.
