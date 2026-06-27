# SOC Analyst Investigation Report

## Ticket Overview

| Field            | Details                                                                                            |
| ---------------- | -------------------------------------------------------------------------------------------------- |
| Ticket ID        | CS-044                                                                                            |
| Alert Name       | Proxy: Large Data Transfers Detected / Possible Data Exfiltration                                  |
| Ticket Status    | Closed                                                                                             |
| Priority / SLA   | High / Medium                                                                                      |
| Created Date     | 3/16/25 5:41 PM                                                                                    |
| Closed By        | Ananda Das                                                                                        |
| Analyst Decision | **True Positive — Cloud Upload Activity Detected / Possible Data Exfiltration Pending Validation** |

## Executive Summary

A proxy alert was triggered for **Large Data Transfers Detected / Possible Data Exfiltration** after user **Anita Pandey** from internal source IP **10.1.2.22** uploaded data to **dropbox.com**, a public file-storage and sharing platform.

The observed Dropbox URL was:

`https://www.dropbox.com/u/1/my-drive`

Proxy logs showed multiple Dropbox sessions, including login/navigation activity and two upload-related **PUT** requests involving the file:

`Data.zip`

The upload-related events showed:

| Time                | File     | Method | Response Code | Bytes Sent |
| ------------------- | -------- | ------ | ------------: | ---------: |
| 2025-03-14 21:29:00 | Data.zip | PUT    |           100 |     51,200 |
| 2025-03-14 21:33:00 | Data.zip | PUT    |           200 |     55,500 |

Total observed bytes sent across the two upload events: **106,700 bytes**.

This confirms cloud upload activity to Dropbox. However, the provided logs do **not** confirm whether the file contained sensitive data, whether Dropbox usage was business-approved, or whether the upload was malicious.

Because the user belongs to the **HR Department** and the uploaded file was named **Data.zip**, the event should be treated as **possible data exfiltration / unauthorized cloud upload pending user and DLP validation**.

## Alert Details

| Field                       | Value                                  |
| --------------------------- | -------------------------------------- |
| Timestamp                   | 3/14/2025 21:29 and 21:33              |
| Username                    | Anita Pandey                           |
| Source IP                   | 10.1.2.22                              |
| Destination IP              | 162.125.3.18                           |
| URL Domain                  | dropbox.com                            |
| URL                         | `https://www.dropbox.com/u/1/my-drive` |
| Web Category                | File Storage/Sharing                   |
| Proxy Action                | Allowed                                |
| HTTP Method                 | PUT                                    |
| Response Codes              | 100, 200                               |
| Observed File               | Data.zip                               |
| Total Observed Upload Bytes | 106,700 bytes                          |

## Affected Assets

| Asset Field             | Details                    |
| ----------------------- | -------------------------- |
| User                    | Anita Pandey               |
| Role                    | Employee Relations Manager |
| Department              | HR Department              |
| Source IP               | 10.1.2.22                  |
| Endpoint                | ENDP-011                   |
| Endpoint OS             | Windows 11-64              |
| External Domain         | dropbox.com                |
| External Destination IP | 162.125.3.18               |
| File Involved           | Data.zip                   |
| Data Sensitivity        | Not Confirmed              |
| Business Approval       | Not Provided               |

## Investigation Flow

### 1. Alert Review

The alert was reviewed as a possible data exfiltration case because it involved upload activity to **Dropbox**, which is categorized as **File Storage/Sharing**.

Key alert observations:

| Indicator              | Observation                                            |
| ---------------------- | ------------------------------------------------------ |
| Cloud Storage Platform | Dropbox                                                |
| Upload Method          | PUT                                                    |
| Action                 | Allowed                                                |
| File Name              | Data.zip                                               |
| User Department        | HR                                                     |
| Risk Type              | Possible unauthorized cloud upload / data exfiltration |

The proxy allowed the activity, which means the upload was not blocked by web security controls at the time of the event.

### 2. User and Asset Identification

The activity was associated with **Anita Pandey**, identified as an **Employee Relations Manager** in the **HR Department**, using endpoint **ENDP-011 / Windows 11-64**.

This context increases the sensitivity of the investigation because HR users may handle employee records, personal information, contracts, payroll-related documents, and internal business data.

### 3. Destination and Service Identification

The destination domain was **dropbox.com**, and the destination IP was **162.125.3.18**.

Dropbox is a legitimate file-sharing service, but uploads to public or unmanaged cloud storage can represent data loss risk if not approved by company policy.

### 4. Timeline Reconstruction

| Time                | Activity                                                                                |
| ------------------- | --------------------------------------------------------------------------------------- |
| 2025-03-14 21:27:00 | User accessed Dropbox login page from Google search                                     |
| 2025-03-14 21:27:00 | Dropbox POST/logout-related activity observed                                           |
| 2025-03-14 21:28:00 | Dropbox login-related activity observed                                                 |
| 2025-03-14 21:29:00 | Upload-related PUT request for `Data.zip`; response code **100**; **51,200 bytes sent** |
| 2025-03-14 21:33:00 | Upload-related PUT request for `Data.zip`; response code **200**; **55,500 bytes sent** |

The timeline shows a clear sequence of Dropbox access, login/session activity, and file upload activity.

### 5. SIEM Evidence Review

The proxy evidence confirms:

| Evidence Point          | Result       |
| ----------------------- | ------------ |
| Dropbox access          | Confirmed    |
| File-sharing category   | Confirmed    |
| Upload method PUT       | Confirmed    |
| File name `Data.zip`    | Confirmed    |
| Final response code 200 | Confirmed    |
| Upload bytes sent       | Confirmed    |
| File content            | Not Provided |
| DLP classification      | Not Provided |
| Business approval       | Not Provided |

### 6. Threat and Risk Context

The activity is suspicious because:

| Risk Factor                 | Why It Matters                                                      |
| --------------------------- | ------------------------------------------------------------------- |
| Public file-sharing service | May bypass approved corporate storage controls                      |
| HTTP PUT method             | Indicates upload or write activity                                  |
| File name `Data.zip`        | Compressed files may contain multiple documents                     |
| HR department user          | Potential sensitivity of employee-related data                      |
| Proxy action Allowed        | Transfer was not blocked                                            |
| Response code 200           | Final Dropbox interaction appears successful                        |
| After-hours timing          | Activity occurred at 21:29–21:33, which may require user validation |

This does not automatically confirm malicious exfiltration, but it does justify DLP and user validation.

### 7. Impact Validation

| Impact Area             | Validation Result           |
| ----------------------- | --------------------------- |
| Upload Activity         | Confirmed                   |
| File Name               | Data.zip                    |
| Sensitive Data Exposure | Not Confirmed               |
| Unauthorized Transfer   | Not Confirmed               |
| External Sharing        | Not Provided                |
| Endpoint Compromise     | Not Observed                |
| Malware Activity        | Not Observed                |
| Account Compromise      | Not Observed                |
| Data Exfiltration       | Possible, but not confirmed |

The correct SOC conclusion is: **Dropbox upload activity confirmed; data exfiltration impact requires user, DLP, and account validation.**

## Evidence Reviewed

### Initial Proxy Alert Evidence

| Timestamp       | Username     | Source IP | Destination IP | URL Domain  | URL                                    | Web Category         | Action  | HTTP Method | Response Code |
| --------------- | ------------ | --------- | -------------- | ----------- | -------------------------------------- | -------------------- | ------- | ----------- | ------------: |
| 3/14/2025 21:29 | Anita Pandey | 10.1.2.22 | 162.125.3.18   | dropbox.com | `https://www.dropbox.com/u/1/my-drive` | File Storage/Sharing | Allowed | PUT         |           100 |
| 3/14/2025 21:33 | Anita Pandey | 10.1.2.22 | 162.125.3.18   | dropbox.com | `https://www.dropbox.com/u/1/my-drive` | File Storage/Sharing | Allowed | PUT         |           200 |

## SIEM / Splunk Analysis

### Splunk Query Used

```spl id="cs0251_proxy_query"
index=main "URL Domain"="dropbox.com" sourcetype=proxy_logs
| table _time Referrer "HTTP Method" "Response Code" "Source IP" "Destination IP" Action URL "File Type" "User Agent" Username "Web Category" "Bytes Sent" "Bytes Received"
```

### Full Unique Splunk Log Results

```text id="cs0251_proxy_results"
_time	Referrer	HTTP Method	Response Code	Source IP	Destination IP	Action	URL	File Type	User Agent	Username	Web Category	Bytes Sent	Bytes Received
2025-03-14 21:33:00	https://www.dropbox.com/u/1/my-drive	PUT	200	10.1.2.22	162.125.3.18	Allowed	https://www.dropbox.com/u/1/my-drive	Data.zip	Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/123.0.0.0 Safari/537.36	Anita Pandey	File Storage/Sharing	55,500	1039
2025-03-14 21:29:00	https://www.dropbox.com/u/1/my-drive	PUT	100	10.1.2.22	162.125.3.18	Allowed	https://www.dropbox.com/u/1/my-drive	Data.zip	Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/123.0.0.0 Safari/537.36	Anita Pandey	File Storage/Sharing	51,200	1039
2025-03-14 21:28:00	https://www.dropbox.com/login	GET	200	10.1.2.22	162.125.3.18	Allowed	https://www.dropbox.com/u/1/my-drive		Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/123.0.0.0 Safari/537.36	Anita Pandey	File Storage/Sharing	3988	14901
2025-03-14 21:28:00	https://www.dropbox.com	POST	200	10.1.2.22	162.125.3.18	Allowed	https://www.dropbox.com/login		Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/123.0.0.0 Safari/537.36	Anita Pandey	File Storage/Sharing	2465	32451
2025-03-14 21:27:00	https://www.dropbox.com/logout	GET	200	10.1.2.22	162.125.3.18	Allowed	https://www.dropbox.com/login		Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/123.0.0.0 Safari/537.36	Anita Pandey	File Storage/Sharing	3988	14901
2025-03-14 21:27:00	https://www.dropbox.com/u/1/my-drive	POST	200	10.1.2.22	162.125.3.18	Allowed	https://www.dropbox.com/logout		Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/123.0.0.0 Safari/537.36	Anita Pandey	File Storage/Sharing	3266	1343
2025-03-14 21:27:00	https://www.google.com/search?q=https://www.dropbox.com	GET	200	10.1.2.22	162.125.3.18	Allowed	https://www.dropbox.com/login		Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/123.0.0.0 Safari/537.36	Anita Pandey	File Storage/Sharing	3988	14901
```

### Evidence Interpretation

| Observation                                    | Analyst Interpretation                                |
| ---------------------------------------------- | ----------------------------------------------------- |
| User accessed Dropbox from Google search       | User initiated Dropbox browsing/login flow            |
| Multiple Dropbox login/session events observed | User interacted with Dropbox account/session          |
| Two PUT requests observed                      | Upload/write activity confirmed                       |
| File name `Data.zip` observed                  | File transfer involved a compressed archive           |
| Final PUT returned HTTP 200                    | Final upload-related request appears successful       |
| Web category was File Storage/Sharing          | Activity involved cloud storage platform              |
| DLP/file content not available                 | Sensitivity cannot be confirmed from proxy logs alone |

## MITRE ATT&CK Mapping

| Tactic              | Technique                                 | ID        | Reason                                                                        |
| ------------------- | ----------------------------------------- | --------- | ----------------------------------------------------------------------------- |
| Exfiltration        | Exfiltration Over Web Service             | T1567     | Data was uploaded to a web-based cloud storage service                        |
| Exfiltration        | Exfiltration to Cloud Storage             | T1567.002 | Dropbox upload activity was observed                                          |
| Exfiltration        | Archive Collected Data                    | T1560     | File was named `Data.zip`, suggesting compressed data; contents not confirmed |
| Command and Control | Application Layer Protocol: Web Protocols | T1071.001 | HTTPS web traffic to Dropbox was used                                         |

## Analyst Assessment

**Assessment:** **True Positive — Dropbox Upload Activity / Possible Data Exfiltration**

The alert is valid because proxy logs confirm upload-related **PUT** requests to Dropbox involving **Data.zip**. The activity occurred from an HR user endpoint, which increases the need for data sensitivity validation.

This is **not confirmed malicious data exfiltration** based only on the provided evidence. The logs confirm upload activity, but they do not confirm file contents, business authorization, external sharing, user intent, or compromise.

## Impact Analysis

| Area             | Assessment                                                      |
| ---------------- | --------------------------------------------------------------- |
| Confidentiality  | Possible risk; file contents not confirmed                      |
| Integrity        | No endpoint or file tampering evidence confirmed                |
| Availability     | No service impact reported                                      |
| Data Loss Risk   | Possible, pending DLP/file validation                           |
| Business Impact  | Unknown until file sensitivity and sharing status are confirmed |
| Current Risk     | High priority due to HR context and cloud upload activity       |
| Confirmed Impact | Upload activity confirmed; data exposure not confirmed          |

## User Validation Required

SOC should contact **Anita Pandey** and confirm:

1. What was contained inside **Data.zip**?
2. Was the upload business-approved?
3. Was Dropbox approved for this transfer?
4. Was the Dropbox account personal or company-managed?
5. Why was Dropbox used instead of approved internal storage?
6. Was the file related to HR data, employee records, payroll, contracts, or internal documents?
7. Was the file shared externally after upload?
8. Was the upload requested by a manager, vendor, or external party?
9. Was the activity performed intentionally by Anita?
10. Is there an approval, ticket, or business reference for this transfer?

## DLP / Data Validation Required

The DLP or data security team should validate:

| Validation Item                   | Purpose                                                          |
| --------------------------------- | ---------------------------------------------------------------- |
| File classification of `Data.zip` | Determine whether sensitive data was involved                    |
| Dropbox account type              | Confirm personal vs company-managed account                      |
| External sharing status           | Determine whether file was shared outside the organization       |
| DLP alerts                        | Check for PII, HR records, payroll, or confidential documents    |
| File path on endpoint             | Confirm source location and ownership                            |
| Similar uploads                   | Identify repeated or broader activity                            |
| Other HR user activity            | Identify possible policy gap or wider exposure                   |
| CASB logs                         | Confirm cloud account, sharing permissions, and recipient access |

## Recommended Actions

1. Contact **Anita Pandey** for business justification.
2. Validate the contents and sensitivity of **Data.zip** through approved DLP or endpoint review.
3. Confirm whether the Dropbox account was personal or corporate-managed.
4. Confirm whether the uploaded file was shared externally.
5. Check endpoint **ENDP-011** for the local file path, creation time, and recent compression activity.
6. Review DLP/CASB logs for file classification, sharing permissions, and external access.
7. Review additional proxy logs for repeated uploads by the same user.
8. Search for similar Dropbox upload activity from other HR users.
9. Restrict Dropbox uploads if the platform is not approved for business use.
10. Escalate to SOC L2 / DLP / Insider Risk if sensitive or unauthorized transfer is confirmed.

## Containment / Blocking Plan

| Control      | Indicator / Scope                   | Recommended Action                                              |
| ------------ | ----------------------------------- | --------------------------------------------------------------- |
| Proxy / SWG  | dropbox.com                         | Block or restrict if not approved                               |
| Firewall     | 162.125.3.18                        | Block outbound only if policy allows                            |
| DLP          | File Storage/Sharing uploads        | Enable inspection and alerting                                  |
| CASB         | Dropbox uploads and sharing         | Review account, file, sharing, and recipient details            |
| SIEM         | Anita Pandey / 10.1.2.22 / ENDP-011 | Add to watchlist for follow-up                                  |
| Endpoint     | ENDP-011                            | Check local file and compression history                        |
| User Account | Anita Pandey                        | Review activity only if compromise or insider risk is suspected |

**Blocking Note:** If Dropbox is used by the organization for legitimate workflows, do not block it globally without business approval. Instead, restrict personal Dropbox usage, enforce DLP controls, and allow only approved corporate-managed accounts.

## Severity Recommendation

**Recommended Severity:** **Medium to High**

Severity can remain **Medium** if:

| Condition                           | Reason                     |
| ----------------------------------- | -------------------------- |
| Upload was business-approved        | Legitimate transfer        |
| Data was non-sensitive              | Low exposure risk          |
| Dropbox account was company-managed | Controlled environment     |
| No external sharing occurred        | Reduced data loss risk     |
| No DLP violation found              | No confirmed data exposure |

Severity should remain or be raised to **High** if:

| Condition                                | Reason                                 |
| ---------------------------------------- | -------------------------------------- |
| File contained HR/employee data          | Sensitive data exposure risk           |
| Upload was unauthorized                  | Possible data exfiltration             |
| Dropbox account was personal/unmanaged   | Loss of company control                |
| File was externally shared               | Confirmed exposure path                |
| Similar uploads occurred repeatedly      | Possible insider risk or policy bypass |
| Endpoint/account compromise is suspected | Potential attacker-driven exfiltration |

## Escalation Decision

**Decision:** **Conditional escalation to SOC L2 / DLP / Insider Risk.**

**Reason:** Upload activity to Dropbox was confirmed, but the evidence does not prove malicious data exfiltration. Escalation depends on whether the upload was unauthorized, sensitive, externally shared, or linked to compromise.

SOC L2 escalation is **not required** if:

1. Anita confirms the upload was approved.
2. Dropbox is allowed by policy.
3. DLP confirms the file was non-sensitive.
4. No external sharing occurred.
5. No suspicious endpoint or account activity is found.

Escalate to **SOC L2 / DLP / Insider Risk** if:

1. Anita cannot justify the transfer.
2. **Data.zip** contains HR, employee, payroll, legal, or confidential data.
3. The Dropbox account was personal or unmanaged.
4. External sharing occurred.
5. Similar uploads are identified.
6. Endpoint or account compromise is suspected.

## Final Ticket Closure Comment

SOC investigated ticket **CS-044 — Proxy: Large Data Transfers Detected / Possible Data Exfiltration**. Proxy logs show user **Anita Pandey** from **10.1.2.22 / ENDP-011** accessed **dropbox.com** and performed upload-related **PUT** requests to `https://www.dropbox.com/u/1/my-drive`. The observed file was **Data.zip**. Two PUT events showed **51,200 bytes sent** and **55,500 bytes sent**, with the final event returning HTTP **200**, confirming Dropbox upload activity. No endpoint compromise, malware activity, or confirmed malicious intent was identified from the provided logs. However, because the user belongs to the HR Department and the file name suggests a compressed data archive, this case requires user validation and DLP/file sensitivity review. Ticket closed as **True Positive — Dropbox Upload Activity / Possible Data Exfiltration Pending Validation**, with DLP validation, user confirmation, Dropbox policy review, and conditional escalation to SOC L2/DLP/Insider Risk recommended if the upload was unauthorized, sensitive, or externally shared.

## Skills Demonstrated

Proxy alert triage, possible data exfiltration investigation, cloud storage upload analysis, timeline reconstruction, user and endpoint correlation, Splunk proxy log review, DLP validation planning, insider-risk assessment, MITRE ATT&CK mapping, impact analysis, containment planning, escalation decision-making, and SOC ticket documentation.

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
