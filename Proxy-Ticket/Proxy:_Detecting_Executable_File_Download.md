# SOC Analyst Investigation Report

## Ticket Overview

| Field            | Details                                                                        |
| ---------------- | ------------------------------------------------------------------------------ |
| Ticket ID        | CS-038                                                                         |
| Alert Name       | Proxy: Detecting Executable File Download                                      |
| Ticket Status    | Closed                                                                         |
| Priority / SLA   | High / Default SLA                                                             |
| Created Date     | 3/21/25 6:52 PM                                                                |
| Closed By        | Ananda Das                                                                     |
| Analyst Decision | **True Positive — Executable Download Attempt / Endpoint Validation Required** |

## Executive Summary

A proxy alert was triggered for **Detecting Executable File Download** involving user **Eva Smith** from internal source IP **10.1.2.14** accessing an executable file hosted on **bitbucket.org**.

The requested file was **Invoice_2024.exe** from the URL:

`https://bitbucket.org/riskwca/cscacxxxc/downloads/ads/Invoice_2024.exe`

The web category was **Malicious Sources/Malnets**, and the proxy action was **Allowed**. The request came from a Google search referrer, which indicates the user may have searched for or clicked a search result leading to the executable file.

No confirmed malware execution, endpoint compromise, C2 callback, persistence, or data exfiltration was identified from the provided proxy evidence. However, because the file is an **.exe** from a malicious-category source, user validation and endpoint review are required before confirming no impact.

## Alert Details

| Field               | Value                                                                                |
| ------------------- | ------------------------------------------------------------------------------------ |
| Timestamp           | 3/6/2025 12:44                                                                       |
| Username            | Eva Smith                                                                            |
| Source IP           | 10.1.2.14                                                                            |
| Destination IP      | 203.0.221.161                                                                        |
| URL Domain          | bitbucket.org                                                                        |
| URL                 | `https://bitbucket.org/riskwca/cscacxxxc/downloads/ads/Invoice_2024.exe`             |
| Referrer            | `https://www.google.com/search?q= https://bitbucket.org/riskwca/cscacxxxc/downloads` |
| Web Category        | Malicious Sources/Malnets                                                            |
| Proxy Action        | Allowed                                                                              |
| HTTP Method         | GET                                                                                  |
| File Name           | Invoice_2024.exe                                                                     |
| File Type           | Executable                                                                           |
| Destination Details | Suncorp Corporate Services Pty Ltd; Commercial; AS9435; Sydney, Australia            |

## Affected Assets

| Asset Field     | Details           |
| --------------- | ----------------- |
| User            | Eva Smith         |
| Role            | System Admin L1   |
| Department      | IT Infrastructure |
| Source IP       | 10.1.2.14         |
| Endpoint        | ENDP-184          |
| Endpoint OS     | Windows 11-64     |
| Destination IP  | 203.0.221.161     |
| Suspicious File | Invoice_2024.exe  |

## Evidence Reviewed

| Evidence Source     | Observation                       |
| ------------------- | --------------------------------- |
| Proxy Alert         | Executable file download detected |
| File Name           | `Invoice_2024.exe`                |
| File Extension      | `.exe`                            |
| URL Category        | Malicious Sources/Malnets         |
| Proxy Action        | Allowed                           |
| HTTP Method         | GET                               |
| Referrer            | Google search result              |
| Malware Execution   | Not Observed                      |
| EDR Alert           | Not Provided                      |
| C2 Callback         | Not Observed                      |
| Endpoint Compromise | Not Observed                      |

## SIEM / Splunk Analysis

```spl id="cs0260_proxy_query"
index=main "Invoice_2024.exe" sourcetype="proxy_logs"
| table _time, "File Type", Referrer, "Response Code", URL, "URL Domain", Username, "User Agent", "Web Category"
```

```text id="cs0260_proxy_result"
_time	File Type	Referrer	Response Code	URL	URL Domain	Username	User Agent	Web Category
2025-03-06 12:44:00	Invoice_2024.exe	https://www.google.com/search?q= https://bitbucket.org/riskwca/cscacxxxc/downloads		https://bitbucket.org/riskwca/cscacxxxc/downloads/ads/Invoice_2024.exe	bitbucket.org	Eva Smith	Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/123.0.0.0 Safari/537.36	Malicious Sources/Malnets
```

**Analysis Note:** The proxy evidence confirms an executable download attempt from a malicious-category source. The provided logs do not confirm whether the file was fully downloaded, opened, or executed on the endpoint.

## MITRE ATT&CK Mapping

| Tactic              | Technique                                 | ID        | Reason                                                                                         |
| ------------------- | ----------------------------------------- | --------- | ---------------------------------------------------------------------------------------------- |
| Initial Access      | Phishing                                  | T1566     | Invoice-themed executable could be linked to social engineering; source delivery not confirmed |
| Execution           | User Execution: Malicious File            | T1204.002 | Impact would require the user to open/execute the downloaded `.exe`; execution not confirmed   |
| Command and Control | Application Layer Protocol: Web Protocols | T1071.001 | Web-based download from suspicious infrastructure was observed; C2 not confirmed               |

## Analyst Assessment

**Assessment:** **True Positive — Suspicious Executable Download Attempt**

The alert is valid because the user accessed an executable file named **Invoice_2024.exe** from a URL categorized as **Malicious Sources/Malnets**. The invoice-themed filename and unusual Bitbucket repository path increase suspicion.

This is **not confirmed compromise**. No endpoint execution, malware detection, process creation, C2 callback, persistence, or data exfiltration evidence was provided.

## Impact Analysis

| Area            | Assessment                                             |
| --------------- | ------------------------------------------------------ |
| Confidentiality | No credential theft or data exposure confirmed         |
| Integrity       | No endpoint modification confirmed                     |
| Availability    | No service impact reported                             |
| Business Impact | No confirmed impact                                    |
| Current Risk    | High until file download/execution status is validated |

## Recommended Actions

1. Contact **Eva Smith** to confirm whether the file was intentionally downloaded.
2. Confirm whether **Invoice_2024.exe** was opened or executed.
3. Check endpoint **ENDP-184** for the file in Downloads, Desktop, Temp, browser cache, and quarantine.
4. Collect file hash if the file is present.
5. Review EDR/AV logs for execution, quarantine, or malware detection.
6. Review process execution logs for **Invoice_2024.exe** and suspicious child processes.
7. Review outbound connections from **10.1.2.14** after **2025-03-06 12:44**.
8. Block the specific suspicious Bitbucket URL and repository path in proxy/SWG.
9. Block destination IP **203.0.221.161** if no business requirement exists.
10. Do not block the full **bitbucket.org** domain globally unless policy allows it, because it may be used for legitimate development activity.
11. Escalate to SOC L2 if file execution, malware detection, C2 callback, persistence, or suspicious endpoint behavior is confirmed.

## Escalation Decision

**Decision:** **User and endpoint validation required; conditional SOC L2 escalation.**

**Reason:** The proxy allowed access to an executable file from a malicious-category source. The event cannot be closed as fully no-impact until endpoint checks confirm the file was not executed and no suspicious activity occurred.

SOC L2 escalation is required if **Invoice_2024.exe** was executed, confirmed malicious, quarantined by EDR/AV, or followed by suspicious process/network activity.

## Final Ticket Closure Comment

SOC investigated ticket **CS-038 — Proxy: Detecting Executable File Download**. Proxy logs show user **Eva Smith** from **10.1.2.14 / ENDP-184** accessed **Invoice_2024.exe** from `bitbucket.org` using HTTP **GET**. The URL was categorized as **Malicious Sources/Malnets**, and the proxy action was **Allowed**. No confirmed malware execution, endpoint compromise, C2 callback, persistence, or data exfiltration was identified from the provided logs. Ticket closed as **True Positive — Executable Download Attempt / Endpoint Validation Required**, with user validation, endpoint review, URL/path blocking, and SOC L2 escalation recommended only if execution or endpoint impact is confirmed.

## Skills Demonstrated

Proxy alert triage, executable download investigation, suspicious file analysis, user and endpoint correlation, Splunk proxy log review, IOC handling, MITRE ATT&CK mapping, impact assessment, escalation decision-making, and SOC ticket documentation.

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
