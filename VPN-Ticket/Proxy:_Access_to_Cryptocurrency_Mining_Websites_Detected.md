# SOC Analyst Investigation Report

## Ticket Overview

| Field            | Details                                                                                             |
| ---------------- | --------------------------------------------------------------------------------------------------- |
| Ticket ID        | CS-042                                                                                              |
| Alert Name       | Proxy: Access to Cryptocurrency Mining Websites Detected                                            |
| Ticket Status    | Closed                                                                                              |
| Priority / SLA   | Normal / Default SLA                                                                                |
| Created Date     | 3/16/25 6:26 PM                                                                                     |
| Closed By        | Ananda Das                                                                                          |
| Analyst Decision | **True Positive — Cryptomining Site Access and Executable Download / Endpoint Validation Required** |

## Executive Summary

A proxy alert was triggered for **Access to Cryptocurrency Mining Websites** involving user **Kavya Batra** from internal source IP **10.1.2.33** accessing **cryptotabbrowser.com**.

The accessed URL was:

`https://cryptotabbrowser.com/en/`

The site was categorized as **Cryptomining**, the proxy action was **Allowed**, and the response code was **200**, confirming successful access. Additional proxy logs show the user downloaded an executable installer:

`CTBrowserSetup.exe`

Email log correlation identified that the same URL was delivered to **[Kavya.Batra@abc.com](mailto:Kavya.Batra@abc.com)** from **[chris.tan@gmail.com](mailto:chris.tan@gmail.com)** with a crypto/bitcoin earning-themed subject. Reputation evidence also categorized the URL as a security risk, with **3/91 security vendors** flagging it as malicious.

No confirmed execution, endpoint compromise, cryptomining activity, C2 callback, credential theft, or data exfiltration was identified from the provided logs. However, because an executable was downloaded from a cryptomining/security-risk site, user validation and EDR review are required before confirming no impact.

## Alert Details

| Field                   | Value                                                                      |
| ----------------------- | -------------------------------------------------------------------------- |
| Timestamp               | 3/13/2025 02:47                                                            |
| Username                | Kavya Batra                                                                |
| Source IP               | 10.1.2.33                                                                  |
| Destination IP          | 172.67.69.233                                                              |
| URL Domain              | cryptotabbrowser.com                                                       |
| URL                     | `https://cryptotabbrowser.com/en/`                                         |
| Web Category            | Cryptomining                                                               |
| Proxy Action            | Allowed                                                                    |
| HTTP Method             | GET                                                                        |
| Response Code           | 200                                                                        |
| Downloaded File         | CTBrowserSetup.exe                                                         |
| Related Email Sender    | [chris.tan@gmail.com](mailto:chris.tan@gmail.com)                          |
| Related Email Recipient | [Kavya.Batra@abc.com](mailto:Kavya.Batra@abc.com)                          |
| Related Email Subject   | Work From Home / Start Earning in Crypto / Join Our Bitcoin Mining Program |

## Affected Assets

| Asset Field             | Details              |
| ----------------------- | -------------------- |
| User                    | Kavya Batra          |
| Source IP               | 10.1.2.33            |
| Endpoint                | Not Provided         |
| Endpoint OS             | Not Provided         |
| External Destination IP | 172.67.69.233        |
| External Domain         | cryptotabbrowser.com |
| Risky File              | CTBrowserSetup.exe   |
| Business Criticality    | Not Provided         |

## Evidence Reviewed

| Evidence Source   | Observation                                        |
| ----------------- | -------------------------------------------------- |
| Proxy Alert       | Access to cryptomining website detected            |
| Web Category      | Cryptomining                                       |
| Proxy Action      | Allowed                                            |
| Response Code     | 200                                                |
| File Download     | `CTBrowserSetup.exe` observed                      |
| Email Logs        | Same URL delivered to user via crypto-themed email |
| URL Reputation    | Security risk; 3/91 vendors flagged malicious      |
| File Execution    | Not Observed                                       |
| EDR Alert         | Not Provided                                       |
| C2 Callback       | Not Observed                                       |
| Data Exfiltration | Not Observed                                       |

## SIEM / Splunk Analysis

### Proxy Log Query

```spl id="cs0253_proxy_query"
index=main "Kavya Batra" sourcetype=proxy_logs "cryptotabbrowser.com"
| table _time Referrer "HTTP Method" "Response Code" "Source IP" "Destination IP" Action URL "File Type" "User Agent" Username "Web Category"
```

### Full Unique Proxy Log Results

```text id="cs0253_proxy_results"
_time	Referrer	HTTP Method	Response Code	Source IP	Destination IP	Action	URL	File Type	User Agent	Username	Web Category
2025-03-13 02:48:00	https://cryptotabbrowser.com/en/	GET	200	10.1.2.33	172.67.69.233	Allowed	https://cryptotabbrowser.com/get/CTBrowserSetup.exe	CTBrowserSetup.exe	Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/123.0.0.0 Safari/537.36	Kavya Batra	Cryptomining
2025-03-13 02:48:00	https://www.google.com/search?q=cryptotabbrowser.com	GET	200	10.1.2.33	172.67.69.233	Allowed	https://cryptotabbrowser.com/en/		Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/123.0.0.0 Safari/537.36	Kavya Batra	Cryptomining
2025-03-13 02:47:00	https://www.google.com/search?q=cryptotabbrowser.com	GET	200	10.1.2.33	172.67.69.233	Allowed	https://cryptotabbrowser.com/en/		Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/123.0.0.0 Safari/537.36	Kavya Batra	Cryptominin
```

### Email Log Query

```spl id="cs0253_email_query"
index=main "cryptotabbrowser.com" sourcetype=email_logs
| table _time Email_Subject Sender SenderIP Recipient Status URL Action
```

### Full Unique Email Log Results

```text id="cs0253_email_results"
_time	Email_Subject	Sender	SenderIP	Recipient	Status	URL	Action
2025-03-12 23:30:00	Work From Home – Start Earning in Crypto" - "Join Our Bitcoin Mining Program	chris.tan@gmail.com	142.250.153.27	Kavya.Batra@abc.com	delivered	https://cryptotabbrowser.com/en/	allowed
```

### Reputation Evidence

| Field            | Value                                                            |
| ---------------- | ---------------------------------------------------------------- |
| Reviewed URL     | `https://cryptotabbrowser.com:443/en/`                           |
| Categorization   | Security Risk                                                    |
| Vendor Detection | 3/91 security vendors flagged this URL as malicious              |
| Status           | 200                                                              |
| Content Type     | text/html; charset=utf-8                                         |
| Domain           | cryptotabbrowser.com                                             |
| Detections       | Chong Lua Dao — Malicious; CRDF — Malicious; Webroot — Malicious |

## MITRE ATT&CK Mapping

| Tactic              | Technique                                 | ID        | Reason                                                                                           |
| ------------------- | ----------------------------------------- | --------- | ------------------------------------------------------------------------------------------------ |
| Initial Access      | Phishing                                  | T1566     | Suspicious crypto-themed email delivered the URL to the user                                     |
| Execution           | User Execution: Malicious File            | T1204.002 | Executable file was downloaded; execution not confirmed                                          |
| Impact              | Resource Hijacking                        | T1496     | Cryptomining-related software may lead to unauthorized resource usage if executed; not confirmed |
| Command and Control | Application Layer Protocol: Web Protocols | T1071.001 | Web-based access to suspicious external infrastructure was observed; C2 not confirmed            |

## Analyst Assessment

**Assessment:** **True Positive — Cryptomining Website Access with Executable Download**

The alert is valid because proxy logs confirm access to a cryptomining-category website and download of **CTBrowserSetup.exe**. Email logs also show the URL was delivered to the user through a crypto/earning-themed email, increasing the likelihood of social engineering.

This is **not confirmed endpoint compromise**. No execution evidence, mining process, EDR detection, persistence, C2 callback, credential theft, or data exfiltration was provided.

## Impact Analysis

| Area            | Assessment                                                            |
| --------------- | --------------------------------------------------------------------- |
| Confidentiality | No credential theft or data exposure confirmed                        |
| Integrity       | No endpoint modification confirmed                                    |
| Availability    | No confirmed resource abuse or mining activity                        |
| Business Impact | No confirmed impact                                                   |
| Current Risk    | Medium to High until EDR confirms whether the executable was executed |

## Recommended Actions

1. Contact **Kavya Batra** to confirm whether the email was opened and the link was clicked.
2. Confirm whether **CTBrowserSetup.exe** was downloaded successfully.
3. Confirm whether the executable was opened or installed.
4. Check EDR/AV telemetry for execution of **CTBrowserSetup.exe**.
5. Search the endpoint for the file in Downloads, Desktop, Temp, browser cache, and quarantine.
6. Collect the file hash if the file is present.
7. Review endpoint process logs for child processes, browser installation activity, persistence, scheduled tasks, or mining-related processes.
8. Review outbound traffic from **10.1.2.33** after **2025-03-13 02:48** for mining pools, suspicious domains, or C2 connections.
9. Block **cryptotabbrowser.com** and related URLs in proxy/DNS/email gateway controls.
10. Remove or quarantine the delivered email if still present.
11. Avoid broad blocking of Cloudflare IP ranges; prioritize domain/URL-based blocking.
12. Escalate to SOC L2 only if execution, malware detection, mining activity, suspicious outbound traffic, persistence, or credential compromise is confirmed.

## Escalation Decision

**Decision:** **User and EDR validation required; conditional SOC L2 escalation.**

**Reason:** The proxy logs confirm access to a cryptomining/security-risk site and download of an executable file. However, the provided logs do not confirm execution or endpoint compromise. SOC L2 escalation is required only if EDR or user validation confirms execution, malware activity, mining behavior, C2 callback, persistence, or credential theft.

## Final Ticket Closure Comment

SOC investigated ticket **CS-042 — Proxy: Access to Cryptocurrency Mining Websites Detected**. Proxy logs show user **Kavya Batra** from **10.1.2.33** accessed **cryptotabbrowser.com**, categorized as **Cryptomining**, and downloaded **CTBrowserSetup.exe** from `https://cryptotabbrowser.com/get/CTBrowserSetup.exe`. The traffic was Allowed and returned HTTP **200**. Email logs show the same URL was delivered to **[Kavya.Batra@abc.com](mailto:Kavya.Batra@abc.com)** from **[chris.tan@gmail.com](mailto:chris.tan@gmail.com)** with a crypto/bitcoin earning-themed subject. Reputation evidence categorized the URL as a security risk, with **3/91 vendors** flagging it as malicious. No confirmed file execution, endpoint compromise, mining activity, credential theft, C2 callback, or data exfiltration was identified. Ticket closed as **True Positive — Cryptomining Site Access and Executable Download / Endpoint Validation Required**, with user validation, EDR review, email quarantine, and domain/URL blocking recommended.

## Skills Demonstrated

Proxy alert triage, cryptomining site investigation, executable download analysis, email log correlation, user validation planning, endpoint/EDR investigation planning, IOC handling, MITRE ATT&CK mapping, impact assessment, escalation decision-making, and SOC ticket documentation.

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
