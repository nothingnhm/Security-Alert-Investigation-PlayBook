# SOC Analyst Investigation Report

## Ticket Overview

| Field            | Details                                                                        |
| ---------------- | ------------------------------------------------------------------------------ |
| Ticket ID        | CS-0255                                                                        |
| Alert Name       | Proxy: Unusual Access to VPN or Proxy Avoidance Detected                       |
| Ticket Status    | Closed                                                                         |
| Priority / SLA   | Normal / Default SLA                                                           |
| Created Date     | 3/16/25 7:06 PM                                                                |
| Closed By        | Ananda Das                                                                     |
| Analyst Decision | **True Positive — Proxy Avoidance Policy Violation / No Confirmed Compromise** |

## Executive Summary

A proxy alert was triggered for **Unusual Access to VPN or Proxy Avoidance** involving access to **aproxy.com**, categorized as **Proxy Avoidance**.

The observed URL was:

`https://aproxy.com/?device=c&keyword=aproxy&gad_source=1`

The proxy action was **Allowed**, HTTP method was **GET**, and response code was **200**, confirming the site was successfully accessed. Additional proxy logs show user **Daniel Nair** from source IP **10.1.2.44 / ENDP-219** accessed the AProxy website from a Google search referrer and then accessed the AProxy login page.

This activity is a **true positive policy violation / risky proxy avoidance access** because proxy avoidance services may be used to bypass corporate web filtering, monitoring, and security controls.

No malware download, endpoint compromise, data exfiltration, or confirmed malicious activity was identified from the provided logs.

## Alert Details

| Field              | Value                                                      |
| ------------------ | ---------------------------------------------------------- |
| Destination IP     | 203.0.219.120                                              |
| URL Domain         | aproxy.com                                                 |
| Initial URL        | `https://aproxy.com/?device=c&keyword=aproxy&gad_source=1` |
| Observed Login URL | `https://aproxy.com/login/`                                |
| Web Category       | Proxy Avoidance                                            |
| Proxy Action       | Allowed                                                    |
| HTTP Method        | GET                                                        |
| Response Code      | 200                                                        |
| Username           | Daniel Nair                                                |
| Source IP          | 10.1.2.44                                                  |
| Endpoint           | ENDP-219                                                   |
| Endpoint OS        | Windows 11-64                                              |
| Department         | IT Infrastructure                                          |
| Role               | Helpdesk Manager                                           |

## Affected Assets

| Asset Field             | Details           |
| ----------------------- | ----------------- |
| User                    | Daniel Nair       |
| Source IP               | 10.1.2.44         |
| Endpoint                | ENDP-219          |
| Endpoint OS             | Windows 11-64     |
| Department              | IT Infrastructure |
| Role                    | Helpdesk Manager  |
| External Destination IP | 203.0.219.120     |
| External Domain         | aproxy.com        |
| Risk Category           | Proxy Avoidance   |

## Evidence Reviewed

| Evidence Source       | Observation                                                |
| --------------------- | ---------------------------------------------------------- |
| Proxy Alert           | Access to proxy avoidance website detected                 |
| Initial URL           | `https://aproxy.com/?device=c&keyword=aproxy&gad_source=1` |
| Login Page Access     | `https://aproxy.com/login/`                                |
| Web Category          | Proxy Avoidance                                            |
| Proxy Action          | Allowed                                                    |
| Response Code         | 200                                                        |
| Referrer              | Google search and AProxy page                              |
| Malware Download      | Not Observed                                               |
| Endpoint Compromise   | Not Observed                                               |
| Data Exfiltration     | Not Observed                                               |
| Confirmed Proxy Usage | Not Provided                                               |

## SIEM / Splunk Analysis

```spl id="cs0255_proxy_query"
index=main "aproxy.com" sourcetype=proxy_logs
| table _time Referrer "HTTP Method" "Response Code" "Source IP" "Destination IP" Action URL "User Agent" Username "Web Category"
```

```text id="cs0255_proxy_results"
_time	Referrer	HTTP Method	Response Code	Source IP	Destination IP	Action	URL	User Agent	Username	Web Category
2025-03-11 03:41:00	https://aproxy.com/?device=c&keyword=aproxy&gad_source=1	GET	200	10.1.2.44	203.0.219.120	Allowed	https://aproxy.com/login/	Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/123.0.0.0 Safari/537.36	Daniel Nair	Proxy Avoidance
2025-03-11 03:41:00	https://www.google.com/search?q=AProxy&sca_esv=f981d700d01e44ab&ei	GET	200	10.1.2.44	203.0.219.120	Allowed	https://aproxy.com/?device=c&keyword=aproxy&gad_source=1	Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/123.0.0.0 Safari/537.36	Daniel Nair	Proxy Avoidance
```

**Analysis Note:** The logs show the user accessed AProxy through Google search and then reached the AProxy login page. Both requests were allowed and returned HTTP **200**.

## MITRE ATT&CK Mapping

| Tactic              | Technique                                 | ID        | Reason                                                                                   |
| ------------------- | ----------------------------------------- | --------- | ---------------------------------------------------------------------------------------- |
| Command and Control | Proxy                                     | T1090     | Proxy avoidance service was accessed; actual proxy tunneling/use not confirmed           |
| Command and Control | Application Layer Protocol: Web Protocols | T1071.001 | Web traffic to external proxy service was observed                                       |
| Defense Evasion     | Impair Defenses                           | T1562     | Proxy avoidance could bypass monitoring/filtering if used; bypass activity not confirmed |

## Analyst Assessment

**Assessment:** **True Positive — Proxy Avoidance Access**

The alert is valid because proxy logs confirm access to **aproxy.com**, categorized as **Proxy Avoidance**. The user also reached the proxy service login page, which increases concern that the service may have been used or intended for use.

This is **not confirmed endpoint compromise**. No malware download, credential exposure, data exfiltration, suspicious payload, or endpoint compromise evidence was provided.

## Impact Analysis

| Area            | Assessment                                                 |
| --------------- | ---------------------------------------------------------- |
| Confidentiality | No data leakage confirmed                                  |
| Integrity       | No endpoint modification confirmed                         |
| Availability    | No service impact reported                                 |
| Policy Impact   | Proxy avoidance access detected on corporate endpoint      |
| Current Risk    | Medium due to successful access to proxy avoidance service |

## Recommended Actions

1. Contact **Daniel Nair** to confirm the business reason for accessing **aproxy.com**.
2. Confirm whether the user logged in to the AProxy service.
3. Confirm whether the proxy service was used to access any restricted or risky websites.
4. Confirm whether any corporate credentials or sensitive data were entered into the proxy service.
5. Review browser history after the AProxy access.
6. Check endpoint **ENDP-219** for downloads, suspicious browser activity, or EDR/AV alerts.
7. Block **aproxy.com** in proxy/DNS security controls.
8. Block destination IP **203.0.219.120** if no business requirement exists.
9. Enforce blocking for the **Proxy Avoidance** web category by default.
10. Escalate only if the proxy service was used for malicious browsing, credential entry, data transfer, malware download, or repeated policy violation.

## Escalation Decision

**Decision:** **No immediate SOC L2 escalation required; close after user validation and blocking.**

**Reason:** The logs confirm proxy avoidance access, but no malware download, endpoint compromise, data exfiltration, or malicious follow-up activity was confirmed. This should be handled as a policy/security control violation unless additional impact is found.

## Final Ticket Closure Comment

SOC investigated ticket **CS-0255 — Proxy: Unusual Access to VPN or Proxy Avoidance Detected**. Proxy logs show user **Daniel Nair** from **10.1.2.44 / ENDP-219** accessed **aproxy.com**, categorized as **Proxy Avoidance**. The user reached the site through a Google search referrer and then accessed `https://aproxy.com/login/`. The proxy action was Allowed, and both requests returned HTTP **200**. No malware download, endpoint compromise, data exfiltration, or confirmed malicious activity was observed from the provided logs. Ticket closed as **True Positive — Proxy Avoidance Policy Violation / No Confirmed Compromise**, with user validation, domain/IP blocking, and Proxy Avoidance category enforcement recommended.

## Skills Demonstrated

Proxy alert triage, proxy avoidance investigation, web filtering policy analysis, user and endpoint correlation, Splunk proxy log review, acceptable-use policy assessment, MITRE ATT&CK mapping, impact analysis, escalation decision-making, and SOC ticket documentation.

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
