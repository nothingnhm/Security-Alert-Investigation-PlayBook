# SOC Analyst Investigation Report

## Ticket Overview

| Field            | Details                                                                  |
| ---------------- | ------------------------------------------------------------------------ |
| Ticket ID        | CS-041                                                                   |
| Alert Name       | Proxy: Unusual Browser User-Agent Detected                               |
| Ticket Status    | Closed                                                                   |
| Priority / SLA   | Normal / Default SLA                                                     |
| Created Date     | 3/16/25 6:35 PM                                                          |
| Closed By        | Ananda Das                                                               |
| Analyst Decision | **True Positive — Unusual Browser User-Agent / No Confirmed Compromise** |

## Executive Summary

A proxy alert was triggered for **Unusual Browser User-Agent Detected** involving user **Aaina Jhaveri** from internal source IP **10.1.2.41** accessing **google.com**.

The initial event showed a Brave browser user-agent:

`Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Brave/99.1.35.100 Safari/537.36`

The request was **Allowed**, used HTTP **GET**, and returned HTTP **200**. Additional proxy logs show both Brave and Chrome user-agent activity from the same user/source IP, which indicates multi-browser activity or possible use of a non-standard browser on a corporate endpoint.

No malware download, phishing access, C2 callback, credential theft, endpoint compromise, or data exfiltration was confirmed from the provided logs.

## Alert Details

| Field            | Value                                                                                                              |
| ---------------- | ------------------------------------------------------------------------------------------------------------------ |
| Timestamp        | 3/8/2025 11:07                                                                                                     |
| Username         | Aaina Jhaveri                                                                                                      |
| Source IP        | 10.1.2.41                                                                                                          |
| Destination IP   | 52.85.61.9                                                                                                         |
| URL Domain       | google.com                                                                                                         |
| URL              | google.com                                                                                                         |
| Web Category     | Search Engines/Portals                                                                                             |
| Proxy Action     | Allowed                                                                                                            |
| HTTP Method      | GET                                                                                                                |
| Response Code    | 200                                                                                                                |
| User-Agent       | `Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Brave/99.1.35.100 Safari/537.36` |
| Detection Reason | Brave browser / unusual browser user-agent                                                                         |

## Affected Assets

| Asset Field          | Details                                       |
| -------------------- | --------------------------------------------- |
| User                 | Aaina Jhaveri                                 |
| Role                 | Logistics Coordinator                         |
| Department           | Operations                                    |
| Source IP            | 10.1.2.41                                     |
| Endpoint             | ENDP-768                                      |
| Endpoint OS          | Windows 11-64                                 |
| Primary Finding      | Brave and Chrome user-agent activity observed |
| Business Criticality | Not Provided                                  |

## Evidence Reviewed

| Evidence Source       | Observation                                                                                                              |
| --------------------- | ------------------------------------------------------------------------------------------------------------------------ |
| Proxy Alert           | Brave browser user-agent detected                                                                                        |
| Additional Proxy Logs | Chrome user-agent activity also observed                                                                                 |
| Proxy Action          | Allowed                                                                                                                  |
| Response Codes        | 200                                                                                                                      |
| Browsing Categories   | Search Engines/Portals, Technology/Internet, Games, Shopping, Social Networking, Restaurants/Food, Travel, Entertainment |
| Malware Download      | Not Observed                                                                                                             |
| C2 Callback           | Not Observed                                                                                                             |
| Credential Theft      | Not Observed                                                                                                             |
| Endpoint Compromise   | Not Observed                                                                                                             |

## SIEM / Splunk Analysis

```spl id="cs0254_proxy_query"
index=main "aaina jhaveri" sourcetype=proxy_logs "google.com"
| table _time Referrer "HTTP Method" "Response Code" "Source IP" "Destination IP" Action URL "User Agent" Username "Web Category"
| dedup "Web Category"
```

```text id="cs0254_proxy_results"
_time	Referrer	HTTP Method	Response Code	Source IP	Destination IPSource IP" "Destination IP" Action URL "User Agent" Username "Web Category"
| dedup "Web Category"
```

```text id="cs0254_proxy_results"
_time	Referrer	HTTP Method	Response Code	Source IP	Destination IP	Action	URL	User Agent	Username	Web Category
2025-03-08 11:07:00	https://www.google.com/	GET	200	10.1.2.41	52.85.61.9	Allowed	google.com	Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Brave/99.1.35.100 Safari/537.36	Aaina Jhaveri	Search Engines/Portals
2025-03-08 11:07:00	https://www.google.com/search?q=Brave&sca_esv=f981d700d01e44ab&ei=w8nWZ86KFZKhseMP0duT	GET	200	10.1.2.41	52.85.61.9	Allowed	https://brave.com/	Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/123.0.0.0 Safari/537.36	Aaina Jhaveri	Technology/Internet
2025-03-08 11:07:00	https://www.google.com/search?q=www.steampowered.com	GET	200	10.1.2.41	203.0.228.31	Allowed	https://www.steampowered.com	Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/123.0.0.0 Safari/537.36	Aaina Jhaveri	Games
2025-03-10 21:41:00	https://www.google.com/search?q=www.amazon.com	GET	200	10.1.2.41	203.0.155.126	Allowed	https://www.amazon.com	Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/123.0.0.0 Safari/537.36	Aaina Jhaveri	Shopping
2025-03-12 13:00:00	https://www.google.com/search?q=www.twitter.com	GET	200	10.1.2.41	203.0.1.113	Allowed	https://www.twitter.com	Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/123.0.0.0 Safari/537.36	Aaina Jhaveri	Social Networking
2025-03-12 15:46:00	https://www.google.com/search?q=www.zomato.com	GET	200	10.1.2.41	203.0.208.175	Allowed	https://www.zomato.com	Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/123.0.0.0 Safari/537.36	Aaina Jhaveri	Restaurants/Food
2025-03-12 17:42:00	https://www.google.com/search?q=www.expedia.com	GET	200	10.1.2.41	203.0.37.47	Allowed	https://www.expedia.com	Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/123.0.0.0 Safari/537.36	Aaina Jhaveri	Travel
2025-03-13 17:31:00	https://www.google.com/search?q=www.ebay.com	POST	200	10.1.2.41	203.0.164.168	Allowed	https://www.ebay.com	Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/123.0.0.0 Safari/537.36	Aaina Jhaveri	Entertainment
```

**Analysis Note:** The logs confirm unusual browser user-agent activity and multi-browser browsing behavior. The evidence does not show a malicious URL category, exploit payload, malware download, or confirmed endpoint compromise.

## MITRE ATT&CK Mapping

| Tactic          | Technique           | ID             | Reason                                                                                               |
| --------------- | ------------------- | -------------- | ---------------------------------------------------------------------------------------------------- |
| Not Confirmed   | Not Mapped          | Not Applicable | No malicious behavior or confirmed ATT&CK technique was observed                                     |
| Defense Evasion | Masquerading        | T1036          | Only a possible consideration if user-agent spoofing is confirmed; not confirmed in current evidence |
| Initial Access  | Drive-by Compromise | T1189          | Not mapped as confirmed because no malicious site or exploit activity was observed                   |

## Analyst Assessment

**Assessment:** **True Positive — Unusual Browser User-Agent / Policy Review Required**

The alert is valid because a Brave browser user-agent was detected and additional logs show multi-browser activity from the same endpoint. This may indicate use of a non-standard browser, unauthorized browser installation, or browser policy deviation.

This is **not confirmed compromise**. No malware download, malicious domain access, exploit activity, C2 callback, credential theft, or endpoint compromise was identified from the provided logs.

## Impact Analysis

| Area            | Assessment                                                   |
| --------------- | ------------------------------------------------------------ |
| Confidentiality | No data exposure confirmed                                   |
| Integrity       | No endpoint modification confirmed from logs                 |
| Availability    | No service impact reported                                   |
| Policy Impact   | Possible unauthorized browser or non-standard software usage |
| Current Risk    | Low to Medium depending on browser approval status           |

## Recommended Actions

1. Contact **Aaina Jhaveri** to confirm whether Brave browser was intentionally installed or used.
2. Validate whether Brave is approved by IT/security policy.
3. Check endpoint **ENDP-768** for installed browsers and browser extensions.
4. Review browser download history around **2025-03-08 11:07**.
5. Check EDR/AV logs for any suspicious browser-related activity.
6. Remove or block Brave if it is not approved by company policy.
7. Enforce approved browser/application control policy.
8. Monitor for repeated unusual user-agent activity from **10.1.2.41**.
9. Escalate only if user-agent spoofing, malicious downloads, suspicious extensions, C2 traffic, or endpoint compromise indicators are found.

## Escalation Decision

**Decision:** **No immediate SOC L2 escalation required; close after user and endpoint validation.**

**Reason:** The logs show unusual browser user-agent and multi-browser activity, but no malicious domain, malware download, phishing access, C2 callback, credential theft, data exfiltration, or endpoint compromise was confirmed.

## Final Ticket Closure Comment

SOC investigated ticket **CS-041 — Proxy: Unusual Browser User-Agent Detected**. Proxy logs show user **Aaina Jhaveri** from **10.1.2.41 / ENDP-768** accessed **google.com** using a Brave browser user-agent. Additional logs show Chrome user-agent activity from the same user and source IP across multiple browsing categories. All reviewed requests were Allowed and returned HTTP **200**. No malware download, malicious URL access, exploit activity, C2 callback, credential theft, endpoint compromise, or data exfiltration was identified. Ticket closed as **True Positive — Unusual Browser User-Agent / No Confirmed Compromise**, with user validation, endpoint browser review, and approved browser policy enforcement recommended.

## Skills Demonstrated

Proxy alert triage, user-agent analysis, multi-browser activity review, user and endpoint correlation, Splunk proxy log analysis, acceptable-use policy assessment, impact analysis, escalation decision-making, and SOC ticket documentation.

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
