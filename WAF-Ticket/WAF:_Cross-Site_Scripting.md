# SOC Analyst Investigation Report

## Ticket Overview

| Field            | Details                                   |
| ---------------- | ----------------------------------------- |
| Ticket ID        | CS-025                                    |
| Alert Name       | WAF: Cross-Site Scripting                 |
| Ticket Status    | Closed                                    |
| Priority / SLA   | Normal / Default SLA                      |
| Created Date     | 3/2/25 7:45 PM                            |
| Closed By        | Ananda Das                                |
| Analyst Decision | **True Positive — Denied/Blocked by WAF** |

## Executive Summary

A WAF alert was triggered for **Cross-Site Scripting** involving inbound HTTPS traffic from external source IP **45.227.255.2** to internal web server **10.0.2.32 / LinITWebServer01** on **443/TCP**.

The initial request targeted **it.abc.com/admin** with an XSS payload attempting JavaScript execution and possible cookie access using `document.cookie`. The initial event showed **Allowed** while the WAF was in **Monitoring** mode; however, the response code was **401**, meaning successful access was not confirmed. Later WAF logs showed repeated XSS attempts from the same source were **Blocked** in **Blocking** mode with HTTP **403**.

No successful XSS execution, session theft, user compromise, application compromise, or service impact was confirmed from the provided evidence.

## Alert Details

| Field                 | Value                                                                                                    |
| --------------------- | -------------------------------------------------------------------------------------------------------- |
| Receive Time          | 12/28/2024 05:06                                                                                         |
| Source IP             | 45.227.255.2                                                                                             |
| Source Port           | 43544                                                                                                    |
| Destination IP        | 10.0.2.32                                                                                                |
| Destination Port      | 443                                                                                                      |
| Site Name             | it.abc.com                                                                                               |
| Initial URL           | /admin                                                                                                   |
| HTTP Method           | GET                                                                                                      |
| Threat Name           | Cross-Site Scripting                                                                                     |
| Severity              | Medium                                                                                                   |
| Initial Action        | Allowed                                                                                                  |
| Initial Response Code | 401                                                                                                      |
| Later WAF Action      | Blocked                                                                                                  |
| Later Response Code   | 403                                                                                                      |
| WAF Mode              | Monitoring / Blocking                                                                                    |
| Source Details        | Okpay Investment Company; Data Center/Web Hosting/Transit; AS43350; web4net.org; Roosendaal, Netherlands |

## Affected Assets

| Asset Field          | Details                                           |
| -------------------- | ------------------------------------------------- |
| Destination IP       | 10.0.2.32                                         |
| Hostname             | LinITWebServer01                                  |
| Operating System     | Linux - RHEL 8                                    |
| Platform             | Linux                                             |
| Asset Role           | Web Server                                        |
| Hosting              | AWS Cloud                                         |
| Business Criticality | Not Provided                                      |
| Exposure Concern     | Public web application targeted with XSS payloads |

## Evidence Reviewed

| Evidence Source             | Observation                                              |
| --------------------------- | -------------------------------------------------------- |
| WAF Alert                   | XSS detected against `/admin`                            |
| Affected URLs               | `/admin`, `/api`, `/products`, `/search`, `/login`       |
| Payload Pattern             | JavaScript execution via `iframe`, `img`, and `svg` tags |
| Cookie Access Attempt       | `document.cookie` observed in payloads                   |
| HTTP Methods                | GET, POST, PUT                                           |
| Initial Result              | Allowed in Monitoring mode, HTTP **401**                 |
| Later Results               | Blocked in Blocking mode, HTTP **403**                   |
| Successful Script Execution | Not Observed                                             |
| Session Theft               | Not Observed                                             |
| Service Impact              | Not Provided                                             |

## SIEM / Splunk Analysis

```spl id="uh6k2p"
index=main sourcetype="waf_logs" "45.227.255.2" "10.0.2.32" Threat_Name="Cross-Site Scripting"
| table _time, srcIP, dstIP, Action, http_method, response_code, Severity, Threat_Name, URL, waf_mode, matched_string, user_agent
| sort - _time
```

| Observation           | Result                                             |
| --------------------- | -------------------------------------------------- |
| Repeated XSS attempts | Observed                                           |
| Targeted paths        | `/admin`, `/api`, `/products`, `/search`, `/login` |
| Initial WAF mode      | Monitoring                                         |
| Later WAF mode        | Blocking                                           |
| Response codes        | 401 / 403                                          |
| Confirmed compromise  | Not Observed                                       |

**Analysis Note:** The first event was logged as **Allowed** because the WAF was in Monitoring mode, but the request returned **401**. Later related requests were blocked with **403**, indicating WAF enforcement was active.

## MITRE ATT&CK Mapping

| Tactic            | Technique                                     | ID        | Reason                                                              |
| ----------------- | --------------------------------------------- | --------- | ------------------------------------------------------------------- |
| Initial Access    | Exploit Public-Facing Application             | T1190     | XSS payloads targeted public web application paths                  |
| Execution         | Command and Scripting Interpreter: JavaScript | T1059.007 | Payloads attempted JavaScript execution                             |
| Credential Access | Steal Web Session Cookie                      | T1539     | Payloads attempted access to `document.cookie`; theft not confirmed |

## Analyst Assessment

**Assessment:** **True Positive — Blocked XSS Attempt**

The alert is valid because WAF logs show repeated XSS payloads attempting JavaScript execution and possible cookie access. The activity targeted multiple web application paths and repeated over several events.

This is **not confirmed compromise**. No successful XSS execution, session theft, account compromise, or service impact was observed.

## Impact Analysis

| Area            | Assessment                                          |
| --------------- | --------------------------------------------------- |
| Confidentiality | No cookie/session theft observed                    |
| Integrity       | No application modification confirmed               |
| Availability    | No service disruption reported                      |
| Business Impact | No confirmed impact                                 |
| Current Risk    | Reduced because requests were denied/blocked by WAF |

## Recommended Actions

1. Block source IP **45.227.255.2** at the firewall as per policy.
2. Keep WAF XSS protection in **Blocking** mode.
3. Add **45.227.255.2** to IPS/WAF denylist or watchlist if supported.
4. Review web logs for any similar XSS payloads returning HTTP **200**.
5. Validate whether `PUT` is required on `/admin`, `/products`, `/search`, and `/api`.
6. Disable unnecessary HTTP methods if not required.
7. Review input validation and output encoding on affected paths.
8. Escalate only if script execution, session theft, HTTP 200 response, account compromise, or application compromise is observed.

## Escalation Decision

**Decision:** **No SOC L2 escalation required; close after firewall/IPS/WAF rule update.**

**Reason:** The WAF denied/blocked the malicious XSS attempts with HTTP **401/403**, and no successful script execution, session theft, account compromise, application compromise, or service impact was confirmed from the reviewed logs.

## Final Ticket Closure Comment

SOC investigated ticket **CS-025 — WAF: Cross-Site Scripting**. Inbound HTTPS traffic from **45.227.255.2** to **10.0.2.32 / LinITWebServer01** targeted **it.abc.com** with XSS payloads attempting JavaScript execution and cookie access via `document.cookie`. The initial event was allowed while WAF was in Monitoring mode but returned HTTP **401**. Later related events were blocked in Blocking mode with HTTP **403**. No successful XSS execution, session theft, user compromise, application compromise, or service impact was observed. Ticket closed as **True Positive — Denied/Blocked by WAF**, with source IP blocking and WAF/IPS rule enforcement recommended.

## Skills Demonstrated

WAF alert triage, XSS investigation, payload analysis, web server risk assessment, Splunk log review, source context validation, MITRE ATT&CK mapping, impact assessment, escalation decision-making, and SOC ticket documentation.

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
