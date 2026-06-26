# SOC Analyst Investigation Report

## Ticket Overview

| Field            | Details                                                               |
| ---------------- | --------------------------------------------------------------------- |
| Ticket ID        | CS-033                                                                |
| Alert Name       | WAF: HTTP Flood Detected                                              |
| Ticket Status    | Closed                                                                |
| Priority / SLA   | High / High                                                           |
| Created Date     | 3/2/25 7:45 PM                                                        |
| Closed By        | Ananda Das                                                            |
| Analyst Decision | **True Positive — HTTP Flood Detected / No Confirmed Service Impact** |

## Executive Summary

A WAF alert was triggered for **HTTP Flood** involving inbound HTTPS traffic from external source IP **91.194.84.10** to internal web server **10.0.2.32 / LinITWebServer01** on **443/TCP**.

The activity targeted **it.abc.com/login** using HTTP method **GET** with matched string `/index.php`. Splunk review confirmed **63 total events** at the same timestamp: **59 blocked requests** with HTTP **401** and **4 allowed requests** with HTTP **200**.

No successful login, service outage, application downtime, or compromise was confirmed from the provided evidence. However, the source generated repeated login-page requests and some responses returned HTTP **200**, so firewall/IPS/WAF blocking and rate-limit tuning are recommended.

## Alert Details

| Field            | Value                                                                                                    |
| ---------------- | -------------------------------------------------------------------------------------------------------- |
| Receive Time     | 12/25/2024 05:06                                                                                         |
| Source IP        | 91.194.84.10                                                                                             |
| Source Port      | 43544                                                                                                    |
| Destination IP   | 10.0.2.32                                                                                                |
| Destination Port | 443                                                                                                      |
| Site Name        | it.abc.com                                                                                               |
| URL              | /login                                                                                                   |
| HTTP Method      | GET                                                                                                      |
| Threat ID        | 2354                                                                                                     |
| Threat Name      | HTTP Flood                                                                                               |
| Severity         | High                                                                                                     |
| Matched String   | `/index.php`                                                                                             |
| Initial Action   | Allowed                                                                                                  |
| WAF Mode         | Monitoring                                                                                               |
| Source Details   | WIIT AG; Data Center/Web Hosting/Transit; AS24961; mail.legaltricks.com; wiit.cloud; Dusseldorf, Germany |
| Abuse Confidence | 26%                                                                                                      |

## Affected Assets

| Asset Field          | Details          |
| -------------------- | ---------------- |
| Destination IP       | 10.0.2.32        |
| Hostname             | LinITWebServer01 |
| Operating System     | Linux - RHEL 8   |
| Platform             | Linux            |
| Asset Role           | Web Server       |
| Hosting              | AWS Cloud        |
| Site                 | it.abc.com       |
| Targeted Endpoint    | `/login`         |
| Business Criticality | Not Provided     |

## Evidence Reviewed

| Evidence Source        | Observation                            |
| ---------------------- | -------------------------------------- |
| WAF Alert              | HTTP Flood detected against `/login`   |
| Request Pattern        | Repeated GET requests for `/index.php` |
| Total Events           | 63                                     |
| Blocked Events         | 59 requests with HTTP **401**          |
| Allowed Events         | 4 requests with HTTP **200**           |
| WAF Mode               | Monitoring                             |
| Successful Login       | Not Observed                           |
| Service Impact         | Not Provided                           |
| Application Compromise | Not Observed                           |

## SIEM / Splunk Analysis

```spl id="p2w8lm"
index=main "91.194.84.10" "10.0.2.32" sourcetype=waf_logs Threat_Name="HTTP Flood"
| stats count by _time, srcIP, dstIP, Action, http_method, matched_string, response_code, URL, user_agent, waf_mode
| sort - count
```

| _time               | srcIP        | dstIP     | Action  | Method | Matched String | Response | URL    | WAF Mode   | Count |
| ------------------- | ------------ | --------- | ------- | ------ | -------------- | -------: | ------ | ---------- | ----: |
| 2024-12-25 05:06:00 | 91.194.84.10 | 10.0.2.32 | Blocked | GET    | `/index.php`   |      401 | /login | Monitoring |    59 |
| 2024-12-25 05:06:00 | 91.194.84.10 | 10.0.2.32 | Allowed | GET    | `/index.php`   |      200 | /login | Monitoring |     4 |

**Analysis Note:** Most requests were blocked or unauthorized, but **4 HTTP 200 responses** require review to confirm whether they were normal page loads or meaningful successful access.

## MITRE ATT&CK Mapping

| Tactic         | Technique                  | ID        | Reason                                                                                |
| -------------- | -------------------------- | --------- | ------------------------------------------------------------------------------------- |
| Impact         | Endpoint Denial of Service | T1499     | Repeated HTTP requests targeted a web service endpoint                                |
| Impact         | Service Exhaustion Flood   | T1499.002 | HTTP flood behavior may exhaust application or web server resources                   |
| Reconnaissance | Active Scanning            | T1595     | Repeated login-page requests may indicate automated probing; compromise not confirmed |

## Analyst Assessment

**Assessment:** **True Positive — HTTP Flood / Request Burst**

The alert is valid because WAF logs show repeated HTTP requests from the same external source IP to the login endpoint. The traffic volume in the provided evidence is limited, but the pattern matches HTTP flood/request burst behavior.

This is **not confirmed service impact**. No outage, slowdown, successful authentication, or application compromise was observed from the provided logs.

## Impact Analysis

| Area            | Assessment                                                            |
| --------------- | --------------------------------------------------------------------- |
| Confidentiality | No unauthorized access observed                                       |
| Integrity       | No application modification confirmed                                 |
| Availability    | No outage or degradation reported                                     |
| Business Impact | No confirmed impact                                                   |
| Current Risk    | Medium to High due to login endpoint targeting and HTTP 200 responses |

## Recommended Actions

1. Block source IP **91.194.84.10** at firewall/IPS/WAF as per policy.
2. Move HTTP Flood detection from **Monitoring** to **Blocking** after validation.
3. Enable or tune WAF rate limiting for `/login`.
4. Review whether the **4 HTTP 200** responses indicate normal page loads or successful authenticated access.
5. Check application logs for successful login or session creation from **91.194.84.10**.
6. Review web server performance metrics around **2024-12-25 05:06**.
7. Monitor for recurrence from the same source or related hosting ranges.
8. Correlate with other web attack alerts from **91.194.84.10**.
9. Escalate only if service degradation, repeated flood activity, successful login, or application compromise is confirmed.

## Escalation Decision

**Decision:** **No SOC L2 escalation required; close after blocking and WAF rate-limit tuning.**

**Reason:** The WAF detected HTTP Flood activity, but no service outage, application slowdown, successful login, or compromise was confirmed from the reviewed evidence. Blocking and rate-limit tuning are sufficient unless recurrence or impact is observed.

## Final Ticket Closure Comment

SOC investigated ticket **CS-033 — WAF: HTTP Flood Detected**. Inbound HTTPS traffic from **91.194.84.10** to **10.0.2.32 / LinITWebServer01** targeted **it.abc.com/login** using HTTP **GET** with matched string `/index.php`. Splunk review confirmed **63 total requests**, including **59 blocked/unauthorized HTTP 401 responses** and **4 allowed HTTP 200 responses**. No successful login, service outage, application compromise, or confirmed business impact was observed. Ticket closed as **True Positive — HTTP Flood Detected / No Confirmed Service Impact**, with source IP blocking and WAF/IPS rate-limit enforcement recommended.

## Skills Demonstrated

WAF alert triage, HTTP flood investigation, Splunk aggregation review, web login endpoint analysis, source reputation assessment, MITRE ATT&CK mapping, impact analysis, escalation decision-making, and SOC ticket documentation.

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
