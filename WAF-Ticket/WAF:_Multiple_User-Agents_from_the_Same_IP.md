# SOC Analyst Investigation Report

## Ticket Overview

| Field            | Details                                                  |
| ---------------- | -------------------------------------------------------- |
| Ticket ID        | CS-035                                                   |
| Alert Name       | WAF: Multiple User-Agents from the Same IP               |
| Ticket Status    | Closed                                                   |
| Priority / SLA   | Normal / Default SLA                                     |
| Created Date     | 3/2/25 7:45 PM                                           |
| Closed By        | Ananda Das                                               |
| Analyst Decision | **True Positive — Blocked by WAF / No Confirmed Impact** |

## Executive Summary

A WAF alert was triggered for **Multiple User-Agents from the Same IP** involving inbound HTTPS traffic from external source IP **13.250.46.201** to internal web server **10.0.11.10 / LinFDWebServer06** on **443/TCP**.

The initial alert showed traffic to **finance.abc.com/products** using HTTP method **GET**. The WAF action was **Blocked**. Additional Splunk evidence showed related activity from the same source to **/admin**, blocked by WAF in **Blocking** mode with HTTP response code **401**.

No successful authentication, admin access, exploitation, data exposure, application compromise, or service impact was confirmed from the provided evidence.

## Alert Details

| Field               | Value                                                                   |
| ------------------- | ----------------------------------------------------------------------- |
| Receive Time        | 2/25/2025 14:05                                                         |
| Source IP           | 13.250.46.201                                                           |
| Source Port         | 65082                                                                   |
| Destination IP      | 10.0.11.10                                                              |
| Destination Port    | 443                                                                     |
| Site Name           | finance.abc.com                                                         |
| Initial URL         | /products                                                               |
| Splunk Observed URL | /admin                                                                  |
| HTTP Method         | GET                                                                     |
| Threat Name         | Multiple User-Agents from the Same IP                                   |
| Severity            | High                                                                    |
| WAF Action          | Blocked                                                                 |
| WAF Mode            | Blocking                                                                |
| Response Code       | 401                                                                     |
| Source Details      | Amazon Data Services Singapore; AWS EC2; AS16509; amazon.com; Singapore |
| Abuse Confidence    | 100%                                                                    |

## Affected Assets

| Asset Field          | Details               |
| -------------------- | --------------------- |
| Destination IP       | 10.0.11.10            |
| Hostname             | LinFDWebServer06      |
| Operating System     | Linux - RHEL 8        |
| Platform             | Linux                 |
| Asset Role           | Web Server            |
| Hosting              | AWS Cloud             |
| Site                 | finance.abc.com       |
| Targeted Endpoints   | `/products`, `/admin` |
| Business Criticality | Not Provided          |

## Evidence Reviewed

| Evidence Source        | Observation                                              |
| ---------------------- | -------------------------------------------------------- |
| WAF Alert              | Multiple user-agent anomaly detected from same source IP |
| Initial Target         | `/products`                                              |
| Splunk Observed Target | `/admin`                                                 |
| HTTP Method            | GET                                                      |
| WAF Action             | Blocked                                                  |
| WAF Mode               | Blocking                                                 |
| Response Code          | 401                                                      |
| Successful Login       | Not Observed                                             |
| Admin Access           | Not Observed                                             |
| Exploitation           | Not Observed                                             |
| Service Impact         | Not Provided                                             |

## SIEM / Splunk Analysis

```spl id="b7j42v"
index=main "13.250.46.201" "10.0.11.10" sourcetype=waf_logs Threat_Name="Multiple User-Agents from the Same IP"
| table _time, srcIP, dstIP, Action, http_method, response_code, URL, user_agent, waf_mode
| dedup response_code
```

| _time               | srcIP         | dstIP      | Action  | Method | Response | URL    | User-Agent                                                                             | WAF Mode |
| ------------------- | ------------- | ---------- | ------- | ------ | -------: | ------ | -------------------------------------------------------------------------------------- | -------- |
| 2025-02-25 23:44:00 | 13.250.46.201 | 10.0.11.10 | Blocked | GET    |      401 | /admin | `Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/605.1.15 Safari/605.1.15` | Blocking |

**Analysis Note:** The WAF blocked the observed request and returned HTTP **401**, which supports unauthorized access being denied. The full user-agent rotation list was not provided, so the assessment is based on WAF detection, source reputation, and blocked request evidence.

## MITRE ATT&CK Mapping

| Tactic         | Technique                         | ID        | Reason                                                                     |
| -------------- | --------------------------------- | --------- | -------------------------------------------------------------------------- |
| Reconnaissance | Active Scanning                   | T1595     | User-agent anomaly from same source suggests automated probing             |
| Reconnaissance | Vulnerability Scanning            | T1595.002 | Cloud-hosted source targeted web application paths                         |
| Initial Access | Exploit Public-Facing Application | T1190     | Public web application endpoints were targeted; exploitation not confirmed |

## Analyst Assessment

**Assessment:** **True Positive — Suspicious User-Agent Anomaly Blocked**

The alert is valid because the WAF detected multiple user-agent behavior from the same source IP, which can indicate automated scanning, bot activity, evasion attempts, or scripted probing. The source IP is associated with AWS cloud infrastructure and has reported high abuse confidence.

This is **not confirmed compromise**. The reviewed request was blocked by WAF in Blocking mode and returned HTTP **401**. No successful login, admin access, exploitation, or service impact was observed.

## Impact Analysis

| Area            | Assessment                                     |
| --------------- | ---------------------------------------------- |
| Confidentiality | No data exposure observed                      |
| Integrity       | No unauthorized change confirmed               |
| Availability    | No service disruption reported                 |
| Business Impact | No confirmed impact                            |
| Current Risk    | Low to Medium because WAF blocked the activity |

## Recommended Actions

1. Block source IP **13.250.46.201** at the firewall/IPS as per policy.
2. Keep WAF multiple user-agent anomaly detection in **Blocking** mode.
3. Add the source IP to WAF denylist or watchlist if repeated activity continues.
4. Review related activity from the same source IP against **10.0.11.10**.
5. Check web logs for any HTTP **200** responses from the same source IP to sensitive paths.
6. Confirm no successful authentication or admin session was created.
7. Restrict `/admin` access to trusted IP ranges, VPN, or authenticated users only.
8. Enable rate limiting and bot protection for sensitive paths.
9. Escalate only if successful login, repeated activity after blocking, exploit payloads, HTTP 200 sensitive access, or application compromise is observed.

## Escalation Decision

**Decision:** **No SOC L2 escalation required; close after firewall/IPS block documentation.**

**Reason:** The WAF blocked the suspicious activity in Blocking mode and the request returned HTTP **401**. No successful authentication, admin access, application compromise, or service impact was confirmed from the reviewed evidence.

## Final Ticket Closure Comment

SOC investigated ticket **CS-035 — WAF: Multiple User-Agents from the Same IP**. Inbound HTTPS traffic from **13.250.46.201** to **10.0.11.10 / LinFDWebServer06** targeted **finance.abc.com**, with the initial alert showing `/products` and Splunk evidence showing `/admin`. The WAF detected multiple user-agent anomaly behavior from the same source IP, blocked the request in Blocking mode, and returned HTTP **401**. No successful login, admin access, exploitation, data exposure, application compromise, or service impact was observed. Ticket closed as **True Positive — Blocked by WAF / No Confirmed Impact**, with source IP blocking and continued WAF enforcement recommended.

## Skills Demonstrated

WAF alert triage, user-agent anomaly investigation, bot/scanner activity analysis, Splunk log review, source reputation assessment, web application risk assessment, MITRE ATT&CK mapping, impact analysis, escalation decision-making, and SOC ticket documentation.

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
