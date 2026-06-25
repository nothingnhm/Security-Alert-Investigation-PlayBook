# SOC Analyst Investigation Report

## Ticket Overview

| Field            | Details                                   |
| ---------------- | ----------------------------------------- |
| Ticket ID        | CS-024                                    |
| Alert Name       | WAF: Directory Traversal                  |
| Ticket Status    | Closed                                    |
| Priority / SLA   | High / Default SLA                        |
| Created Date     | 3/2/25 7:45 PM                            |
| Closed By        | Ananda Das                                |
| Analyst Decision | **True Positive — Denied/Blocked by WAF** |

## Executive Summary

A WAF alert was triggered for **Directory Traversal** involving inbound HTTPS traffic from external source IP **45.227.255.2** to internal web server **10.0.2.32 / LinITWebServer01** on **443/TCP**.

The initial event targeted **it.cybersecxperts.com/admin** with a traversal payload attempting to access `/etc/passwd`. The initial action showed **Allowed** while WAF mode was **Monitoring**, but the response code was **403**. Later reviewed WAF logs showed repeated traversal attempts from the same source were **Blocked** in **Blocking** mode with HTTP **403**.

No successful file disclosure, unauthorized file access, web server compromise, or service impact was confirmed from the provided evidence.

## Alert Details

| Field                  | Value                                                                                                    |
| ---------------------- | -------------------------------------------------------------------------------------------------------- |
| Receive Time           | 12/27/2024 05:06                                                                                         |
| Source IP              | 45.227.255.2                                                                                             |
| Source Port            | 43544                                                                                                    |
| Destination IP         | 10.0.2.32                                                                                                |
| Destination Port       | 443                                                                                                      |
| Site Name              | it.cybersecxperts.com                                                                                    |
| Initial URL            | /admin                                                                                                   |
| Initial Matched String | `../../../../../etc/passwd`                                                                              |
| Threat Name            | Directory Traversal                                                                                      |
| Severity               | High                                                                                                     |
| Initial Action         | Allowed                                                                                                  |
| Later WAF Action       | Blocked                                                                                                  |
| Response Code          | 403                                                                                                      |
| WAF Mode               | Monitoring / Blocking                                                                                    |
| Source Reputation      | 100% abuse confidence                                                                                    |
| Source Details         | Okpay Investment Company; Data Center/Web Hosting/Transit; AS43350; web4net.org; Roosendaal, Netherlands |

## Affected Assets

| Asset Field          | Details                                                 |
| -------------------- | ------------------------------------------------------- |
| Destination IP       | 10.0.2.32                                               |
| Hostname             | LinITWebServer01                                        |
| Operating System     | Linux - RHEL 8                                          |
| Platform             | Linux                                                   |
| Asset Role           | Web Server                                              |
| Hosting              | AWS Cloud                                               |
| Business Criticality | Not Provided                                            |
| Exposure Concern     | Public web application targeted with traversal payloads |

## Evidence Reviewed

| Evidence Source            | Observation                                                 |
| -------------------------- | ----------------------------------------------------------- |
| WAF Alert                  | Directory traversal detected against `/admin`               |
| Initial Payload            | `../../../../../etc/passwd`                                 |
| Additional Payloads        | Encoded `/etc/passwd` traversal and `/../../../../boot.ini` |
| Affected URLs              | `/admin`, `/login`, `/products`, `/search`, `/api`          |
| HTTP Methods               | GET, POST, PUT                                              |
| WAF Response               | HTTP **403**                                                |
| Successful File Disclosure | Not Observed                                                |
| Host Compromise            | Not Observed                                                |
| Service Impact             | Not Provided                                                |

## SIEM / Splunk Analysis

```spl
index=main sourcetype="waf_logs" "45.227.255.2" "10.0.2.32" Threat_Name="Directory Traversal"
| table _time, srcIP, dstIP, Action, http_method, response_code, Severity, Threat_Name, URL, waf_mode, matched_string, user_agent
| sort - _time
```

| Observation                 | Result                                |
| --------------------------- | ------------------------------------- |
| Repeated traversal attempts | Observed                              |
| WAF blocking status         | Later events blocked in Blocking mode |
| Response code               | 403                                   |
| Sensitive file access       | Not confirmed                         |
| Successful compromise       | Not observed                          |

**Analysis Note:** The initial event showed **Allowed** while the WAF was in **Monitoring** mode; however, the response code was still **403**. Later events show enforcement in **Blocking** mode.

## MITRE ATT&CK Mapping

| Tactic         | Technique                         | ID    | Reason                                                                    |
| -------------- | --------------------------------- | ----- | ------------------------------------------------------------------------- |
| Initial Access | Exploit Public-Facing Application | T1190 | Traversal payloads targeted a public-facing web application               |
| Discovery      | File and Directory Discovery      | T1083 | Payloads attempted access to sensitive system files such as `/etc/passwd` |
| Collection     | Data from Local System            | T1005 | Attempted file retrieval could expose local system data if successful     |

## Analyst Assessment

**Assessment:** **True Positive — Directory Traversal Attempt Denied/Blocked**

The alert is valid because WAF logs show repeated directory traversal payloads targeting sensitive files and multiple application paths. The source IP has high abuse reputation and appears to be probing for file disclosure weaknesses.

This is **not confirmed compromise**. The reviewed evidence shows HTTP **403** responses and later WAF blocks, with no confirmed retrieval of `/etc/passwd`, `boot.ini`, configuration files, or application secrets.

## Impact Analysis

| Area            | Assessment                                   |
| --------------- | -------------------------------------------- |
| Confidentiality | No sensitive file disclosure observed        |
| Integrity       | No file modification observed                |
| Availability    | No service disruption reported               |
| Business Impact | No confirmed impact                          |
| Current Risk    | Reduced because requests were denied/blocked |

## Recommended Actions

1. Block source IP **45.227.255.2** at the firewall as per policy.
2. Ensure WAF Directory Traversal protection remains in **Blocking** mode.
3. Add **45.227.255.2** to IPS/WAF denylist or watchlist if supported.
4. Review web server logs for any traversal payloads returning HTTP **200**.
5. Confirm no access to `/etc/passwd`, `boot.ini`, config files, backup files, or application secrets.
6. Validate whether **PUT** is required on `/login`, `/products`, `/search`, or `/api`.
7. Disable unnecessary HTTP methods and strengthen input/path validation.
8. Escalate only if successful file disclosure, HTTP 200 response, web shell activity, or host compromise indicators are observed.

## Escalation Decision

**Decision:** **No SOC L2 escalation required; close after firewall/IPS/WAF rule update.**

**Reason:** The WAF denied/blocked the traversal attempts with HTTP **403**, and no successful file disclosure, unauthorized file access, host compromise, or service impact was confirmed from the reviewed logs.

## Final Ticket Closure Comment

SOC investigated ticket **CS-024 — WAF: Directory Traversal**. Inbound HTTPS traffic from **45.227.255.2** to **10.0.2.32 / LinITWebServer01** targeted **it.cybersecxperts.com** with directory traversal payloads, including attempts to access `/etc/passwd` and `boot.ini`. The initial event showed Allowed while WAF was in Monitoring mode, but the response was HTTP **403**. Later WAF events were blocked in Blocking mode. No successful file disclosure, web application compromise, host compromise, or service impact was observed. Ticket closed as **True Positive — Denied/Blocked by WAF**, with source IP blocking and WAF/IPS rule enforcement recommended.

## Skills Demonstrated

WAF alert triage, directory traversal investigation, payload analysis, web server risk assessment, Splunk log review, source reputation validation, MITRE ATT&CK mapping, impact assessment, escalation decision-making, and SOC ticket documentation.

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
