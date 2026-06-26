# SOC Analyst Investigation Report

## Ticket Overview

| Field            | Details                                                                     |
| ---------------- | --------------------------------------------------------------------------- |
| Ticket ID        | CS-032                                                                      |
| Alert Name       | WAF: HTTP Smuggling                                                         |
| Ticket Status    | Closed                                                                      |
| Priority / SLA   | Normal / Default SLA                                                        |
| Created Date     | 3/2/25 7:45 PM                                                              |
| Closed By        | Ananda Das                                                                  |
| Analyst Decision | **True Positive — HTTP Smuggling Attempt / No Confirmed Successful Access** |

## Executive Summary

A WAF alert was triggered for **HTTP Smuggling** involving inbound HTTPS traffic from external source IP **48.207.20.146** to internal web server **10.0.11.10 / LinFDWebServer06** on **443/TCP**.

The request targeted **finance.abc.com/admin** using HTTP method **POST**. The WAF detected conflicting HTTP headers, including `Content-Length: 13` and `Transfer-Encoding: chunked`, followed by an embedded request to `GET /admin HTTP/1.1`. This pattern is consistent with an HTTP request smuggling attempt.

The WAF action was **Allowed**, WAF mode was **Monitoring**, and the application returned HTTP **302**. No successful admin access, session compromise, request queue poisoning, application compromise, or service impact was confirmed from the provided evidence.

## Alert Details

| Field            | Value                                                                                             |
| ---------------- | ------------------------------------------------------------------------------------------------- |
| Receive Time     | 2/16/2025 23:38                                                                                   |
| Source IP        | 48.207.20.146                                                                                     |
| Source Port      | 41769                                                                                             |
| Destination IP   | 10.0.11.10                                                                                        |
| Destination Port | 443                                                                                               |
| Site Name        | finance.abc.com                                                                                   |
| URL              | /admin                                                                                            |
| HTTP Method      | POST                                                                                              |
| Threat Name      | HTTP Smuggling                                                                                    |
| Severity         | High                                                                                              |
| WAF Action       | Allowed                                                                                           |
| WAF Mode         | Monitoring                                                                                        |
| Response Code    | 302                                                                                               |
| Source Details   | Microsoft Limited; Data Center/Web Hosting/Transit; AS8075; microsoft.com; Amsterdam, Netherlands |
| Abuse Confidence | 0%                                                                                                |

## Affected Assets

| Asset Field          | Details                                                              |
| -------------------- | -------------------------------------------------------------------- |
| Destination IP       | 10.0.11.10                                                           |
| Hostname             | LinFDWebServer06                                                     |
| Operating System     | Linux - RHEL 8                                                       |
| Platform             | Linux                                                                |
| Asset Role           | Web Server                                                           |
| Hosting              | AWS Cloud                                                            |
| Site                 | finance.abc.com                                                      |
| Business Criticality | Not Provided                                                         |
| Exposure Concern     | Finance web application targeted with HTTP request smuggling payload |

## Evidence Reviewed

| Evidence Source         | Observation                                         |
| ----------------------- | --------------------------------------------------- |
| WAF Alert               | HTTP Smuggling detected                             |
| Header Pattern          | `Content-Length: 13` + `Transfer-Encoding: chunked` |
| Embedded Request        | `GET /admin HTTP/1.1`                               |
| HTTP Method             | POST                                                |
| WAF Action              | Allowed                                             |
| WAF Mode                | Monitoring                                          |
| Response Code           | 302                                                 |
| Successful Admin Access | Not Observed                                        |
| Session Compromise      | Not Observed                                        |
| Service Impact          | Not Provided                                        |

## SIEM / Splunk Analysis

```spl id="rijl91"
index=main "48.207.20.146" "10.0.11.10" sourcetype=waf_logs Threat_Name="HTTP Smuggling"
| table _time, srcIP, dstIP, Action, http_method, matched_string, response_code, URL, user_agent, waf_mode
```

```text id="c4v6km"
_time	srcIP	dstIP	Action	http_method	matched_string	response_code	URL	user_agent	waf_mode
2025-02-16 23:38:00	48.207.20.146	10.0.11.10	Allowed	POST	matched_string: POST / HTTP/1.1\r\nContent-Length: 13\r\nTransfer-Encoding: chunked\r\n\r\n0\r\n\r\nGET /admin HTTP/1.1\r\nHost: finance.abc.com	302	/admin	Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/605.1.15 Safari/605.1.15	Monitoring
```

**Analysis Note:** The request was allowed by WAF monitoring mode, but the HTTP **302** response does not confirm successful access to `/admin`. No HTTP **200**, authenticated session, or post-exploitation activity was provided.

## MITRE ATT&CK Mapping

| Tactic                     | Technique                         | ID         | Reason                                                                                        |
| -------------------------- | --------------------------------- | ---------- | --------------------------------------------------------------------------------------------- |
| Initial Access             | Exploit Public-Facing Application | T1190      | HTTP smuggling payload targeted a public web application                                      |
| Defense Evasion            | Exploitation for Defense Evasion  | T1211      | Request attempted to abuse parsing differences between security controls and backend services |
| Credential Access / Impact | Not Confirmed                     | Not Mapped | No session theft, admin access, or successful impact observed                                 |

## Analyst Assessment

**Assessment:** **True Positive — HTTP Smuggling Attempt**

The alert is valid because the request contained conflicting `Content-Length` and `Transfer-Encoding` headers with an embedded `/admin` request. This is consistent with HTTP request smuggling or request desynchronization probing.

This is **not confirmed compromise**. The response code was **302**, and there is no evidence of successful admin access, backend request execution, session compromise, request queue poisoning, or application impact.

## Impact Analysis

| Area            | Assessment                                                              |
| --------------- | ----------------------------------------------------------------------- |
| Confidentiality | No data exposure observed                                               |
| Integrity       | No unauthorized application change confirmed                            |
| Availability    | No service disruption reported                                          |
| Business Impact | No confirmed impact                                                     |
| Current Risk    | Medium to High due to allowed smuggling attempt against finance web app |

## Recommended Actions

1. Block source IP **48.207.20.146** at the firewall/IPS as per policy.
2. Move WAF HTTP smuggling detection from **Monitoring** to **Blocking** after validation.
3. Add or enforce IPS/WAF signatures for CL.TE and TE.CL request smuggling patterns.
4. Review reverse proxy, load balancer, and backend server parsing behavior.
5. Reject requests containing both `Content-Length` and `Transfer-Encoding` unless safely handled.
6. Review web logs for HTTP **200** responses or successful access to `/admin` from the same source.
7. Correlate with other alerts from **48.207.20.146** against **10.0.11.10** around **2025-02-16 23:38**.
8. Escalate if admin access, session compromise, request queue poisoning, RCE, or related malicious upload activity is confirmed.

## Escalation Decision

**Decision:** **No immediate SOC L2 escalation required for this standalone event; close after control update and correlation review.**

**Reason:** The WAF detected an HTTP smuggling attempt and allowed it while in Monitoring mode, but the response was HTTP **302** and no successful admin access, session compromise, application compromise, or service impact was confirmed.

**Conditional Escalation:** Escalate to SOC L2 if related events from the same source confirm successful upload, RCE, HTTP **200** response, authenticated admin access, or backend desynchronization impact.

## Final Ticket Closure Comment

SOC investigated ticket **CS-032 — WAF: HTTP Smuggling**. Inbound HTTPS traffic from **48.207.20.146** to **10.0.11.10 / LinFDWebServer06** targeted **finance.abc.com/admin** using HTTP **POST**. The WAF detected a request smuggling pattern containing both `Content-Length: 13` and `Transfer-Encoding: chunked`, followed by an embedded `GET /admin HTTP/1.1` request. The WAF was in Monitoring mode and allowed the request, but the application returned HTTP **302**. No successful admin access, session compromise, request queue poisoning, application compromise, or service impact was observed from the provided log. Ticket closed as **True Positive — HTTP Smuggling Attempt / No Confirmed Successful Access**, with firewall/IPS source block and WAF/IPS smuggling signature enforcement recommended.

## Skills Demonstrated

WAF alert triage, HTTP request smuggling analysis, header manipulation review, Splunk log analysis, web application risk assessment, control-gap identification, MITRE ATT&CK mapping, impact assessment, escalation decision-making, and SOC ticket documentation.

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
