# SOC Analyst Investigation Report

## Ticket Overview

| Field            | Details                                                                             |
| ---------------- | ----------------------------------------------------------------------------------- |
| Ticket ID        | CS-043                                                                              |
| Alert Name       | Proxy: Access to Dark Web Sites Detected                                            |
| Ticket Status    | Closed                                                                              |
| Priority / SLA   | Normal / Default SLA                                                                |
| Created Date     | 3/16/25 6:00 PM                                                                     |
| Closed By        | Ananda Das                                                                          |
| Analyst Decision | **True Positive — Proxy Avoidance / Dark Web Access Attempt / No Confirmed Impact** |

## Executive Summary

A proxy alert was triggered for **Access to Dark Web Sites Detected** after user **James Jain** from internal source IP **10.1.2.37** accessed the domain **tor2web.io**.

The accessed URL was:

`http://tor2web.io`

The domain was categorized as **Proxy Avoidance** and noted as **Security Risk / Proxy Avoidance and Suspicious**. The proxy action was listed as **Allowed**, but the HTTP response code was **403**, indicating the request did not successfully load normal web content or was denied by the destination/proxy/security layer.

Email log correlation showed that the same URL was delivered to **[james.jain@abc.com](mailto:james.jain@abc.com)** from **[francis.lunar@gmail.com](mailto:francis.lunar@gmail.com)** with a suspicious package/order-themed subject. This indicates the proxy event was likely caused by a suspicious email link click or user interaction with a phishing-style message.

No malware download, credential submission, endpoint compromise, C2 callback, or data exfiltration was confirmed from the provided evidence.

## Alert Details

| Field                   | Value                                                                |
| ----------------------- | -------------------------------------------------------------------- |
| Timestamp               | 3/13/2025 21:04                                                      |
| Username                | James Jain                                                           |
| Source IP               | 10.1.2.37                                                            |
| Destination IP          | 128.31.0.39                                                          |
| URL Domain              | tor2web.io                                                           |
| URL                     | `http://tor2web.io`                                                  |
| Web Category            | Proxy Avoidance                                                      |
| Proxy Action            | Allowed                                                              |
| HTTP Method             | GET                                                                  |
| Response Code           | 403                                                                  |
| URL Risk Note           | Security Risk / Proxy Avoidance and Suspicious                       |
| Related Email Sender    | [francis.lunar@gmail.com](mailto:francis.lunar@gmail.com)            |
| Related Email Recipient | [james.jain@abc.com](mailto:james.jain@abc.com)                      |
| Related Email Subject   | Your Package Could Not Be Delivered / Order Confirmation – #INV12345 |

## Affected Entities

| Entity Type       | Details                                                   |
| ----------------- | --------------------------------------------------------- |
| User              | James Jain                                                |
| Source IP         | 10.1.2.37                                                 |
| Endpoint          | Not Provided                                              |
| Destination IP    | 128.31.0.39                                               |
| Suspicious Domain | tor2web.io                                                |
| Suspicious URL    | `http://tor2web.io`                                       |
| Web Category      | Proxy Avoidance                                           |
| Related Sender    | [francis.lunar@gmail.com](mailto:francis.lunar@gmail.com) |
| Sender IP         | 142.251.16.27                                             |
| Impact Status     | No confirmed compromise observed                          |

## Destination / Infrastructure Details

### Destination IP Reputation

| Field            | Value                                 |
| ---------------- | ------------------------------------- |
| Destination IP   | 128.31.0.39                           |
| Abuse Confidence | 7%                                    |
| ISP              | Massachusetts Institute of Technology |
| Usage Type       | University/College/School             |
| ASN              | AS38726                               |
| Hostname         | belegost.csail.mit.edu                |
| Domain           | mit.edu                               |
| Country          | United States of America              |
| City             | Boston, Massachusetts                 |

### Email Sender Infrastructure

| Field      | Value                    |
| ---------- | ------------------------ |
| Sender IP  | 142.251.16.27            |
| ISP        | Google LLC               |
| Usage Type | Content Delivery Network |
| ASN        | AS15169                  |
| Hostname   | bl-in-f27.1e100.net      |
| Domain     | google.com               |
| Country    | United States of America |
| City       | Leesburg, Virginia       |

## Investigation Flow

### 1. Alert Review

The alert was generated when proxy logs detected access to **tor2web.io**, a domain associated with proxy avoidance / Tor2Web-style access. Even though the ticket title references **Dark Web Sites**, the observed category in the log was **Proxy Avoidance**, which still represents a security and acceptable-use concern because such services may allow users to bypass normal web filtering and monitoring controls.

Key initial findings:

| Field       | Observation                              |
| ----------- | ---------------------------------------- |
| User        | James Jain                               |
| Source IP   | 10.1.2.37                                |
| Destination | tor2web.io / 128.31.0.39                 |
| Category    | Proxy Avoidance                          |
| Action      | Allowed                                  |
| Response    | 403                                      |
| Risk        | Suspicious proxy/dark-web access attempt |

### 2. Entity Identification

The user involved in the proxy event was **James Jain** from source IP **10.1.2.37**. Endpoint hostname and operating system were not provided in the available evidence.

The destination domain was **tor2web.io**, and the destination IP was **128.31.0.39**. Reputation enrichment identified the IP as associated with **MIT / mit.edu**, but the risk assessment should remain focused on the observed URL domain and category rather than broadly blocking trusted infrastructure.

### 3. Timeline Reconstruction

| Time                | Event                                                                                                                                                                        |
| ------------------- | ---------------------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| 2025-03-13 19:34:00 | Email containing `http://tor2web.io` was delivered to **[james.jain@abc.com](mailto:james.jain@abc.com)** from **[francis.lunar@gmail.com](mailto:francis.lunar@gmail.com)** |
| 2025-03-13 21:04:00 | User **James Jain** accessed `http://tor2web.io` from source IP **10.1.2.37**                                                                                                |
| 2025-03-13 21:04:00 | Proxy logged the request as **Allowed**, but the response code was **403**                                                                                                   |

### 4. Email-to-Proxy Correlation

Email log correlation is the strongest contextual evidence in this case. The suspicious URL was delivered to the user approximately **1 hour and 30 minutes before** the proxy access event.

The email subject used a package/order lure:

`Your Package Could Not Be Delivered" - "Order Confirmation – #INV12345`

This pattern is commonly used in phishing and social engineering attempts. Based on the timing and matching URL, the proxy event was likely caused by the user opening or clicking the email link.

### 5. Threat Context

The activity is suspicious because:

| Indicator                 | Why It Matters                                                                |
| ------------------------- | ----------------------------------------------------------------------------- |
| `tor2web.io`              | Associated with proxy avoidance / Tor2Web-style access                        |
| Proxy Avoidance category  | May bypass corporate filtering and monitoring                                 |
| Suspicious email delivery | Same URL was delivered to the user before access                              |
| Package/order email lure  | Common phishing theme                                                         |
| HTTP 403 response         | Suggests access was not fully successful, but user interaction still occurred |
| Corporate source IP       | Activity originated from internal network/user context                        |

### 6. Impact Validation

The available evidence does **not** confirm successful compromise.

| Impact Area               | Validation Result                    |
| ------------------------- | ------------------------------------ |
| Successful Website Access | Not confirmed; HTTP **403** observed |
| Credential Submission     | Not Observed                         |
| File Download             | Not Observed                         |
| Malware Execution         | Not Observed                         |
| Endpoint Compromise       | Not Observed                         |
| C2 Callback               | Not Observed                         |
| Data Exfiltration         | Not Observed                         |
| Business Impact           | Not Confirmed                        |

The event should not be closed as “false positive” because the user accessed a suspicious proxy avoidance URL that was delivered through email. The correct assessment is **true positive suspicious access attempt with no confirmed impact**.

## Evidence Reviewed

### Initial Proxy Alert Evidence

| Field          | Value               |
| -------------- | ------------------- |
| Timestamp      | 3/13/2025 21:04     |
| Username       | James Jain          |
| Source IP      | 10.1.2.37           |
| Destination IP | 128.31.0.39         |
| URL Domain     | tor2web.io          |
| URL            | `http://tor2web.io` |
| Web Category   | Proxy Avoidance     |
| Action         | Allowed             |
| HTTP Method    | GET                 |
| Response Code  | 403                 |

## SIEM / Splunk Analysis

### Splunk Query Used

```spl id="cs0252_investigation_query"
index=main "tor2web.io"
| table _time "Email_Subject" "HTTP Method" "Response Code" Sender SenderIP Recipient Username "URL" "Web Category" "User Agent" Status
```

### Full Unique Splunk Log Results

```text id="cs0252_splunk_results"
_time	Email_Subject	HTTP Method	Response Code	Sender	SenderIP	Recipient	Username	URL	Web Category	User Agent	Status
2025-03-13 21:04:00		GET	403				James Jain	http://tor2web.io	Proxy Avoidance	Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/123.0.0.0 Safari/537.36	
2025-03-13 19:34:00	Your Package Could Not Be Delivered" - "Order Confirmation – #INV12345			francis.lunar@gmail.com	142.251.16.27	james.jain@abc.com		http://tor2web.io			delivered
```

### Evidence Interpretation

| Observation                                | Analyst Interpretation                                |
| ------------------------------------------ | ----------------------------------------------------- |
| Proxy event shows `GET http://tor2web.io`  | User attempted to access the suspicious URL           |
| Response code was **403**                  | Successful content access was not confirmed           |
| Email log shows same URL delivered earlier | Likely phishing/social engineering source             |
| Email status was **delivered**             | The suspicious email reached the user mailbox         |
| User-agent shows Chrome on Windows         | Browser-based access from user endpoint               |
| No file/hash/process evidence provided     | No confirmed malware execution or endpoint compromise |

## MITRE ATT&CK Mapping

| Tactic              | Technique                                 | ID        | Reason                                                                            |
| ------------------- | ----------------------------------------- | --------- | --------------------------------------------------------------------------------- |
| Initial Access      | Phishing                                  | T1566     | Suspicious URL was delivered to the user through email                            |
| Initial Access      | Spearphishing Link                        | T1566.002 | Email contained a link that the user later accessed                               |
| Command and Control | Proxy                                     | T1090     | Tor2Web/proxy avoidance service may proxy traffic; actual proxy use not confirmed |
| Command and Control | Application Layer Protocol: Web Protocols | T1071.001 | HTTP web request to suspicious external infrastructure was observed               |

## Analyst Assessment

**Assessment:** **True Positive — Suspicious Proxy Avoidance / Dark Web Access Attempt**

The alert is valid because the user accessed **tor2web.io**, which was categorized as **Proxy Avoidance** and marked as suspicious. Email correlation shows the same URL was delivered to the user through a suspicious package/order-themed email before the proxy event.

This is **not confirmed compromise**. The request returned HTTP **403**, and no malware download, credential submission, browser exploitation, C2 callback, endpoint compromise, or data exfiltration was identified from the available logs.

## Impact Analysis

| Area             | Assessment                                                              |
| ---------------- | ----------------------------------------------------------------------- |
| Confidentiality  | No credential submission or data exposure confirmed                     |
| Integrity        | No endpoint modification confirmed                                      |
| Availability     | No service impact reported                                              |
| Policy Impact    | Access attempt to proxy avoidance / dark-web-related service            |
| Current Risk     | Medium due to suspicious email correlation and proxy avoidance category |
| Confirmed Impact | No confirmed compromise observed                                        |

## User Validation Required

SOC should contact **James Jain** and confirm:

1. Did the user receive and open the email from **[francis.lunar@gmail.com](mailto:francis.lunar@gmail.com)**?
2. Did the user click the `http://tor2web.io` link?
3. Was the click intentional, accidental, or caused by email preview/security scanning?
4. Did the page show a block/error page?
5. Did the user enter any credentials, OTP, MFA code, or personal information?
6. Did the user download or open any file?
7. Did any file automatically download?
8. Did the browser show pop-ups, redirects, or suspicious behavior?
9. Was this activity part of approved security testing?
10. Does the email still exist in the mailbox for quarantine/removal?

## Recommended Actions

1. Contact **James Jain** for user validation.
2. Quarantine or remove the delivered email from **[james.jain@abc.com](mailto:james.jain@abc.com)** if still present.
3. Block `tor2web.io` in proxy/SWG.
4. Block or sinkhole `tor2web.io` in DNS security controls.
5. Block `http://tor2web.io` in the email gateway.
6. Add sender **[francis.lunar@gmail.com](mailto:francis.lunar@gmail.com)** to watchlist or blocklist if no business requirement exists.
7. Search email logs for additional recipients of the same sender, subject, or URL.
8. Search proxy logs for other users who accessed `tor2web.io`.
9. Review endpoint/browser logs for file downloads or suspicious follow-up activity.
10. Escalate only if credential entry, file download, endpoint alert, C2 callback, or repeated access is confirmed.

## Containment / Blocking Plan

| Control          | Indicator                                                 | Recommended Action                                                 |
| ---------------- | --------------------------------------------------------- | ------------------------------------------------------------------ |
| Proxy / SWG      | tor2web.io                                                | Block                                                              |
| DNS Security     | tor2web.io                                                | Sinkhole / block                                                   |
| Firewall         | 128.31.0.39                                               | Block outbound only if policy allows and no business impact exists |
| IPS              | tor2web.io / 128.31.0.39                                  | Add to watchlist/blocklist                                         |
| Email Gateway    | `http://tor2web.io`                                       | Block URL in inbound emails                                        |
| Email Gateway    | [francis.lunar@gmail.com](mailto:francis.lunar@gmail.com) | Block/quarantine if no business requirement exists                 |
| SIEM             | James Jain / 10.1.2.37 / tor2web.io                       | Add monitoring correlation                                         |
| Mailbox Response | Delivered email                                           | Remove or quarantine                                               |

**Blocking Note:** Do not globally block broad infrastructure domains such as **google.com** or **mit.edu** based on this event. Blocking should be scoped to **tor2web.io**, the suspicious URL, and destination IP only if approved by policy.

## Severity Recommendation

**Recommended Severity:** **Medium**

The event should remain Medium because the user accessed a suspicious proxy avoidance/security-risk domain that was delivered via email. However, severity does not need to be raised to High because HTTP **403** was observed and no credential submission, file download, malware execution, C2 callback, or endpoint compromise was confirmed.

Raise severity to **High** if any of the following are later confirmed:

| Escalation Condition                        | Reason                              |
| ------------------------------------------- | ----------------------------------- |
| User entered credentials or OTP             | Potential credential compromise     |
| File was downloaded or opened               | Possible malware delivery           |
| EDR alert triggered                         | Endpoint compromise risk            |
| Additional users clicked the same URL       | Potential phishing campaign         |
| C2 or suspicious outbound traffic observed  | Possible compromise                 |
| Repeated proxy avoidance activity continues | Policy/security control bypass risk |

## Escalation Decision

**Decision:** **No immediate SOC L2 escalation required; close after user validation, email cleanup, and IOC blocking if no impact is confirmed.**

**Reason:** The proxy and email evidence confirm suspicious activity, but the request returned HTTP **403** and no direct compromise indicators were observed.

SOC L2 escalation is required only if user validation or endpoint telemetry confirms credential entry, file download, malware execution, browser exploit behavior, C2 communication, or additional affected users.

## Final Ticket Closure Comment

SOC investigated ticket **CS-043 — Proxy: Access to Dark Web Sites Detected**. Logs show user **James Jain** from source IP **10.1.2.37** accessed **http://tor2web.io**, categorized as **Proxy Avoidance** and marked as security risk/suspicious. The proxy action was Allowed, but the request returned HTTP **403**, so successful site access was not confirmed. Email correlation showed the same URL was delivered to **[james.jain@abc.com](mailto:james.jain@abc.com)** from **[francis.lunar@gmail.com](mailto:francis.lunar@gmail.com)** with a suspicious package/order-themed subject, indicating a likely phishing-driven access attempt. No malware download, credential submission, endpoint compromise, C2 callback, or data exfiltration was identified from the provided evidence. Ticket closed as **True Positive — Proxy Avoidance / Dark Web Access Attempt / No Confirmed Impact**, with user validation, email quarantine, IOC blocking, and monitoring recommended.

## Skills Demonstrated

Proxy alert triage, dark-web/proxy avoidance investigation, phishing email correlation, timeline reconstruction, user and source IP analysis, IOC handling, Splunk log review, MITRE ATT&CK mapping, impact validation, containment planning, escalation decision-making, and SOC ticket documentation.

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
