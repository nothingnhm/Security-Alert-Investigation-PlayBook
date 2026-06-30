# SOC Analyst Investigation Report

## Ticket Overview

| Field            | Details                                                                                                     |
| ---------------- | ----------------------------------------------------------------------------------------------------------- |
| Ticket ID        | CS-052                                                                                                     |
| Alert Name       | Email Gateway: Mass Mailing and Spam Detection                                                              |
| Ticket Status    | Closed                                                                                                      |
| Priority / SLA   | Normal / Default SLA                                                                                        |
| Created Date     | 3/10/25 6:21 PM                                                                                             |
| Closed By        | Ananda Das                                                                                                  |
| Severity         | High                                                                                                        |
| Analyst Decision | **True Positive — Phishing/Mass Mailing Campaign with User Interaction and Possible Credential Compromise** |

## Executive Summary

An email gateway alert was triggered for a mass mailing/spam campaign targeting users in the **abc.com** environment.

The initial alert involved an email sent from:

`gloria.pheco@hairbrasdnkfnsdnk.com`

to:

`anjali.chauhan@abc.com`

with the subject:

`Important: Password Expiration Notice`

The email contained a suspicious Outlook Web Access-style URL:

`https://centraltraders.ae/owa-auth.asspx/index.html`

The URL was categorized as a **Security Risk** and classified under **Phishing** and **Technology/Internet**. Reputation analysis showed that **12/92 security vendors** flagged the URL as malicious.

Further investigation identified a related email from the same sender domain with the subject:

`Action Required: Policy Update`

This related message contained the URL:

`http://ai22.hgva.net`

Proxy logs confirmed that multiple users accessed the suspicious `centraltraders.ae` phishing URL. GET and POST requests were observed. POST requests were identified for **Anjali Chauhan** and **Sneha Nair**, which may indicate credential or form submission.

VPN logs also showed suspicious authentication activity from source IP:

`185.220.101.40`

This IP was identified as a **Tor exit node**. VPN activity included a **successful VPN login for Sneha Nair** and failed attempts for **Anjali Chauhan** from the same suspicious source IP.

Based on the delivered phishing email, multiple user clicks, POST requests, malicious URL reputation, and suspicious VPN activity from a Tor exit node, this case is assessed as a **true positive phishing/mass mailing campaign with possible credential compromise**.

## Alert Details

| Field                     | Value                                                 |
| ------------------------- | ----------------------------------------------------- |
| Initial Alert Timestamp   | 3/9/2025 13:36                                        |
| Primary Sender            | `gloria.pheco@hairbrasdnkfnsdnk.com`         |
| Related Sender            | `sean.morgan@hairbraidingwarnerrobins.com`            |
| Sender Domain             | hairbraidingwarnerrobins.com                          |
| Initial Recipient         | `anjali.chauhan@abc.com`                              |
| Primary Subject           | Important: Password Expiration Notice                 |
| Related Subject           | Action Required: Policy Update                        |
| Initial Sender IP         | 172.67.202.253                                        |
| Email Log Sender IP       | 184.106.54.1                                          |
| Primary URL               | `https://centraltraders.ae/owa-auth.asspx/index.html` |
| Related URL               | `http://ai22.hgva.net`                                |
| Status                    | delivered                                             |
| Action                    | allowe / allowed                                      |
| Suspicious VPN Source IP  | 185.220.101.40                                        |
| VPN Source Classification | Tor Exit Node                                         |

## Affected Assets

| User           | Evidence Observed                                                       | Risk Level    |
| -------------- | ----------------------------------------------------------------------- | ------------- |
| Anjali Chauhan | Email received, URL clicked, GET/POST observed, failed VPN attempts     | High          |
| Sneha Nair     | URL clicked, GET/POST observed, successful VPN login from Tor exit node | Critical      |
| Sneha Johnson  | URL clicked, GET observed                                               | Medium        |
| Manikya Chana  | URL clicked, GET observed                                               | Medium        |
| Sonia Mehra    | URL access blocked with HTTP 403                                        | Low to Medium |

## Evidence Reviewed

### IOC Summary

| IOC Type                 | Indicator                                             |
| ------------------------ | ----------------------------------------------------- |
| Sender Email             | `gloria.pheco@hairbrasdnkfnsdnk.com`         |
| Sender Email             | `sean.morgan@hairbraidingwarnerrobins.com`            |
| Sender Domain            | hairbraidingwarnerrobins.com                          |
| Recipient                | `anjali.chauhan@abc.com`                              |
| Email Subject            | Important: Password Expiration Notice                 |
| Email Subject            | Action Required: Policy Update                        |
| Phishing URL             | `https://centraltraders.ae/owa-auth.asspx/index.html` |
| Related URL              | `http://ai22.hgva.net`                                |
| Phishing Domain          | centraltraders.ae                                     |
| Related Domain           | ai22.hgva.net                                         |
| Sender IP                | 184.106.54.1                                          |
| Initial Alert Sender IP  | 172.67.202.253                                        |
| Suspicious VPN Source IP | 185.220.101.40                                        |
| Affected User            | anjali.chauhan                                        |
| Affected User            | sneha.nair                                            |
| Affected User            | sneha johnson                                         |
| Affected User            | manikya chana                                         |
| Affected User            | sonia mehra                                           |
| Threat Type              | Phishing / Credential Harvesting / Mass Mailing       |

### Sender IP Reputation

| IP Address     | Details                                                                                                 |
| -------------- | ------------------------------------------------------------------------------------------------------- |
| 184.106.54.1   | Rackspace Hosting, `mx1.emailsrvr.com`, Data Center/Web Hosting/Transit, 4 reports, 7% abuse confidence |
| 172.67.202.253 | Cloudflare, CDN infrastructure, 3 reports, 0% abuse confidence                                          |
| 185.220.101.40 | Tor Exit Node, high-risk anonymous access source, associated with suspicious VPN activity               |

### URL Reputation

| URL                                                   | Category / Detection                                                          | Risk                                |
| ----------------------------------------------------- | ----------------------------------------------------------------------------- | ----------------------------------- |
| `https://centraltraders.ae/owa-auth.asspx/index.html` | Security Risk, Phishing, Technology/Internet, 12/92 vendors flagged malicious | Possible credential harvesting page |
| `http://ai22.hgva.net`                                | Related suspicious campaign URL, email action blocked/deferred                | Suspicious related URL              |

## SIEM / Splunk Analysis

### Investigation Flow

#### 1. Alert Review

The alert was reviewed as a mass mailing/spam detection event with phishing indicators. The subject **Important: Password Expiration Notice** is commonly used in credential phishing campaigns because it creates urgency and pushes the user to verify or update credentials.

Key suspicious indicators:

| Indicator       | Observation                            |
| --------------- | -------------------------------------- |
| Sender Domain   | hairbraidingwarnerrobins.com           |
| Subject Theme   | Password expiration                    |
| URL Path        | `/owa-auth.asspx/index.html`           |
| URL Style       | Fake OWA/authentication-themed path    |
| Email Delivery  | Delivered and allowed                  |
| URL Reputation  | 12/92 vendors flagged malicious        |
| User Activity   | Multiple users accessed the URL        |
| VPN Correlation | Suspicious activity from Tor exit node |

#### 2. Email Delivery Review

The initial email gateway alert confirmed delivery to **Anjali Chauhan**. Splunk email logs also identified a related email from the same sender domain.

```spl id="cs0233_email_query"
index=main "184.106.54.1" "anjali.chauhan"
| table _time Sender SenderIP Recipient Email_Subject URL Status Action
```

```text id="cs0233_email_results"
_time	Sender	SenderIP	Recipient	Email_Subject	URL	Status	Action
2025-03-09 13:45:00	sean.morgan@hairbraidingwarnerrobins.com	184.106.54.1	anjali.chauhan@abc.com	Action Required: Policy Update	http://ai22.hgva.net	deferred	blocked
2025-03-09 13:36:00	gloria.pheco@hairbrasdnkfnsdnk.com	184.106.54.1	anjali.chauhan@abc.com	Important: Password Expiration Notice	https://centraltraders.ae/owa-auth.asspx/index.html	delivered	allowed
```

#### 3. Initial Email Gateway Alert Evidence

| Timestamp      | Sender                                        | Recipient                | Email Subject                         | Sender IP      | Status    | Action | Reason       |
| -------------- | --------------------------------------------- | ------------------------ | ------------------------------------- | -------------- | --------- | ------ | ------------ |
| 3/9/2025 13:36 | `gloria.pheco@hairbrasdnkfnsdnk.com` | `anjali.chauhan@abc.com` | Important: Password Expiration Notice | 172.67.202.253 | delivered | allowe | Not Provided |

**Evidence Note:** The initial ticket row shows sender IP **172.67.202.253**, while the Splunk email log shows **184.106.54.1** for related email events. Both were preserved as observed evidence and should be validated during deeper mail-flow review.

#### 4. Proxy Activity Review

Proxy logs confirmed that multiple users accessed the suspicious `centraltraders.ae` phishing URL.

```spl id="cs0233_proxy_query"
index=main sourcetype="proxy_logs" "centraltraders.ae"
| table _time Username "Source IP" "Destination IP" URL "HTTP Method" Action "Response Code" "Web Category"
```

### Proxy Result Summary

| User           | Action  | Method   | Response | Category | Assessment                                |
| -------------- | ------- | -------- | -------- | -------- | ----------------------------------------- |
| anjali chauhan | Allowed | GET/POST | 200      | Misc     | High risk; possible credential submission |
| sneha nair     | Allowed | GET/POST | 200      | Misc     | High risk; possible credential submission |
| sneha johnson  | Allowed | GET      | 200      | Misc     | URL clicked/accessed                      |
| manikya chana  | Allowed | GET      | 200      | Misc     | URL clicked/accessed                      |
| sonia mehra    | Blocked | GET      | 403      | Phishing | Blocked after detection improvement       |

#### 5. VPN Activity Review

VPN logs were reviewed for suspicious activity from Tor exit node **185.220.101.40**.

```spl id="cs0233_vpn_query"
index=main sourcetype="vpn_logs" (User="sneha.nair" OR User="anjali.chauhan") source_ip="185.220.101.40"
| table _time User Message source_ip session_status mfa_status authentication_method
```

### VPN Result Summary

| User           | Status           | MFA     | Observation                                     |
| -------------- | ---------------- | ------- | ----------------------------------------------- |
| sneha.nair     | Successful login | Success | Suspicious session from Tor exit node           |
| anjali.chauhan | Failed attempts  | Failed  | Possible credential abuse / brute-force attempt |

#### 6. Timeline Reconstruction

| Time               | Event                                                                               |
| ------------------ | ----------------------------------------------------------------------------------- |
| 2025-03-09 13:36   | Phishing email delivered to `anjali.chauhan@abc.com` with URL `centraltraders.ae`   |
| 2025-03-09 13:45   | Related email from same sender domain was deferred/blocked with URL `ai22.hgva.net` |
| Investigation Time | URL `centraltraders.ae` categorized as a security risk and flagged by 12/92 vendors |
| Investigation Time | Proxy logs showed multiple users clicked/accessed `centraltraders.ae`               |
| Investigation Time | GET and POST requests observed for Anjali Chauhan and Sneha Nair                    |
| Investigation Time | Sonia Mehra’s access was blocked with HTTP 403 after improved detection             |
| Investigation Time | VPN logs showed suspicious activity from Tor exit node `185.220.101.40`             |
| Investigation Time | Sneha Nair had successful VPN login with MFA success from suspicious source IP      |
| Investigation Time | Anjali Chauhan had failed VPN attempts from the same suspicious source IP           |

#### 7. Attack Chain Correlation

The evidence supports the following attack chain:

1. A password-expiration phishing email was delivered and allowed.
2. A related policy-update phishing email from the same sender domain was later blocked.
3. The phishing URL used an OWA-style path, likely designed to harvest email or corporate credentials.
4. Multiple users accessed the phishing URL.
5. POST requests were observed for Anjali Chauhan and Sneha Nair, indicating possible form submission.
6. Suspicious VPN activity followed from Tor exit node **185.220.101.40**.
7. Sneha Nair had a successful VPN login with MFA success from the Tor exit node.
8. Anjali Chauhan had failed VPN attempts from the same suspicious source.
9. This correlation raises strong concern for credential compromise or unauthorized VPN access.

## MITRE ATT&CK Mapping

| Tactic              | Technique                                 | ID        | Reason                                                        |
| ------------------- | ----------------------------------------- | --------- | ------------------------------------------------------------- |
| Initial Access      | Phishing                                  | T1566     | Phishing email was delivered to user mailbox                  |
| Initial Access      | Spearphishing Link                        | T1566.002 | Email contained credential-harvesting style URL               |
| Credential Access   | Input Capture                             | T1056     | POST requests may indicate submitted credentials or form data |
| Credential Access   | Valid Accounts                            | T1078     | VPN activity suggests possible credential use                 |
| Initial Access      | External Remote Services                  | T1133     | Corporate VPN was accessed/targeted                           |
| Defense Evasion     | Proxy                                     | T1090     | VPN source IP was identified as Tor exit node                 |
| Command and Control | Application Layer Protocol: Web Protocols | T1071.001 | Users accessed phishing infrastructure using web traffic      |

## Analyst Assessment

**Assessment:** **True Positive — Phishing/Mass Mailing Campaign with Possible Credential Compromise**

The alert is valid because a phishing email was delivered, a malicious URL was included, multiple users accessed the URL, POST requests were observed, and suspicious VPN activity from a Tor exit node was identified.

The case is especially high risk because **Sneha Nair had a successful VPN login with MFA success from 185.220.101.40**, which is identified as a Tor exit node. This should be treated as potential unauthorized access until validated.

This is not just spam. The evidence shows a phishing campaign with user interaction and identity/VPN risk.

## Impact Analysis

| Impact Area                                           | Status        |
| ----------------------------------------------------- | ------------- |
| Phishing/spam email delivered                         | Confirmed     |
| Suspicious URL delivered to user                      | Confirmed     |
| URL categorized as security risk                      | Confirmed     |
| URL flagged malicious by vendors                      | Confirmed     |
| Multiple users clicked/accessed URL                   | Confirmed     |
| POST requests observed                                | Confirmed     |
| Suspicious Tor exit node VPN activity                 | Confirmed     |
| Sneha Nair successful VPN login from suspicious IP    | Confirmed     |
| Anjali Chauhan failed VPN attempts from suspicious IP | Confirmed     |
| Later proxy blocking for Sonia Mehra                  | Confirmed     |
| Exact credentials submitted                           | Not Confirmed |
| Account takeover for Anjali Chauhan                   | Not Confirmed |
| Malware execution                                     | Not Confirmed |
| Endpoint compromise                                   | Not Confirmed |
| Data exfiltration                                     | Not Confirmed |
| Lateral movement                                      | Not Confirmed |
| Mailbox rule creation                                 | Not Confirmed |

Current impact: **High risk. Credential compromise is possible, and Sneha Nair’s successful VPN login from a Tor exit node requires immediate validation and escalation.**

## Recommended Actions

1. Escalate the case to SOC L2 / Identity Team due to successful VPN login from a Tor exit node.
2. Reset passwords for **Sneha Nair** and **Anjali Chauhan**.
3. Revoke active sessions and refresh tokens for users with POST activity or suspicious VPN activity.
4. Review VPN logs for **Sneha Nair** and confirm whether the Tor exit node login was authorized.
5. Review VPN logs for **Anjali Chauhan** and validate failed login attempts from the same source IP.
6. Review MFA logs for Sneha Nair and Anjali Chauhan.
7. Check mailbox forwarding rules and inbox rules for impacted users.
8. Contact all affected users and confirm whether credentials, OTP, or MFA details were entered.
9. Remove/quarantine phishing emails from all mailboxes.
10. Search for additional recipients of the same sender, subject, sender domain, and URLs.
11. Block `hairbraidingwarnerrobins.com` in the email gateway if no business requirement exists.
12. Block `gloria.pheco@hairbrasdnkfnsdnk.com` and `sean.morgan@hairbraidingwarnerrobins.com`.
13. Block `centraltraders.ae` and `ai22.hgva.net` in proxy/SWG and DNS security.
14. Block `185.220.101.40` in VPN, firewall, and IPS controls.
15. Block `184.106.54.1` and `172.67.202.253` only if policy allows and business impact is reviewed.
16. Add all IOCs and affected users to SIEM watchlist.
17. Review endpoint/browser activity for users with GET/POST activity.
18. Monitor all impacted users for **2–3 days** after containment.

## Escalation Decision

**Decision:** **Escalate to SOC L2 / Identity Team.**

**Reason:** This case involves confirmed phishing delivery, multiple user interactions, POST requests, and suspicious VPN activity from a Tor exit node. Sneha Nair’s successful VPN login from **185.220.101.40** significantly increases the risk of account compromise.

Escalation is required because:

| Reason                              | Evidence                                                   |
| ----------------------------------- | ---------------------------------------------------------- |
| Multiple users clicked phishing URL | Proxy logs show multiple GET events                        |
| Possible credential submission      | POST requests observed for Anjali Chauhan and Sneha Nair   |
| Suspicious VPN source               | 185.220.101.40 identified as Tor exit node                 |
| Successful VPN login                | Sneha Nair had successful VPN login with MFA success       |
| Failed VPN attempts                 | Anjali Chauhan had failed attempts from same suspicious IP |
| Malicious URL reputation            | centraltraders.ae flagged by 12/92 vendors                 |

## Final Ticket Closure Comment

SOC investigated ticket **CS-052 — Email Gateway: Mass Mailing and Spam Detection**. The campaign used password-expiration and policy-update themes to target users. The primary phishing email was sent from `gloria.pheco@hairbrasdnkfnsdnk.com` to `anjali.chauhan@abc.com` with subject **Important: Password Expiration Notice** and included the phishing URL `https://centraltraders.ae/owa-auth.asspx/index.html`. The URL was categorized as a security risk and flagged by **12/92 vendors** as malicious. A related blocked email from `sean.morgan@hairbraidingwarnerrobins.com` contained `http://ai22.hgva.net`. Proxy logs confirmed multiple users accessed the suspicious URL, including GET and POST requests. POST requests were observed for **Anjali Chauhan** and **Sneha Nair**, indicating possible credential submission. VPN logs showed suspicious activity from Tor exit node `185.220.101.40`, including a successful VPN login for **Sneha Nair** and failed attempts for **Anjali Chauhan**. Ticket closed as **True Positive — Phishing/Mass Mailing Campaign with Possible Credential Compromise**, with password resets, session revocation, IOC blocking, mailbox cleanup, SOC L2/Identity escalation, and 2–3 days of monitoring recommended.

## Skills Demonstrated

Email gateway alert triage, mass mailing investigation, phishing campaign analysis, suspicious URL review, proxy log correlation, POST request interpretation, VPN authentication investigation, Tor exit node risk analysis, credential compromise assessment, IOC extraction, MITRE ATT&CK mapping, impact validation, containment planning, escalation decision-making, and SOC ticket documentation.

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
