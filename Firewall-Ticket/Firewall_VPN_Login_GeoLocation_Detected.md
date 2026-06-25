# SOC Analyst Investigation Report

## Ticket Overview

| Field            | Details                                         |
| ---------------- | ----------------------------------------------- |
| Ticket ID        | CS-012                                          |
| Alert Name       | Firewall: VPN Login GeoLocation Detected        |
| Ticket Status    | Closed                                          |
| Priority / SLA   | Normal / Medium                                 |
| Created Date     | 3/2/25 7:45 PM                                  |
| Closed By        | ananda das                                      |
| Analyst Decision | **Needs Escalation — User Validation Required** |

## Executive Summary

A firewall alert was triggered for **VPN Login GeoLocation Detected** involving inbound VPN traffic from external source IP **201.172.173.50** to internal VPN server **10.0.2.12 / IvantiVPN01** on **4500/UDP**.

Firewall logs show the traffic was **allowed** and marked with **Geo** context. VPN logs show authentication was initiated for user **priya.verma** using **Password** authentication from an **iOS / iPhone 14 Pro** device, with MFA status **Prompted**. No successful VPN login, MFA approval, internal access, endpoint compromise, or data access was confirmed from the provided evidence.

## Alert Details

| Field                | Value                                                                              |
| -------------------- | ---------------------------------------------------------------------------------- |
| Receive Time         | 2/8/2025 08:29 AM                                                                  |
| Source IP            | 201.172.173.50                                                                     |
| Source Port          | 25113                                                                              |
| Destination IP       | 10.0.2.12                                                                          |
| Destination Port     | 4500                                                                               |
| Service              | IPsec NAT-T / VPN                                                                  |
| Protocol             | UDP                                                                                |
| Direction            | Inbound                                                                            |
| Threat Name          | VPN Traffic                                                                        |
| Severity             | NA                                                                                 |
| Recommended Severity | Medium                                                                             |
| Firewall Action      | Allowed                                                                            |
| VA Field             | Geo                                                                                |
| Source Details       | Television Internacional, S.A. de C.V.; Fixed Line ISP; izzi.mx; Monterrey, Mexico |
| Abuse Confidence     | 100%                                                                               |

## Affected Assets

| Asset Field          | Details                        |
| -------------------- | ------------------------------ |
| Destination IP       | 10.0.2.12                      |
| Hostname             | IvantiVPN01                    |
| Operating System     | Windows Server 2022            |
| Asset Role           | VPN Server                     |
| User                 | priya.verma                    |
| Department           | Finance                        |
| Role                 | Accounts Receivable Specialist |
| Device               | iOS / iPhone 14 Pro            |
| Endpoint             | ENDP-053                       |
| Business Criticality | Not Provided                   |

## Evidence Reviewed

| Evidence Source          | Observation                                                       |
| ------------------------ | ----------------------------------------------------------------- |
| Firewall Logs            | Inbound VPN traffic from **201.172.173.50** to **10.0.2.12:4500** |
| Firewall Action          | **Allowed**                                                       |
| VPN Logs                 | Authentication initiated for **priya.verma**                      |
| VPN Realm                | Corporate_VPN                                                     |
| Authentication Method    | Password                                                          |
| MFA Status               | Prompted                                                          |
| Alert Status             | Suspicious                                                        |
| Successful VPN Login     | Not Observed                                                      |
| MFA Approval             | Not Observed                                                      |
| Internal Access Evidence | Not Observed                                                      |
| Endpoint/EDR Evidence    | Not Provided                                                      |

## SIEM / Splunk Analysis

```spl id="dyw8hc"
index=main srcIP="201.172.173.50" dstIP="10.0.2.12" dstPort=4500 sourcetype="firewall_logs"
| table _time, srcIP, VA, dstIP, srcPort, dstPort, Threat_Name, Severity, Action, Protocol, Direction
| dedup dstIP
```

| _time               | srcIP          | VA           | dstIP     | srcPort | dstPort | Threat_Name | Severity | Action  | Protocol | Direction |
| ------------------- | -------------- | ------------ | --------- | ------: | ------: | ----------- | -------- | ------- | -------- | --------- |
| 2025-02-08 08:34:00 | 201.172.173.50 | Not Provided | 10.0.2.12 |   25113 |    4500 | NA          | NA       | allowed | udp      | Inbound   |

```spl id="svzql9"
index=main sourcetype="vpn_logs" "201.172.173.50"
| table source_ip destination_ip user alert_status authentication_method device_type mfa_status Message Realm Hostname
| dedup source_ip
```

| source_ip      | destination_ip | user        | alert_status | authentication_method | device_type | mfa_status | Realm         | Hostname      |
| -------------- | -------------- | ----------- | ------------ | --------------------- | ----------- | ---------- | ------------- | ------------- |
| 201.172.173.50 | 10.0.2.12      | priya.verma | suspicious   | Password              | iOS         | Prompted   | Corporate_VPN | iPhone 14 Pro |

## MITRE ATT&CK Mapping

| Tactic            | Technique                                      | ID    | Reason                                                                                     |
| ----------------- | ---------------------------------------------- | ----- | ------------------------------------------------------------------------------------------ |
| Initial Access    | External Remote Services                       | T1133 | VPN authentication was initiated against corporate remote access infrastructure            |
| Initial Access    | Valid Accounts                                 | T1078 | Authentication attempt involved a valid user account; success not confirmed                |
| Credential Access | Brute Force / Credential Stuffing              | T1110 | Password-based VPN login attempt from unusual geolocation; credential misuse not confirmed |
| Credential Access | Multi-Factor Authentication Request Generation | T1621 | MFA prompt was generated; approval or MFA abuse not confirmed                              |

## Analyst Assessment

**Assessment:** **Needs Escalation — User Validation Required**

The activity is suspicious due to VPN geolocation context, high source abuse confidence, password-based authentication, MFA prompt generation, and involvement of a Finance user account. However, the logs only confirm **authentication initiated**, not successful login.

This is **not confirmed account compromise** based on the provided evidence. User validation and VPN authentication status review are required before final benign or malicious closure.

## Impact Analysis

| Area            | Assessment                                              |
| --------------- | ------------------------------------------------------- |
| Confidentiality | No data access observed                                 |
| Integrity       | No unauthorized modification observed                   |
| Availability    | No service disruption reported                          |
| Business Impact | Potentially high if Finance VPN access succeeded        |
| Current Risk    | Medium; successful login and MFA approval not confirmed |

## Recommended Actions

1. Validate whether VPN authentication succeeded, failed, or timed out.
2. Confirm whether MFA was approved, denied, or ignored.
3. Contact **priya.verma** to validate travel/location and device ownership.
4. Review VPN session logs for session start time, duration, and internal access.
5. Check authentication logs for impossible travel, repeated attempts, and new-device activity.
6. Review mailbox activity for suspicious inbox rules, forwarding rules, or sent emails.
7. Review endpoint **ENDP-053** for EDR alerts or phishing indicators.
8. Reset password, revoke sessions, and require MFA re-registration if user denies the activity.
9. Escalate to SOC L2 if successful login, unexpected MFA approval, user denial, or suspicious post-login activity is confirmed.

## Escalation Decision

**Decision:** **User validation required; escalate if suspicious activity is confirmed.**

**Reason:** Firewall and VPN logs confirm suspicious VPN authentication activity, but do not confirm successful VPN login, MFA approval, compromise, or internal access. The ticket should not be closed as benign unless user confirmation and VPN authentication status are validated.

## Final Ticket Closure Comment

SOC investigated ticket **CS-012— Firewall: VPN Login GeoLocation Detected**. Firewall logs show inbound VPN traffic from **201.172.173.50** to **10.0.2.12 / IvantiVPN01** on **4500/UDP**, with action **allowed** and geolocation context observed. VPN logs show authentication initiated for **priya.verma** from an **iOS / iPhone 14 Pro** device, with MFA status **Prompted**. No successful VPN login, MFA approval, internal access, endpoint compromise, or data access was confirmed from the provided evidence. User validation and VPN authentication result review are required; escalate if the user denies the activity or if successful login/MFA approval is confirmed.

## Skills Demonstrated

VPN alert triage, geolocation anomaly analysis, firewall/VPN log correlation, MFA-risk assessment, user validation planning, account compromise investigation, MITRE ATT&CK mapping, impact analysis, escalation decision-making, and SOC ticket documentation.


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
