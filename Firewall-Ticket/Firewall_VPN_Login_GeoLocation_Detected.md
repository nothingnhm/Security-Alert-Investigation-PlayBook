# SOC Analyst Investigation Report

## Ticket Overview

| Field                | Details                                         |
| -------------------- | ----------------------------------------------- |
| Ticket ID            | CS-012                                          |
| Alert Name           | Firewall: VPN Login GeoLocation Detected        |
| Ticket Status        | Not Provided                                    |
| Priority / SLA       | Not Provided                                    |
| Recommended Severity | Medium                                          |
| Analyst Decision     | **Needs Escalation — User Validation Required** |

## Executive Summary

A firewall alert was triggered for **VPN Login GeoLocation Detected** involving inbound VPN traffic from external source IP **201.172.173.50** to internal VPN server **10.0.2.12 / IvantiVPN01** on **4500/UDP**.

Firewall logs show the traffic was **allowed**. VPN logs show authentication was initiated for user **priya.verma**, using **Password** authentication from an **iOS / iPhone 14 Pro** device, with MFA status **Prompted**. No successful VPN login, MFA approval, internal access, endpoint compromise, or data access was confirmed from the provided evidence.

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
| Firewall Threat Name | VPN Traffic                                                                        |
| Firewall Severity    | NA                                                                                 |
| Firewall Action      | Allowed                                                                            |
| VA Field             | Geo                                                                                |
| Source Details       | Television Internacional, S.A. de C.V.; Fixed Line ISP; izzi.mx; Monterrey, Mexico |
| Abuse Confidence     | 100%                                                                               |

## Affected Assets

| Asset Field          | Details             |
| -------------------- | ------------------- |
| Destination IP       | 10.0.2.12           |
| Hostname             | IvantiVPN01         |
| Operating System     | Windows Server 2022 |
| Asset Role           | VPN Server          |
| User                 | priya.verma         |
| Department           | Finance             |
| Device               | iOS / iPhone 14 Pro |
| Endpoint             | ENDP-053            |
| Business Criticality | Not Provided        |

## Evidence Reviewed

| Evidence Source          | Observation                                                       |
| ------------------------ | ----------------------------------------------------------------- |
| Firewall Logs            | Inbound VPN traffic from **201.172.173.50** to **10.0.2.12:4500** |
| Firewall Action          | **Allowed**                                                       |
| VPN Logs                 | Authentication initiated for **priya.verma**                      |
| VPN Realm                | Corporate_VPN                                                     |
| Authentication Method    | Password                                                          |
| MFA Status               | Prompted                                                          |
| Successful VPN Login     | Not Observed                                                      |
| MFA Approval             | Not Observed                                                      |
| Internal Access Evidence | Not Observed                                                      |
| Endpoint/EDR Evidence    | Not Provided                                                      |

## SIEM / Splunk Analysis

```spl id="x21r8m"
index=main srcIP="201.172.173.50" dstIP="10.0.2.12" dstPort=4500 sourcetype="firewall_logs"
| table _time, srcIP, VA, dstIP, srcPort, dstPort, Threat_Name, Severity, Action, Protocol, Direction
| dedup dstIP
```

| _time               | srcIP          | VA           | dstIP     | srcPort | dstPort | Threat_Name | Severity | Action  | Protocol | Direction |
| ------------------- | -------------- | ------------ | --------- | ------: | ------: | ----------- | -------- | ------- | -------- | --------- |
| 2025-02-08 08:34:00 | 201.172.173.50 | Not Provided | 10.0.2.12 |   25113 |    4500 | NA          | NA       | allowed | udp      | Inbound   |

```spl id="ay8g3p"
index=main sourcetype="vpn_logs" "201.172.173.50"
| table source_ip destination_ip user alert_status authentication_method device_type mfa_status Message Realm Hostname
| dedup source_ip
```

| source_ip      | destination_ip | user        | alert_status | authentication_method | device_type | mfa_status | Realm         | Hostname      |
| -------------- | -------------- | ----------- | ------------ | --------------------- | ----------- | ---------- | ------------- | ------------- |
| 201.172.173.50 | 10.0.2.12      | priya.verma | suspicious   | Password              | iOS         | Prompted   | Corporate_VPN | iPhone 14 Pro |

## MITRE ATT&CK Mapping

| Tactic            | Technique                                      | ID    | Reason                                                                                          |
| ----------------- | ---------------------------------------------- | ----- | ----------------------------------------------------------------------------------------------- |
| Initial Access    | Valid Accounts                                 | T1078 | VPN authentication was initiated for a valid user account                                       |
| Initial Access    | External Remote Services                       | T1133 | Attempt involved external VPN access to corporate remote access infrastructure                  |
| Credential Access | Brute Force / Credential Stuffing              | T1110 | Password-based authentication attempt from unusual geolocation; credential misuse not confirmed |
| Defense Evasion   | Multi-Factor Authentication Request Generation | T1621 | MFA was prompted; MFA fatigue/abuse is possible but not confirmed                               |

## Analyst Assessment

**Assessment:** **Needs Escalation — User Validation Required**

The activity is suspicious due to unusual geolocation, high source abuse confidence, VPN access targeting, password-based authentication, and MFA prompt generation. However, the evidence only confirms **authentication initiated**, not successful VPN login.

This is **not confirmed account compromise** based on the provided logs. User validation and VPN authentication result review are required before closure.

## Impact Analysis

| Area            | Assessment                                               |
| --------------- | -------------------------------------------------------- |
| Confidentiality | No data access observed                                  |
| Integrity       | No unauthorized modification observed                    |
| Availability    | No service disruption reported                           |
| Business Impact | Potentially high if Finance account VPN access succeeded |
| Current Risk    | Medium; successful login and MFA approval not confirmed  |

## Recommended Actions

1. Validate whether VPN authentication succeeded or failed.
2. Confirm whether MFA was approved, denied, or timed out.
3. Contact **priya.verma** to confirm travel/location and device ownership.
4. Review VPN session logs for session start/end time and internal resource access.
5. Review authentication logs for impossible travel, repeated attempts, and new-device activity.
6. Check mailbox activity for suspicious inbox rules, forwarding, or sent emails.
7. Review endpoint **ENDP-053** for EDR alerts or phishing indicators.
8. If user denies the activity, reset password, revoke sessions, and require MFA re-registration.
9. Escalate to SOC L2 if successful login, unexpected MFA approval, user denial, or suspicious post-login activity is confirmed.

## Escalation Decision

**Decision:** **User validation required; escalate only if suspicious activity is confirmed.**

**Reason:** Firewall and VPN logs confirm suspicious VPN authentication activity, but do not confirm successful login, MFA approval, compromise, or internal access. The ticket should remain under review until user confirmation and VPN authentication status are validated.

## Final Ticket Closure Comment

SOC investigated ticket **CS-012 — Firewall: VPN Login GeoLocation Detected**. Firewall logs show inbound VPN traffic from **201.172.173.50** to **10.0.2.12 / IvantiVPN01** on **4500/UDP**, with action **allowed**. VPN logs show authentication initiated for user **priya.verma** from an **iOS / iPhone 14 Pro** device, with MFA status **Prompted**. No successful VPN login, MFA approval, internal access, endpoint compromise, or data access was confirmed from the provided evidence. User validation and VPN authentication result review are required before final closure.

## Skills Demonstrated

VPN alert triage, geolocation anomaly investigation, firewall/VPN log correlation, MFA-risk analysis, user validation planning, account compromise assessment, MITRE ATT&CK mapping, impact analysis, escalation decision-making, and SOC ticket documentation.

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
