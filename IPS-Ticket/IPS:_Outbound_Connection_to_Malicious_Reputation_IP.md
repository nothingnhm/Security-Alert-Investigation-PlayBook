# SOC Analyst Investigation Report

## Ticket Overview

| Field            | Details                                             |
| ---------------- | --------------------------------------------------- |
| Ticket ID        | CS-023                                              |
| Alert Name       | IPS: Outbound Connection to Malicious Reputation IP |
| Ticket Status    | In Progress                                         |
| Priority / SLA   | Low / Default SLA                                   |
| Created Date     | 3/2/25 7:45 PM                                      |
| Assigned To      | Ananda Das / SOC Team                               |
| Analyst Decision | **Needs Escalation — User Validation Required**     |

## Executive Summary

An IPS alert was reviewed for **Outbound Connection to Malicious Reputation IP** involving VPN-related traffic between external IP **186.23.212.74** and internal VPN infrastructure. Firewall/IPS logs showed **allowed UDP VPN traffic** on port **4500**.

VPN logs identified authentication activity for user **rahul.joshi** in realm **Corporate_VPN**. Authentication was initiated using **Password**, MFA was triggered, OTP was sent, and MFA failed due to **incorrect OTP**. No successful VPN session was confirmed.

The source IP has **100% abuse confidence** and is associated with **Telecentro S.A.** in Argentina. Because authentication reached the MFA stage, possible credential exposure cannot be ruled out until user validation is completed.

## Alert Details

| Field                            | Value                                                                |
| -------------------------------- | -------------------------------------------------------------------- |
| Receive Time                     | 2/23/2025 08:29 AM                                                   |
| External IP                      | 186.23.212.74                                                        |
| Source Port                      | 43678                                                                |
| Internal IP in Firewall/IPS Logs | 10.0.2.13                                                            |
| VPN Destination in VPN Logs      | 10.0.2.12                                                            |
| Destination Port                 | 4500                                                                 |
| Service                          | VPN / IPsec NAT-T                                                    |
| Protocol                         | UDP                                                                  |
| Threat Name                      | VPN Traffic                                                          |
| Severity                         | NA                                                                   |
| Recommended Severity             | High                                                                 |
| Firewall Action                  | Allowed                                                              |
| IPS Action                       | Allowed                                                              |
| Source Reputation                | 100% abuse confidence                                                |
| Source Details                   | Telecentro S.A.; AS27747; telecentro.com.ar; Buenos Aires, Argentina |

## Affected Assets

| Asset Field    | Details                                                  |
| -------------- | -------------------------------------------------------- |
| Internal IP    | 10.0.2.13 / 10.0.2.12                                    |
| Asset Role     | VPN Infrastructure                                       |
| Hostname       | Not Provided                                             |
| User           | rahul.joshi                                              |
| Full Name      | Rahul Joshi                                              |
| Department     | Marketing Department                                     |
| Role           | Marketing Coordinator                                    |
| Endpoint       | ENDP-084                                                 |
| Endpoint OS    | Windows 11-64                                            |
| Validation Gap | Asset mapping mismatch between firewall/IPS and VPN logs |

## Evidence Reviewed

| Evidence Source          | Observation                                  |
| ------------------------ | -------------------------------------------- |
| Firewall Logs            | Inbound and outbound VPN traffic allowed     |
| IPS Logs                 | VPN traffic allowed                          |
| VPN Logs                 | Authentication initiated for **rahul.joshi** |
| MFA Logs                 | OTP sent; MFA failed due to incorrect OTP    |
| Session Status           | No successful VPN session confirmed          |
| Source Reputation        | Malicious reputation / 100% abuse confidence |
| Endpoint/EDR Evidence    | Not Provided                                 |
| Internal Access Evidence | Not Observed                                 |
| Confirmed Compromise     | Not Observed                                 |

## SIEM / Splunk Analysis

```spl
index=main "186.23.212.74" "10.0.2.13"
| table _time sourcetype Action srcIP dstIP dstPort Threat_Name Severity Direction
```

| sourcetype    | Action  | srcIP         | dstIP         | dstPort | Threat_Name | Direction |
| ------------- | ------- | ------------- | ------------- | ------: | ----------- | --------- |
| IPS_logs      | allowed | 10.0.2.13     | 186.23.212.74 |   43678 | VPN Traffic | Outbound  |
| IPS_logs      | allowed | 186.23.212.74 | 10.0.2.13     |    4500 | VPN Traffic | Inbound   |
| firewall_logs | allowed | 10.0.2.13     | 186.23.212.74 |   43678 | NA          | Outbound  |
| firewall_logs | allowed | 186.23.212.74 | 10.0.2.13     |    4500 | NA          | Inbound   |

```spl
index=main "186.23.212.74" sourcetype="vpn_logs"
| table _time, source_ip, destination_ip, alert_status, authentication_method, disconnect_reason, Message, mfa_status, session_status, user, device_type, realm
```

| Event                    | User        | MFA Status | Session Status           | Result                |
| ------------------------ | ----------- | ---------- | ------------------------ | --------------------- |
| Authentication initiated | rahul.joshi | Prompted   | Authentication initiated | Suspicious            |
| MFA challenge            | rahul.joshi | OTP Sent   | Pending Authentication   | Normal                |
| MFA failed               | rahul.joshi | Failed     | None                     | Incorrect OTP entered |

## MITRE ATT&CK Mapping

| Tactic            | Technique                                      | ID    | Reason                                                                                   |
| ----------------- | ---------------------------------------------- | ----- | ---------------------------------------------------------------------------------------- |
| Initial Access    | External Remote Services                       | T1133 | VPN authentication was initiated against remote access infrastructure                    |
| Initial Access    | Valid Accounts                                 | T1078 | Authentication attempt involved valid user **rahul.joshi**; success not confirmed        |
| Credential Access | Multi-Factor Authentication Request Generation | T1621 | MFA/OTP challenge was generated; approval failed                                         |
| Credential Access | Brute Force / Credential Stuffing              | T1110 | Password-based VPN attempt from malicious reputation IP; credential misuse not confirmed |

## Analyst Assessment

**Assessment:** **Needs Escalation — Suspicious VPN Authentication Attempt**

The activity is suspicious because VPN authentication was initiated from a malicious reputation IP and reached the MFA stage. The failed OTP prevented confirmed access, but reaching MFA may indicate the correct password was used.

This is **not confirmed compromise** based on the provided evidence. User validation is required before closure.

## Impact Analysis

| Area            | Assessment                                                       |
| --------------- | ---------------------------------------------------------------- |
| Confidentiality | No data access observed                                          |
| Integrity       | No unauthorized modification observed                            |
| Availability    | No service disruption reported                                   |
| Business Impact | Potentially moderate/high if user password is exposed            |
| Current Risk    | Elevated until user validation and password status are confirmed |

## Recommended Actions

1. Contact **Rahul Joshi** to confirm whether he attempted VPN login from Argentina.
2. Validate whether VPN authentication succeeded, failed, or timed out.
3. Confirm whether the user received and entered the OTP.
4. If the user denies the activity, reset password, revoke sessions, and require MFA re-registration.
5. Review endpoint **ENDP-084** for EDR alerts or phishing indicators.
6. Review mailbox activity for suspicious inbox rules, forwarding, or sent emails.
7. Block **186.23.212.74** on firewall/IPS/proxy if unauthorized.
8. Validate the asset mismatch between **10.0.2.13** and **10.0.2.12** before final closure.
9. Escalate to SOC L2 if user denial, successful VPN login, endpoint compromise, or mailbox abuse is confirmed.

## Escalation Decision

**Decision:** **User validation required; conditional SOC L2 escalation.**

**Reason:** No successful VPN session was confirmed, but authentication reached MFA from a malicious reputation IP. If Rahul Joshi denies the attempt or suspicious endpoint/mailbox activity is found, escalate to SOC L2 / Incident Response.

## Final Ticket Closure Comment

SOC investigated ticket **CS-023 — IPS: Outbound Connection to Malicious Reputation IP**. Firewall and IPS logs showed allowed VPN-related traffic involving **186.23.212.74** and internal VPN infrastructure. VPN logs confirmed authentication activity for user **rahul.joshi** in **Corporate_VPN**. MFA OTP was sent and failed due to incorrect OTP; no successful VPN session was confirmed. The source IP has **100% abuse confidence** and is associated with Telecentro S.A. in Argentina. Ticket should remain open pending user validation, VPN result confirmation, and asset mapping review. If user denies the activity, perform password reset, revoke sessions, review endpoint/mailbox activity, and escalate to SOC L2.

## Skills Demonstrated

VPN alert triage, malicious reputation IP investigation, firewall/IPS/VPN log correlation, MFA failure analysis, user validation planning, account compromise assessment, MITRE ATT&CK mapping, impact analysis, and escalation decision-making.

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
