# SOC Analyst Investigation Report

## Ticket Overview

| Field            | Details                                                                                      |
| ---------------- | -------------------------------------------------------------------------------------------- |
| Ticket ID        | CS-039                                                                                       |
| Alert Name       | Proxy: Unusual Access to P2P Sites                                                           |
| Ticket Status    | In Progress                                                                                  |
| Priority / SLA   | Normal / Default SLA                                                                         |
| Created Date     | 3/16/25 7:22 PM                                                                              |
| Assigned To      | Ananda Das / SOC Team                                                                        |
| Analyst Decision | **True Positive — P2P Site Access and Torrent Installer Download / No Confirmed Compromise** |

## Executive Summary

A proxy alert was triggered for **Unusual Access to P2P Sites** involving access to **utorrent.com**, categorized as **Peer-to-Peer (P2P)**.

The proxy evidence shows access to:

`https://www.utorrent.com/`

The action was **Allowed**, the HTTP method was **GET**, and the response code was **200**, indicating the site was successfully accessed. Additional proxy evidence shows user **Vivek Kapoor** from source IP **10.1.2.44 / ENDP-047** downloaded the torrent installer file:

`utweb_installer.exe`

Because the user is identified as a **Financial Analyst** from the **Finance Department**, P2P/torrent software does not appear business-required from the provided evidence. This activity should be treated as a **policy violation / risky software download** until endpoint validation confirms whether the installer was executed or installed.

No malware execution, endpoint compromise, C2 callback, or data exfiltration was confirmed from the provided logs.

## Alert Details

| Field           | Value                     |
| --------------- | ------------------------- |
| Destination IP  | 203.0.22.125              |
| URL Domain      | utorrent.com              |
| URL             | https://www.utorrent.com/ |
| Web Category    | Peer-to-Peer (P2P)        |
| Proxy Action    | Allowed                   |
| HTTP Method     | GET                       |
| Response Code   | 200                       |
| Downloaded File | utweb_installer.exe       |
| User            | Vivek Kapoor              |
| Source IP       | 10.1.2.44                 |
| Endpoint        | ENDP-047                  |
| Endpoint OS     | Windows 11-64             |
| Department      | Finance Department        |
| Role            | Financial Analyst         |

## Affected Assets

| Asset Field             | Details             |
| ----------------------- | ------------------- |
| User                    | Vivek Kapoor        |
| Source IP               | 10.1.2.44           |
| Endpoint                | ENDP-047            |
| Endpoint OS             | Windows 11-64       |
| Department              | Finance Department  |
| Role                    | Financial Analyst   |
| External Destination IP | 203.0.22.125        |
| External Domain         | utorrent.com        |
| Risky File              | utweb_installer.exe |

## Evidence Reviewed

| Evidence Source   | Observation                         |
| ----------------- | ----------------------------------- |
| Proxy Alert       | Access to P2P website detected      |
| Web Category      | Peer-to-Peer (P2P)                  |
| Proxy Action      | Allowed                             |
| Response Code     | 200                                 |
| File Download     | `utweb_installer.exe` observed      |
| Referrer          | Google search and utorrent.com page |
| Malware Execution | Not Observed                        |
| EDR Alert         | Not Provided                        |
| C2 Callback       | Not Observed                        |
| Data Exfiltration | Not Observed                        |

## SIEM / Splunk Analysis

```spl id="cs0256_proxy_query"
index=main "utorrent.com" sourcetype=proxy_logs
| table _time "File Type" Referrer "HTTP Method" "Response Code" "Source IP" "Destination IP" Action "User Agent" Username "Web Category"
```

```text id="cs0256_proxy_results"
_time	File Type	Referrer	HTTP Method	Response Code	Source IP	Destination IP	Action	User Agent	Username	Web Category
2025-03-16 14:22:00	utweb_installer.exe	https://www.utorrent.com/	GET	200	10.1.2.44	203.0.22.125	Allowed	Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/123.0.0.0 Safari/537.36	Vivek Kapoor	Peer-to-Peer (P2P)
2025-03-16 14:21:00		https://www.google.com/search?q=utorrent.com&sca_esv=f981d700d01e44ab&source=	GET	200	10.1.2.44	203.0.22.125	Allowed	Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/123.0.0.0 Safari/537.36	Vivek Kapoor	Peer-to-Peer (P2P)
```

**Analysis Note:** The logs show the user first accessed the site through a Google search referrer and then downloaded **utweb_installer.exe**. Both requests were allowed and returned HTTP **200**.

## MITRE ATT&CK Mapping

| Tactic              | Technique                                 | ID        | Reason                                                                         |
| ------------------- | ----------------------------------------- | --------- | ------------------------------------------------------------------------------ |
| Initial Access      | Drive-by Compromise                       | T1189     | User accessed a risky public website that could host unwanted software         |
| Execution           | User Execution: Malicious File            | T1204.002 | Torrent installer execution would require user action; execution not confirmed |
| Command and Control | Application Layer Protocol: Web Protocols | T1071.001 | Web traffic to external infrastructure was observed; C2 not confirmed          |

## Analyst Assessment

**Assessment:** **True Positive — P2P Access and Risky Installer Download**

The alert is valid because proxy logs confirm access to a P2P website and successful download of **utweb_installer.exe**. P2P/torrent software is risky on corporate endpoints because it can introduce malware, unwanted applications, data leakage, compliance issues, and unauthorized network sharing.

This is **not confirmed compromise**. No evidence was provided showing the installer was executed, uTorrent was installed, malware was detected, company data was shared, or C2 communication occurred.

## Impact Analysis

| Area            | Assessment                                                             |
| --------------- | ---------------------------------------------------------------------- |
| Confidentiality | No data leakage confirmed                                              |
| Integrity       | No endpoint modification confirmed                                     |
| Availability    | No service impact reported                                             |
| Policy Impact   | Possible acceptable-use violation                                      |
| Current Risk    | Medium until endpoint validation confirms no execution or installation |

## Recommended Actions

1. Contact **Vivek Kapoor** to confirm why **utorrent.com** was accessed.
2. Confirm whether **utweb_installer.exe** was downloaded, opened, or executed.
3. Check endpoint **ENDP-047** for `utweb_installer.exe` in Downloads, Desktop, Temp, browser cache, and quarantine.
4. Check installed applications for uTorrent or related P2P software.
5. Review EDR/AV logs for execution, detection, or quarantine events.
6. Review outbound traffic from **10.1.2.44** for P2P connections or unknown external peers.
7. Remove/quarantine the installer if present.
8. Block **utorrent.com** in proxy/DNS security controls if company policy prohibits P2P usage.
9. Block destination IP **203.0.22.125** if no business requirement exists.
10. Escalate only if the installer was executed, P2P software was installed/used, malware was detected, company data was shared, or suspicious outbound traffic is observed.

## Escalation Decision

**Decision:** **No immediate SOC L2 escalation required; user and endpoint validation required.**

**Reason:** The logs confirm P2P site access and torrent installer download, but no malware execution, endpoint compromise, C2 callback, or data exfiltration was confirmed. SOC L2 escalation is required only if endpoint validation shows execution, installation, malware activity, data leakage, or suspicious network activity.

## Final Ticket Closure Comment

SOC investigated ticket **CS-039 — Proxy: Unusual Access to P2P Sites**. Proxy logs show user **Vivek Kapoor** from **10.1.2.44 / ENDP-047** accessed **utorrent.com**, categorized as **Peer-to-Peer (P2P)**. The traffic was allowed and returned HTTP **200**. Splunk evidence shows the user first accessed the site through a Google search referrer and later downloaded **utweb_installer.exe**. No malware execution, endpoint compromise, C2 callback, or data exfiltration was identified from the provided logs. Ticket should be handled as **True Positive — P2P Site Access and Risky Installer Download / No Confirmed Compromise**, with user validation, endpoint review, installer removal if present, and proxy/DNS blocking recommended.

## Skills Demonstrated

Proxy alert triage, P2P access investigation, risky software download analysis, user and endpoint correlation, Splunk proxy log review, policy violation assessment, MITRE ATT&CK mapping, impact analysis, escalation decision-making, and SOC ticket documentation.

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
