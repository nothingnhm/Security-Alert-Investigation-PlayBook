# SOC Analyst Investigation Report

## Ticket Overview

| Field             | Details                                                                                                   |
| ----------------- | --------------------------------------------------------------------------------------------------------- |
| Ticket ID         | CS-077                                                                                                    |
| Alert Name        | Linux:- Failed SSH Login – Account Brute Force Detection                                                  |
| Incident Category | Linux / SSH Brute Force                                                                                   |
| Ticket Status     | Closed                                                                                                    |
| Priority / SLA    | Normal / Default SLA                                                                                      |
| Department        | Support                                                                                                   |
| Created Date      | 5/12/25 7:14 PM                                                                                           |
| Closed By         | Ananda Das                                                                                                |
| Detection Source  | Linux Logs / SIEM Splunk                                                                                  |
| Affected Host     | LinQAWebServer07                                                                                          |
| Host IP           | 10.0.15.16                                                                                                |
| Operating System  | Linux - RHEL 8                                                                                            |
| Analyst Decision  | **True Positive — SSH Brute Force Attack Against Multiple Linux Accounts / No Successful Login Observed** |

## Executive Summary

A Linux SSH brute-force alert was triggered for host **LinQAWebServer07** after multiple failed SSH authentication attempts were observed from the external source IP:

`191.241.142.85`

The affected server was:

`LinQAWebServer07 / 10.0.15.16`

The affected system was a **Linux RHEL 8** server, and the SSH daemon process involved was:

`sshd`

Splunk logs showed repeated SSH pre-authentication failures against multiple common Linux accounts, including:

`admin`
`ec2-user`
`root`
`test`
`ubuntu`
`user1`

The source IP had **100% abuse confidence** and was associated with Argentina. All observed attempts failed, and no successful SSH login was observed in the provided logs.

Final assessment: **True Positive SSH brute-force attack. The source IP should be blocked, the host should be monitored, and SSH hardening controls should be reviewed. No successful authentication or confirmed compromise was observed from the provided evidence.**

## Alert Details

| Field                     | Value                 |
| ------------------------- | --------------------- |
| Timestamp                 | 5/11/2025 15:00       |
| Hostname                  | LinQAWebServer07      |
| IP Address                | 10.0.15.16            |
| OS                        | Linux - RHEL 8        |
| Platform                  | Linux                 |
| User                      | admin                 |
| User Role                 | External Attacker     |
| PID                       | 5019                  |
| PPID                      | 1337                  |
| Process                   | sshd                  |
| Executable                | /usr/sbin/sshd        |
| Command                   | sshd: admin [preauth] |
| Current Working Directory | /                     |
| Source Address            | 191.241.142.85        |
| Session                   | 3                     |
| Success                   | no                    |
| Result                    | failed                |
| Log Path                  | /var/log/secure       |
| Event Key                 | log_ssh_brute_force   |

## Source IP Reputation Analysis

| Field            | Value                                     |
| ---------------- | ----------------------------------------- |
| Source IP        | 191.241.142.85                            |
| Abuse Confidence | 100%                                      |
| ISP              | Paralelo 46 TV SA                         |
| Usage Type       | Fixed Line ISP                            |
| ASN              | AS270106                                  |
| Hostname         | host-191-241-142-85.red.paralelo46.com.ar |
| Domain Name      | paralelo46.com.ar                         |
| Country          | Argentina                                 |
| City             | Las Heras, Santa Cruz                     |

### Source IP Assessment

The source IP `191.241.142.85` had **100% abuse confidence**, which strongly indicates abusive or malicious activity.

The same source IP attempted SSH authentication against multiple Linux usernames within a short time window. This behavior is consistent with automated SSH brute-force activity or credential-guessing attempts against an exposed Linux server.

## Affected Asset Details

| Field            | Value               |
| ---------------- | ------------------- |
| Hostname         | LinQAWebServer07    |
| Host IP          | 10.0.15.16          |
| Operating System | Linux - RHEL 8      |
| Platform         | Linux               |
| Service Targeted | SSH                 |
| Process          | sshd                |
| Executable       | /usr/sbin/sshd      |
| Log Source       | /var/log/secure     |
| Event Key        | log_ssh_brute_force |
| Result           | failed              |

## IOCs / Indicators Identified

| IOC Type             | Indicator                                 |
| -------------------- | ----------------------------------------- |
| Source IP            | 191.241.142.85                            |
| Source Hostname      | host-191-241-142-85.red.paralelo46.com.ar |
| Source Domain        | paralelo46.com.ar                         |
| Source Country       | Argentina                                 |
| Destination Host     | LinQAWebServer07                          |
| Destination IP       | 10.0.15.16                                |
| Operating System     | Linux - RHEL 8                            |
| Process              | sshd                                      |
| Executable           | /usr/sbin/sshd                            |
| Log File             | /var/log/secure                           |
| Event Key            | log_ssh_brute_force                       |
| Targeted Account     | admin                                     |
| Targeted Account     | ec2-user                                  |
| Targeted Account     | root                                      |
| Targeted Account     | test                                      |
| Targeted Account     | ubuntu                                    |
| Targeted Account     | user1                                     |
| Result               | failed                                    |
| Attack Type          | SSH Brute Force / Credential Guessing     |
| Successful SSH Login | Not observed                              |

## SIEM / Splunk Analysis

### Investigation Flow

#### 1. Alert Review

SOC reviewed the Linux SSH brute-force alert for host `LinQAWebServer07`. The alert indicated repeated SSH authentication failures from source IP `191.241.142.85`.

Because multiple common Linux usernames were targeted from a single external source IP, SOC treated the event as a likely automated SSH brute-force attack.

#### 2. Entity Identification

| Entity           | Value               |
| ---------------- | ------------------- |
| Source IP        | 191.241.142.85      |
| Destination Host | LinQAWebServer07    |
| Destination IP   | 10.0.15.16          |
| OS               | Linux - RHEL 8      |
| Process          | sshd                |
| Executable       | /usr/sbin/sshd      |
| Log Path         | /var/log/secure     |
| Event Key        | log_ssh_brute_force |

#### 3. Splunk Query Used

```spl id="cs0359_linux_ssh_query"
index=main sourcetype="linux_logs" "191.241.142.85"
| table _time hostname ip_address os platform user user_role pid ppid comm exe cmd cwd addr ses success res path key
```

#### 4. Full Unique Splunk Log Results

```text id="cs0359_linux_ssh_results"
_time	hostname	ip_address	os	platform	user	user_role	pid	ppid	comm	exe	cmd	cwd	addr	ses	success	res	path	key
2025-05-11 15:04:00	LinQAWebServer07	10.0.15.16	Linux - RHEL 8	Linux	admin	External Attacker	4084	1131	sshd	/usr/sbin/sshd	sshd: admin [preauth]	/	191.241.142.85	5	no	failed	/var/log/secure	log_ssh_brute_force
2025-05-11 15:03:00	LinQAWebServer07	10.0.15.16	Linux - RHEL 8	Linux	admin	External Attacker	3080	1292	sshd	/usr/sbin/sshd	sshd: admin [preauth]	/	191.241.142.85	5	no	failed	/var/log/secure	log_ssh_brute_force
2025-05-11 15:03:00	LinQAWebServer07	10.0.15.16	Linux - RHEL 8	Linux	admin	External Attacker	4114	1207	sshd	/usr/sbin/sshd	sshd: admin [preauth]	/	191.241.142.85	4	no	failed	/var/log/secure	log_ssh_brute_force
2025-05-11 15:01:00	LinQAWebServer07	10.0.15.16	Linux - RHEL 8	Linux	admin	External Attacker	5729	692	sshd	/usr/sbin/sshd	sshd: admin [preauth]	/	191.241.142.85	5	no	failed	/var/log/secure	log_ssh_brute_force
2025-05-11 15:00:00	LinQAWebServer07	10.0.15.16	Linux - RHEL 8	Linux	admin	External Attacker	3841	1369	sshd	/usr/sbin/sshd	sshd: admin [preauth]	/	191.241.142.85	2	no	failed	/var/log/secure	log_ssh_brute_force
2025-05-11 15:00:00	LinQAWebServer07	10.0.15.16	Linux - RHEL 8	Linux	admin	External Attacker	5641	549	sshd	/usr/sbin/sshd	sshd: admin [preauth]	/	191.241.142.85	1	no	failed	/var/log/secure	log_ssh_brute_force
2025-05-11 15:00:00	LinQAWebServer07	10.0.15.16	Linux - RHEL 8	Linux	admin	External Attacker	5019	1337	sshd	/usr/sbin/sshd	sshd: admin [preauth]	/	191.241.142.85	3	no	failed	/var/log/secure	log_ssh_brute_force
2025-05-11 15:04:00	LinQAWebServer07	10.0.15.16	Linux - RHEL 8	Linux	ec2-user	External Attacker	6387	1050	sshd	/usr/sbin/sshd	sshd: ec2-user [preauth]	/	191.241.142.85	3	no	failed	/var/log/secure	log_ssh_brute_force
2025-05-11 15:03:00	LinQAWebServer07	10.0.15.16	Linux - RHEL 8	Linux	ec2-user	External Attacker	6599	1374	sshd	/usr/sbin/sshd	sshd: ec2-user [preauth]	/	191.241.142.85	5	no	failed	/var/log/secure	log_ssh_brute_force
2025-05-11 15:02:00	LinQAWebServer07	10.0.15.16	Linux - RHEL 8	Linux	ec2-user	External Attacker	5280	958	sshd	/usr/sbin/sshd	sshd: ec2-user [preauth]	/	191.241.142.85	5	no	failed	/var/log/secure	log_ssh_brute_force
2025-05-11 15:02:00	LinQAWebServer07	10.0.15.16	Linux - RHEL 8	Linux	ec2-user	External Attacker	3200	1314	sshd	/usr/sbin/sshd	sshd: ec2-user [preauth]	/	191.241.142.85	3	no	failed	/var/log/secure	log_ssh_brute_force
2025-05-11 15:01:00	LinQAWebServer07	10.0.15.16	Linux - RHEL 8	Linux	ec2-user	External Attacker	6595	1145	sshd	/usr/sbin/sshd	sshd: ec2-user [preauth]	/	191.241.142.85	2	no	failed	/var/log/secure	log_ssh_brute_force
2025-05-11 15:03:00	LinQAWebServer07	10.0.15.16	Linux - RHEL 8	Linux	root	External Attacker	6023	1186	sshd	/usr/sbin/sshd	sshd: root [preauth]	/	191.241.142.85	1	no	failed	/var/log/secure	log_ssh_brute_force
2025-05-11 15:04:00	LinQAWebServer07	10.0.15.16	Linux - RHEL 8	Linux	test	External Attacker	7781	1216	sshd	/usr/sbin/sshd	sshd: test [preauth]	/	191.241.142.85	5	no	failed	/var/log/secure	log_ssh_brute_force
2025-05-11 15:01:00	LinQAWebServer07	10.0.15.16	Linux - RHEL 8	Linux	test	External Attacker	6771	675	sshd	/usr/sbin/sshd	sshd: test [preauth]	/	191.241.142.85	1	no	failed	/var/log/secure	log_ssh_brute_force
2025-05-11 15:04:00	LinQAWebServer07	10.0.15.16	Linux - RHEL 8	Linux	ubuntu	External Attacker	5733	1338	sshd	/usr/sbin/sshd	sshd: ubuntu [preauth]	/	191.241.142.85	4	no	failed	/var/log/secure	log_ssh_brute_force
2025-05-11 15:01:00	LinQAWebServer07	10.0.15.16	Linux - RHEL 8	Linux	ubuntu	External Attacker	6398	730	sshd	/usr/sbin/sshd	sshd: ubuntu [preauth]	/	191.241.142.85	4	no	failed	/var/log/secure	log_ssh_brute_force
2025-05-11 15:00:00	LinQAWebServer07	10.0.15.16	Linux - RHEL 8	Linux	ubuntu	External Attacker	7424	670	sshd	/usr/sbin/sshd	sshd: ubuntu [preauth]	/	191.241.142.85	3	no	failed	/var/log/secure	log_ssh_brute_force
2025-05-11 15:02:00	LinQAWebServer07	10.0.15.16	Linux - RHEL 8	Linux	user1	External Attacker	4244	1253	sshd	/usr/sbin/sshd	sshd: user1 [preauth]	/	191.241.142.85	5	no	failed	/var/log/secure	log_ssh_brute_force
2025-05-11 15:02:00	LinQAWebServer07	10.0.15.16	Linux - RHEL 8	Linux	user1	External Attacker	3807	1262	sshd	/usr/sbin/sshd	sshd: user1 [preauth]	/	191.241.142.85	4	no	failed	/var/log/secure	log_ssh_brute_force
```

**Evidence Note:** All unique SSH brute-force log rows provided for this ticket were preserved.

## Attack Summary by User

| Targeted User | Failed Attempts Observed | Assessment                               |
| ------------- | -----------------------: | ---------------------------------------- |
| admin         |                        7 | Common privileged/admin account targeted |
| ec2-user      |                        5 | Common cloud Linux account targeted      |
| root          |                        1 | Highly privileged account targeted       |
| test          |                        2 | Common weak/test account targeted        |
| ubuntu        |                        3 | Common Linux cloud account targeted      |
| user1         |                        2 | Generic user account targeted            |

| Metric                         | Value |
| ------------------------------ | ----: |
| Total Failed Attempts Observed |    20 |
| Successful Attempts Observed   |     0 |
| Source IP Count                |     1 |
| Targeted User Count            |     6 |

## SSH Brute-Force Pattern Review

| Observation                                        | Analyst Interpretation                           |
| -------------------------------------------------- | ------------------------------------------------ |
| Multiple usernames targeted                        | Automated credential guessing likely             |
| Common Linux usernames targeted                    | Indicates generic SSH brute-force behavior       |
| Same source IP used                                | Single-source attack pattern                     |
| Short time window                                  | Automated or scripted activity likely            |
| All attempts failed                                | No successful access confirmed                   |
| Source IP had 100% abuse confidence                | Strong malicious reputation indicator            |
| `root`, `admin`, `ubuntu`, and `ec2-user` targeted | Common privileged/cloud account guessing pattern |

## Investigation Findings

1. Multiple failed SSH login attempts were observed on `LinQAWebServer07`.
2. The affected host IP was `10.0.15.16`.
3. The affected operating system was `Linux - RHEL 8`.
4. All observed attempts originated from source IP `191.241.142.85`.
5. The source IP had **100% abuse confidence**.
6. The source IP was associated with `host-191-241-142-85.red.paralelo46.com.ar`.
7. The SSH daemon process `sshd` generated the events.
8. The executable involved was `/usr/sbin/sshd`.
9. Events were recorded in `/var/log/secure`.
10. Multiple usernames were targeted from the same source IP.
11. Targeted accounts included `admin`, `ec2-user`, `root`, `test`, `ubuntu`, and `user1`.
12. The targeted accounts are commonly used in Linux and cloud environments.
13. All observed attempts were marked as `success=no` and `res=failed`.
14. No successful SSH login was observed in the provided logs.
15. The activity occurred within a short time window between `15:00` and `15:04`.
16. The pattern is consistent with an automated SSH brute-force or credential-guessing attack.

## Timeline of Events

| Time               | Event                                                                      |
| ------------------ | -------------------------------------------------------------------------- |
| 2025-05-11 15:00   | SSH brute-force activity started from `191.241.142.85`                     |
| 2025-05-11 15:00   | Failed attempts observed against `admin` and `ubuntu`                      |
| 2025-05-11 15:01   | Failed attempts observed against `admin`, `ec2-user`, `test`, and `ubuntu` |
| 2025-05-11 15:02   | Failed attempts observed against `ec2-user` and `user1`                    |
| 2025-05-11 15:03   | Failed attempts observed against `admin`, `ec2-user`, and `root`           |
| 2025-05-11 15:04   | Failed attempts observed against `admin`, `ec2-user`, `test`, and `ubuntu` |
| Investigation Time | SOC reviewed Linux SSH logs in Splunk                                      |
| Investigation Time | SOC confirmed multiple users were targeted                                 |
| Containment Time   | Source IP block was recommended/performed                                  |
| Closure Time       | Ticket closed after confirming no successful SSH login was observed        |

## MITRE ATT&CK Mapping

| Tactic            | Technique               | ID        | Reason                                                                                                                     |
| ----------------- | ----------------------- | --------- | -------------------------------------------------------------------------------------------------------------------------- |
| Credential Access | Brute Force             | T1110     | Multiple failed SSH authentication attempts were observed                                                                  |
| Credential Access | Password Guessing       | T1110.001 | Common Linux usernames were targeted with failed authentication attempts                                                   |
| Initial Access    | Valid Accounts          | T1078     | Attacker attempted to authenticate using common Linux account names                                                        |
| Lateral Movement  | SSH                     | T1021.004 | SSH was the remote access service targeted for authentication                                                              |
| Discovery         | Cloud Account Discovery | T1087.004 | Cloud-related usernames such as `ec2-user` and `ubuntu` were targeted, indicating possible cloud account guessing behavior |

**MITRE Note:** SSH brute-force behavior was observed. Successful SSH login, privilege escalation, persistence, lateral movement, and data exfiltration were not observed in the provided logs.

## Analyst Assessment

**Assessment:** **True Positive — SSH Brute Force Attack / No Successful SSH Login Observed**

The alert is valid because a single external source IP attempted SSH authentication multiple times against multiple Linux usernames.

The evidence supporting this conclusion includes:

1. A single external source IP attempted SSH authentication repeatedly.
2. Source IP `191.241.142.85` had **100% abuse confidence**.
3. Multiple common Linux usernames were targeted.
4. Attempts occurred repeatedly within a short time window.
5. All attempts were logged as SSH pre-authentication failures.
6. All attempts failed.
7. No successful SSH login was observed.

The use of common usernames such as `admin`, `root`, `ubuntu`, `ec2-user`, `test`, and `user1` indicates automated scanning or credential guessing commonly seen against internet-facing Linux servers.

## Impact Analysis

| Impact Area                | Status                            |
| -------------------------- | --------------------------------- |
| SSH brute force            | Confirmed                         |
| Multiple accounts targeted | Confirmed                         |
| Source IP reputation       | 100% abuse confidence             |
| Targeted host              | LinQAWebServer07                  |
| Targeted IP                | 10.0.15.16                        |
| Successful SSH login       | Not observed                      |
| Account compromise         | Not observed                      |
| Privilege escalation       | Not observed                      |
| Lateral movement           | Not observed                      |
| Data exfiltration          | Not observed                      |
| Business impact            | Low                               |
| Security impact            | Medium                            |
| Residual risk              | Low after IP block and monitoring |

### Impact Summary

The brute-force attack targeted multiple Linux accounts on `LinQAWebServer07`. All attempts failed, and no successful login was observed in the provided logs. The main risk was unauthorized SSH access if weak credentials existed on the server.

## Containment and Remediation

| Control Area              | Action                                                           |
| ------------------------- | ---------------------------------------------------------------- |
| Firewall / Security Group | Block source IP `191.241.142.85`                                 |
| Linux Host                | Confirm no successful SSH login occurred                         |
| Linux Host                | Review SSH configuration                                         |
| Linux Host                | Confirm root login is disabled                                   |
| Linux Host                | Confirm password authentication is restricted or disabled        |
| Linux Host                | Review and disable unused accounts                               |
| SIEM                      | Add source IP and destination host to watchlist                  |
| SOC                       | Monitor for repeated SSH attempts from same or related IP ranges |

## Additional Splunk Queries for Follow-Up

### Check Successful SSH Logins from Same Source IP

```spl id="cs0359_successful_ssh_check"
index=main sourcetype="linux_logs" addr="191.241.142.85" comm="sshd" (success="yes" OR res="success" OR key="log_auth_success")
| table _time hostname ip_address user comm exe cmd addr success res path key
```

### Check SSH Activity by Source IP and User

```spl id="cs0359_ssh_by_user"
index=main sourcetype="linux_logs" addr="191.241.142.85" comm="sshd"
| stats count values(res) as result values(success) as success values(cmd) as commands by user addr hostname
| sort - count
```

### Check Top SSH Brute-Force Sources

```spl id="cs0359_top_ssh_bruteforce_sources"
index=main sourcetype="linux_logs" comm="sshd" key="log_ssh_brute_force"
| stats count dc(user) as targeted_users values(user) as users by addr hostname
| sort - count
```

### Check Other Hosts Targeted by Same Source IP

```spl id="cs0359_same_source_other_hosts"
index=main sourcetype="linux_logs" addr="191.241.142.85" comm="sshd"
| stats count values(user) as users values(hostname) as targeted_hosts by addr
| sort - count
```

## Recommended Actions

1. Keep source IP `191.241.142.85` blocked.
2. Review firewall or cloud security group rules for SSH exposure.
3. Restrict SSH access to approved VPN, jump host, or admin IP ranges.
4. Disable direct root SSH login.
5. Disable password-based SSH authentication where possible.
6. Enforce SSH key-based authentication.
7. Remove or disable unused accounts such as `test` or `user1` if not required.
8. Validate whether `admin`, `ubuntu`, and `ec2-user` are required on this host.
9. Enable account lockout or rate limiting for SSH failures.
10. Deploy or tune fail2ban / SSH guard if approved by the Linux team.
11. Monitor for additional attempts from the same ASN, ISP, country, or related IP range.
12. Review Linux logs for successful authentication around the same time window.

## Escalation Decision

**Decision:** **No further escalation required after IP block and validation. Escalate only if a successful SSH login or post-login suspicious activity is identified.**

**Reason:** The activity was confirmed as a brute-force attack, but all observed attempts failed and no successful SSH login was identified in the provided logs. Blocking the source IP, monitoring the host, and reviewing SSH hardening controls are sufficient unless additional compromise indicators appear.

Escalate to **SOC L2 / Linux Team / Incident Response** if:

1. Successful SSH login is identified.
2. Failed attempts continue after IP block.
3. Multiple source IPs target the same host.
4. Privileged accounts show successful authentication.
5. New users, suspicious processes, or persistence activity is observed.
6. Lateral movement or data access anomalies are detected.
7. Root login or password authentication is enabled and exposed externally.

## Final Ticket Closure Comment

SOC investigated ticket **CS-077 — Linux Failed SSH Login / Account Brute Force Detection** for host `LinQAWebServer07 / 10.0.15.16`. Linux logs showed multiple SSH pre-authentication failures from source IP `191.241.142.85`. The source IP had **100% abuse confidence** and was associated with `host-191-241-142-85.red.paralelo46.com.ar / paralelo46.com.ar` in Argentina. Splunk evidence confirmed failed SSH attempts against multiple common Linux accounts, including `admin`, `ec2-user`, `root`, `test`, `ubuntu`, and `user1`. All observed events were generated by `sshd`, executed from `/usr/sbin/sshd`, recorded in `/var/log/secure`, and marked as `success=no` / `res=failed`. No successful SSH login, account compromise, privilege escalation, lateral movement, or data exfiltration was observed. Source IP `191.241.142.85` was blocked/recommended for blocking, SSH hardening controls were recommended, and the host was monitored for further activity. Ticket closed as **True Positive — SSH Brute Force Attack Against Multiple Linux Accounts / No Successful SSH Login Observed**.

## Skills Demonstrated

Linux log analysis, SSH brute-force triage, Splunk investigation, `/var/log/secure` review, failed authentication analysis, source IP reputation review, multi-account attack analysis, cloud Linux account validation, IOC extraction, MITRE ATT&CK mapping, containment planning, SSH hardening recommendation, escalation criteria definition, and SOC ticket documentation.

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
