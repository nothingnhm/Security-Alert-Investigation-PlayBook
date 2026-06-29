# SOC Analyst Investigation Report

## Ticket Overview

| Field             | Details                                                               |
| ----------------- | --------------------------------------------------------------------- |
| Ticket ID         | CS-082                                                                |
| Alert Name        | Linux:- Suspicious Cron Job or Scheduled Task Creation                |
| Incident Category | Linux / Cron Job Modification                                         |
| Ticket Status     | Closed                                                                |
| Priority / SLA    | Normal / Default SLA                                                  |
| Department        | Support                                                               |
| Created Date      | 5/12/25 7:11 PM                                                       |
| Closed By         | Ananda Das                                                            |
| Detection Source  | Linux Logs / SIEM Splunk                                              |
| Affected Host     | LinMRDB06                                                             |
| Host IP           | 10.0.15.28                                                            |
| Operating System  | Linux - Ubuntu 20.04                                                  |
| User Involved     | Arun Jain                                                             |
| Analyst Decision  | **False Positive — Authorized Backup Cron Job Created by Linux Lead** |

## Executive Summary

A Linux security alert was triggered on **LinMRDB06** after a cron job modification was detected.

The affected server was:

`LinMRDB06 / 10.0.15.28`

The activity was performed by:

`Arun Jain`

The user role was identified as:

`Linux Lead`

The activity originated from source address:

`10.1.4.143`

Splunk logs showed that Arun Jain opened the root crontab and added the following scheduled task:

`0 2 * * * /usr/local/bin/backup.sh`

This cron entry is configured to execute the backup script `/usr/local/bin/backup.sh` every day at **02:00 AM**.

Cron jobs can be abused by attackers for persistence. However, in this case, the command points to a backup script, was executed by a Linux Lead, originated from an internal source address, and did not contain suspicious payloads such as reverse shells, download commands, encoded commands, or unknown external callbacks.

Final assessment: **False Positive — Authorized Scheduled Backup Cron Job. No malicious activity was observed in the provided evidence.**

## Alert Details

| Field             | Value                                                             |
| ----------------- | ----------------------------------------------------------------- |
| First Event Time  | 5/11/2025 22:30                                                   |
| Second Event Time | 5/11/2025 22:31                                                   |
| Hostname          | LinMRDB06                                                         |
| IP Address        | 10.0.15.28                                                        |
| OS                | Linux - Ubuntu 20.04                                              |
| Platform          | Linux                                                             |
| User              | Arun Jain                                                         |
| User Role         | Linux Lead                                                        |
| Source Address    | 10.1.4.143                                                        |
| Working Directory | /home/arun                                                        |
| First Command     | crontab -e                                                        |
| Second Command    | echo "0 2 * * * /usr/local/bin/backup.sh" >> /var/spool/cron/root |
| Cron File Path    | /var/spool/cron/root                                              |
| Script Path       | /usr/local/bin/backup.sh                                          |
| Result            | success                                                           |

## Observed Activity

| Time             | Process | Executable       | Command                                                           | Path                     | Result  |
| ---------------- | ------- | ---------------- | ----------------------------------------------------------------- | ------------------------ | ------- |
| 2025-05-11 22:30 | crontab | /usr/bin/crontab | crontab -e                                                        | /var/spool/cron/root     | success |
| 2025-05-11 22:31 | bash    | /usr/bin/bash    | echo "0 2 * * * /usr/local/bin/backup.sh" >> /var/spool/cron/root | /usr/local/bin/backup.sh | success |

## Cron Job Explanation

The cron entry below means the backup script will run every day at **02:00 AM**:

```text
0 2 * * * /usr/local/bin/backup.sh
```

| Cron Field   | Value                    | Meaning                  |
| ------------ | ------------------------ | ------------------------ |
| Minute       | 0                        | Run at minute 0          |
| Hour         | 2                        | Run at 02:00 AM          |
| Day of Month | *                        | Every day                |
| Month        | *                        | Every month              |
| Day of Week  | *                        | Every day of the week    |
| Script       | /usr/local/bin/backup.sh | Backup script to execute |

## Affected Asset Details

| Field             | Value                    |
| ----------------- | ------------------------ |
| Hostname          | LinMRDB06                |
| IP Address        | 10.0.15.28               |
| Operating System  | Linux - Ubuntu 20.04     |
| Platform          | Linux                    |
| Working Directory | /home/arun               |
| Cron Path         | /var/spool/cron/root     |
| Script Path       | /usr/local/bin/backup.sh |
| User Role         | Linux Lead               |

## Data Quality Note

The host is identified as **Linux - Ubuntu 20.04**, while the cron path is recorded as `/var/spool/cron/root`. The path is preserved exactly as provided in the evidence. If exact cron file location is important for validation, it should be confirmed against the raw host configuration and distribution-specific cron storage path.

## IOCs / Technical Indicators Identified

**Note:** These are investigation indicators, not confirmed malicious IOCs.

| Indicator Type   | Indicator                                                         |
| ---------------- | ----------------------------------------------------------------- |
| Source Address   | 10.1.4.143                                                        |
| Destination Host | LinMRDB06                                                         |
| Destination IP   | 10.0.15.28                                                        |
| User             | Arun Jain                                                         |
| User Role        | Linux Lead                                                        |
| Process          | crontab                                                           |
| Process          | bash                                                              |
| Executable       | /usr/bin/crontab                                                  |
| Executable       | /usr/bin/bash                                                     |
| Command          | crontab -e                                                        |
| Command          | echo "0 2 * * * /usr/local/bin/backup.sh" >> /var/spool/cron/root |
| Cron File        | /var/spool/cron/root                                              |
| Script Path      | /usr/local/bin/backup.sh                                          |
| Event Key        | log_cron_mod                                                      |
| Event Key        | log_cron_script                                                   |
| Result           | success                                                           |
| Final Assessment | Benign / Authorized scheduled backup task                         |

## SIEM / Splunk Analysis

### Investigation Flow

#### 1. Alert Review

SOC reviewed the Linux cron modification alert for host `LinMRDB06`. The alert triggered because cron jobs and scheduled tasks can be used by attackers to establish persistence.

#### 2. Entity Identification

| Entity           | Value                    |
| ---------------- | ------------------------ |
| Hostname         | LinMRDB06                |
| Host IP          | 10.0.15.28               |
| OS               | Linux - Ubuntu 20.04     |
| User             | Arun Jain                |
| User Role        | Linux Lead               |
| Source Address   | 10.1.4.143               |
| Cron File        | /var/spool/cron/root     |
| Script Scheduled | /usr/local/bin/backup.sh |

#### 3. Splunk Query Used

```spl id="cs0350_cron_job_query"
index=main sourcetype="linux_logs" "10.1.4.143"
| table _time hostname ip_address os platform user user_role pid ppid comm exe cmd cwd addr ses success res path key
```

#### 4. Full Unique Splunk Log Results

```text id="cs0350_cron_job_results"
_time	hostname	ip_address	os	platform	user	user_role	pid	ppid	comm	exe	cmd	cwd	addr	ses	success	res	path	key
2025-05-11 22:31:00	LinMRDB06	10.0.15.28	Linux - Ubuntu 20.04	Linux	Arun Jain	Linux Lead	4130	764	bash	/usr/bin/bash	echo "0 2 * * * /usr/local/bin/backup.sh" >> /var/spool/cron/root	/home/arun	10.1.4.143	2	yes	success	/usr/local/bin/backup.sh	log_cron_script
2025-05-11 22:30:00	LinMRDB06	10.0.15.28	Linux - Ubuntu 20.04	Linux	Arun Jain	Linux Lead	2851	709	crontab	/usr/bin/crontab	crontab -e	/home/arun	10.1.4.143	5	yes	success	/var/spool/cron/root	log_cron_mod
```

**Evidence Note:** All unique Linux cron modification events provided for this ticket were preserved.

## Cron Activity Review

| Observation                                | Analyst Interpretation                                                   |
| ------------------------------------------ | ------------------------------------------------------------------------ |
| `crontab -e` was executed                  | Root cron modification activity confirmed                                |
| Backup script was added to cron            | Scheduled task creation confirmed                                        |
| Script path was `/usr/local/bin/backup.sh` | Appears consistent with backup automation                                |
| User was `Arun Jain`                       | Activity performed by named admin user                                   |
| User role was `Linux Lead`                 | Role supports legitimate administrative activity                         |
| Source address was internal                | Likely internal admin workstation or jump host                           |
| No suspicious payload observed             | No reverse shell, downloader, encoded payload, or callback command found |
| Result was successful                      | Cron modification completed                                              |

## Investigation Findings

1. Cron job modification was detected on host `LinMRDB06`.
2. The affected host IP was `10.0.15.28`.
3. The host was running `Linux - Ubuntu 20.04`.
4. The activity was performed by `Arun Jain`.
5. The user role was identified as `Linux Lead`.
6. The source address was `10.1.4.143`.
7. The command `crontab -e` was executed successfully.
8. A cron entry was added to `/var/spool/cron/root`.
9. The scheduled command points to `/usr/local/bin/backup.sh`.
10. The cron job is configured to run daily at `02:00 AM`.
11. The command appears related to backup automation.
12. No suspicious payload, encoded command, download command, reverse shell, or unauthorized user creation was observed.
13. No evidence of failed login, privilege abuse, malware execution, or data exfiltration was identified in the provided logs.
14. Based on the user role and command context, the activity appears authorized.
15. The alert was classified as a false positive.

## Timeline of Events

| Time               | Event                                                                  |
| ------------------ | ---------------------------------------------------------------------- |
| 2025-05-11 22:30   | Arun Jain opened root crontab using `crontab -e`                       |
| 2025-05-11 22:31   | Arun Jain added a daily backup cron job for `/usr/local/bin/backup.sh` |
| Investigation Time | SOC reviewed Linux cron modification logs in Splunk                    |
| Investigation Time | SOC validated the command and script path                              |
| Investigation Time | SOC confirmed the activity was consistent with backup scheduling       |
| Closure Time       | Ticket closed as false positive / authorized administrative activity   |

## MITRE ATT&CK Mapping

| Tactic      | Technique                | ID        | Reason                                         |
| ----------- | ------------------------ | --------- | ---------------------------------------------- |
| Persistence | Scheduled Task/Job: Cron | T1053.003 | Cron job creation was observed on a Linux host |

**MITRE Note:** MITRE mapping is included for detection reference only. The observed cron job was assessed as a legitimate backup schedule and not malicious persistence.

## Analyst Assessment

**Assessment:** **False Positive — Authorized Backup Cron Job Creation**

The alert was triggered because cron job modification can be used by attackers for persistence. However, the observed activity appears benign based on the available evidence.

The reasons for false positive classification are:

1. The activity was performed by `Arun Jain`, a Linux Lead.
2. The source address `10.1.4.143` appears to be an internal/admin source.
3. The cron job points to a backup script.
4. The scheduled time of `02:00 AM` is consistent with normal backup activity.
5. The command does not contain suspicious payloads.
6. No unauthorized account creation was observed.
7. No sensitive file tampering was observed.
8. No malicious network command was observed.
9. No suspicious post-execution activity was provided.
10. The activity matches expected administrative maintenance.

Current assessment: **Authorized scheduled backup task / no malicious activity observed.**

## Impact Analysis

| Impact Area             | Status                   |
| ----------------------- | ------------------------ |
| Cron modification       | Confirmed                |
| Scheduled task creation | Confirmed                |
| User involved           | Arun Jain                |
| User role               | Linux Lead               |
| Script scheduled        | /usr/local/bin/backup.sh |
| Malicious payload       | Not observed             |
| Unauthorized access     | Not observed             |
| Privilege abuse         | Not observed             |
| Persistence abuse       | Not observed             |
| Data exfiltration       | Not observed             |
| Business impact         | None                     |
| Security impact         | Low                      |
| Residual risk           | Low                      |

### Impact Summary

The cron job modification was confirmed, but the command was related to a scheduled backup script. No malicious indicators were observed in the provided evidence. The event is considered benign administrative activity.

## Validation Performed / Recommended

Although the ticket is assessed as false positive, the following validation should be documented:

1. Confirm the cron job was part of an approved backup activity.
2. Confirm `/usr/local/bin/backup.sh` is an approved backup script.
3. Confirm the file ownership and permissions of `backup.sh`.
4. Confirm the cron job was expected on `LinMRDB06`.
5. Confirm Arun Jain performed the activity.
6. Attach the change request or maintenance reference if available.
7. Confirm the script does not contain suspicious network callbacks or destructive commands.

## Additional Splunk Queries for Follow-Up

### Check Cron Activity on Same Host

```spl id="cs0350_cron_activity_same_host"
index=main sourcetype="linux_logs" hostname="LinMRDB06" (comm="crontab" OR key="log_cron_mod" OR key="log_cron_script")
| table _time hostname user comm exe cmd cwd addr success res path key
| sort _time
```

### Check Activity by Arun Jain

```spl id="cs0350_arun_activity"
index=main sourcetype="linux_logs" user="Arun Jain"
| table _time hostname user comm exe cmd cwd addr success res path key
| sort _time
```

### Check Backup Script Execution or Modification

```spl id="cs0350_backup_script_activity"
index=main sourcetype="linux_logs" "/usr/local/bin/backup.sh"
| table _time hostname user comm exe cmd cwd addr success res path key
| sort _time
```

### Hunt for Suspicious Cron Entries

```spl id="cs0350_suspicious_cron_hunt"
index=main sourcetype="linux_logs" (comm="crontab" OR key="log_cron_mod" OR cmd="*cron*")
| search cmd="*curl*" OR cmd="*wget*" OR cmd="*nc*" OR cmd="*bash -i*" OR cmd="*python*" OR cmd="*base64*" OR cmd="*/tmp/*"
| table _time hostname user comm exe cmd cwd addr success res path key
| sort _time
```

## Recommended Actions

1. Document the cron job as an authorized backup schedule.
2. Confirm backup script ownership and permissions.
3. Ensure only authorized Linux administrators can modify root crontab.
4. Maintain change approval records for cron modifications.
5. Continue monitoring cron modifications on critical Linux servers.
6. Alert on cron jobs containing suspicious commands such as `curl`, `wget`, `nc`, `bash -i`, encoded payloads, unknown scripts, `/tmp` execution, or public IP callbacks.
7. Keep `/usr/local/bin/backup.sh` under file integrity monitoring if the server is critical.
8. Review scheduled tasks periodically for unauthorized entries.
9. Confirm source address `10.1.4.143` belongs to an approved admin workstation or jump host.
10. Validate backup script integrity using checksum or file integrity monitoring.

## Escalation Decision

**Decision:** **No escalation required.**

**Reason:** The observed cron job was created by a Linux Lead and points to a backup script. No malicious command, unauthorized access, suspicious payload, or suspicious post-execution activity was identified in the provided logs.

Escalation would be required only if:

1. Arun Jain denies the activity.
2. The backup script is unknown or unauthorized.
3. The script contains suspicious commands.
4. The cron job was not part of approved maintenance.
5. Additional suspicious activity is observed on the host.
6. The source address is not an approved admin workstation or jump host.

## Final Ticket Closure Comment

SOC investigated ticket **CS-082 — Suspicious Cron Job or Scheduled Task Creation** on host `LinMRDB06 / 10.0.15.28`. Splunk Linux logs showed that user `Arun Jain`, identified as a Linux Lead, executed `crontab -e` from source address `10.1.4.143`, followed by a successful command adding `0 2 * * * /usr/local/bin/backup.sh` to `/var/spool/cron/root`. The cron entry schedules `/usr/local/bin/backup.sh` to run daily at `02:00 AM`, which is consistent with backup automation. No malicious payload, encoded command, reverse shell, unauthorized account creation, suspicious file modification, data exfiltration, or compromise indicator was observed in the provided logs. The event was assessed as authorized administrative activity and closed as **False Positive — Authorized Backup Cron Job Creation / No Malicious Activity Observed**.

## Skills Demonstrated

Linux log analysis, Splunk investigation, cron job review, scheduled task triage, persistence detection validation, command-line analysis, backup script validation, false-positive assessment, IOC extraction, MITRE ATT&CK mapping, administrative activity validation, escalation decision-making, and SOC ticket documentation.
