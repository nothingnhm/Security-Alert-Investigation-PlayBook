# SOC Analyst Investigation Report

**Ticket ID:** CS-01
**Alert Name:** Firewall: DNS DDoS Attack

---

## 1. Executive Summary

A firewall alert was triggered for a **DNS DDoS Attack** involving inbound UDP traffic from external source IP **104.168.46.10** to internal destination IP **10.0.2.26** on destination port **53/DNS**.

The firewall identified the activity as **“DNS DDOS Attack”** with **medium severity** and blocked the traffic. A Splunk review showed **269 blocked inbound events** from the same source IP to the internal DNS server.

Based on the available evidence, there is **no indication that the traffic was successfully delivered to the internal host**, as the firewall action was **blocked**. No immediate containment action is required at this time, but monitoring is recommended for recurrence or increased volume.

---

## 2. Alert Details

| Field               | Details                                                                                                  |
| ------------------- | -------------------------------------------------------------------------------------------------------- |
| Ticket ID           | CS-01                                                                                                    |
| Alert Name          | Firewall: DNS DDoS Attack                                                                                |
| Severity            | Medium                                                                                                   |
| Receive Time        | 2/10/2025 16:07                                                                                          |
| Source IP           | 104.168.46.10                                                                                            |
| Source IP Details   | ISP: HostPapa; Usage Type: Data Center/Web Hosting/Transit; Domain: hostpapa.com; Country: United States |
| Destination IP      | 10.0.2.26                                                                                                |
| Destination Host    | Windows Server 2022                                                                                      |
| Destination Service | DNS                                                                                                      |
| Source Port         | 57070                                                                                                    |
| Destination Port    | 53                                                                                                       |
| Protocol            | UDP                                                                                                      |
| Direction           | Inbound                                                                                                  |
| Firewall Action     | Blocked                                                                                                  |
| Threat Name         | DNS DDOS Attack                                                                                          |
| Log Source          | Firewall Logs / Splunk                                                                                   |

---

## 3. Investigation Performed

The following investigation steps were performed:

1. Reviewed the firewall alert details for source IP, destination IP, port, protocol, direction, threat name, severity, and action.
2. Confirmed that the traffic was inbound from external source IP **104.168.46.10** to internal destination IP **10.0.2.26**.
3. Verified that the destination port was **53/UDP**, which is commonly used for DNS traffic.
4. Checked the firewall action and confirmed that the traffic was **blocked**.
5. Reviewed Splunk firewall logs to identify repeated activity from the same source IP to the same destination.
6. Confirmed that Splunk results showed **269 blocked events** related to the same DNS DDoS alert.
7. Reviewed source IP information and identified it as associated with **HostPapa**, categorized as **Data Center/Web Hosting/Transit**, located in the **United States**.
8. Assessed whether there was any evidence of successful traffic delivery or internal host compromise based on the provided logs.

---

## 4. Evidence Observed

### Firewall Event Evidence

| Field            | Value           |
| ---------------- | --------------- |
| Receive Time     | 2/10/2025 16:07 |
| Source IP        | 104.168.46.10   |
| Destination IP   | 10.0.2.26       |
| Source Port      | 57070           |
| Destination Port | 53              |
| Threat Name      | DNS DDOS Attack |
| Severity         | Medium          |
| Action           | Blocked         |
| Protocol         | UDP             |
| Direction        | Inbound         |

### Splunk Query Used

```spl
index=main sourcetype="firewall_logs" dstPort=53 srcIP="104.168.46.10"
| where Threat_Name="DNS DDOS Attack"
| stats count by srcIP, dstIP, dstPort, Action, Protocol, Direction, Severity
| sort - count
```

### Splunk Result

| srcIP         | dstIP     | dstPort | Action  | Protocol | Direction | Severity | Count |
| ------------- | --------- | ------- | ------- | -------- | --------- | -------- | ----- |
| 104.168.46.10 | 10.0.2.26 | 53      | blocked | udp      | Inbound   | medium   | 269   |

---

## 5. Analysis

The observed activity involved inbound UDP traffic from external IP **104.168.46.10** to internal server **10.0.2.26** on DNS port **53**. The firewall classified the activity as **DNS DDOS Attack** and blocked the traffic.

The activity is considered **suspicious** because:

* The traffic was inbound from an external data center/web hosting IP.
* The destination service was **DNS**, which is commonly targeted in DNS flood and DNS amplification-related activity.
* The firewall detected the traffic as **DNS DDOS Attack**.
* The same source IP generated **269 blocked events** toward the same internal DNS destination.

However, based on the provided logs, there is **no confirmed evidence of compromise**. The firewall action was **blocked**, which indicates the traffic was prevented from reaching or impacting the internal server through this path.

Current assessment: **Suspicious but blocked. No confirmed compromise observed from the provided evidence.**

---

## 6. Possible False Positive Reason

This alert may be a false positive or non-impacting event due to the following reasons:

1. The firewall blocked the traffic before it could reach the internal host.
2. The traffic may be internet background noise targeting exposed or reachable DNS services.
3. The source may belong to a hosting provider where compromised servers, scanners, or misconfigured systems can generate unwanted traffic.
4. The alert may have been triggered due to a high volume of DNS-like UDP traffic matching the firewall signature.
5. If the internal DNS server is intentionally exposed for public DNS resolution, some inbound DNS traffic may be expected, but the volume and firewall signature still require validation.

False positive closure should only be considered after confirming that **10.0.2.26** is expected to receive inbound DNS traffic and that no related allowed traffic or service impact occurred.

---

## 7. Impact Assessment

Based on the available evidence, the firewall blocked the traffic, and there is **no confirmed impact** to the internal host.

If the activity were successful or allowed, the potential impact could include:

* DNS service degradation or outage
* Increased CPU, memory, or network utilization on the DNS server
* Disruption to internal name resolution services
* Possible impact to authentication, application access, and domain services if the DNS server is critical
* Potential use of the DNS service in a broader DDoS or amplification attempt

Current confirmed impact: **No confirmed impact observed from the provided logs.**

---

## 8. Actions Taken

The following actions were completed by SOC L1:

1. Reviewed the firewall alert for key event details.
2. Validated source IP, destination IP, destination port, protocol, direction, severity, and firewall action.
3. Confirmed that the firewall action was **blocked**.
4. Ran a Splunk query to check repeated activity from source IP **104.168.46.10** to destination IP **10.0.2.26** on port **53**.
5. Identified **269 blocked inbound DNS DDoS events**.
6. Reviewed source IP ownership and confirmed it is associated with **HostPapa / data center hosting infrastructure**.
7. Documented findings in the ticket.

No immediate containment action was required because the firewall blocked the traffic.

---

## 9. Recommendation

Recommended next steps:

1. Continue monitoring for repeated DNS DDoS alerts from **104.168.46.10**
2. Check whether other external source IPs are also targeting **10.0.2.26** on port **53/UDP**.
3. Validate whether **10.0.2.26** is an internal-only DNS server or an internet-facing DNS server.
4. Review firewall logs for any **allowed** DNS traffic from the same source IP or similar external sources.
5. Check DNS server health metrics if available, including CPU usage, memory usage, DNS query volume, and service availability.
6. If repeated events continue, consider blocking the source IP at the perimeter as per organizational policy.
7. Escalate to SOC L2 or Network Security team if the volume increases, multiple sources are involved, any traffic is allowed, or DNS service impact is observed.

---

## 10. Escalation Decision

**Decision:** Monitor / No immediate escalation required

**Reason:**

The firewall successfully blocked the inbound UDP traffic from **104.168.46.10** to **10.0.2.26** on port **53**. The provided evidence shows **269 blocked events**, but there is no indication that the traffic was allowed or that the internal DNS server was impacted.

Escalation is recommended if:

* The same activity continues or increases in volume
* Multiple external source IPs target the same destination
* Any related DNS traffic is allowed
* The destination server shows performance or availability issues
* The destination host **10.0.2.26** is confirmed as a critical DNS server or Domain Controller
* Additional indicators of compromise are observed

Current SOC L1 decision: **Monitor the activity and escalate only if recurrence, allowed traffic, or service impact is observed.**

---

## 11. Final Analyst Note

SOC investigated firewall alert **CS-01 — DNS DDOS Attack**. Logs show inbound UDP traffic from external source IP **104.168.46.10** to internal destination IP **10.0.2.26** on destination port **53/DNS**. The source IP is associated with **HostPapa**, categorized as **Data Center/Web Hosting/Transit**, located in the **United States**.

Splunk review confirmed **269 events** matching the DNS DDoS threat signature. All observed events were **blocked** by the firewall. No evidence from the provided logs indicates successful traffic delivery, internal host compromise, or service impact.

Assessment: **Suspicious inbound DNS DDoS activity blocked by firewall. No immediate action required at this time. Continue monitoring and escalate if repeated activity, allowed traffic, multiple source IPs, or DNS server impact is observed.**

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
