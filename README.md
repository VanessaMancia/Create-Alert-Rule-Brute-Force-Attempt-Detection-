# 🔐 Brute Force Detection with Microsoft Sentinel

This lab demonstrates the implementation of a brute force detection capability in Microsoft Sentinel, aligned with the incident response lifecycle as defined in NIST Special Publication 800-61 Revision 2: *Computer Security Incident Handling Guide*. The activity focuses on the detection and initial response phases, simulating a scenario in which an adversary attempts unauthorized access via repeated failed logon attempts from a single remote IP address.

---

## 🧽 Objective

The objective of this lab is to establish proactive monitoring within Microsoft Sentinel to detect and analyze brute force activity. The detection mechanism uses Kusto Query Language (KQL) to identify excessive failed logon attempts, and a scheduled analytics rule to generate alerts and incidents for further triage and response.

---

## 🛠️ Tools & Environment

* **SIEM Platform**: Microsoft Sentinel
* **Log Source**: Azure Log Analytics (DeviceLogonEvents table)
* **Query Language**: Kusto Query Language (KQL)
* **Threat Framework Reference**: MITRE ATT\&CK – T1110 (Brute Force)

---

## 1. 🪰 Preparation 

Ensure the following controls and logging mechanisms are in place:

* Microsoft Defender for Endpoint is integrated with Microsoft Sentinel.
* Logging is enabled for sign-in events, including successful and failed logon attempts.
* Sentinel workspace is properly configured with Analytics Rules and connected log sources.
* Access permissions are granted to create and manage scheduled query rules.

---

## 2. 🔎 Detection and Analysis 

### 📊 KQL Detection Logic

```kql
DeviceLogonEvents
| where TimeGenerated >= ago(5h)
| where ActionType == "LogonFailed"
| summarize NumberOfFailures = count() by RemoteIP, ActionType, DeviceName
| where NumberOfFailures >= 10
```

This query filters for logon failures within a 5-hour window, groups them by remote IP and device, and flags those with 10 or more failures as potential brute force attempts.

![Screenshot 2025-01-13 182228](https://github.com/user-attachments/assets/741713f3-e1f0-47d3-8e80-a63cf5c489cd)

---

### 🕎️ Scheduled Analytics Rule Configuration

| **Field**         | **Value**                             |
| ----------------- | ------------------------------------- |
| Rule Name         | Brute Force Detection – Failed Logins |
| Rule Type         | Scheduled query                       |
| Frequency         | Every 5 hours                         |
| Lookup Period     | Last 5 hours                          |
| Trigger Threshold | Number of results >= 10               |
| Severity          | Medium                                |
| MITRE Tactic      | Credential Access                     |
| MITRE Technique   | T1110 – Brute Force                   |
| Entity Mappings   | DeviceName, RemoteIP, AccountName     |

---

### 🔍 Brute Force Activity Observed

| **Remote IP**    | **Failed Attempts**                          | **Target Machine(s)**                     |
| ---------------- | -------------------------------------------- | ----------------------------------------- |
| `59.3.82.127`    | 100 (`pkb-mde-test`), 68 (`lois-test-vm-md`) | `pkb-mde-test`, `lois-test-vm-md`         |
| `52.234.251.139` | 26 (`win10-stigs`), 23 (`us-east-pc5`)       | `win10-stigs`, `us-east-pc5`              |
| `103.215.77.53`  | 16                                           | `win10-stigs`                             |
| `116.98.175.64`  | 15                                           | `linux-target-1.cx.internal.cloudapp.net` |
| `223.27.84.67`   | 11                                           | `cavada-cyber-pc`                         |
| `80.94.95.15`    | 20, 10                                       | `linux-target-1.cx.internal.cloudapp.net` |

![Screenshot 2025-01-06 181511](https://github.com/user-attachments/assets/68b6a810-93a7-4f80-8c0a-0bb386af5138)

```kql
DeviceLogonEvents
| where RemoteIP in ("59.3.82.127","52.234.251.139","103.215.77.53","116.98.175.64","223.27.84.67","80.94.95.15")
| where ActionType != "LogonFailed"
```

**Result:** No successful logins from these IPs were detected.

#### Analysis Steps:

1. **Review Patterns:**

   * Investigated thresholds and IP geolocations.
2. **Document Findings:**

   * Captured logs and flagged anomalous activity.
3. **Prioritize:**

   * High: Privileged accounts targeted off-hours.
   * Low: Isolated failures on standard user accounts.

---

## 3️⃣ Containment

### Immediate Actions:

1. **Device Isolation:** Used Microsoft Defender to isolate impacted systems.
2. **NSG Update:** Restricted RDP access and blocked attacker IPs.
3. **Malware Scans:** Checked affected systems for compromise.

---

## 4️⃣ Eradication & Recovery

* Reset passwords and enforced strong policies.
* Enabled MFA for all privileged accounts.
* Geo-blocked login attempts from high-risk countries.

---

## 5️⃣ Post-Incident Activity

* **Lessons Learned:** Assessed speed and coverage of detection.
* **System Improvements:** Adjusted detection logic and user training.
* **Documentation:** Captured full IR process and findings.

---

## ✨ Step-by-Step: Create Alert Rule in Sentinel

1. Go to Sentinel → Workspace → Configuration → Analytics → ➕ Create → **Scheduled query rule**

### Rule Details

| Field         | Example Value                           |
| ------------- | --------------------------------------- |
| Name          | 🔥 Brute Force Attack Detection 🔐      |
| Description   | Detects excessive failed sign-ins       |
| Rule Type     | Scheduled                               |
| Frequency     | Every 5 minutes                         |
| Lookup Period | Last 1 hour                             |
| Severity      | 🔴 High                                 |
| Tactics       | 🎯 Initial Access, 🔑 Credential Access |

![Screenshot 2025-01-14 103734](https://github.com/user-attachments/assets/f6558c4d-585b-4e63-b787-1cc071cc0ad0)

### Detection Query

```kql
DeviceLogonEvents
| where TimeGenerated >= ago(5h)
| where ActionType == "LogonFailed"
| summarize NumberOfFailures = count() by RemoteIP, ActionType, DeviceName
| where NumberOfFailures >= 10
```

![Screenshot 2025-01-14 111832](https://github.com/user-attachments/assets/b1164c0f-6022-444e-a409-43c1d4e9a579)

---

### Automation & Validation

* Enable incident creation and grouping by entity.
* Add a playbook to automate responses: block IPs, send alerts, isolate hosts.
* Simulate brute-force attempts or use historical data to test.

---

## ❌ Outcome

* **Attack Status:** Unsuccessful brute force attempts.
* **Recommendations:** Lock down NSG rules and enforce MFA.

🎉 **Status:** Incident resolved. No further action required.

---
