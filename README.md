


# 🔐 Brute Force Detection with Microsoft Sentinel

This lab demonstrates the implementation of a brute force detection capability in Microsoft Sentinel, aligned with the incident response lifecycle as defined in NIST Special Publication 800-61 Revision 2: *Computer Security Incident Handling Guide*. The activity focuses on the detection and initial response phases, simulating a scenario in which an adversary attempts unauthorized access via repeated failed logon attempts from a single remote IP address.

---

## 🧭 Objective

The objective of this lab is to establish proactive monitoring within Microsoft Sentinel to detect and analyze brute force activity. The detection mechanism uses Kusto Query Language (KQL) to identify excessive failed logon attempts, and a scheduled analytics rule to generate alerts and incidents for further triage and response.

---

## 🛠️ Tools & Environment

- **SIEM Platform**: Microsoft Sentinel
- **Log Source**: Azure Log Analytics (DeviceLogonEvents table)
- **Query Language**: Kusto Query Language (KQL)
- **Threat Framework Reference**: MITRE ATT&CK – T1110 (Brute Force)

---

## 1. 🧰 Preparation (NIST IR Step 1)

As part of the preparation phase, ensure the following controls and logging mechanisms are in place:

- Microsoft Defender for Endpoint is integrated with Microsoft Sentinel.
- Logging is enabled for sign-in events, including successful and failed logon attempts.
- Sentinel workspace is properly configured with an Analytics Rules engine and connected log sources.
- Access permissions are established for creating and managing scheduled query rules.

---

## 2. 🔎 Detection and Analysis (NIST IR Step 2)

In this stage, I defined a query to detect brute force attempts based on repeated failed logins and then configure an alert rule to automate detection.

### 📊 KQL Detection Logic

```kql
DeviceLogonEvents
| where TimeGenerated >= ago(5h)
| where ActionType == "LogonFailed"
| summarize NumerofFailures = count() by RemoteIP, ActionType, DeviceName
| where NumerofFailures >= 10
```

This query filters for logon failures (`ActionType == "LogonFailed"`) within a 5-hour window. It then groups the results by `DeviceName` and `RemoteIP`, counting the number of failures. If 10 or more failures are observed from a single remote IP to a single host, this suggests potential brute force behavior.


![Screenshot 2025-01-13 182228](https://github.com/user-attachments/assets/741713f3-e1f0-47d3-8e80-a63cf5c489cd)



### 🛎️ Scheduled Analytics Rule Configuration

| **Field**             | **Value**                              |
|-----------------------|----------------------------------------|
| Rule Name             | Brute Force Detection – Failed Logins  |
| Rule Type             | Scheduled query                        |
| Frequency             | Every 5 hours                          |
| Lookup Period         | Last 5 hours                           |
| Trigger Threshold     | Number of results >= 10                  |
| Severity              | Medium                                 |
| MITRE Tactic          | Credential Access                      |
| MITRE Technique       | T1110 – Brute Force                    |
| Entity Mappings       | `DeviceName`, `RemoteIP`, `AccountName` | 
<br>

---

### 🔍 Brute Force Activity Observed

The following table summarizes repeated failed login attempts observed within the last 5 hours, indicating potential brute-force attack behavior against several Azure virtual machines:

| **Remote IP**        | **Failed Attempts**                                | **Target Machine(s)**                             |
|----------------------|----------------------------------------------------|---------------------------------------------------|
| `59.3.82.127`        | 100 (`pkb-mde-test`), 68 (`lois-test-vm-md`)       | `pkb-mde-test`, `lois-test-vm-md`                 |
| `52.234.251.139`     | 26 (`win10-stigs`), 23 (`us-east-pc5`)             | `win10-stigs`, `us-east-pc5`                      |
| `103.215.77.53`      | 16                                                 | `win10-stigs`                                     |
| `116.98.175.64`      | 15                                                 | `linux-target-1.p2zfvso05mlezjev3ck4vqd3kd.cx.internal.cloudapp.net` |
| `223.27.84.67`       | 11                                                 | `cavada-cyber-pc`                                 |
| `80.94.95.15`        | 20, 10                                             | `linux-target-1.p2zfvso05mlezjev3ck4vqd3kd.cx.internal.cloudapp.net` |


![Screenshot 2025-01-06 181511](https://github.com/user-attachments/assets/68b6a810-93a7-4f80-8c0a-0bb386af5138)

- KQL Query to detect failed logins:  
  ```kql
  DeviceLogonEvents
  | where RemoteIP in ("59.3.82.127","52.234.251.139","103.215.77.53","116.98.175.64","223.27.84.67","80.94.95.15")
  | where ActionType != "LogonFailed"

 ```
  **Result:** No successful logins from these IPs were detected.

#### Analysis Steps:
1. **Review Patterns:**
   - Investigated failed login thresholds in Azure AD logs.
   - Identified off-hours timing and suspicious IP geolocations.

2. **Document Findings:**
   - Retained logs detailing the frequency, origin, and targets of failed attempts.

3. **Prioritize:**
   - **High Priority:** Privileged accounts targeted during off-hours.
   - **Low Priority:** Isolated, user-specific failed attempts.

---

### 3️⃣ Containment
#### Immediate Actions:
1. **Device Isolation:**
   - Isolated affected devices using **Microsoft Defender for Endpoint**.

2. **Network Security Group (NSG) Update:**
   - Restricted RDP access to authorized IPs only.
   - Blocked all external IPs linked to failed login attempts.

3. **Anti-Malware Scans:**
   - Performed scans on affected devices for potential compromise.

---

### 4️⃣ Eradication & Recovery
1. **Password Reset:**
   - Reset passwords for targeted accounts.
   - Enforced strong password policies for privileged accounts.

2. **MFA Enforcement:**
   - Enabled multi-factor authentication for all high-value accounts.

3. **Geo-blocking:**
   - Blocked login attempts from high-risk geolocations.

---

### 5️⃣ Post-Incident Activity
1. **Lessons Learned:**
   - Was detection quick and effective?
   - Were privileged accounts adequately protected?

2. **System Improvements:**
   - Adjusted login thresholds for quicker detection.
   - Expanded employee training on password security.

3. **Documentation:**
   - Recorded all findings, actions taken, and future recommendations.
---

### **Step 1: Create-Alert-Rule** 
how to create a alert rule in Microsoft Sentinel , go to Microsoft Sentinel, click on your group, click on configuration, click on Analytics, click create with the + beside it , click scheduled query rule
After clicking **"Scheduled query rule"**, you’ll see the **Analytics rule details** tab. Fill in the following fields:

1. **Name**:  
   - Enter a name for your rule, e.g., **"🔥 Brute Force Attack Detection 🔐"**.

2. **Description**:  
   - Add a brief description of what the rule does, e.g.,  
     *"🔍 This rule detects potential brute-force login attempts based on failed sign-ins exceeding a defined threshold."*

3. **Severity**:  
   - Choose a severity level:
     - **Low** 🟢
     - **Medium** 🟡
     - **High** 🔴 (Recommended for brute force detection)

4. **Tactics**:  
   - Select the **MITRE ATT&CK Tactics** related to brute force:
     - **🎯 Initial Access**
     - **🔑 Credential Access**
      
![Screenshot 2025-01-14 103734](https://github.com/user-attachments/assets/f6558c4d-585b-4e63-b787-1cc071cc0ad0)

5. **Rule type**:  
   - Select **Scheduled 🕒**.

6. **Set rule frequency**:  
   - Choose how often the query should run (e.g., **Every 5 minutes ⏱️**).

7. **Set query results to look back**:  
   - Define the time window for the query (e.g., **Last 1 hour ⏳**).

---

### **Step 2: Add the KQL Query**  
In the **Set rule query** step, paste your KQL query to detect brute-force attempts:  

```kql
DeviceLogonEvents
| where TimeGenerated >= ago(5h)
| where ActionType == "LogonFailed"
| summarize NumberOfFailures = count() by RemoteIP, ActionType, DeviceName
| where NumberOfFailures >= 10s
```
![Screenshot 2025-01-14 111832](https://github.com/user-attachments/assets/b1164c0f-6022-444e-a409-43c1d4e9a579)

- 🛠️ This query filters **sign-in logs** for failed login attempts and identifies unusual patterns.  
- 💡 Adjust thresholds based on your environment (e.g., `> 5 failed attempts`).

---

### **Step 3: Define Incident Settings**  
1. **Create incidents based on alert results**: Ensure this is selected ✅.  
2. **Group alerts into incidents**:  
   - Choose **"🧩 Grouped into a single incident if they share the same entities"** to avoid duplicates.

---

### **Step 4: Add Actions and Automation**  
1. Configure **actions** to trigger when the rule is activated:  
   - Add a **Playbook 🛠️** for automated responses, such as:  
     - Blocking an IP 🚫.  
     - Sending an email to your security team 📧.  
     - Triggering a Teams or Slack notification 💬.  

2. Example Playbook: A Logic App that sends an **email notification 📤** to the SOC.

---

### **Step 5: Review and Enable**  
1. **Review everything** to ensure it’s correct:
   - Name 🔖, description 📝, KQL query 📊, frequency ⏱️, and action settings ⚙️.  

2. Click **"Create"** to enable the rule 🎉.  

---

### **Step 6: Validate Your Rule**  
1. Test the rule by simulating a brute-force attack or using sample logs:
   - Run a script that triggers **failed login attempts** (simulated safely) 🧑‍💻.
   - Replay historical logs using KQL 📜.

2. Verify that alerts are generated 🚨 and incidents are grouped as expected ✅.  
---
## 🚫 **Outcome**
- **Attack Status:** Brute force attempts **unsuccessful**.  
- **Recommendations:** Lockdown NSG rules for all VMs and enforce MFA on privileged accounts.

🎉 **Status:** Incident resolved. No further action required.

---
