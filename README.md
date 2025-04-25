
# 🕵️‍♂️ External Recon: Hunting Internet-Facing Infrastructure

![image](https://github.com/user-attachments/assets/6f7aadc8-e2f5-4925-a836-eaac22423527)



## 📌 Introduction

During routine maintenance, as a security analyst was tasked with identifying any **Virtual Machines (VMs)** in the shared services cluster (DNS, DHCP, Domain Services, etc.) that were mistakenly exposed to the public internet. These machines are critical infrastructure, and their exposure poses serious risks including brute force attacks.  

This guide details how I detected, investigated, and responded to a brute-force login attempt using **KQL (Kusto Query Language)**, and outlines steps to improve security hygiene moving forward.

---

## 📋 Prerequisites  

✅ Microsoft Defender for Endpoint (MDE) onboarded  
✅ Access to Microsoft 365 Defender Advanced Hunting  
✅ Access to logs: `DeviceInfo` and `DeviceLogonEvents`  

---
1️⃣ **Identifying Exposed Devices**

Before executing the detection rules, we must identify devices that are exposed to the internet.

Open PowerShell and run:
```powershell
Invoke-RestMethod -Uri "http://ifconfig.me/ip"
```
Verify the public IP address and check whether the device is exposed.  
(🚨 Devices with a public IP address are at higher risk of cyber threats.)

2️⃣ **Disabling Windows Firewall**

To simulate a vulnerable system, turn off the Windows Firewall:

Open Run (Win + R), type `wf.msc`, and hit Enter.  
Select **Turn Windows Firewall on or off** and disable it for all profiles.

⚠️ *This step is for testing purposes only! Ensure you enable the firewall after completing the lab.*

3️⃣ **Onboarding the VM to Microsoft Defender for Endpoint**

Navigate to the MDE Portal: [security.microsoft.com/machines](https://security.microsoft.com/machines)  
Confirm the VM appears as onboarded.

Check logs using Advanced Hunting with the following KQL query:
--------------------------

# 🛡️ Detecting and Investigating Brute Force Activity on Exposed Virtual Machines 

---

## 🔍 1️⃣ Identifying Exposed Devices  

We began by searching for machines exposed to the internet.

**KQL Query:**
```kql
DeviceInfo
| where DeviceName contains "yusuf"
| where IsInternetFacing == 1
| order by Timestamp desc
```
![image](https://github.com/user-attachments/assets/b3c24e53-17c3-418d-9d78-2dced2eb7d0d)



📆 **Last Detected Exposure:** `April 17, 2025 – 8:34:46 PM`  

---

## 🧠 2️⃣ Scenario Overview  

Based on known weaknesses (e.g., lack of account lockout on legacy systems), it was observed in a real-world environment that:  
**“Devices exposed to the internet were subjected to brute-force attacks due to excessive failed login attempts without triggering security mechanisms.”**
---

## 📈 3️⃣ Detecting Brute Force Attempts  

**Objective:** Identify failed logins from external sources.

**KQL Query:**
```kql
DeviceLogonEvents
| where AccountName contains "yusuf"
| where LogonType has_any("Network", "Interactive", "RemoteInteractive", "Unlock")
| where ActionType == "LogonFailed"
| where isnotempty(RemoteIP)
| summarize Attempts = count() by ActionType, RemoteIP, DeviceName
| order by Attempts
```
![image](https://github.com/user-attachments/assets/97895a2e-262b-40d3-b198-e7430e2720df)

💥 Several unauthorized attempts detected targeting `user: yusuf`.



📉 I also saw **13 failed login attempts** using **unknown usernames**, strongly suggesting brute-force activity.
![image](https://github.com/user-attachments/assets/685e7b89-6c23-42e3-9196-4fccb9f20718)





---


## ✅ 4️⃣ Verifying Successful Logins  

I checked whether any of the attacks led to successful access.

**Suspicious IP List:**
```kql
let suspiciousIPs = dynamic([
  "111.68.102.195", "39.154.135.4", "10.0.8.8", "10.0.8.6",
  "117.254.36.103", "46.105.132.55", "203.135.57.98",
  "196.189.185.249", "186.10.248.54", "37.255.251.17", "211.140.151.7"
]);
DeviceLogonEvents
| where DeviceName contains "yusuf"
| where LogonType has_any("Network", "Interactive", "RemoteInteractive", "Unlock")
| where ActionType == "LogonSuccess"
| where RemoteIP has_any(suspiciousIPs)
| summarize Attempts = count() by ActionType, RemoteIP, DeviceName, LogonType, AccountName
```

🔓 **20 successful logins** from external or suspicious IPs using `user: yusuf`.
![image](https://github.com/user-attachments/assets/3fd11be5-a506-47d7-a10b-d4bb0a1054ac)
---
I reviewed all login attempts and analyzed the suspicious locations based on the associated IP addresses.
![image](https://github.com/user-attachments/assets/e820c1f9-404d-44cc-b51f-5c64195d5550)


---

## 🕵️ 5️⃣ MITRE ATT&CK Mapping  

I mapped our findings to the MITRE ATT&CK framework for standardized threat understanding.

### 🎯 TTPs Identified:
| Tactic               | Technique | ID       | Evidence |
|----------------------|-----------|----------|----------|
| Credential Access    | Brute Force | T1110 | Multiple failed login attempts from external IPs |
| Initial Access       | Valid Accounts | T1078 | Repeated successful logins from suspicious IPs |
| Initial Access       | Exploit Public-Facing App | T1190 | Device exposed to the internet |

---

## 🧯 6️⃣ Response Actions  

Based on the findings, we recommend the following immediate remediations:

🚫 **Block all malicious IPs** on the firewall or NSG  
🔐 **Reset Yusuf’s account password**  
🔐 **Enable MFA** for all administrative accounts  
🔒 **Harden NSGs** to restrict RDP to internal IPs only  
🚨 **Enable account lockout policies** on all exposed systems  
🧪 **Isolate compromised VMs** for forensic analysis  
🧭 **Review logs for lateral movement** indicators  

---

## 📝 7️⃣ Documentation  

**Summary:**  
- Device “yusuf” was exposed to the internet.  
- Multiple failed login attempts suggest brute force attempts.  
- Successful logins from suspicious IPs indicate a possible credential compromise.  

---

## 🚀 8️⃣ Improvements & Lessons Learned  

### 🔍 What We Can Do Better:
- Set up alert rules for brute-force thresholds and anomalous remote access.  
- Regularly review NSGs and firewall rules for exposure.  
- Conduct proactive hunts across internet-facing assets.

---

## 📊 Analysis & Insights  

✅ **Internet-exposed devices must be continuously monitored.**  
✅ **Legacy systems without lockout policies are high-risk.**  
✅ **Successful brute-force login can lead to persistent threats.**

---

## 🔔 Conclusion  

This investigation demonstrates the real-world impact of misconfigured infrastructure and the importance of active threat hunting using **KQL** and **Microsoft Defender for Endpoint**.  

By identifying internet-exposed VMs and monitoring for suspicious logon patterns, we significantly reduce the risk of unauthorized access and lateral movement.

---
