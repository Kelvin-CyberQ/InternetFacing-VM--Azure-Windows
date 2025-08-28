## <img width="651" height="496" alt="image" src="https://github.com/user-attachments/assets/cf93f4a2-8600-471a-8c60-3cb71b734ec8" />



## Lab Overview
During this lab, I simulated a real-world threat hunt focused on detecting brute-force login attempts against an internet-facing Windows virtual machine. The investigation centered on windows-target-1, which had been unintentionally exposed to the internet for several days.

## Objectives
* Identify brute-force login attempts targeting the VM
* Determine whether any unauthorized access was successful
* Map findings to MITRE ATT&CK techniques
* Recommend remediation and hardening steps

## Investigation Timeline & KQL Queries
# Windows-target-1 has remained exposed to the internet for several days.
```kql
DeviceInfo
| where DeviceName == "windows-target-1"
| where IsInternetFacing == true
| order by Timestamp desc
```
<img width="975" height="300" alt="image" src="https://github.com/user-attachments/assets/4e6cd795-65f9-4ad7-9ca9-b7d605bbf40b" />

---

# Multiple unauthorized actors attempted to brute-force logins against the target machine.
```kql
DeviceLogonEvents
| where DeviceName == "windows-target-1"
| where LogonType has_any("Network", "Interactive", "RemoteInteractive", "Unlock")
| where ActionType == "LogonFailed"
```
<img width="728" height="416" alt="image" src="https://github.com/user-attachments/assets/a2ce399d-6820-4df7-9a0e-76a97cad160a" />

---

## The five IP addresses responsible for the highest number of failed login attempts were unsuccessful in gaining access to the VM.
```kql
let RemoteIPsInQuestion = dynamic(["59.3.82.127","103.191.179.40", "45.150.128.246", "88.214.25.20", "204.157.179.2"]);
DeviceLogonEvents
| where DeviceName == "windows-target-1"
| where LogonType has_any("Network", "Interactive", "RemoteInteractive", "Unlock")
| where ActionType == "Logonfailed"
| where RemoteIP has_any(RemoteIPsInQuestion)
```
# Query no results.

---

# In the past 30 days, the only successful remote network logins were from the labuser account, totaling 13 logons.
```kql
DeviceLogonEvents
| where DeviceName == "windows-target-1"
| where LogonType == "Network"
| where ActionType == "LogonSuccess"
| where AccountName == "labuser"
| summarize count()
```

---

# The labuser account recorded zero failed logon attempts, confirming that it was not targeted by brute-force activity and making a one-time password guess highly unlikely.
```kql
DeviceLogonEvents
| where DeviceName == "windows-target-1"
| where LogonType == "Network"
| where ActionType == "LogonFailed"
| where AccountName == "labuser"
| summarize count()
```
---


# All successful logins for the labuser account were reviewed by IP address, and no unusual or unexpected locations were identified. The activity originated from Japan and appeared normal.
```kql
DeviceLogonEvents
| where DeviceName == "windows-target-1"
| where LogonType == "Network"
| where ActionType == "LogonSuccess"
| where AccountName == "labuser"
| summarize Logincount = count() by DeviceName, ActionType, AccountName, RemoteIP
```
<img width="856" height="411" alt="image" src="https://github.com/user-attachments/assets/bcdff9ba-ea4a-4e57-8fc1-f084b6d507a8" />

---

# MITRE ATT&CK Mapping

* T1110 – Brute Force
* T1078 – Valid Accounts
* T1190 – Exploit Public-Facing Application
* T1587.001 – Develop Capabilities: Exploit Code

---

# Response & Mitigation

* Restricted RDP access by tightening NSG rules (no public internet exposure).
* Implemented account lockout policies.
* Enforced multi-factor authentication (MFA) for remote access.

# Lessons Learned

This exercise demonstrated how exposure of a VM to the public internet can quickly attract brute-force attempts. Proactive monitoring with KQL queries and alignment with MITRE ATT&CK improves detection and incident response.


