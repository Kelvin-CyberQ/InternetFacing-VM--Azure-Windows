# InternetFacing VM-Azure Windows (Brute-Force Detection Lab)

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




