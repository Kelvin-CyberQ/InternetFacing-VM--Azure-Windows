# InternetFacing VM-Azure Windows (Brute-Force Detection Lab)

## Lab Overview
This lab walks through a real-world style investigation of brute-force login attempts against a Windows virtual machine that was exposed to the internet. By running KQL queries and analyzing Azure Defender telemetry, I reviewed the system’s exposure, login patterns, and possible signs of compromise, while also mapping the activity to the MITRE ATT&CK framework.

## Incident Summary
As part of routine maintenance, the security team reviews VMs in the shared services cluster (responsible for services like DNS, Domain Services, and DHCP) to ensure none have been accidentally exposed to the public internet. The objective is to spot misconfigurations and investigate for possible brute-force login attempts or successful logins coming from external sources.
