# Microsoft Sentinel Detection Lab

A cloud-native SIEM detection lab built in Microsoft Azure to develop hands-on threat detection, KQL querying, and incident response skills relevant to SOC analyst roles.

---

## Overview

This lab simulates a real-world attack chain against a Windows 11 endpoint and detects it using Microsoft Sentinel. All detections are custom-built KQL analytics rules mapped to MITRE ATT&CK techniques.

**Attack chain simulated:**
1. Brute force login attempts (Credential Access)
2. New local user account created (Persistence)
3. User added to local Administrators group (Privilege Escalation)
4. Reconnaissance commands executed (Discovery)
5. Account lockout triggered (Impact)

---

## Architecture
┌─────────────────────────────────────────────┐

│           Azure (rg-soc-lab)                │

│                                             │

│  ┌──────────────────┐                       │

│  │  vm-target-      │  NSG: RDP restricted  │

│  │  endpoint        │  to analyst IP only   │

│  │  Windows 11 Pro  │                       │

│  │  Standard D2s v3 │                       │

│  └────────┬─────────┘                       │

│           │ Azure Monitor Agent (AMA)        │

│           │ v1.43.0.0                        │

│           ▼                                 │

│  ┌──────────────────┐                       │

│  │  Data Collection │  Collects:            │

│  │  Rule (DCR)      │  - Windows Security   │

│  │  dcr-sysmon-     │    Events (Security!*)│

│  │  ingest          │  - Sysmon Events      │

│  └────────┬─────────┘                       │

│           │                                 │

│           ▼                                 │

│  ┌──────────────────┐                       │

│  │  Log Analytics   │  law-soc-sentinel     │

│  │  Workspace (LAW) │                       │

│  └────────┬─────────┘                       │

│           │                                 │

│           ▼                                 │

│  ┌──────────────────┐                       │

│  │  Microsoft       │  5 custom analytics   │

│  │  Sentinel        │  rules + workbook     │

│  └──────────────────┘                       │

└─────────────────────────────────────────────┘

## Technologies Used

| Technology | Purpose |
|---|---|
| Microsoft Azure | Cloud platform |
| Microsoft Sentinel | SIEM / SOAR |
| Log Analytics Workspace | Log storage and KQL querying |
| Azure Monitor Agent (AMA) | Log collection from VM |
| Data Collection Rule (DCR) | Define what logs to collect |
| Sysmon (SwiftOnSecurity config) | Enhanced endpoint telemetry |
| Windows Security Event Log | Authentication and account events |
| KQL (Kusto Query Language) | Detection rules and threat hunting |
| MITRE ATT&CK | Detection framework mapping |
| Network Security Group (NSG) | Network access control |
| Azure Logic Apps | SOAR playbook automation |

## Lab Components

### Infrastructure
- **Resource Group:** rg-soc-lab (UK South)
- **Virtual Machine:** vm-target-endpoint — Windows 11 Pro, Standard D2s v3 (2 vCPUs, 8 GiB RAM)
- **VNet:** vm-target-endpoint-vnet — Address space 10.0.0.0/16
- **Subnet:** default — 10.0.0.0/24
- **NSG:** vm-target-endpoint-nsg — RDP (port 3389) restricted to analyst IP only, DenyAllInbound default rule
- **Log Analytics Workspace:** law-soc-sentinel
- **Microsoft Sentinel:** Deployed on top of LAW

### Data Collection
- **Azure Monitor Agent (AMA)** v1.43.0.0 installed on VM via DCR association
- **DCR:** dcr-sysmon-ingest — Custom XPath rules collecting:
  - Security!* — All Windows Security events
  - Microsoft-Windows-Sysmon/Operational* — All Sysmon events
- **Sysmon** installed with SwiftOnSecurity sysmon-config for high-quality endpoint telemetry

## Detection Rules

Five custom KQL analytics rules built in Microsoft Sentinel, each running every 5 minutes:

### 1. Brute Force — Multiple Failed Logons
**Severity:** Medium | **MITRE:** T1110 — Brute Force

Detects 5 or more failed login attempts from a single source IP within 1 hour.

```kql
SecurityEvent
| where EventID == 4625
| where TimeGenerated > ago(1h)
| summarize FailedAttempts = count(),
            TargetAccounts = make_set(TargetUserName),
            FirstAttempt = min(TimeGenerated),
            LastAttempt = max(TimeGenerated)
    by IpAddress, Computer
| where FailedAttempts >= 5
```

### 2. Persistence — User Added to Local Administrators
**Severity:** High | **MITRE:** T1098 — Account Manipulation

Detects any user being added to the local Administrators group.

```kql
SecurityEvent
| where EventID == 4732
| where TargetUserName == "Administrators"
| project TimeGenerated, Computer, SubjectUserName, MemberName
```

### 3. Persistence — New Local User Account Created
**Severity:** Medium | **MITRE:** T1136.001 — Create Account: Local Account

Detects creation of new local user accounts.

```kql
SecurityEvent
| where EventID == 4720
| project TimeGenerated, Computer, SubjectUserName, TargetUserName
```

### 4. Execution — Suspicious Reconnaissance Commands
**Severity:** Medium | **MITRE:** T1059 — Command and Scripting Interpreter

Detects execution of common post-exploitation reconnaissance commands.

```kql
SecurityEvent
| where EventID == 4688
| where CommandLine has_any ("net user", "net localgroup", "whoami", "ipconfig", "systeminfo")
| project TimeGenerated, Computer, Account, NewProcessName, CommandLine
```

### 5. Impact — User Account Lockout
**Severity:** Medium | **MITRE:** T1110.001 — Brute Force: Password Guessing

Detects user account lockout events which may indicate a brute force attack.

```kql
SecurityEvent
| where EventID == 4740
| project TimeGenerated, Computer, TargetUserName, SubjectUserName
```

## Attack Simulation

The following PowerShell script was run on the victim VM to generate real attack telemetry:

```powershell
# Enable audit policies
auditpol /set /subcategory:"Logon" /success:enable /failure:enable
auditpol /set /subcategory:"Process Creation" /success:enable /failure:enable
auditpol /set /subcategory:"User Account Management" /success:enable /failure:enable
auditpol /set /subcategory:"Security Group Management" /success:enable /failure:enable
reg add "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System\Audit" /v ProcessCreationIncludeCmdLine_Enabled /t REG_DWORD /d 1 /f

# Simulate brute force (Event ID 4625)
$pw = ConvertTo-SecureString "wrongpassword" -AsPlainText -Force
$cred = New-Object System.Management.Automation.PSCredential("fakeuser", $pw)
1..10 | ForEach-Object { try { Start-Process cmd -Credential $cred -ErrorAction Stop } catch {} }

# Create backdoor account (Event ID 4720)
net user hacker Password123! /add

# Escalate to admin (Event ID 4732)
net localgroup administrators hacker /add

# Run recon (Event ID 4688)
whoami
net user
net localgroup administrators
ipconfig /all
systeminfo

# Clean up (Event ID 4726)
net user hacker /delete
```

## Automated Response

Built a Logic App playbook and automation rule to automatically respond to High severity incidents:

- **Playbook:** Sentinel-Auto-Comment-High-Severity
- **Logic:** When a High severity incident is created, automatically adds an analyst comment
- **Automation Rule:** Trigger-Playbook-High-Severity — fires on incident creation where severity equals High
- **Result:** Automated triage comment added within seconds of incident creation

## Threat Hunting

Three custom proactive hunt queries built in Microsoft Sentinel Hunting:

| Query | Tactic | MITRE | Result |
|---|---|---|---|
| Hunt - Lateral Movement via Network Logon | Lateral Movement | T1021 | 0 results — single endpoint lab |
| Hunt - User Account Created Outside Business Hours | Persistence | T1136.001 | 1 result — hacker account at 20:13 |
| Hunt - Reconnaissance Command Burst | Discovery | T1087 | 1 result — whoami, ipconfig, systeminfo |

## Incidents Generated

The attack simulation generated 42 incidents across all 5 detection rules.

| Incident | Severity | MITRE Technique |
|---|---|---|
| Brute Force - Multiple Failed Logons | Medium | T1110 |
| Persistence - User Added to Local Administrators | High | T1098 |
| Persistence - New Local User Account Created | Medium | T1136.001 |
| Execution - Suspicious Reconnaissance Commands | Medium | T1059 |
| Impact - User Account Lockout | Medium | T1110.001 |

See incidents/investigation-001.md for a full incident investigation writeup.

## Screenshots

| Screenshot | Description |
|---|---|
| 00-resource-group | Resource group rg-soc-lab created |
| 01-log-analytics-workspace | LAW law-soc-sentinel created |
| 02-sentinel-activated | Microsoft Sentinel activated |
| 03-vm-overview | VM vm-target-endpoint running |
| 04-ama-installed | AMA v1.43.0.0 Provisioning succeeded |
| 05-dcr-data-sources | DCR collecting Sysmon and Security events |
| 06-ama-heartbeat | Heartbeat query confirming AMA working |
| 07-security-events-flowing | Security events flowing into Sentinel |
| 08-attack-simulation | PowerShell attack simulation output |
| 09-all-analytics-rules | All 5 detection rules enabled |
| 10-workbook-dashboard | Detection dashboard with live data |
| 11-incidents-list | 42 incidents generated |
| 12-incident-investigation | Incident investigation with MITRE mapping |
| 20-playbook-created | Playbook active in Sentinel |
| 21-automation-rule | Automation rule configured |
| 22-playbook-comment | Automated comment added to incident |

## Key Lessons Learned

See lessons-learned.md for a full writeup of issues encountered and how they were resolved. Key issues included AMA installation changes, DCR missing Security events, Defender portal filter hiding incidents, and Logic App authentication across tenants.

## SC-200 Relevance

Built while preparing for the SC-200 Microsoft Security Operations Analyst exam. This lab directly covers:

- Configure Microsoft Sentinel data collection
- Create and manage analytics rules
- Investigate and respond to incidents
- Perform threat hunting in Microsoft Sentinel
- Automate responses with playbooks

## Certifications

CompTIA A+, CompTIA Security+, AZ-900, Splunk Power User

## Author

Mason Lewis

LinkedIn: https://www.linkedin.com/in/mason-lewis-0abba6295/
