# Threat Hunting Queries

Three custom threat hunting queries built in Microsoft Sentinel Hunting, covering Lateral Movement, Persistence, and Discovery tactics.

Threat hunting goes beyond reactive alerting — these queries are run proactively to find evidence of attacker activity that may not have triggered an analytics rule.

## Hunt 1 — Lateral Movement via Network Logon

**Tactic:** Lateral Movement
**MITRE Technique:** T1021 — Remote Services
**Data source:** SecurityEvent (Event ID 4624)

Hunts for user accounts authenticating to multiple computers via network logon (LogonType 3) within the same time window. This pattern is consistent with lateral movement techniques such as Pass the Hash or credential reuse across systems.

```kql
SecurityEvent
| where EventID == 4624
| where LogonType == 3
| where Account !endswith "$"
| where Account != "ANONYMOUS LOGON"
| summarize LogonCount = count(),
            Computers = make_set(Computer),
            FirstSeen = min(TimeGenerated),
            LastSeen = max(TimeGenerated)
    by Account, IpAddress
| where array_length(Computers) > 1
| extend ComputerCount = array_length(Computers)
| project Account, IpAddress, LogonCount, ComputerCount, Computers, FirstSeen, LastSeen
| order by ComputerCount desc
```

**Result in lab:** 0 results — expected, as this is a single-endpoint lab with no lateral movement simulated. In a multi-machine environment this query would surface accounts moving between hosts.

## Hunt 2 — User Account Created Outside Business Hours

**Tactic:** Persistence
**MITRE Technique:** T1136.001 — Create Account: Local Account
**Data source:** SecurityEvent (Event ID 4720)

Hunts for new local user accounts created outside of normal business hours (08:00-18:00). Attackers commonly create backdoor accounts during off-hours to avoid detection by security teams.

```kql
SecurityEvent
| where EventID == 4720
| extend HourOfDay = datetime_part("hour", TimeGenerated)
| where HourOfDay !between (8 .. 18)
| project TimeGenerated, Computer, SubjectUserName,
          TargetUserName, HourOfDay
| order by TimeGenerated desc
```

**Result in lab:** 1 result — the hacker account created during the attack simulation at 20:13 UTC, outside business hours. Confirms the detection logic works correctly.

## Hunt 3 — Reconnaissance Command Burst

**Tactic:** Discovery
**MITRE Technique:** T1087 — Account Discovery
**Data source:** SecurityEvent (Event ID 4688)

Hunts for accounts executing 3 or more reconnaissance commands within a 5-minute window. Attackers commonly run multiple discovery commands in rapid succession immediately after gaining access to understand the environment.

```kql
SecurityEvent
| where EventID == 4688
| where CommandLine has_any ("net user", "net localgroup", "whoami",
                              "ipconfig", "systeminfo", "netstat", "tasklist")
| summarize CommandCount = count(),
            Commands = make_set(CommandLine),
            FirstSeen = min(TimeGenerated),
            LastSeen = max(TimeGenerated)
    by Account, Computer, bin(TimeGenerated, 5m)
| where CommandCount >= 3
| order by CommandCount desc
```

**Result in lab:** 1 result — confirmed hit on the attack simulation.

| Field | Value |
|---|---|
| Account | vm-target-endpo\labuser |
| Computer | vm-target-endpo |
| CommandCount | 3 |
| Commands | whoami.exe, ipconfig.exe /all, systeminfo.exe |
| FirstSeen | 23 Jun 2026 20:13:15 |
| LastSeen | 23 Jun 2026 20:13:15 |

This confirms the recon phase of the simulated attack chain was successfully detected through proactive hunting, complementing the reactive analytics rule that also fired on the same activity.

## Key Difference: Hunting vs Analytics Rules

| | Analytics Rules | Threat Hunting |
|---|---|---|
| Approach | Reactive — alerts when condition met | Proactive — analyst-driven investigation |
| Frequency | Runs automatically on schedule | Run on demand by analyst |
| Output | Incident created automatically | Results reviewed manually |
| Use case | Known patterns, high confidence | Hypothesis-driven, lower confidence |
| SC-200 domain | Configure detection in Sentinel | Perform threat hunting in Sentinel |
