# Incident Investigation — Persistence: User Added to Local Administrators

**Incident ID:** 20
**Date:** 23 June 2026
**Severity:** High
**Status:** Resolved
**Analyst:** Mason Lewis

## Executive Summary

A high-severity incident was triggered by Microsoft Sentinel analytics rule "Persistence - User Added to Local Administrators" on the endpoint vm-target-endpo. Investigation confirmed that a user account named hacker was created and immediately added to the local Administrators group, consistent with a post-exploitation persistence technique. The activity was part of a simulated attack chain and was contained within the lab environment.

## Timeline

| Time (UTC) | Event |
|---|---|
| 20:13:14 | Event ID 4720 — New local user account hacker created by labuser |
| 20:13:14 | Event ID 4732 — User hacker added to local Administrators group |
| 20:46:45 | Microsoft Sentinel incident created (ID 20) |
| 21:32:00 | Analyst investigation initiated |
| 21:32:00 | MITRE ATT&CK mapping confirmed: T1098 Account Manipulation |

## Detection

**Rule triggered:** Persistence - User Added to Local Administrators

**KQL query that fired:**
```kql
SecurityEvent
| where EventID == 4732
| where TargetUserName == "Administrators"
| project TimeGenerated, Computer, SubjectUserName, MemberName
```

**Alert details:**
- Event ID: 4732 — A member was added to a security-enabled local group
- Target group: Administrators
- Member added: hacker
- Performed by: vm-target-endpo\labuser
- Computer: vm-target-endpo

## Investigation

### Step 1 — Confirm the alert
Reviewed the raw SecurityEvent log for Event ID 4732. Confirmed hacker was added to the local Administrators group at 20:13:14 UTC.

### Step 2 — Establish context
Queried for related activity in the same timeframe:

```kql
SecurityEvent
| where TimeGenerated between (datetime(2026-06-23T20:00:00Z) .. datetime(2026-06-23T21:00:00Z))
| where EventID in (4625, 4720, 4732, 4688, 4726)
| project TimeGenerated, EventID, Activity, Account, Computer
| order by TimeGenerated asc
```

Results revealed a full attack chain:
1. 10x Event ID 4625 — Failed logon attempts by fakeuser (brute force simulation)
2. Event ID 4720 — User hacker created
3. Event ID 4732 — User hacker added to Administrators
4. Multiple Event ID 4688 — Recon commands: whoami, net user, ipconfig, systeminfo
5. Event ID 4726 — User hacker deleted (cleanup)

### Step 3 — Assess impact
- No lateral movement detected
- No data exfiltration detected
- Account was deleted after simulation
- Activity confined to lab VM vm-target-endpo

### Step 4 — MITRE ATT&CK Mapping

| Technique ID | Technique Name | Evidence |
|---|---|---|
| T1110 | Brute Force | 10x Event ID 4625 from same source |
| T1136.001 | Create Account: Local Account | Event ID 4720 — hacker created |
| T1098 | Account Manipulation | Event ID 4732 — added to Administrators |
| T1059 | Command and Scripting Interpreter | Event ID 4688 — recon commands |

## Findings

This incident represents a simulated post-exploitation persistence technique commonly used by threat actors after gaining initial access to a system. The attacker created a backdoor local account and escalated it to Administrator level, which would allow persistent access even if the original compromise vector was remediated.

In a real incident, this pattern would indicate:
- The attacker already has code execution on the host
- They are establishing persistence for continued access
- They have or are attempting to gain full administrative control

## Recommendations

1. Remove the unauthorised account — net user hacker /delete (completed in simulation)
2. Audit all local administrator group members — identify any other unexpected accounts
3. Review logon events — check for successful logons by hacker before deletion
4. Investigate initial access vector — determine how labuser was able to create local accounts
5. Implement Privileged Identity Management (PIM) — require justification and approval for admin group changes
6. Enable Microsoft Defender for Endpoint — provides additional telemetry and automated response

## Conclusion

The incident was confirmed as a simulated attack chain and successfully detected by Microsoft Sentinel within the expected timeframe. All 5 stages of the attack were detected by corresponding analytics rules. The detection pipeline performed as designed.

**Incident status:** Closed — True Positive (Simulated)
