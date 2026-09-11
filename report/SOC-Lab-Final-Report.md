# Microsoft Sentinel SOC Lab - Final Report

## Executive Summary

This project demonstrates a hands on Security Operations Center (SOC) investigation workflow using Microsoft Azure, Log Analytics, Windows Security Event logs, KQL, and Microsoft Sentinel.

A Windows virtual machine was monitored through a Log Analytics workspace. Security events were investigated to identify failed authentication activity, suspicious PowerShell execution, new user account creation, privileged group membership changes, and scheduled task creation.

## Environment

- Microsoft Azure
- Windows Virtual Machine
- Log Analytics Workspace
- Microsoft Sentinel
- Azure Monitor Agent
- Windows Security Event Logs
- Kusto Query Language (KQL)
- PowerShell

## Security Events Investigated

### Event ID 4625 = Failed Logon

Repeated failed Windows logon attempts were detected against Administrator related accounts from multiple external IP addresses.

One source IP generated more than 3,000 failed authentication attempts.

The activity was consistent with automated credential guessing behavior.

### Event ID 4688 = Process Creation

A PowerShell process creation event was identified using encoded command syntax.

The activity was reviewed because encoded PowerShell commands can be used to obscure command execution.

### Event ID 4720 = User Account Creation

A Windows user account named `SOC-LAB-USER` was identified through Security Event logging.

The event was reviewed to determine whether the account creation was expected and authorized.

### Event ID 4732 = Local Group Membership Change

A local security group membership change was identified.

The results included membership changes involving `Builtin\Users` and `Builtin\Administrators`.

Unexpected additions to privileged groups may indicate privilege escalation or unauthorized administrative access.

### Event ID 4698 = Scheduled Task Creation

A Windows scheduled task named `SOC-LAB-PERSISTENCE` was identified.

Scheduled tasks can be used legitimately but may also be abused to maintain persistence on a system.

## Brute Force Investigation

Failed authentication activity was analyzed using KQL.

The investigation included:

- Counting failed logon attempts by IP address and account.
- Reviewing first seen and last seen timestamps.
- Examining detailed Event ID 4625 records.
- Reviewing LogonType, failure reason, status, and substatus.
- Investigating a high volume source IP.
- Creating detection logic for repeated failed logons within a five minute window.

One investigated source IP was:

`79.140.30.89`

The IP lookup associated the address with JSC Ufanet and geolocated it to Ufa, Russian Federation.

IP geolocation alone does not confirm malicious intent.

## Brute Force Detection Logic

```kql
SecurityEvent
| where EventID == 4625
| summarize FailedAttempts = count() by IpAddress, Account, bin(TimeGenerated, 5m)
| where FailedAttempts >= 10
```

This detection identifies source IP and account combinations with 10 or more failed Windows logon attempts within five minutes.

## Alert Configuration

A custom Azure Monitor log search alert was configured.

 Alert name:

Possible Brute Force Attack

Severity:

Warning

The alert was designed to detect 10 or more failed Windows logon attempts from the same source IP and account within a five-minute window.

## Analyst Assessment

The failed authentication activity showed high volume and repeated attempts against Administrator related accounts, indicating likely automated credential guessing.
The PowerShell, account creation, privileged group membership, and scheduled task events demonstrated additional Windows behaviors that a SOC analyst may investigate when reviewing potentially suspicious activity.
Each event was analyzed using Windows Security Event logs and KQL to determine the relevant account, computer, process, group, or task information.

## Recommended Response

For suspicious activity identified during investigation:

Review affected accounts.

Validate whether activity was authorized.

Investigate related authentication and process activity.

Review privileged group membership changes.

Inspect scheduled task configurations.

Restrict unnecessary remote access.

Apply strong password and account lockout controls.

Disable unauthorized accounts or scheduled tasks if confirmed.

## Skills Demonstrated

SIEM investigation

Microsoft Sentinel

Azure Log Analytics

KQL querying

Windows Event ID analysis

Brute force detection

PowerShell investigation

Account creation investigation

Privilege escalation investigation

Persistence investigation

Alert rule configuration

SOC documentation

## Conclusion

This lab demonstrated the process of collecting Windows Security Event logs, investigating suspicious activity, writing KQL detection queries, configuring an alert, analyzing findings, and documenting recommended response actions.

The project reflects a practical Tier 1 SOC analyst workflow for reviewing and documenting security events in a controlled lab environment.
