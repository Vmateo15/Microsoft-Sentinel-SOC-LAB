# Suspicious PowerShell Investigation

## Detection

Windows process creation activity — Event ID `4688`

## Summary

A PowerShell process creation event was identified that matched encoded-command detection criteria.

Encoded PowerShell commands can be legitimate, but they may also be used to obscure command execution and should be reviewed.

## Investigation

I reviewed Windows process creation events using Microsoft Azure Log Analytics and KQL.

The investigation included:

- Filtering Event ID 4688 process creation events.
- Identifying PowerShell process execution.
- Searching for `-EncodedCommand` or `-enc` command-line syntax.
- Reviewing the user account associated with the process.
- Reviewing the affected computer.
- Reviewing the PowerShell process path.
- Reviewing the command line.
- Reviewing the parent process information.

## KQL Query

```kql
SecurityEvent
| where EventID == 4688
| where NewProcessName contains "powershell"
| where CommandLine contains "-EncodedCommand" or CommandLine contains "-enc"
| project TimeGenerated, Account, Computer, NewProcessName, CommandLine, ParentProcessName
| sort by TimeGenerated desc
```

## Findings

The query returned a PowerShell process creation event matching the encoded-command detection criteria.

The event included the user account, affected computer, PowerShell process path, command line, and parent process information.

## Analyst Assessment

Encoded PowerShell execution may be legitimate administrative activity, but encoded commands can also be used to obscure potentially suspicious behavior.

The activity should be reviewed to determine whether the command was expected and authorized.

## Recommended Response

Review the full PowerShell command line.

Identify the user account that executed the command.

Review the parent process that launched PowerShell.

Determine whether the activity was expected and authorized.

Investigate related process creation events around the same timestamp.
