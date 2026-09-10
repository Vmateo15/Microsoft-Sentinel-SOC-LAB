# Suspicious PowerShell Execution Detection

## Event ID

`4688` — A New Process Has Been Created

## Objective

Identify potentially suspicious PowerShell execution by reviewing Windows process creation events and filtering for PowerShell commands that use encoded command execution.

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

The event included the user account, computer name, PowerShell process path, command line, and parent process information for investigation.

## Analyst Assessment

Encoded PowerShell commands can be used legitimately, but they are also commonly associated with obfuscated or suspicious command execution.

Because the query identified PowerShell execution using encoded-command syntax, the activity should be reviewed to determine whether the command was expected and authorized.

## Recommended Response

Review the full PowerShell command line.

Identify the user account that executed the command.

Review the parent process that launched PowerShell.

Determine whether the activity was expected or authorized.

Investigate related process creation events around the same timestamp.
