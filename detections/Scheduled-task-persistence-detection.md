# Scheduled Task Persistence Detection

## Event ID

`4698` — A Scheduled Task Was Created

## Objective

Identify newly created Windows scheduled tasks that may be used for persistence or unauthorized recurring execution.

## KQL Query

```kql
SecurityEvent
| where EventID == 4698
| where EventData contains "SOC-LAB-PERSISTENCE"
| project TimeGenerated, Account, Computer, Activity, EventData
| sort by TimeGenerated desc
```

## Findings

The query returned a scheduled task creation event associated with SOC-LAB-PERSISTENCE.
The event showed the affected computer, the Windows activity description, and the scheduled task event data.

![Privileged group membership change detected in Azure Log Analytics](../screenshots/privileged-group-membership-results.png)

## Analyst Assessment

Scheduled tasks are commonly used for legitimate automation, but they can also be abused to maintain persistence on a system.
Because the query identified creation of the SOC-LAB-PERSISTENCE scheduled task, the activity should be reviewed to determine whether the task was expected and authorized.

## Recommended Response

Review the scheduled task name and configuration.

Identify the account associated with the task creation event.

Inspect the command or program configured to run.

Determine whether the scheduled task was expected and authorized.

Remove or disable the task if it is determined to be unauthorized.
