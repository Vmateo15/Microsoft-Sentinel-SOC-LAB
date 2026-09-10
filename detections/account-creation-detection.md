# New User Account Creation Detection

## Event ID

`4720` — A User Account Was Created

## Objective

Identify newly created Windows user accounts that may require investigation to determine whether the account creation was expected and authorized.

## KQL Query

```kql
SecurityEvent
| where EventID == 4720
| project TimeGenerated, Account, TargetAccount, Computer, Activity
| sort by TimeGenerated desc
```

## Findings

The query returned user account creation events for the account SOC-LAB-USER.
The events showed the account that performed the action, the newly created target account, the affected computer, and the Windows activity description.

## Analyst Assessment
New user account creation can be legitimate administrative activity, but unexpected account creation may indicate unauthorized access or persistence.
The account creation events should be reviewed to determine whether the new account was expected and approved.

## Recommended Response
Verify who created the new account.
Confirm whether the account creation was authorized.
Review the privileges and group memberships assigned to the new account.
Check for related authentication or administrative activity around the same timestamp.
Disable or remove the account if it is determined to be unauthorized.
