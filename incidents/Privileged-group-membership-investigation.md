# Privileged Group Membership Change Investigation

## Detection

Windows local security group membership change — Event ID `4732`

## Summary

A local security group membership change was identified through Windows Security Event logging.

Changes to privileged local groups can be legitimate administrative activity, but unexpected additions to groups such as `Builtin\Administrators` may indicate privilege escalation or unauthorized administrative access.

## Investigation

I reviewed Windows security group membership change events using Microsoft Azure Log Analytics and KQL.

The investigation included:

- Filtering for Event ID 4732.
- Identifying the account that performed the group membership change.
- Reviewing the target local group.
- Reviewing the member that was added.
- Reviewing the affected computer.
- Reviewing related account creation or administrative activity around the same timestamp.

## KQL Query

```kql
SecurityEvent
| where EventID == 4732
| project TimeGenerated, Account, TargetAccount, MemberName, Computer, Activity
| sort by TimeGenerated desc
```
## Findings

The query returned local security group membership change events.
The results showed changes involving local groups including Builtin\Users and Builtin\Administrators.
The events included the account that performed the action, the target group, the affected computer, and the Windows activity description.

![Privileged Group Membership Results](../screenshots/privileged-group-membership-results.png)

## Analyst Assessment

Changes to privileged local groups can be legitimate administrative activity, but unexpected additions to Builtin\Administrators may indicate privilege escalation or unauthorized access.
The membership change should be reviewed to determine whether it was expected and authorized.

## Recommended Response

Verify which account performed the group membership change.

Confirm whether the change was authorized.

Review the account or member added to the group.

Check for related account creation or administrative activity around the same timestamp.

Remove unauthorized privileged group membership if confirmed.
