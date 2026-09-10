# Brute Force Authentication Detection

## Event ID

`4625` — Failed Logon

## Objective

Identify repeated failed Windows logon attempts that may indicate brute-force activity.

## KQL Query

```kql
SecurityEvent
| where EventID == 4625
| summarize FailedAttempts = count() by IpAddress, Account
| sort by FailedAttempts desc

Findings

The query showed repeated failed authentication attempts against Administrator-related accounts from multiple external IP addresses.

One source IP generated more than 3,000 failed logon attempts, which is highly suspicious and consistent with automated brute-force activity.

Detection Logic

To identify concentrated failed login activity within a short time window, I used:

SecurityEvent
| where EventID == 4625
| summarize FailedAttempts = count() by IpAddress, Account, bin(TimeGenerated, 5m)
| where FailedAttempts >= 10

This flags cases where the same source IP and account combination has 10 or more failed logon attempts within five minutes.

Analyst Assessment

The volume and repetition of failed logon attempts indicate likely automated credential guessing against the exposed Windows system.

Recommended Response

Review the targeted account.
Investigate the source IP address.
Confirm whether any successful logons followed the failed attempts.
Restrict unnecessary remote access.
Enforce strong passwords and account lockout controls.
