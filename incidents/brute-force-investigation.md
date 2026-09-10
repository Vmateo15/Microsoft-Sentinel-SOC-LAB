# Brute Force Investigation

## Detection

Windows failed logon activity — Event ID `4625`

## Summary

Repeated failed Windows logon attempts were identified against Administrator-related accounts from multiple external IP addresses.

The volume and repetition of failed authentication attempts were consistent with automated brute-force activity.

## Investigation

I reviewed failed logon events using Microsoft Azure Log Analytics and KQL.

The investigation included:

- Counting failed logon attempts by source IP address and account.
- Reviewing first-seen and last-seen timestamps.
- Examining detailed Event ID 4625 records.
- Reviewing LogonType, failure reason, status, and substatus fields.
- Investigating a high-volume source IP address.
- Creating detection logic for repeated failed logons within a five-minute window.

## IP Enrichment

One high-volume source IP investigated was:

`79.140.30.89`

The IP lookup showed the address was associated with JSC Ufanet and geolocated to Ufa, Russian Federation.

IP geolocation alone does not confirm malicious intent, but it provided additional context for the investigation.

## Detection Logic

```kql
SecurityEvent
| where EventID == 4625
| summarize FailedAttempts = count() by IpAddress, Account, bin(TimeGenerated, 5m)
| where FailedAttempts >= 10
```

## Alert Configuration

A custom Azure Monitor log-search alert was configured with the name:
Possible Brute Force Attack

The alert was designed to identify 10 or more failed Windows logon attempts from the same source IP and account within a five-minute window.
Severity: Warning

## Analyst Assessment

The repeated failed logon activity, high attempt volume, and concentration against Administrator-related accounts indicate likely automated credential-guessing activity.
No conclusion about successful compromise was made based only on the failed logon evidence.

## Recommended Response

Review the targeted accounts.

Investigate the source IP addresses.

Check whether successful logons followed the failed attempts.

Restrict unnecessary remote access.

Enforce strong passwords and account lockout controls.
