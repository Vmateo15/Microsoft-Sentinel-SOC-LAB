# Microsoft-Sentinel-SOC-LAB
Hands on SOC Lab using Microsoft Azure, Log Analytics, KQL, and Windows Security Events to detect and investigate brute force, powershell, account creation, privilege escalation, and persistence activity.
## Project Overview

In this lab, I deployed a Windows virtual machine in Microsoft Azure and connected it to a Log Analytics workspace for centralized security monitoring.

I used Windows Security Event logs and Kusto Query Language (KQL) to investigate authentication activity, PowerShell execution, account creation, privilege escalation, and persistence-related behavior.

The goal of this project was to simulate the investigation workflow of a Tier 1 SOC Analyst by reviewing logs, identifying suspicious activity, writing detection queries, and documenting findings.

## Technologies Used

- Microsoft Azure

- Microsoft Sentinel

- Log Analytics Workspace

- Windows Virtual Machine

- Windows Security Event Logs

- Azure Monitor Agent

- Kusto Query Language (KQL)

- PowerShell

## Security Events Investigated

### 1. Brute Force / Failed Logon Attempts

Windows Event ID: `4625`

I investigated repeated failed logon attempts against the Azure Windows VM.

The logs showed multiple external IP addresses repeatedly attempting to authenticate to Administrator-related accounts.

Example KQL:

```kql

SecurityEvent

| where EventID == 4625

| summarize FailedAttempts = count() by IpAddress, Account

| sort by FailedAttempts desc
