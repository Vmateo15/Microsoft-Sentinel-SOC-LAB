# Lab Setup

## Environment

This SOC lab was built in Microsoft Azure using a Windows virtual machine connected to a Log Analytics workspace for centralized security monitoring.

## Components

- Microsoft Azure
- Windows Virtual Machine
- Log Analytics Workspace: `LAW-soc-lab`
- Microsoft Sentinel
- Azure Monitor Agent
- Windows Security Event Logs
- Kusto Query Language (KQL)
- PowerShell

## Log Collection

Windows Security Event logs were collected from the Azure virtual machine and sent to the Log Analytics workspace using the Azure Monitor Agent.

The `SecurityEvent` table was used to investigate Windows authentication, process creation, account creation, local group membership changes, and scheduled task activity.

## Security Events Used

- Event ID 4625 = Failed Logon
- Event ID 4688 = Process Creation
- Event ID 4720 = User Account Creation
- Event ID 4732 = Member Added to a Security-Enabled Local Group
- Event ID 4698 = Scheduled Task Created

## Investigation Workflow

The lab followed a SOC-style investigation process:

1. Collect Windows Security Event logs.
2. Query the logs using KQL.
3. Identify potentially suspicious activity.
4. Review event details and supporting fields.
5. Document findings and analyst assessment.
6. Develop detection logic.
7. Recommend appropriate response actions.

## Lab Scope

All activity documented in this repository was performed in a controlled lab environment for cybersecurity education and SOC analyst training
