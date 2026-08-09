# Threat-Hunting-brute-force-persistence
# Incident Case Study: Brute-Force Intrusion and Multi-Stage Persistence on a Finance Workstation

**Incident ID:** #4451  
**Date:** 22 April 2026  
**Severity:** High  
**Affected Hosts:** `npt-ws01` (primary), `npt-srv01` (secondary indicators)  
**Analyst Role:** Incident Response / Threat Hunting  

---

## Overview

This case study documents the end-to-end investigation of a suspected compromise on a finance workstation (`npt-ws01`). The incident began with a user report of repeated login prompts overnight and evolved into a confirmed intrusion involving credential abuse, remote execution, multiple persistence mechanisms, and indicators of lateral movement.

The investigation was conducted using Microsoft Sentinel (KQL-based hunting), leveraging device logon, process, network, file, and registry telemetry. The analysis followed NIST SP 800-61 guidelines for incident handling and mapped attacker behaviors to the MITRE ATT&CK framework.

The goal of this write-up is to demonstrate a structured, analyst-driven approach to detecting, analyzing, and responding to a realistic intrusion scenario.

---

## Initial Alert and Scope Definition

### User Report

- **Received:** 22 April 2026, 09:14 UTC  
- **Reporter:** Mark Smith, Finance  
- **Affected Machine:** `npt-ws01`  
- **Reported Symptom:**  
  > “My machine was throwing login prompts at me through the night. I ignored it and went back to sleep. Seems fine this morning. Can someone take a look?”

The ticket did not specify the exact time the login prompts began. To ensure full coverage of the suspicious window, the investigation time range was set from:

- **Start:** 21 April 2026, 18:00 UTC  
- **End:** 22 April 2026, 08:00 UTC  

This window captured overnight activity while allowing buffer time before and after the user’s reported experience.

---

## Step 1: Authentication Anomaly – Identifying Suspicious Logons

### Objective

Determine whether the reported login prompts were part of normal activity or indicated unauthorized access attempts.

### Approach

The first step was to review authentication events on `npt-ws01` using the `DeviceLogonEvents` table. The query focused on:

- Successful and failed logons.
- Network and RemoteInteractive logon types (commonly abused in remote attacks).
- Accounts, source IPs, and devices involved in repeated logons.

**KQL Query:**

```kql
let start_time = datetime(2026-04-21T18:00:00Z);
let end_time = datetime(2026-04-22T08:00:00Z);
let HostInQuestion = "npt-ws01";
DeviceLogonEvents
| where Timestamp between (start_time .. end_time)
| where DeviceName =~ HostInQuestion
| where ActionType in~ ("LogonSuccess", "LogonFailed")
| where LogonType in~ ("Network", "RemoteInteractive")
| where isnotempty(RemoteIP) or isnotempty(RemoteDeviceName)
| summarize
    TotalEvents = count(),
    SuccessfulLogons = countif(ActionType =~ "LogonSuccess"),
    FailedLogons = countif(ActionType =~ "LogonFailed"),
    FirstSeen = min(Timestamp),
    LastSeen = max(Timestamp),
    SourceDevices = make_set_if(RemoteDeviceName, isnotempty(RemoteDeviceName)),
    SourceIPs = make_set_if(RemoteIP, isnotempty(RemoteIP))
    by DeviceName, AccountDomain, AccountName, LogonType
| order by SuccessfulLogons desc, FailedLogons desc
```

<--IMAGE-->

**Caption suggestion:** Aggregated view of logon events on `npt-ws01` by account, showing successful and failed attempts, source IPs, and logon types.

### Findings

- Multiple accounts attempted to log on to `npt-ws01` during the selected time window.
- The `helpdesk` account stood out with **10 successful logons**, far more than other accounts.
- The pattern of repeated logons, especially from remote sources, was consistent with credential abuse or brute-force activity.

This justified drilling deeper into the `helpdesk` account’s activity.

---

## Step 2: Source IP Analysis – Internal vs External Access

### Objective

Identify where the successful `helpdesk` logons originated from and determine whether they were legitimate.

### Approach

The results from the previous query were expanded to inspect the source IPs associated with successful `helpdesk` logons.

<--IMAGE-->

**Caption suggestion:** Detailed view of successful `helpdesk` logons on `npt-ws01`, showing source IP addresses.

### Findings

Two distinct source IPs were observed:

- `10.3.0.10` – an internal IP within the corporate subnet (`10.3.0.x`).
- `20.110.92.50` – a public IP with no known relationship to the organization.

The presence of successful logons from an external IP to a workstation using a shared service account (`helpdesk`) was highly suspicious and indicated possible unauthorized remote access.

---

## Step 3: Process Activity – Detecting Suspicious Execution

### Objective

Determine whether the suspicious logons led to malicious activity on the endpoint, such as execution of unusual processes or commands.

### Approach

Using `DeviceProcessEvents`, the investigation focused on processes executed under the `helpdesk` account on `npt-ws01` during the same time window.

**KQL Query:**

```kql
let start_time = datetime(2026-04-21T18:00:00.00Z);
let end_time = datetime(2026-04-22T08:00:00.00Z);
let HostInQuestion = "npt-ws01";

DeviceProcessEvents
| where TimeGenerated between (start_time .. end_time)
| where DeviceName == HostInQuestion
| where AccountName == "helpdesk"
| project Timestamp, FileName, ProcessCommandLine, InitiatingProcessFileName
| sort by Timestamp asc
```

<--IMAGE-->

**Caption suggestion:** Process events for the `helpdesk` account on `npt-ws01`, highlighting unusual executions.

### Findings

Two notable entries were observed. One involved `WindowsUpdate.exe` executed from an unusual location (`C:\Windows\Temp\`) and initiated via remote WMI rather than a local interactive session.

To better understand the execution chain, the query was refined to focus on `WindowsUpdate.exe`:

```kql
let start_time = datetime(2026-04-21T18:00:00.00Z);
let end_time = datetime(2026-04-22T08:00:00.00Z);
let HostInQuestion = "npt-ws01";

DeviceProcessEvents
| where TimeGenerated between (start_time .. end_time)
| where DeviceName == HostInQuestion
| where AccountName == "helpdesk"
| where ProcessCommandLine has "WindowsUpdate.exe"
| project Timestamp,
          Child       = FileName,
          ChildCmd    = ProcessCommandLine,
          Parent      = InitiatingProcessFileName,
          ParentCmd   = InitiatingProcessCommandLine,
          Grandparent = InitiatingProcessParentFileName
| sort by Timestamp asc
```

<--IMAGE-->

**Caption suggestion:** Process tree showing the execution chain leading to `WindowsUpdate.exe`.

### Findings

The full execution chain was:

- `svchost.exe` → `wmiprvse.exe` → `cmd.exe` → `WindowsUpdate.exe`

This sequence is consistent with:

- Remote WMI execution (`wmiprvse.exe`) used to spawn `cmd.exe`.
- A command issued to run `WindowsUpdate.exe` from a non-standard location.

This behavior strongly suggested that an external actor had established command-and-control (C2) activity and was issuing remote commands on `npt-ws01`.

---

## Step 4: Network Activity – Identifying Command-and-Control Indicators

### Objective

Validate the C2 hypothesis by examining outbound network connections associated with the suspicious process activity.

### Approach

Using `DeviceNetworkEvents`, the investigation reviewed successful outbound connections initiated by processes running under the `helpdesk` account on `npt-ws01`.

**KQL Query:**

```kql
let start_time = datetime(2026-04-21T18:00:00.00Z);
let end_time = datetime(2026-04-22T08:00:00.00Z);
let HostInQuestion = "npt-ws01";

DeviceNetworkEvents
| where TimeGenerated between (start_time .. end_time)
| where DeviceName == HostInQuestion
| where ActionType == "ConnectionSuccess"
| where InitiatingProcessAccountName == "helpdesk"
| project TimeGenerated, DeviceName, RemoteIP, ActionType, RemoteUrl
```

<--IMAGE-->

**Caption suggestion:** Network connections from `npt-ws01` under the `helpdesk` account, showing destination IPs and URLs.

### Findings

Among the connections, one URL stood out:

- `updates.abordasync.website`

This domain resolved to the same public IP observed earlier (`20.110.92.50`). The domain name and its association with the suspicious activity indicated it was likely being used as a C2 endpoint.

---

## Step 5: File Activity – Hashing the Malicious Payload

### Objective

Obtain file hashes for the malicious `WindowsUpdate.exe` payload to support blocking, hunting, and future detection.

### Approach

Using `DeviceFileEvents`, the investigation searched for file creation events matching `WindowsUpdate.exe` in `C:\Windows\Temp\`.

**KQL Query:**

```kql
let start_time = datetime(2026-04-21T18:00:00.00Z);
let end_time = datetime(2026-04-22T08:00:00.00Z);
let HostInQuestion = "npt-ws01";

DeviceFileEvents
| where TimeGenerated between (start_time .. end_time)
| where DeviceName == HostInQuestion
| where ActionType == "FileCreated"
| where FolderPath contains "C:\\Windows\\Temp\\WindowsUpdate.exe"
| project Timestamp, FileName, FolderPath, SHA1, SHA256, MD5, InitiatingProcessFileName
| sort by Timestamp asc
```

<--IMAGE-->

**Caption suggestion:** File creation event for `WindowsUpdate.exe` in `C:\Windows\Temp\`, including file hashes.

### Findings

The query confirmed the creation of `WindowsUpdate.exe` in `C:\Windows\Temp\` and returned its hashes (SHA1, SHA256, MD5). These hashes were recorded for use in:

- EDR/XDR blocklists.
- Hunting queries across the environment.
- Sharing with threat intelligence or internal detection engineering teams.

---

## Step 6: Registry Activity – Detecting Persistence via Run Key

### Objective

Determine whether the attacker established persistence by modifying registry keys that execute at user logon.

### Approach

Using `DeviceRegistryEvents`, the investigation searched for registry key creation events on `npt-ws01` during the incident window.

**KQL Query:**

```kql
let start_time = datetime(2026-04-21T18:00:00.00Z);
let end_time = datetime(2026-04-22T08:00:00.00Z);
let HostInQuestion = "npt-ws01";

DeviceRegistryEvents
| where TimeGenerated between (start_time .. end_time)
| where DeviceName == HostInQuestion
| where ActionType == "RegistryKeyCreated"
| project TimeGenerated, DeviceName, RegistryKey, InitiatingProcessCommandLine, InitiatingProcessFileName, InitiatingProcessFolderPath
```

<--IMAGE-->

**Caption suggestion:** Registry key creation events on `npt-ws01`, highlighting the malicious Run key.

### Findings

A suspicious registry modification was identified:

```text
reg add HKCU\Software\Microsoft\Windows\CurrentVersion\Run /v WindowsHealthCheck /t REG_SZ /d C:\Windows\Temp\WindowsUpdate.exe /f
```

Key details:

- **Registry Path:** `HKCU\Software\Microsoft\Windows\CurrentVersion\Run`
- **Value Name:** `WindowsHealthCheck`
- **Data:** `C:\Windows\Temp\WindowsUpdate.exe`

This is the per-user Run key, meaning any executable listed here is launched automatically each time that user logs on. This represented the first persistence mechanism installed by the attacker.

---

## Step 7: Additional Process Activity – Scheduled Task and Service Persistence

### Objective

Identify any additional persistence mechanisms, such as scheduled tasks or Windows services, that could ensure continued access.

### Approach

Using `DeviceProcessEvents`, the investigation searched for command lines referencing the malicious file path `Windows\Temp\WindowsUpdate`.

**KQL Query:**

```kql
let start_time = datetime(2026-04-21T18:00:00.00Z);
let end_time = datetime(2026-04-22T08:00:00.00Z);
let HostInQuestion = "npt-ws01";

DeviceProcessEvents
| where TimeGenerated between (start_time .. end_time)
| where DeviceName == HostInQuestion
| where ProcessCommandLine contains "Windows\\Temp\\WindowsUpdate"
```

<--IMAGE-->

**Caption suggestion:** Process events showing creation of scheduled tasks and services tied to `WindowsUpdate.exe`.

### Findings

Two highly suspicious command lines were observed.

#### 1. Scheduled Task Persistence

```text
schtasks /create /tn GoogleUpdaterTask /tr C:\Windows\Temp\WindowsUpdate.exe /sc daily /st 09:00 /f
```

This command:

- Creates a scheduled task named `GoogleUpdaterTask`.
- Executes `WindowsUpdate.exe` from `C:\Windows\Temp\` daily at 09:00.
- Uses `/f` to force-overwrite any existing task with that name.

Indicators of malicious intent:

- **Name spoofing:** Labeled as a “Google” task but runs a generic `WindowsUpdate.exe`.
- **Suspicious location:** Legitimate updaters do not run from `C:\Windows\Temp\`.
- **Force flag:** Suggests automated, scripted deployment.
- **Daily recurrence:** Ensures durability across reboots.

This aligns with **MITRE ATT&CK T1053.005 – Scheduled Task/Job**.

#### 2. Windows Service Persistence

```text
sc.exe create WindowsHealthSvc "binPath= C:\Windows\Temp\WindowsUpdate.exe" "start= auto" "DisplayName= Windows Health Service"
```

This command:

- Creates a new Windows service named `WindowsHealthSvc`.
- Sets it to auto-start at boot.
- Displays as “Windows Health Service” in `services.msc`.

Indicators of malicious intent:

- **No legitimate counterpart:** Microsoft does not ship a “Windows Health Service” with this name or binary.
- **Same payload:** Reuses `C:\Windows\Temp\WindowsUpdate.exe`, confirming a second persistence layer.
- **Masquerading:** The name is designed to appear benign to defenders.

This aligns with **MITRE ATT&CK T1543.003 – Create or Modify System Process: Windows Service**.

---

## Step 8: Local Account Creation – Backdoor Admin Account

### Objective

Check whether the attacker created new local accounts to maintain privileged access.

### Approach

Using `DeviceProcessEvents`, the investigation searched for `net.exe` or `net1.exe` usage to create or modify user accounts.

<--IMAGE-->

**Caption suggestion:** Process events showing creation of the `nexus_admin` account and addition to the local Administrators group.

### Findings

The following commands were observed:

```text
cmd.exe /c net user nexus_admin ******** /add
```

Subsequently, `nexus_admin` was added to the local Administrators group.

This behavior is consistent with:

- **MITRE ATT&CK T1136.001 – Local Account**.
- Creation of a backdoor administrative account for persistent, privileged access.

---

## Incident Summary

- **Ticket:** #4451  
- **Date/Time (UTC):** 22 April 2026, ~04:30–06:00  
- **Affected Hosts:** `npt-ws01` (primary), `npt-srv01` (secondary indicators)  
- **Severity:** High (confirmed intrusion with persistence and lateral movement indicators)  

### Timeline of Events (Reconstructed)

| Time (UTC) | Activity                                                                 | Evidence                                      |
|------------|--------------------------------------------------------------------------|-----------------------------------------------|
| ~04:30     | Attacker logs on via `helpdesk` account from `20.110.92.50` (LogonType 3) | `DeviceLogonEvents`                           |
| ~04:32     | Remote WMI execution spawns `cmd.exe` to run `WindowsUpdate.exe`         | `DeviceProcessEvents` (parent: `wmiprvse.exe`) |
| ~04:33     | Malicious `WindowsUpdate.exe` dropped in `C:\Windows\Temp\`              | `DeviceFileEvents` (SHA256: `20cef6...`)      |
| ~04:35     | C2 beaconing to `updates.abordasync.website` over HTTPS (443)            | `DeviceNetworkEvents`                         |
| ~04:40     | Persistence via Registry Run Key (`WindowsHealthCheck`)                  | `DeviceRegistryEvents`                        |
| ~04:42     | Persistence via Scheduled Task (`GoogleUpdaterTask`)                     | `DeviceProcessEvents` (`schtasks.exe`)        |
| ~04:44     | Persistence via Windows Service (`WindowsHealthSvc`)                     | `DeviceProcessEvents` (`sc.exe`)              |
| ~04:46     | Backdoor account `nexus_admin` created and added to Administrators       | `DeviceProcessEvents` (`net user`)            |
| ~04:50+    | Indicators of lateral movement toward `npt-srv01`                        | Alert evidence (multiple ATT&CK techniques)   |

---

## MITRE ATT&CK Mapping

| Tactic            | Technique(s)                                                              | Evidence                                                   |
|-------------------|---------------------------------------------------------------------------|------------------------------------------------------------|
| Initial Access    | Valid Accounts (T1078)                                                    | `helpdesk` account logon from external IP                  |
| Execution         | Command and Scripting Interpreter (T1059), WMI (T1047)                    | `cmd.exe` via `wmiprvse.exe`                               |
| Persistence       | Registry Run Keys (T1547.001), Scheduled Task (T1053.005), Create Service (T1543.003) | `WindowsHealthCheck`, `GoogleUpdaterTask`, `WindowsHealthSvc` |
| Defense Evasion   | Masquerading (T1036)                                                      | `WindowsUpdate.exe`, `GoogleUpdaterTask` naming            |
| Credential Access | Local Account (T1136.001)                                                 | `nexus_admin` creation                                     |
| Command and Control | Application Layer Protocol (T1071.001)                                  | `updates.abordasync.website`                               |
| Lateral Movement  | Remote Services (T1021)                                                   | Indicators of movement to `npt-srv01`                      |

---

## Impact Assessment

- **Confidentiality:** Attacker gained interactive access to a finance workstation and potentially a server.
- **Integrity:** Multiple persistence mechanisms installed; system integrity compromised.
- **Availability:** No immediate disruption observed, but risk of ransomware deployment or data exfiltration remained high.

---

## Response Plan (NIST 800-61 Aligned)

### 1. Containment

- Isolate host `npt-ws01` from the network.
- Preserve volatile memory (if feasible) before shutdown.
- Disable the `helpdesk` account immediately.
- Disable and remove the local `nexus_admin` account from `npt-ws01`.
- Reset Mark Smith’s (`m.smith`) password and enforce MFA; monitor for suspicious activity.
- Block the attacker IP (`20.110.92.50`) and domain (`updates.abordasync.website`) at the firewall/proxy.
- Add the `WindowsUpdate.exe` SHA256 hash to EDR/XDR blocklists.

### 2. Eradication

On `npt-ws01`:

- **Remove persistence mechanisms:**
  - Registry Run Key:  
    Delete `HKCU\Software\Microsoft\Windows\CurrentVersion\Run\WindowsHealthCheck`
  - Scheduled Task:  
    ```powershell
    schtasks /delete /tn "GoogleUpdaterTask" /f
    ```
  - Windows Service:  
    ```powershell
    sc stop WindowsHealthSvc
    sc delete WindowsHealthSvc
    ```

- **Delete malicious files:**
  - Remove `C:\Windows\Temp\WindowsUpdate.exe`.
  - Quarantine using Defender for Endpoint or manually delete after hash verification.

- **Validate no additional backdoors:**
  - Audit `HKLM` Run keys, startup folders, WMI subscriptions, and other scheduled tasks.
  - Review `net localgroup administrators` to ensure `nexus_admin` is fully removed.

### 3. Recovery (Restore & Validate)

- Re-image or rebuild `npt-ws01` if integrity is in doubt; otherwise, restore from a known-good backup.
- Re-enable accounts only after password reset and MFA enforcement.
- Reconnect hosts to the network only after IOC validation and EDR confirmation of a clean state.
- Monitor closely for 7–14 days post-recovery using Sentinel hunting queries for the same IOCs.

### 4. Post-Incident (Lessons Learned)

Update detection rules in Sentinel to flag:

- Remote logons from external IPs to workstations:
  ```kql
  DeviceLogonEvents
  | where RemoteIP !~ "10.|172.|192."
  ```
- Suspicious `cmd.exe /Q /c start` patterns.
- Creation of scheduled tasks or services by non-admin workflows (`schtasks.exe`, `sc.exe`).
- New local admin accounts created outside of approved change processes.

Conduct a tabletop exercise with the helpdesk and IT teams to review:

- Handling of unusual login prompts.
- Escalation paths for suspected credential abuse.
- Awareness of shared service account risks.

---

## Detection Rationale

The initial detection point was an **anomalous remote logon**: the `helpdesk` account connecting from a public IP to a workstation. This aligns with NIST SP 800-61 guidance to prioritize authentication anomalies as early indicators of compromise.

Subsequent correlation of process, network, file, and registry telemetry confirmed:

- Remote execution via WMI.
- Deployment of a malicious payload.
- Multiple persistence mechanisms.
- Creation of a backdoor administrative account.
- Indicators of lateral movement.

This end-to-end investigation demonstrates how structured KQL hunting, combined with an understanding of attacker techniques, can uncover and validate a multi-stage intrusion.

---

## How This Case Study Demonstrates Analyst Skills

This investigation highlights several key capabilities relevant to security operations and incident response roles:

- **Hypothesis-driven hunting:** Each step began with a clear objective (e.g., “Are there suspicious logons?”, “Did this lead to execution?”).
- **Effective use of telemetry:** Logon, process, network, file, and registry data were combined to reconstruct the attack chain.
- **ATT&CK-aligned thinking:** Behaviors were mapped to recognized techniques, showing familiarity with industry frameworks.
- **Clear, structured reporting:** Findings were organized into a coherent narrative suitable for both technical and non-technical stakeholders.
- **Actionable remediation:** The response plan translates technical findings into concrete containment, eradication, and recovery steps.

This case study can serve as a portfolio piece to demonstrate practical incident response, threat hunting, and security analytics skills in a real-world scenario.
