# Possible-logon-breach


# Report Title: Possible logon breach

### **Date of Report**

2025-12-07

### **Reported By**

Olaitan Ajibola (SOC Analyst)

## Severity Level

Critical 

## **Summary Of Findings**

There was a brute-force attack against the domain user "Administrator," which led to a successful logon to MTS-DC. The logon was initiated from two workstations named "Windows7" and "b_307," both associated with the IP address 91[.]238[.]181[.]92. This IP address originated from France, with a 100% abuse confidence level, and has been reported over 11,000 times. Although the logon was successful, no malicious activity or persistence has been detected. Device processes and network events were reviewed and appear normal with no issues identified.

**Investigation Timeline (UTC)**

December 3rd 

- 2025-12-03 12:28:46 PM: Successful network logon using the Administrator account from a workstation named "Windows7."
- 2025-12-03 12:29:17 PM: Successful network logon from the same IP (91[.]238[.]181[.]92) but from a different workstation named "b_307."

**Who, What, When, Where, Why, How**

- **WHO:**
    - Compromised Account: Administrator
    - Source Host/IPs: 91.238.181.92 (France), with aliases "Windows7" and "b_307," tagged with 100% abuse confidence.
- **WHAT:**
    - Successful network and remote login to the domain controller using the Administrator account.
- **WHEN:**
    - 2025-12-03 (times as above).
- **WHERE:**
    - Primary Target: Domain controller MTS-DC (mts-dc.mts.local).
- **WHY (Likely Intent):**
    - Unknown, as no malicious activity was observed. Potential motive could include stealing passwords, creating unauthorized processes, or establishing persistence.
- **HOW (Tactics, Techniques, and Procedures - TTPs):**
    - Use of valid/stolen credentials for the administrator account (MITRE ATT&CK T1078 – Valid Accounts).

**MITRE ATT&CK Techniques:**

- T1078 – Valid Accounts (use of domain administrator credentials from external IPs).

**Impact Assessment**

- **Affected Assets:**
    - Domain controller MTS-DC (critical infrastructure).
    - Administrator account (high-privilege credential).
- **Observed Impact:**
    - Multiple successful external logons using the Administrator account.
- **Risk:**
    - High risk of attacker establishing persistence within the environment, potentially leading to account compromise and exposure or loss of sensitive documents and records.

**Recommendations:**

- Immediate containment of the domain controller and revocation of all active sessions associated with the compromised account.
- If applicable, block the IP address 91[.]238[.]181[.]92 at the firewall or perimeter security.
- Revoke all active sessions for the administrator account and the password to prevent persistence and enforce Multi-Factor Authentication (MFA) on all accounts.
- If possible, restrict domain controller logons to a pre-approved IP range or trusted networks.
- Block work station named "Windows7" and "b_307," 

**Attachment and Evidence** 

XDR Alert 

<img width="1417" height="699" alt="image (4)" src="https://github.com/user-attachments/assets/e0823bc4-0f02-4379-8e30-51b1dacf409d" />



Ipdbabuse

<img width="683" height="524" alt="image (5)" src="https://github.com/user-attachments/assets/ba2f86f7-761e-4ea5-beaf-f15ff84d6078" />



Network Logon

<img width="1197" height="623" alt="image (6)" src="https://github.com/user-attachments/assets/a599c73f-463f-4743-9e64-a294ab2f6f4a" />

IOCs
91[.]238[.]181[.]92
workstations named "Windows7" and "b_307," 


KQL Used

DeviceLogonEvents

|where RemoteDeviceName == "B_114"

//|where ActionType =="LogonSuccess"

|project TimeGenerated, Timestamp, DeviceName, RemoteDeviceName, AccountName, LogonType, AccountDomain, RemoteIP

DeviceProcessEvents

| where TimeGenerated between (datetime(2025-12-03 12:15) .. datetime(2025-12-03 15:00) )

| where DeviceName contains "MTS-dc" and AccountName == "administrator"

|project Timestamp, FileName, FolderPath, ProcessCommandLine, InitiatingProcessFileName, InitiatingProcessCommandLine , InitiatingProcessRemoteSessionIP

DeviceFileEvents

| where TimeGenerated between (datetime(2025-12-03 12:15) .. datetime(2025-12-03 13:00) )

| where DeviceName contains "MTS-dc" and InitiatingProcessAccountName == "administrator"

DeviceNetworkEvents

| where TimeGenerated between (datetime(2025-12-03 12:15) .. datetime(2025-12-03 14:00) )

| where DeviceName == "mts-dc.mts.local" and InitiatingProcessAccountName == "administrator"

| where ActionType == "ConnectionSuccess"

| sort by Timestamp asc

DeviceRegistryEvents

| where TimeGenerated between (datetime(2025-12-03 12:15) .. datetime(2025-12-03 14:00) )

| where DeviceName contains "MTS-dc" and InitiatingProcessAccountName == "administrator"


DeviceProcessEvents 
| where TimeGenerated between (datetime(2025-12-03 12:15) .. datetime(2025-12-03 15:00) )

| where DeviceName contains "MTS-dc" and AccountName == "administrator"

//| where ProcessCommandLine has_any('powershell -e', 'certutil -url', 'rundll32', 'wmic', 'mshta')

| project Timestamp, DeviceName, AccountName, FileName, InitiatingProcessCommandLine, ProcessCommandLine, ProcessTokenElevation

## Report Status:

Open
