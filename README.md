# **dfirtriage**

Digital forensic acquisition tool for Windows-based incident response.   [DOWNLOAD EXE](https://github.com/travisfoley/dfirtriage/blob/master/binary/DFIRtriage-v6-pub.exe)

# How to Use

To run, drop dfirtriage.exe on the target or connected USB drive and execute with admin rights, `-h` for help.

___

# **DFIRTriage v6.0 User's Manual**

## Description

This document outlines the functionality and proper use of the DFIRtriage tool. Also included is detailed information to help with analysis of the output. The goal is to equip the Incident Responder with the tools needed to gather and analyze data quickly.

## About

DFIRtriage is an incident response tool designed to provide the Incident Responder with rapid host data. Upon execution, select host data and information will be gathered and placed into the execution directory. DFIRtriage may be ran from a USB drive or executed remotely on the target host.

## What’s new in v6.0?


**Output restructure**

- Reorganized the output files and directories in a more logical manner

**Logging total run time**

- added total run time to the run log file (runlog.txt)

**Bug fixes**

- non-zero exit status 1 when ntuser.dat is missing from a user profile directory
- now only attempts to pull locked files from user profile directories where an ntuser.dat file exists

**Added arguments for individual system artifacts**

- breaking up the system file acquisition option into individual artifacts cuts down on the total file size when you are only wanting one and not all 3.
` -sdb, --srumdb` (srum database), `-hf, --hiberfil` (hiberfil.sys), `-p, --pagefile` (pagefile.sys)

**Improved executable file hashing capabilites**

- Hashes all .dll and .exe files on the OS drive. Recommended to disable A/V realtime scanning when using the hash arguments.

**Running process details**

- improved the running process information to include PID, PPID, process name, command executed to launch the process, and files opened by the process.

**Bitlocker key dump**

- to dump OS drive bitlocker key information you can now pass the `-bl` or `--bitlocker` argument on the command line

**Memory acquisition no longer default action**

- to acquire memory you must pass the `-m` or `--memory` argument on the command line

**User prompt removed from end of execution**

- no longer need to designate the `-hl` or `--headless` argument to bypass the ending user prompt, script will run to completion, clean up, and exit with no user intervention.

**Windows firewall**

- dumping Windows firewall configuration
- default parsing of key firewall events
- pulling full firewall event log (EVTX) with `-elf` argument

**Improved user account report**

- creating a more detailed user account report that includes account SIDs and last logon time.

**dtfind - admin requirement removed**

- removed the requirement for admin permissions to run dtfind

**3rd party tools update**

- core.ir toolset has been updated with current tool versions

**External IP**

- Grabs endpoint external IP address

**PowerShell**

- Now acquires Powershell history for commands ran by SYSTEM
- Full Powershell EVTX file is now pulled with `-elf`, `--evtlogfiles` argument

**System Information**

- New system and networked data collected in WLAN report


**Event Logs**

- Acquires virtual drive (VHD) drive mount events from VHD operations event log
- New event log events added to default collection.
- Pulling full Powershell and Firewall event logs with `-elf`, `--evtlogfiles` argument

**Application event log**

- WER events for application crashes only (1001)
- User logging on with temporary profile (1511)
- Cannot create profile using temporary profile (1518)
- Application error events, similar to WER/1001. These include full path to faulting EXE/Module (1000)
- Application crash/hang events, similar to WER/1001. These include full path to faulting EXE/Module (1002)

**Security event log**

- Replay attack (4649)
- Kerberos TGT request (4768)
- Kerberos service ticket requested (4769)
- Kerberos service ticket renewal (4770)
- Kerberos pre-authentication failed (4771)
- Workstation locked (4800)
- Workstation unlocked (4801)
- Screensaver was invoked (4802)
- Screensaver was dismissed (4803)
- An attempt was made to change an account's password (4723)
- A user account was disabled (4725)
- A user account was deleted (4726)
- Group creations (4727, 4731, 4754)
- Group member removals (4729, 4733, 4757)
- Group changes (4735, 4737, 4755, 4764)
- A user account was locked out (4740)
- A computer account was created (4741)
- A computer account was changed (4742)
- A computer account was deleted (4743)
- SID history (4765, 4766)
- A user account was unlocked (4767)
- ACL set on accounts (4780)
- System time was changed (4616)
- Kerberos service ticket was denied (4821)
- NTLM authentication failed (4822, 4823)
- Kerberos pre-authentication failed (4824)
- Certificate Services received a certificate request (4886)
- Certificate Services approved a certificate request (4887)
- A Certificate Services template was updated (4899)
- Certificate Services template security was updated (4900)
- Kerberos policy was changed (4713)
- An operation was performed on an object (4662)

**Powershell event log**

- PowerShell executes block activity (4103)
- Remote Command (4104)

**Windows Firewall event log**

Local Modifications (Levels 0, 2, 4) (2004, 2005, 2006, 2009, 2033)


## Dependencies

The tool repository contains the full toolset required for proper execution and is packed into a single a single file named `core.ir`. This `.ir` file is the only required dependency of DFIRtriage when running in Python and should reside in a directory named data, (ie. `./data/core.ir`). The compiled version of DFIRtriage has the full toolset embedded and does not require the addition of the `./data/core.ir` file. 


## Operation

DFIRtriage acquires data from the host on which it is executed.  Behind the keyboard executions are best conducted from a USB device.  For acquisitions of remote hosts, the DFIRtriage files will need to be copied to the target, then executed via remote shell. (ie. SSH or PSEXEC)

## PSEXEC Usage

_WARNING: Do not use PSEXEC arguments to pass credentials to a remote system for authentication. Doing so will send your username and password across the network in the clear._

**The following steps should be taken for proper usage of PSEXEC**

1.  Map a network drive and authenticate with an account that has local administrative privileges on the target host.

> You can used this mapped connection to copy DFIRtriage to the target.

2.  We can now shovel a remote shell to the target host using PSEXEC.
    
    `psexec \\target\_host cmd`
    
3.  You now have a remote shell on the target. All commands executed at this point are done so on the target host.
    

**Usage**

1.  Once the remote shell has been established on the target you can change directory to the location of the extracted DFIRtriage.exe file and execute.
    
2.  Memory acquisition does not occur by default. To dump memory, pass the following argument:  `-m, --memory` 
    
3.  DFIRtriage must be executed with Administrative privileges.
    

## OUTPUT ANALYSIS

Once complete, press enter to cleanup the output directory. If running the executable, the only data remaining with be a zipped archive of the output as well as DFIRtriage.exe. If running the Python code directly only DFIRtriage python script and a zipped archive of the output are left.

## OUTPUT FOLDER

The output folder name includes the target hostname and a date/time code indicating when DFIRtriage was executed. The date/time code format is `YYYYMMDDHHMMSS`.

# ARTIFACTS LIST

The table below provides a general listing of the type of information and artifacts gathered by DFIRtriage v6.0.

|   |   |
|---|---|
|**Artifacts**|**Description**|
|Memory|Raw image acquisition|
|System information|Build, version, installed patches, bitlocker & shadow copy info, etc.|
|Current date and time|Current system date and time|
|Prefetch|Collects and parses prefetch data|
|PowerShell command history|Gathers PowerShell command history for all users including the SYSTEM account|
|User activity|HTML report of recent user activity|
|File hash|Calculates an MD5, SHA-1, or SHA-256 hash of all EXE and DLL files on the OS partition|
|Network information|Network configuration, routing tables, connections, etc.|
|DNS cache entries|List of complete DNS cache contents|
|ARP table information|List of complete ARP cache contents|
|NetBIOS information|Active NetBIOS sessions, transferred files, etc.|
|Windows Update Log|Gathers update information and builds Windows update log|
|Windows Event Logs|Gathers and parses multiple Windows Event logs|
|Process information|Processes, PID, image path, and full command line|
|List of remotely opened files|Files on target system opened by remote hosts|
|List of hidden directories|List of all hidden directories on the system partition|
|Alternate Data Streams|List of files containing alternate data streams|
|Complete file listing|Full list of all files on the system partition|
|List of scheduled tasks|List of all configured scheduled tasks|
|Hash of all collected triage data|SHA-256 hash of all data collected by DFIRtriage|
|Local & domain user account information|Usernames, profile paths, account SID, etc.|
|Autorun information|All autorun locations and content|
|Logged on users|All users currently logged on to target system|
|Registry hives|Pulls down all registry hives|
|USB artifacts|Collects data needed to parse USB usage info|
|Browser History|Aggregated report of browser history|
| SRUM database  | System usage information collected by SRUM (System Usage Resource Monitor) | 


## OUTPUT REFERENCE

This section of the manual is provided to offer guidance during analysis of the DFIRtriage output.  The below information is only provided as a guideline as it would not be practical to detail every possible use of this data. The bulk of analysis will depend on context and the analysis skills of the Incident Responder.

| Output Directory Root           | Analysis Notes                                                                                                                                          |
|---------------------------------|---------------------------------------------------------------------------------------------------------------------------------------------------------|
| ForensicImages\                 | See information below for content details.                                                                                                              |
| LiveResponseData.zip            | Compressed triage collection data                                                                                                                       |
| triage_acquisition_hashlist.csv | This file contains the calculated hash value for all data collected by DFIRtriage. This information can be used to verify integrity of the output data. |


<br>

| ForensicImages \ hdd | Analysis Notes                                                                                                                  |
|----------------------|---------------------------------------------------------------------------------------------------------------------------------|
| .E01, .dd, etc       | The triage script does not acquire a file system image. This folder is here for organizational purposes should one be acquired. |



<br>


| ForensicImages \ memory | Analysis Notes                                                                                                                                                                                                 |
|-------------------------|----------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------|
| memdump.raw             | memdump.raw is a full raw image of volatile memory which should be acquired before a shutdown or reboot of the target machine. Multiple memory analysis tools should be used for cross-validation of findings. |


<br>


| ForensicImages \ system-files | Analysis Notes                                                                                |
|-------------------------------|-----------------------------------------------------------------------------------------------|
| hiberfil.sys                  | Hiberfil.sys is a compressed RAM image created during a system hibernation event.             |
| pagefile.sys                  | Pagefile.sys stores data that would normally be written to RAM when no RAM is available.      |
| srudb.dat                     | Srudb.dat contains system usage information collected by SRUM (System Usage Resource Monitor) |



<br>


| LiveResponseData \ filesystem | Analysis Notes                                                                                                                                                                                                   |
|-------------------------------|------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------|
| Alternate_data_streams.txt    | Contains all files on the target system that contain alternate data stream content.  Alternate data streams can be used to easily hide information, or even entire files while remaining undetected by the user. |
| full_file_list.csv.zip        | This report is very helpful in determining if a known folder or file is present on the target system.                                                                                                            |
| List_hidden_directories.txt   | Log of all directories that have been hidden from the User. This log should be reviewed for suspicious hidden directories in unusual locations (e.g. in user temp folders)                                       |
| psfile.txt                    | Review information to determine if there are any files opened remotely on the target host.                                                                                                                       |
| shadow_files.txt              | Provides details on volume shadow points available on the target system.                                                                                                                                         |



<br>


| LiveResponseData \ hashes | Analysis Notes                                                                                                                                                                                                                                      |
|---------------------------|-----------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------|
| hash-report.csv           | Provides an MD5, SHA-1, or SHA-256 hash value of all accessible EXE and DLL files on the target system if an argument is passed (eg. -sha256).   Data can be reviewed for suspicious filenames and hash values can be used to search IOC databases. |



<br>


| LiveResponseData \ logs               | Analysis Notes                                                                                                                                                                                                                                                                                                                                                                                |
|---------------------------------------|-----------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------|
| BrowsingHistoryView.csv               | Offers a quick review of browser activity. Will contain information from IE, Chrome, Firefox, and Safari if available. The -bho argument can be used when executing to force a browser history “only” acquisition.                                                                                                                                                                            |
| eventlogs_key_events.csv              | There are a total of 96 select events total from the application, system, security, and PowerShell event logs and this log file is generated by default.                                                                                                                                                                                                                                      |
| eventlogs-all.csv                     | Contains parsed data from all events in the Application, System, Security, and Powershell event logs.  Created by the “-elpa, --evtlogparseall” command line argument.                                                                                                                                                                                                                        |
| firewall_events.csv                   | This log contains all Windows Firewall modification events (Levels 0, 2, 4).                                                                                                                                                                                                                                                                                                                  |
| rdp_logon_logoff_events.csv           | Contains all Remote Desktop logon and logoff events from the Windows Terminal Services Local Session Manager event logs.                                                                                                                                                                                                                                                                      |
| vhd_mount_log.csv                     | This log will show details on image files (eg. ISO files) mounted on the system.                                                                                                                                                                                                                                                                                                              |
| EVTX files                            | If the “-elf, --eventlogfiles” argument is used, full copies of the Application, System, Security, Powershell, & Firewall event logs will be acquired.                                                                                                                                                                                                                                        |
| powershell_command_history_<user>.txt | Contains Powershell command history for all users if available.                                                                                                                                                                                                                                                                                                                               |

<br>

| LiveResponseData \ Network    | Analysis Notes                                                                                                                                                                                                                   
| -------------------------------------- | ---------------- |                                                                                                                                                                                                           
| ARP.txt                       | This file contains the ARP cache from the target system. While the ARP protocol is not routable to the internet, it can help to identify additional hosts on a network that may have been compromised or that may have been used to launch the internal attack.                                                                                                                              |
| cports.html                   | This is a very detail report showing TCP/UDP connections on the target host. Additionally, you have information on the process that created the connection (name, PID, etc.), the Window Title (if exists), and more.                                                                                                                                                                         |
| DNS_cache.txt                 | This is a log file of the target system DNS cache. Malware generally can connect to the network in order to do things like gathering additional exploits, join a command & control infrastructure, wait for more commands, etc. It is common for malware to be coded with domain names which must queried and resolved before it can connect. This information can be found in the DNS cache. |
| hosts.txt                     | This is a copy of the contents of the system HOSTS file                                                                                                                                                                                                                                                                                                                                       |
| Internet_settings.txt         | This is a log of the local network adapter configuration on the target host. This log should be reviewed to ensure the settings are correct and have not been altered. (E.g. Suspicious domains added to the DNS Suffix Search List)                                                                                                                                                          |
| NetBIOS_sessions.txt          | This file will contain information on any current NetBIOS sessions to the target host.                                                                                                                                                                                                                                                                                                        |
| NetBIOS_transferred_files.txt | This log will show if any files were transferred over the network from the target host using the “net file” command.                                                                                                                                                                                                                                                                          |
| Open_network_connections.txt  | This file also contains TCP/UDP connection information. The process PID and connection state information is also available. While it may seem redundant, it is essential to identify current and recent network activity. Some of these tools may capture information that the others miss. All findings should be validated.                                                                 |
| routing_table.txt             | This file contains the routing table of the target host. This information should be reviewed to ensure it has not been modified with additional routes or a modified gateway. Comparing this information to the routing table from a known good machine may be helpful.                                                                                                                       |
| Tcpvcon.txt                   | Additional information on network connections from target host. Contains protocol type (TCP/UDP), process name, PID, state, local address, and remote address.                                                                                                                                                                                                                                |


<br>

| LiveResponseData \ Network \ WLAN | Analysis Notes                                                                                                                                                                                                                                                      |
|-----------------------------------|---------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------|
| wlan-report-latest.html           | This is a wireless network report showing all Wi-Fi events from the last three days and groups them by Wi-Fi connection sessions. It also shows the results of several network-related command line scripts and a list of all the network adapters on the endpoing. |



<br>


| LiveResponseData \ persistence | Analysis Notes                                                                                                                                                                                                                                                                                                                         |
|--------------------------------|----------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------|
| autorunsc.txt                  | This information will show all the programs that Windows will automatically execute when starting up. This is a very common method used by malware to maintain persistence on a system. This data can be reviewed for suspicious file names and paths.                                                                                 |
| Loaded_dlls.txt                | This file contains a process listing which includes all loaded DLLs for each running process. Persistence can be gained by injecting a malicious DLL into a normal Windows process. This data should be examined for suspicious DLLs. It is very helpful to have a list of loaded DLLs from a known good system to use for comparison. |
| scheduled_tasks.txt            | This file contains all scheduled tasks found on the target system. Inserting a scheduled task into the target host is a common method used by malware to maintain persistence on the victim machine. This information should be reviewed for suspicious tasks.                                                                         |
| services_aw_processes.txt      | This file provides a list of services running on the target system, with the associated process name and PID. Rogue services are another persistence mechanism that can be utilized by malware.                                                                                                                                        |



<br>


| LiveResponseData \ prefetch  | Analysis Notes                                                                                                                                                                                                                                                               |
|------------------------------|------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------|
| parsed-prefetch.txt          | This file contains parsed data from the prefetch files collected from the target system. Information such as file name, modified, accessed, and created times, number of times executed, last run time, and all loaded DLLs and other dependent files used during execution. |


<br>

| LiveResponseData \ prefetch \ raw | Analysis Notes                                                                                                                                                                                                                                                                                                                                     |
|-----------------------------------|----------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------|
| .pf                               | The “raw” subdirectory contains the raw prefetch files found on the target system. This data is collected and then parsed later in the DFIRtriage process. The filenames of the prefetch files will give you an indication of which programs where recently executed. Especially useful if you already have a binary name from an external source. |



<br>


| LiveResponseData \ processes | Analysis Notes                                                                                                                                                                                                                                                                                       |
|------------------------------|------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------|
| running_processes.csv        | This report provides details on all processes currently running in memory.  The PID and PPID information helps to determine the order in which the processes occur in memory as well as the spawning or parent process.  In addition, it provides the full command line used to execute the process. |



<br>


| LiveResponseData \ registry | Analysis Notes                                   |
|-----------------------------|--------------------------------------------------|
| *-parsed.txt                | Regripper output for each of the registry hives. |



<br>

| LiveResponseData \ registry \ raw | Analysis Notes                                                                                                                                                                                                                                                                                                                                                                                                                                                  |
|-----------------------------------|-----------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------|
| NTUSER & USRCLASS                 | A copy of the user registry hives NTUSER.dat and USRCLASS.dat are acquired for all user profiles found on the target system.  These user registry files contain information on general user behavior such as recently viewed documents, typed URLs, mount points, mapped drives, local search terms, uninstalled software, and more. These files can be parsed with Regripper for easier analysis.                                                              |
| SAM                               | A copy of the Security Accounts Manager registry hive (SAM) from the target system.  The SAM registry file contains local user and group information such as Security Identifiers (SID) for local accounts and groups, account and group creation and deletion information. This file can be parsed with Regripper for easier analysis.                                                                                                                         |
| SECURITY                          | A copy of the Security registry hive (SECURITY) from the target system. The SECURITY registry hive contains account and system security information such as local security policies, user rights assignments, password policies, and more. The SECURITY hive is linked to the SAM hive for update accuracy. This file can be parsed with Regripper for easier analysis.                                                                                         |
| SOFTWARE                          | A copy of the Software registry hive (SOFTWARE) from the target system. The SOFTWARE registry hive contains information about installed software, uninstalled software, file extension associations, last logged on user, and more. This file can be parsed with Regripper for easier analysis.                                                                                                                                                                 |
| SYSTEM                            | A copy of the System registry hive (SYSTEM) from the target system. The SYSTEM registry hive contains information specific to the software and hardware configuration of the target system. For example, the SYSTEM registry contains system startup parameters, device driver configurations, hardware configurations, time zone settings, computer names, USB connections and pointers, and more. This file can be parsed with Regripper for easier analysis. |



<br>


| LiveResponseData \ system | Analysis Notes                                                                                                                                                                                                                            |
|---------------------------|-------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------|
| Bitlocker_key.txt         | This file contains the bitlocker recovery keys found on the endpoint.  Created by the “-bl, --bitlocker” command line argument.                                                                                                           |
| firewall_config.txt       | An export of all configured Windows Firewall rules                                                                                                                                                                                        |
| system_info.txt           | Detailed target system information.                                                                                                                                                                                                       |
| Windows_codepage.txt      | This file contains the active code page identifier on the target system. The typical North America EHI build should have a code page value of “437”. This is typically not an issue but modifying this value will cause data corruption.  |
| Windows_Version.txt       | Contains the version of Windows running on the target system.                                                                                                                                                                             |
| WindowsUpdate.log         | The Windows update log is no longer created by the system as of Windows 10, so we’re building it from converted event trace log (ETL) data.                                                                                               |



<br>


| LiveResponseData \ usbdevices \ usb-install-logs | Analysis Notes                                                                                                                                                                                                                             |
|--------------------------------------------------|--------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------|
| setupapi.*.log                                   | This is a copy of all device installation logs from the target system.  These logs, in correlation with the SYSTEM registry hive, can be used to determine the first time a removable device (e.g. USB drive) was plugged into the system. |
| PsLoggedon.txt                                   | Use this information to help identify any users (local or remote) who are authenticated to target system.                                                                                                                                  |



<br>


| LiveResponseData \ user | Analysis Notes                                                                                                                                   |
|-------------------------|--------------------------------------------------------------------------------------------------------------------------------------------------|
| List_users.txt          | This file simply contains a list of all local user accounts found on the target system. This file can be reviewed for suspicious local accounts. |
| Local_user_list.txt     | A list of all local user accounts.                                                                                                               |
| LastActivityView.html   | An HTML report of recent user activity.                                                                                                          |
| PsLoggedon.txt          | Use this information to help identify any users (local or remote) who are authenticated to target system.                                        |
| user_acct_report.txt    | Provides local & domain usernames, profile paths, account SID, etc.                                                                              |



<br>









## EVENT ID REFERENCE

|   |   |   |
|---|---|---|
|**Event Log**|**Event ID**|**Description**|
|SECURITY|1102|user cleared security log; this is logged regardless of audit policy|
|SECURITY|4616|System time was changed|
|SECURITY|4624|successful logon|
|SECURITY|4625|failed logon|
|SECURITY|4634|Logoff|
|SECURITY|4647|User initiated logoff|
|SECURITY|4648|RunAs usage, privilege escalation, lateral movement|
|SECURITY|4649|Replay attack|
|SECURITY|4662|An operation was performed on an object|
|SECURITY|4672|Special privileges attempted login|
|SECURITY|4697|service creation, details will contain service image name (e.g. psexec), persistence|
|SECURITY|4698|Scheduled task created, potential for persistence|
|SECURITY|4722|a user account was enabled|
|SECURITY|4724|user account password reset attempt|
|SECURITY|4728|member added to security-enabled global group|
|SECURITY|4732|user added to privileged local group|
|SECURITY|4735|security-enabled local group was changed|
|SECURITY|4738|a user account was changed|
|SECURITY|4756|a member was added to a security-enabled universal group|
|SECURITY|4768|Kerberos TGT request|
|SECURITY|4769|Kerberos service ticket requested|
|SECURITY|4713|Kerberos policy was changed|
|SECURITY|4770|Kerberos service ticket renewal|
|SECURITY|4771|Kerberos pre-auth failed|
|SECURITY|4634, 4647|successful logoff|
|SECURITY|4672|account logon with superuser rights _(I.e. administrator)_|
|SECURITY|4776|Domain controller validation attempt|
|SECURITY|4778|an RDP session was reconnected as opposed to a fresh logon seen by event 4624|
|SECURITY|4688|new process created (includes exe path); process exit|
|SECURITY|4699|scheduled task was deleted|
|SECURITY|4700|scheduled task was enabled|
|SECURITY|4701|scheduled task disabled|
|SECURITY|4702|scheduled task was updated|
|SECURITY|4720|an account was created|
|SECURITY|4722|A user account was enabled|
|SECURITY|4723|An attempt was made to change an account’s password|
|SECURITY|4724|An attempt was made to reset an account’s password|
|SECURITY|4725|A user account was disabled|
|SECURITY|4726|A user account was deleted|
|SECURITY|4735, 4737, 4755, 4764|Group creations|
|SECURITY|4738|A user account was changed|
|SECURITY|4740|A user account was locked out|
|SECURITY|4741|A computer account was created|
|SECURITY|4742|A computer account was changed|
|SECURITY|4743|A computer account was deleted|
|SECURITY|4765, 4766|SID history|
|SECURITY|4767|A user account was unlocked|
|SECURITY|4776|account logon success/fail, can identify auth for a mapped drive|
|SECURITY|4779|an RDP session was disconnected as opposed to a logoff seen by events 4647 or 4634|
|SECURITY|4780|ACL set on accounts|
|SECURITY|4798|a user's local group membership was enumerated|
|SECURITY|4799|a security-enabled local group membership was enumerated|
|SECURITY|4800|Workstation locked|
|SECURITY|4801|Workstation unlocked|
|SECURITY|4802|Screensaver was invoked|
|SECURITY|4803|Screensaver was dismissed|
|SECURITY|4821|Kerberos service ticket was denied|
|SECURITY|4822, 4823|NTLM authentication failed|
|SECURITY|4824|Kerberos pre-authentication failed|
|SECURITY|4825|User denied access to Remote Desktop|
|SECURITY|4886|Certificate Services received a certificate request|
|SECURITY|4887|Certificate Services approved a certificate requeset|
|SECURITY|4899|Certificate Services template was updated|
|SECURITY|4900|Certificate Services template security was updated|
|SECURITY|5058|Key file operation|
|SECURITY|5059|Key migration operation|
|SECURITY|5140|network share was accessed|
|SECURITY|5145|shared object was accessed|
|SECURITY|7034|service crashed unexpectedly|
|SECURITY|7036|service started or stopped|
|SECURITY|7040|service start type changed (boot \| on request \| disabled)|
|APPLICATION|1022|new MSI file installed.|
|APPLICATION|1033|program installed using MSI installer|
|APPLICATION|1034|application removal complete (success/failure status)|
|APPLICATION|11707|installation completed successfully|
|APPLICATION|11708|installation operation failed|
|APPLICATION|11724|application removal completed successfully|
|APPLICATION|1000|Application crash/hang events, like WER/1001 and include full path to faulting EXE/Module|
|APPLICATION|1001, 1002|WER events for application crashes only|
|APPLICATION|1511|User logging on with temporary profile|
|APPLICATION|1518|Cannot create profile using temporary profile|
|SYSTEM|6|new kernel filter driver possible indication of kernel-mode rootkit installation|
|SYSTEM|104|user cleared system log OR application log _(note: clearing application log creates event in system log, not app log)_|
|SYSTEM|7035|successful start OR stop control was sent to a service|
|SYSTEM|7045|new Windows service was installed|
|POWERSHELL/OPERATIONAL|600|Powershell command executed|
|POWERSHELL/OPERATIONAL|4105, 4106|Powershell script start/stop|
|POWERSHELL/OPERATIONAL|4103|Powershell executes block activity|
|POWERSHELL/OPERATIONAL|4104|Remote command|
|MICROSOFT-WINDOWS-VHDMP|1|Surface Disk - Shows when a virtual drive image file is mounted.  _Eg. “The VHD C:\Users\<USER>\AppData\Local\Temp\1\Temp1_KYC_BP12(Dec15).zip\KYC#BP12.img has come online (surfaced) as disk number 0.”_|
|WINDOWS FIREWALL WITH ADVANCED SECURITY|2004, 2005, 2006, 2009, 2033|Local Modifications (Levels 0, 2, 4)|


