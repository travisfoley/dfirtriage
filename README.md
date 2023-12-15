# **dfirtriage**
Digital forensic acquisition tool for Windows-based incident response.

How to Use
=
To run, drop dfirtriage.exe on the target and execute with admin rights, "-h" for help.

TEST

***************************************************************************************

**DFIRTriage v5.0 User's Manual**
=

Description
-----------

This document outlines the functionality and proper use of the DFIRtriage tool. Also included is detailed information to help with analysis of the output. The goal is to equip the Incident Responder with the tools needed to gather and analyze data quickly, to assist with accurate and timely escalation decisions.  

About
-----

DFIRtriage is an incident response tool designed to provide the Incident Responder with rapid host data. Upon execution, select host data and information will be gathered and placed into the execution directory.  DFIRtriage may be ran from a USB drive or executed remotely on the target host.   

What’s New?
-----------

*Updates*
- Powershell event logs are now parsed with the "parse all" option (-elpa, --evtlogparseall)
- Added headless argument (-hl) that bypasses the end prompt for SOC automation support
- Collection of user registry files (NTUSER.DAT & USRCLASS.DAT) for all user profiles on system
- SRUM database file now collected
- DFIRtriage search tool (dtfind.exe) now bundled with DFIRtriage.exe for a more fluid user experience
- Launching dtfind.exe will automatically export the LiveResponseData.zip content and present a prompt for immediate content searches
- Parsing select Windows events by default, argument no longer required 

*Fixes*
- Fixed issue where memory dumps fail due to Windows 10 security updates
- Preventing issues with output data size by skipping memory dump when system files is selected
- Fixed issue where the parsed output of the NTUSER.DAT registry files were empty
- Fixed issue with full Eventlog file collection and restored the -elf argument
- Fixed issue with memory only (-mo, --memonly) argument ignoring low disk space check exiting if insufficient free space
- Updated all embedded utilities with latest version
- Removed functions that gathered overlapping network connection information
- Fixed issue where tool crashes running Event log parsing argument (-elp)
- Logged-in user information is now captured and added to Triage-info.txt for all supported versions of the Windows OS
- Code cleanup


Dependencies
-
The tool repository contains the full toolset required for proper execution and is packed into a single a single file named “core.ir”. This “.ir” file is the only required dependency of DFIRtriage when running in Python and should reside in a directory named data, (ie. "./data/core.ir").  The compiled version of DFIRtriage has the full toolset embedded and does not require the addition of the "./data/core.ir" file.  NOTE: TZWorks utilities are no longer utilized.   

Contents
-
 * DFIRtriage.exe 
   - compiled executable
 * .\data\core.ir
   - tool set repository (required for Python version only)
 * manifest.txt
   - file hashes for core components
 * unlicense.txt
   - copy of license agreement
 * source directory
   - all source code
 * dtfind.exe 
   - compiled search tool executable

Operation
-
DFIRtriage acquires data from the host on which it is executed. For acquisitions of remote hosts, the DFIRtriage files will need to be copied to the target, then executed via remote shell. (ie. SSH or PSEXEC)  

PSEXEC Usage
-
*WARNING: Do not use PSEXEC arguments to pass credentials to a remote system for authentication. Doing so will send your username and password across the network in the clear.*  

**The following steps should be taken for proper usage of PSEXEC** 

 1. Map a network drive and authenticate with an account that has local administrative privileges on the target host.
> You can used this mapped connection to copy DFIRtriage to the target.

 2. We can now shovel a remote shell to the target host using PSEXEC.

    psexec \\target_host cmd

 3. You now have a remote shell on the target. All commands executed at this point are done so on the target host. 


Usage

1. Once the remote shell has been established on the target you can change directory to the location of the extracted DFIRtriage.exe file and execute. 

2. Memory acquisition occurs by default, no arguments needed.  To bypass memory acquisition, the "--nomem" argument can be passed. 

3. DFIRtriage must be executed with Administrative privileges.


Output Analysis
-
Once complete, press enter to cleanup the output directory. If running the executable, the only data remaining with be a zipped archive of the output as well as DFIRtriage.exe. If running the Python code directly only DFIRtriage python script and a zipped archive of the output are left.   

Output Folder
-
The output folder name includes the target hostname and a date/time code indicating when DFIRtriage was executed.  The date/time code format is YYYYMMDDHHMMSS.    

Artifacts List
=
The following is a general listing of the information and artifacts gathered.  

* **Memory Raw** --> image acquisition (optional) 

* **System information** --> build, service pack level, installed patches, etc

* **Prefetch** --> Collects all prefetch files an parses into a report 

* **PowerShell command history** --> Gathers PowerShell command history for all users 

* **User activity** --> HTML report of recent user activity 

* **File hash** --> MD5 hash of all files in root of System32 

* **Network information** --> Network configuration, routing tables, etc 

* **Network connections** --> Established network connections 

* **DNS cache entries** --> List of complete DNS cache contents 

* **ARP table information** --> List of complete ARP cache contents 

* **NetBIOS information** --> Active NetBIOS sessions, transferred files, etc 

* **Windows Update Log** --> Gathers event tracelog information and builds Windows update log 

* **Windows Defender Scanlog** --> Gathers event tracelog information and builds Windows update log 

* **Windows Event Logs** --> Gathers and parses Windows Event Logs 

* **Process information** --> Processes, PID, and image path 

* **List of remotely opened files** --> Files on target system opened by remote hosts 

* **Local user account names** --> List of local user accounts 

* **List of hidden directories** --> List of all hidden directories on the system partition 

* **Alternate Data Streams** --> List of files containing alternate data streams 

* **Complete file listing** --> Full list of all files on the system partition 

* **List of scheduled tasks** --> List of all configured scheduled tasks 

* **Hash of all collected data** --> MD5 hash of all data collected by DFIRtriage

* **Installed software** --> List of all installed software through WMI 

* **Autorun information** --> All autorun locations and content 

* **Logged on users** --> All users currently logged on to target system 

* **Registry hives** --> Copy of all registry hives 

* **USB artifacts** --> Collects data needed to parse USB usage info 

* **Browser History** --> browser history collection from multiple browsers

