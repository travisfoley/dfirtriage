# dfirtriage
Digital forensic acquisition tool for Windows based incident response.

How to Use
=
To run, place dfirtriage.exe and core.ir in the same directory on the target and execute dfirtriage.exe with admin rights. 

***************************************************************************************

DFIRTriage v2.4 User's Manual
=
Description
-
This document outlines the functionality and proper use of the DFIRTriage tool. Also included is detailed information to help with analysis of the output.  

About
-
DFIRTriage is a python script intended to provide Incident Responders with rapid host data. The python code has been compiled to eliminate the dependency of python on the target host. The tool will run a variety of commands automatically upon execution. The acquired data will reside in the root of the execution directory. DFIRTriage may be ran from a USB drive or executed in remote shell on the target. Windows-only support. 

What’s New?
-
 * MD5 integrity check
 * Debug mode to bypass code blocks that perform lengthier analysis to speed up script testing.
 * Parsing out specific event log entries. This code has been written so it is easy to add or remove event IDs for future modifications. 
   We are now parsing out 15 specific events from the Event logs. These events are indicate remote connections, possible lateral movement,    privilege escalation, service creation, scheduled tasks for possible persistence, and program installation.
 * Console color has been added to help differentiate between normal, warning, and error states. (Applies to local execution only)
 * Corrected issues with alternate data stream location code
 * Parsing registry hives 

Dependencies
-
The tool repository contains the full toolset required for proper execution and is packed into a single a single file named “core.ir”. This “.ir” file is the only required dependency of DFIRTriage. DFIRTriage is packaged in a zip archived with the following naming convention – “DFIRTriage-pub_2.4.zip”, which contains all of the files required for normal operation.  Please note that the demo version of select TZWorks tools are used in the public release of DFIRTriage. Licensed copies may be purchased at www.tzworks.com. 

Contents
-
 * DFIRTriage.exe 
   - compiled executable
 * core.ir
   - tool set repository (required)
 * manifest.txt
   - hash list for core components
 * unlicense.txt
   - copy of license agreement
 * source directory
   - DFIRTriage-pub_2.4.py

Operation
-
DFIRTriage acquires data from the host on which it is executed. For acquisitions of remote hosts, the DFIRTriage files will need to be copied to the target, then executed via remote shell. (ie. SSH or PSEXEC)  

PSEXEC Usage
-
WARNING: Do not use PSEXEC arguments to pass credentials to a remote system for authentication. Doing so will send your username and password across the network in the clear.  

The following steps should be taken for proper usage of PSEXEC: 
1. Map a network drive and authenticate with an account that has local administrative privileges on the target host. 
   a. You can used this mapped connection to copy the DFIRTriage zip file over to the target host and extract the files to a temp directory. 
2. We can now shovel a remote shell to the target host using PSEXEC. 
   psexec \\<target_host> cmd 
3. You now have a remote shell on the target. All commands executed at this point are done so on the target host. 


Usage
-

1. Once the remote shell has been established on the target you can change directory to the location of the extracted DFIRTriage.exe file and execute.  

NOTE: If running locally and physically at the console of a workstation, DFIRTriage must be executed with Administrative privileges.

2. Immediately after execution, you will be prompted for memory acquisition.
3. Press “y” or “n” and then hit ENTER to continue. 

Output Analysis
-
Once the script has completed, you should find DFIRTriage, core.ir, and an output directory beginning with the hostname of the target.  

Output Folder
-
The output folder name includes the target hostname and a date/time code indicating when DFIRTriage was executed.  The date/time code format is YYYYMMDDHHMMSS.    

Artifacts List
=
The following is a general listing of the information and artifacts gathered.  


* Memory Raw --> image acquisition (optional) 

* Prefetch --> Collects all prefetch files an parses into a report 

* User activity --> HTML report of recent user activity 

* System32 file hash --> MD5 hash of all files in root of System32 

* Network information --> Network configuration, routing tables, etc 

* Extended process list --> Processes, PID, and image path 

* Windows character code page information --> Character set that Windows is using 

* Complete file listing --> Full list of all files on the system partition 

* List of hidden directories --> List of all hidden directories on the system partition 

* Current user information --> User running DFIRTriage script 

* System information --> Build, service pack level, installed patches, etc 

* Windows version --> Logs the version number of the target OS 

* Current date and time --> Current system date and time 

* List of scheduled tasks --> List of all configured scheduled tasks 

* Loaded processes and dlls --> List of all running processes and loaded dlls 

* Running processes --> Additional information on running processes 

* Network configuration --> Network adaptor configuration 

* Network connections --> Established network connections 

* Open TCP/UDP ports --> Active open TCP or UDP ports 

* DNS cache entries --> List of complete DNS cache contents 

* ARP table information --> List of complete ARP cache contents 

* Local user account names --> List of local user accounts 

* NetBIOS information --> Active NetBIOS sessions, transferred files, etc 

* Installed software --> List of all installed software through WMI 

* Autorun information --> All autorun locations and content 

* List of remotely opened files --> Files on target system opened by remote hosts 

* Logged on users --> All users currently logged on to target system 

* Alternate Data Streams --> List of files containing alternate data streams 

* Registry hives --> Copy of all registry hives 

* USB artifacts --> Collects data needed to parse USB usage info 

* Hash of all collected triage data --> MD5 hash of all data collected by DFIRTriage 
