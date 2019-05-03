# **dfirtriage**
Digital forensic acquisition tool for Windows-based incident response.

How to Use
=
To run, drop dfirtriage.exe on the target and execute with admin rights. 

***************************************************************************************

**DFIRTriage v4.0.0 User's Manual**
=

Description
-----------

This document outlines the functionality and proper use of the DFIRtriage tool. Also included is detailed information to help with analysis of the output.  

About
-----

DFIRtriage is a tool intended to provide Incident Responders with rapid host data. Written in Python, the code has been compiled to eliminate the dependency of python on the target host. The tool will run a variety of commands automatically upon execution. The acquired data will reside in the root of the execution directory. DFIRTriage may be ran from a USB drive or executed in remote shell on the target. Windows-only support. 

What’s New?
-----------

*General
- Efficiency updates were made to the code improving flow, cleaning up bugs, and providing performance improvements.
- Cleaned up the output directory structure
- Removed TZworks tools from toolset avoiding licensing issues
- Added commandline arguments for new functionality (run "DFIRtriage --help" for details) 

*Memory acquisition
- memory is now acquired by default
- argument required to bypass memory acquisition
- free space check conducted prior to acquiring memory
- updated acquisition process to avoid Windows 10 crashes

*New artifacts
- windowsupdate.log file
- Windows Defender scan logs
- PowerShell command history
- HOSTS files
- netstat output now includes associated PID for all network connections
- logging all users currently logged in to the target machine to the Triage_info.txt file
- Pulling dozens of new events from the Windows Event logs

*New! DFIRtriage search tool
- Conducts keyword search across DFIRtriage output data and writes findings to log file
- The search tool is a separate executable (dtfind.exe)
- Double-click to run or run from the command line (eg. dtfind -kw badstuff.php)


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
   - DFIRtriage-v4-pub.py
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
Once complete, press enter to cleanup the output directory. If running the executable, the only data remaining with be a zipped archive of the output as well as DFIRtriage.exe. If running the Python code directly only DFIRtriage-v4-pub.py and a zipped archive of the output are left.   

Output Folder
-
The output folder name includes the target hostname and a date/time code indicating when DFIRtriage was executed.  The date/time code format is YYYYMMDDHHMMSS.    

Artifacts List
=
The following is a general listing of the information and artifacts gathered.  

* **Memory Raw** --> image acquisition (optional) 

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

